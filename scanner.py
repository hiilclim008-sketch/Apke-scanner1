import re
import zipfile
import io
import json
from typing import Dict, List, Any
from datetime import datetime, timezone

# ──────────────────────────────────────────────
# Permission → emoji + risk mapping (basic)
# ──────────────────────────────────────────────
PERMISSION_MAP = {
    "android.permission.READ_SMS":          ("🔴", "READ_SMS", "High Risk"),
    "android.permission.RECEIVE_SMS":       ("🔴", "RECEIVE_SMS", "High Risk"),
    "android.permission.SEND_SMS":          ("🔴", "SEND_SMS", "High Risk"),
    "android.permission.READ_CONTACTS":     ("🔴", "READ_CONTACTS", "High Risk"),
    "android.permission.WRITE_CONTACTS":    ("🔴", "WRITE_CONTACTS", "High Risk"),
    "android.permission.ACCESS_FINE_LOCATION": ("🟠", "ACCESS_FINE_LOCATION", "Medium"),
    "android.permission.ACCESS_COARSE_LOCATION": ("🟠", "ACCESS_COARSE_LOCATION", "Medium"),
    "android.permission.CAMERA":            ("🟠", "CAMERA", "Medium"),
    "android.permission.RECORD_AUDIO":      ("🟠", "RECORD_AUDIO", "Medium"),
    "android.permission.INTERNET":          ("✅", "INTERNET", "Normal"),
    "android.permission.ACCESS_NETWORK_STATE": ("✅", "ACCESS_NETWORK_STATE", "Normal"),
    "android.permission.WAKE_LOCK":         ("✅", "WAKE_LOCK", "Normal"),
}

# Telegram Bot Token & Chat ID patterns
TOKEN_REGEX = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")
CHAT_ID_REGEX = re.compile(r"\b-?\d{6,15}\b")


def extract_permissions_from_manifest(manifest_bytes: bytes) -> List[Dict[str, str]]:
    """Very lightweight mock parser – looks for permission strings."""
    text = manifest_bytes.decode("utf-8", errors="ignore")
    found = []
    for perm, (icon, name, risk) in PERMISSION_MAP.items():
        if perm in text or name in text:
            found.append({
                "icon": icon,
                "name": name,
                "risk": risk,
                "riskClass": "high" if "High" in risk else ("medium" if "Medium" in risk else "normal")
            })
    # Always show INTERNET as fallback if nothing found
    if not found:
        found.append({"icon": "✅", "name": "INTERNET", "risk": "Normal", "riskClass": "normal"})
    return found


def scan_for_secrets(file_bytes: bytes, filename: str) -> List[Dict[str, str]]:
    """Scan whole file (and inside APK assets) for Telegram tokens / chat IDs."""
    secrets = []
    text = file_bytes.decode("utf-8", errors="ignore")

    # Direct scan
    for m in TOKEN_REGEX.finditer(text):
        secrets.append({"label": "Telegram Bot Token", "value": m.group(0)})
    for m in CHAT_ID_REGEX.finditer(text):
        # filter obvious non-chat-ids (too short / too long already handled by regex)
        val = m.group(0)
        if len(val) >= 8:
            secrets.append({"label": "Possible Chat ID", "value": val})

    # If APK → also look inside assets/
    if filename.lower().endswith(".apk"):
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                for name in zf.namelist():
                    if name.startswith("assets/") and not name.endswith("/"):
                        try:
                            content = zf.read(name)
                            content_str = content.decode("utf-8", errors="ignore")
                            for m in TOKEN_REGEX.finditer(content_str):
                                secrets.append({"label": f"Token in {name}", "value": m.group(0)})
                            for m in CHAT_ID_REGEX.finditer(content_str):
                                if len(m.group(0)) >= 8:
                                    secrets.append({"label": f"Chat ID in {name}", "value": m.group(0)})
                        except Exception:
                            continue
        except zipfile.BadZipFile:
            pass

    # Deduplicate
    seen = set()
    unique = []
    for s in secrets:
        key = (s["label"], s["value"])
        if key not in seen:
            seen.add(key)
            unique.append(s)
    return unique[:15]  # limit


def scan_apk(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    permissions = []
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            # Try to find AndroidManifest.xml (binary or text)
            for name in zf.namelist():
                if name.endswith("AndroidManifest.xml"):
                    permissions = extract_permissions_from_manifest(zf.read(name))
                    break
    except zipfile.BadZipFile:
        permissions = [{"icon": "⚠️", "name": "Invalid APK", "risk": "High Risk", "riskClass": "high"}]

    secrets = scan_for_secrets(file_bytes, filename)
    threats = len(secrets) > 0 or any(p["riskClass"] == "high" for p in permissions)

    return {
        "fileName": filename,
        "threatsDetected": threats,
        "secrets": secrets,
        "permissions": permissions,
        "raw": {"type": "apk", "size": len(file_bytes)}
    }


def scan_html(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    secrets = scan_for_secrets(file_bytes, filename)
    text = file_bytes.decode("utf-8", errors="ignore").lower()

    # Simple HTML heuristics
    findings = []
    if "telegram" in text or "bot" in text:
        findings.append({"icon": "🔴", "name": "Telegram-related script", "risk": "High Risk", "riskClass": "high"})
    if re.search(r"<form[^>]*action", text):
        findings.append({"icon": "🟠", "name": "Credential form detected", "risk": "Medium", "riskClass": "medium"})
    if "eval(" in text or "atob(" in text:
        findings.append({"icon": "🟠", "name": "Obfuscated JS", "risk": "Medium", "riskClass": "medium"})
    if not findings:
        findings.append({"icon": "✅", "name": "No obvious malicious patterns", "risk": "Normal", "riskClass": "normal"})

    threats = len(secrets) > 0 or any(f["riskClass"] == "high" for f in findings)

    return {
        "fileName": filename,
        "threatsDetected": threats,
        "secrets": secrets,
        "permissions": findings,          # reuse same structure for frontend
        "raw": {"type": "html", "size": len(file_bytes)}
    }


def scan_file(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    lower = filename.lower()
    if lower.endswith(".apk"):
        return scan_apk(file_bytes, filename)
    elif lower.endswith((".html", ".htm")):
        return scan_html(file_bytes, filename)
    else:
        return {
            "fileName": filename,
            "threatsDetected": False,
            "secrets": [],
            "permissions": [{"icon": "⚠️", "name": "Unsupported file type", "risk": "Normal", "riskClass": "normal"}],
            "raw": {"type": "unknown"}
        }


def generate_txt_report(result: Dict[str, Any]) -> str:
    lines = [
        "ADVANCED MALWARE SCANNER — REPORT",
        "========================================",
        f"File: {result.get('fileName', 'unknown')}",
        f"Status: {'THREATS DETECTED' if result.get('threatsDetected') else 'CLEAN'}",
        f"Scanned by: @incognito_4041",
        f"Date: {datetime.now(timezone.utc).isoformat()}",
        "",
        "--- SECRETS & PHISHING ---",
    ]
    secrets = result.get("secrets") or []
    if secrets:
        for s in secrets:
            lines.append(f"{s['label']}: {s['value']}")
    else:
        lines.append("None detected.")

    lines.append("")
    lines.append("--- PERMISSIONS / FINDINGS ---")
    for p in result.get("permissions") or []:
        lines.append(f"[{p.get('risk', '?')}] {p.get('name', '')}")

    lines.extend([
        "",
        "========================================",
        "Security Scan by @incognito_4041",
        "Telegram: @incognito_4041",
        "Developed by @incognito_4041"
    ])
    return "\n".join(lines)


def generate_json_report(result: Dict[str, Any]) -> str:
    payload = {
        "meta": {
            "tool": "Advanced Malware Scanner",
            "developer": "@incognito_4041",
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        "result": result
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
