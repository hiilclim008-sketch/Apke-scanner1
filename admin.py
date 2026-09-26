import time
from datetime import datetime, timezone
from config import ADMIN_CHAT_ID

# Global stats (shared with app.py / scanner.py)
START_TIME = time.time()
TOTAL_SCANS = 0


def is_admin(chat_id: int) -> bool:
    return chat_id == ADMIN_CHAT_ID


def get_stats() -> str:
    uptime_sec = int(time.time() - START_TIME)
    hours, rem = divmod(uptime_sec, 3600)
    minutes, seconds = divmod(rem, 60)

    return (
        "🛡 <b>Admin Panel</b>\n"
        "────────────────────\n"
        f"⏱ Uptime: <code>{hours}h {minutes}m {seconds}s</code>\n"
        f"📁 Total files scanned: <b>{TOTAL_SCANS}</b>\n"
        f"📅 Server time (UTC): <code>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}</code>\n"
        "────────────────────\n"
        "Developed by @incognito_4041"
    )


def increment_scan_count():
    global TOTAL_SCANS
    TOTAL_SCANS += 1
