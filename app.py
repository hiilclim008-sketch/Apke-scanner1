import os
import io
import threading
import telebot
from telebot import types
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

from config import (
    BOT_TOKEN, ADMIN_CHAT_ID, FRONTEND_WEBSITE_URL,
    MAX_TELEGRAM_FILE_MB, MAX_WEB_FILE_MB
)
from admin import is_admin, get_stats, increment_scan_count
from scanner import scan_file, generate_txt_report, generate_json_report

# ──────────────────────────────────────────────
# Flask app + CORS
# ──────────────────────────────────────────────
app = Flask(__name__)
CORS(app)  # Allow requests from GitHub Pages / any origin
app.config["MAX_CONTENT_LENGTH"] = MAX_WEB_FILE_MB * 1024 * 1024

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")


# ─────────────── Web Routes ───────────────
@app.route("/ping")
def ping():
    """UptimeRobot / health check"""
    return "OK", 200


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Frontend uploads file here"""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    filename = secure_filename(f.filename)
    file_bytes = f.read()

    if len(file_bytes) > MAX_WEB_FILE_MB * 1024 * 1024:
        return jsonify({"error": f"File too large (max {MAX_WEB_FILE_MB}MB)"}), 400

    result = scan_file(file_bytes, filename)
    increment_scan_count()

    # Attach ready-to-download reports
    result["report_txt"] = generate_txt_report(result)
    result["report_json"] = generate_json_report(result)

    return jsonify(result)


# ─────────────── Telegram Bot Handlers ───────────────
@bot.message_handler(commands=["start"])
def cmd_start(message):
    markup = types.InlineKeyboardMarkup(row_width=1)
    markup.add(
        types.InlineKeyboardButton("🔗 Check Link / HTML", callback_data="check_html"),
        types.InlineKeyboardButton("📱 Check APK (< 20MB)", callback_data="check_apk"),
        types.InlineKeyboardButton("📦 Check Large APK (> 20MB)", url=FRONTEND_WEBSITE_URL),
    )
    bot.send_message(
        message.chat.id,
        "🛡 <b>Advanced Malware Scanner</b>\n"
        "Deep APK &amp; HTML Analysis\n\n"
        "Choose an option below:",
        reply_markup=markup
    )


@bot.message_handler(commands=["admin"])
def cmd_admin(message):
    if not is_admin(message.chat.id):
        bot.reply_to(message, "⛔ Access denied.")
        return
    bot.reply_to(message, get_stats())


@bot.callback_query_handler(func=lambda call: True)
def callback_handler(call):
    if call.data == "check_html":
        bot.answer_callback_query(call.id)
        bot.send_message(call.message.chat.id, "📄 Send me an HTML file or paste a suspicious link.")
    elif call.data == "check_apk":
        bot.answer_callback_query(call.id)
        bot.send_message(
            call.message.chat.id,
            "📱 Send me an APK file (max 20MB).\n"
            f"For larger files use the website:\n{FRONTEND_WEBSITE_URL}"
        )


@bot.message_handler(content_types=["document"])
def handle_document(message):
    doc = message.document
    file_name = doc.file_name or "unknown"
    file_size_mb = (doc.file_size or 0) / (1024 * 1024)

    # Size gate for Telegram
    if file_size_mb > MAX_TELEGRAM_FILE_MB:
        bot.reply_to(
            message,
            f"⚠️ File is <b>{file_size_mb:.1f} MB</b> (Telegram limit {MAX_TELEGRAM_FILE_MB}MB).\n\n"
            f"Please use the web scanner:\n{FRONTEND_WEBSITE_URL}"
        )
        return

    # Download
    try:
        file_info = bot.get_file(doc.file_id)
        downloaded = bot.download_file(file_info.file_path)
    except Exception as e:
        bot.reply_to(message, f"❌ Download failed: {e}")
        return

    bot.reply_to(message, "🔍 Scanning… please wait.")

    result = scan_file(downloaded, file_name)
    increment_scan_count()

    # Build short summary
    status = "🚨 <b>THREATS DETECTED</b>" if result["threatsDetected"] else "✅ <b>CLEAN</b>"
    secrets_count = len(result.get("secrets") or [])
    perms = result.get("permissions") or []

    summary = (
        f"{status}\n"
        f"📁 <code>{file_name}</code>\n"
        f"🔑 Secrets found: <b>{secrets_count}</b>\n"
        f"📋 Findings: <b>{len(perms)}</b>\n\n"
        "Full reports attached ⬇"
    )
    bot.send_message(message.chat.id, summary)

    # Generate & send report files
    txt_content = generate_txt_report(result)
    json_content = generate_json_report(result)

    bot.send_document(
        message.chat.id,
        io.BytesIO(txt_content.encode("utf-8")),
        visible_file_name="ScanReport_Amarjeet.txt",
        caption="📄 Text Report — Developed by @incognito_4041"
    )
    bot.send_document(
        message.chat.id,
        io.BytesIO(json_content.encode("utf-8")),
        visible_file_name="ScanReport_Amarjeet.json",
        caption="📦 Developer Data — Developed by @incognito_4041"
    )


@bot.message_handler(func=lambda m: True, content_types=["text"])
def handle_text(message):
    text = message.text.strip()
    if text.startswith("http://") or text.startswith("https://"):
        bot.reply_to(
            message,
            "🔗 Link received. For full HTML analysis please upload the page source "
            f"or use the web tool:\n{FRONTEND_WEBSITE_URL}"
        )
    else:
        bot.reply_to(message, "Send an APK/HTML file or use /start")


# ─────────────── Bot runner (background) ───────────────
def run_bot():
    print("🤖 Removing any existing webhook…")
    bot.remove_webhook()          # ← fixes 409 Conflict
    print("🤖 Telegram bot polling started…")
    bot.infinity_polling(timeout=60, long_polling_timeout=30)


# ─────────────── Main entry point ───────────────
if __name__ == "__main__":
    # Start Telegram bot in a background daemon thread
    threading.Thread(target=run_bot, daemon=True).start()

    # Start Flask on the main thread (binds to Render's PORT immediately)
    port = int(os.environ.get("PORT", 10000))
    print(f"🌐 Flask listening on 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
