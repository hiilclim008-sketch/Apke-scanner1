import os
from dotenv import load_dotenv

load_dotenv()

# ──────────────────────────────────────────────
# PASTE YOUR REAL VALUES HERE (or put them in .env)
# ──────────────────────────────────────────────
BOT_TOKEN = os.getenv("BOT_TOKEN", "8776619288:AAGTW6Jh4Tz4b_4SANAzojsC9tXPFWygvs4")
ADMIN_CHAT_ID = int(os.getenv("ADMIN_CHAT_ID", "8691519315"))          # your Telegram user ID
FRONTEND_WEBSITE_URL = os.getenv(
    "FRONTEND_WEBSITE_URL",
    "https://hiilclim008-sketch.github.io/Apke-scanner/"                     # GitHub Pages URL
)

# Optional extras
MAX_TELEGRAM_FILE_MB = 20
MAX_WEB_FILE_MB = 100
