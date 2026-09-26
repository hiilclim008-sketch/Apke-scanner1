import os
from dotenv import load_dotenv

load_dotenv()

# ──────────────────────────────────────────────
# PASTE YOUR REAL VALUES HERE (or put them in .env)
# ──────────────────────────────────────────────
BOT_TOKEN = os.getenv("BOT_TOKEN", "123456:ABC-DEF_YOUR_BOT_TOKEN_HERE")
ADMIN_CHAT_ID = int(os.getenv("ADMIN_CHAT_ID", "123456789"))          # your Telegram user ID
FRONTEND_WEBSITE_URL = os.getenv(
    "FRONTEND_WEBSITE_URL",
    "https://your-username.github.io/your-repo/"                     # GitHub Pages URL
)

# Optional extras
MAX_TELEGRAM_FILE_MB = 20
MAX_WEB_FILE_MB = 100
