import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 🗄️ DATABASE (SUPPORT PERSISTENT STORAGE ON RENDER)
if os.getenv("RENDER"):
    DATABASE = os.path.join(BASE_DIR, "../securenet.sqlite")
 # Path to Render Disk
else:
    DATABASE = os.path.join(BASE_DIR, "../securenet.sqlite")

# 🔐 JWT (SINGLE SOURCE OF TRUTH)
JWT_SECRET_KEY = os.getenv("JWT_SECRET", "securenet_super_secret_key")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 72

# ❌ REMOVE THIS (DO NOT USE FOR JWT)
# SECRET_KEY = os.getenv("SECRET_KEY", "fallback-if-env-fails")

# 👤 ADMIN
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "securenet1121@gmail.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# 👥 DEFAULT GUEST EMAILS (for unauthenticated logs)
DEFAULT_GUEST_EMAILS = [
    "gawadediksha134@gmail.com",
    "sanjaygaykar696@gmail.com",
    "lalitagaykar857@gmail.com",
    "tanu76@gmail.com",
    "lalitagaykar87@gmail.com"
]

# 🤖 AI
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

HOST = os.getenv("HOST", "0.0.0.0") # Use 0.0.0.0 for deployment
PORT = int(os.environ.get("PORT", 5000))

# Allowed frontend URL for CORS
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://yourfrontend.com")

MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

# 🌐 GOOGLE LOGIN
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
