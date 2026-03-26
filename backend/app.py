from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
from flask_mail import Mail
import os
import hashlib

load_dotenv()
app = Flask(__name__)

# 🕵️ SMART PATH FINDER (For Images, JS, HTML)
def get_frontend_path():
    paths = [
        os.path.join(os.getcwd(), '..', 'frontend'),
        os.path.join(os.getcwd(), 'frontend'),
        os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
    ]
    for p in paths:
        if os.path.exists(p): return p
    return None

# ✅ SERVE ALL FRONTEND (Images, Pages, Styles)
@app.route('/', defaults={'path': 'index.html'})
@app.route('/<path:path>')
def serve_frontend(path):
    f_dir = get_frontend_path()
    if not f_dir: return "Frontend Folder Not Found", 404
    if not path or path.endswith('/'): path = 'index.html'
    if not os.path.exists(os.path.join(f_dir, path)) and not '.' in path:
        path += '.html'
    return send_from_directory(f_dir, path)

# 🗄️ SELF-HEALING DATABASE
@app.before_request
def ensure_db():
    if not hasattr(app, 'db_initialized'):
        try:
            from config import DATABASE
            import sqlite3
            conn = sqlite3.connect(DATABASE)
            cur = conn.cursor()
            cur.execute("""CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, first_name TEXT, last_name TEXT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user', status TEXT DEFAULT 'active', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
            admin_email = "securenet1121@gmail.com"
            cur.execute("SELECT id FROM users WHERE email = ?", (admin_email,))
            if not cur.fetchone():
                admin_pass = hashlib.sha256("admin123".encode()).hexdigest()
                cur.execute("INSERT INTO users (first_name, last_name, email, password, role) VALUES (?, ?, ?, ?, ?)", ("System", "Admin", admin_email, admin_pass, "admin"))
            conn.commit()
            conn.close()
            app.db_initialized = True
        except: pass

# Config & Blueprints
from config import MAIL_SERVER, MAIL_PORT, MAIL_USE_TLS, MAIL_USERNAME, MAIL_PASSWORD
app.config.update(MAIL_SERVER=MAIL_SERVER, MAIL_PORT=MAIL_PORT, MAIL_USE_TLS=MAIL_USE_TLS, MAIL_USERNAME=MAIL_USERNAME, MAIL_PASSWORD=MAIL_PASSWORD)
mail = Mail(app); CORS(app, resources={r"/*": {"origins": "*"}})

from api.routes.auth import auth_routes
from api.routes.user import user_routes
from api.routes.admin import admin_routes
from api.routes.security_scan import scan_bp
from api.routes.qr_scanner import qr_bp
from api.routes.call_detector import call_bp
from api.routes.sms_detector import sms_bp
from api.routes.password_analyzer import password_bp
from api.routes.email_detector import email_bp
from api.routes.chatbot import chatbot_bp

app.register_blueprint(auth_routes, url_prefix="/api")
app.register_blueprint(user_routes, url_prefix="/api")
app.register_blueprint(admin_routes, url_prefix="/api")
app.register_blueprint(scan_bp, url_prefix="/api")
app.register_blueprint(qr_bp, url_prefix="/api")
app.register_blueprint(call_bp, url_prefix="/api")
app.register_blueprint(sms_bp, url_prefix="/api")
app.register_blueprint(password_bp, url_prefix="/api")
app.register_blueprint(email_bp, url_prefix="/api")
app.register_blueprint(chatbot_bp, url_prefix="/api")

if __name__ == "__main__":
    from config import HOST, PORT
    app.run(host=HOST, port=PORT, debug=True)
