from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
from flask_mail import Mail
import os
import re

load_dotenv()

app = Flask(__name__)

# ✅ Robust Frontend Seeker
@app.route('/')
def index():
    # Try all possible paths for Render/Local
    possible_paths = [
        os.path.join(os.getcwd(), '..', 'frontend'),
        os.path.join(os.getcwd(), 'frontend'),
        os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend')),
        os.path.abspath(os.path.join(os.path.dirname(__file__), 'frontend'))
    ]
    for path in possible_paths:
        if os.path.exists(os.path.join(path, 'index.html')):
            return send_from_directory(path, 'index.html')
    return f"Frontend Error: Could not find index.html. Searched: {possible_paths}", 404

# Register Blueprints & Config
from config import MAIL_SERVER, MAIL_PORT, MAIL_USE_TLS, MAIL_USERNAME, MAIL_PASSWORD
app.config.update(MAIL_SERVER=MAIL_SERVER, MAIL_PORT=MAIL_PORT, MAIL_USE_TLS=MAIL_USE_TLS, MAIL_USERNAME=MAIL_USERNAME, MAIL_PASSWORD=MAIL_PASSWORD)
mail = Mail(app)
CORS(app, resources={r"/*": {"origins": "*"}})

# Import Routes
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

@app.route('/api/debug/dir')
def debug_dir():
    return jsonify({"cwd": os.getcwd(), "files": os.listdir(os.path.dirname(os.getcwd()))})

if __name__ == "__main__":
    from config import HOST, PORT
    app.run(host=HOST, port=PORT, debug=True)
