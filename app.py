from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# ✅ ADD THESE IMPORTS
from flask_mail import Mail
from config import (
    MAIL_SERVER,
    MAIL_PORT,
    MAIL_USE_TLS,
    MAIL_USERNAME,
    MAIL_PASSWORD
)

load_dotenv()

import os

app = Flask(__name__, 
            static_folder='../frontend', 
            static_url_path='/frontend')

# ✅ ADD THIS BLOCK
app.config.update(
    MAIL_SERVER=MAIL_SERVER,
    MAIL_PORT=MAIL_PORT,
    MAIL_USE_TLS=MAIL_USE_TLS,
    MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=MAIL_PASSWORD
)

mail = Mail(app)

from config import (
    MAIL_SERVER,
    MAIL_PORT,
    MAIL_USE_TLS,
    MAIL_USERNAME,
    MAIL_PASSWORD,
    FRONTEND_URL
)

# ...

import re

CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    supports_credentials=True
)




@app.after_request
def log_response(response):
    return response

# ✅ SERVE FRONTEND (FOR DEPLOYMENT)
@app.route('/')
def index():
    from flask import send_from_directory
    
    # 🕵️ STRATEGY: Try multiple common paths for Render/Local
    possible_paths = [
        os.path.join(os.getcwd(), '..', 'frontend'), # Gunicorn --chdir backend
        os.path.join(os.getcwd(), 'frontend'),      # Local/Root run
        os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend')), # absolute relative to app.py
        os.path.abspath(os.path.join(os.path.dirname(__file__), 'frontend'))         # in same folder
    ]
    
    for path in possible_paths:
        if os.path.exists(os.path.join(path, 'index.html')):
            return send_from_directory(path, 'index.html')
            
    return f"Frontend Error: Could not find index.html in any of: {possible_paths}", 404

# ✅ AUTOMATIC DB FIX ON STARTUP
@app.before_request
def ensure_db():
    if not hasattr(app, 'db_initialized'):
        try:
            from database.init_security_tables import create_tables
            from config import DATABASE
            create_tables(DATABASE)
            app.db_initialized = True
        except:
            pass

# ================= IMPORT ROUTES =================
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
# from api.routes.news import news_bp



@app.route('/api/test')
def test_api():
    from flask import jsonify
    return jsonify({"success": True, "message": "Backend API is reachable"}), 200

@app.route('/api/debug/routes')
def list_routes():
    import urllib.parse
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        url = urllib.parse.unquote(str(rule))
        output.append(f"{url} [{methods}]")
    return jsonify({"success": True, "routes": sorted(output)})

@app.route('/api/debug/dir')
def debug_dir():
    import os
    try:
        current_dir = os.getcwd()
        parent_dir = os.path.dirname(current_dir)
        
        files_current = os.listdir(current_dir)
        files_parent = os.listdir(parent_dir) if parent_dir else []
        
        return jsonify({
            "cwd": current_dir,
            "parent": parent_dir,
            "files_in_cwd": files_current,
            "files_in_parent": files_parent
        })
    except Exception as e:
        return jsonify({"error": str(e)})

# ================= REGISTER BLUEPRINTS =================
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

print("DEBUG: Registered Routes:")
print(app.url_map)




if __name__ == "__main__":
    from config import HOST, PORT
    import os
    
    app.run(host=HOST, port=PORT, debug=True)