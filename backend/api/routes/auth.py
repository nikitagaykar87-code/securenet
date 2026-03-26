from flask import Blueprint, request, jsonify, redirect
import sqlite3
from config import DATABASE
from utils.jwt_utils import generate_token
from utils.otp_mailer import send_otp, otp_store
from werkzeug.security import generate_password_hash, check_password_hash
import time
auth_routes = Blueprint("auth_routes", __name__)

# --------------------------
# DB CONNECTION
# --------------------------
def db():
    return sqlite3.connect(DATABASE)


import hashlib

def hash_password(password):
    """Produces a clean SHA-256 hex string without prefixes."""
    return hashlib.sha256(password.encode()).hexdigest()

# =====================================================
# LOGIN
# POST /api/login
# =====================================================
@auth_routes.route("/login", methods=["POST"])
def login():
    print("--- [DEBUG] Login Request Started ---")
    data = request.get_json(silent=True) or {}
    print(f"[DEBUG] Data: {data}")

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({
            "success": False,
            "message": "Email and password required"
        }), 400

    conn = db()
    cur = conn.cursor()

    # Case-insensitive search
    cur.execute("""
        SELECT id, password, role, status
        FROM users
        WHERE LOWER(email) = LOWER(?)
    """, (email,))
    user = cur.fetchone()
    conn.close()

    ip = request.remote_addr

    if not user:
        from utils.logger import log_login
        log_login(None, email, ip, "Failed (User not found)")
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    user_id, db_password, role, status = user

    # Custom hash comparison (clean hex)
    if hash_password(password) != db_password:
        from utils.logger import log_login
        log_login(user_id, email, ip, "Failed (Invalid password)")
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    if status != "active":
        from utils.logger import log_login
        log_login(user_id, email, ip, "Failed (Blocked)")
        return jsonify({"success": False, "message": "Account blocked"}), 403

    token = generate_token(user_id, email, role)

    from utils.logger import log_login
    log_login(user_id, email, ip, "Success")

    return jsonify({
        "success": True,
        "token": token,
        "role": role
    })


# =====================================================
# SEND OTP FOR SIGNUP
# POST /api/signup/send-otp
# =====================================================
@auth_routes.route("/signup/send-otp", methods=["POST"])
def signup_send_otp():
    data = request.get_json(silent=True) or {}
    email = data.get("email")

    if not email:
        return jsonify({"success": False, "message": "Email required"}), 400

    send_otp(email)
    return jsonify({"success": True, "message": "OTP sent to email"})


# =====================================================
# SIGNUP (OTP VERIFIED)
# POST /api/signup
# =====================================================
@auth_routes.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}

    first_name = data.get("first_name")
    last_name = data.get("last_name")
    email = data.get("email")
    password = data.get("password")
    contact = data.get("contact")
    dob = data.get("dob")
    gender = data.get("gender")
    otp = data.get("otp")

    if not all([first_name, last_name, email, password, otp]):
        return jsonify({
            "success": False,
            "message": "Missing required fields"
        }), 400

    # OTP VALIDATION
    if otp_store.get(email) != otp:
        return jsonify({
            "success": False,
            "message": "Invalid or expired OTP"
        }), 400

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    if cur.fetchone():
        conn.close()
        return jsonify({
            "success": False,
            "message": "Email already registered"
        }), 409

    cur.execute("""
        INSERT INTO users (
            first_name,
            last_name,
            email,
            password,
            contact,
            dob,
            gender,
            role,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 'user', 'active', datetime('now'))
    """, (
        first_name,
        last_name,
        email,
        hash_password(password),
        contact,
        dob,
        gender
    ))

    conn.commit()
    conn.close()

    # REMOVE USED OTP
    otp_store.pop(email, None)

    return jsonify({
        "success": True,
        "message": "Signup successful"
    })


# =====================================================
# FORGOT PASSWORD - SEND OTP
# POST /api/forgot/send-otp
# =====================================================
@auth_routes.route("/forgot/send-otp", methods=["POST"])
def forgot_send_otp():
    data = request.get_json(silent=True) or {}
    email = data.get("email")

    if not email:
        return jsonify({"success": False, "message": "Email required"}), 400

    send_otp(email)
    return jsonify({"success": True, "message": "OTP sent"})


# =====================================================
# FORGOT PASSWORD - RESET
# POST /api/forgot/reset
# =====================================================
@auth_routes.route("/forgot/reset", methods=["POST"])
def forgot_reset_password():
    data = request.get_json(silent=True) or {}

    email = data.get("email")
    otp = data.get("otp")
    new_password = data.get("password")

    if not all([email, otp, new_password]):
        return jsonify({
            "success": False,
            "message": "Missing required fields"
        }), 400

    if otp_store.get(email) != otp:
        return jsonify({"success": False, "message": "Invalid or expired OTP"}), 400

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET password=? WHERE LOWER(email)=LOWER(?)",
        (hash_password(new_password), email)
    )
    conn.commit()
    conn.close()

    otp_store.pop(email, None)

    return jsonify({
        "success": True,
        "message": "Password reset successful"
    })


# =====================================================
# LOGOUT
# POST /api/logout
# =====================================================
@auth_routes.route("/logout", methods=["POST"])
def logout():
    return jsonify({
        "success": True,
        "message": "Logged out successfully"
    })


# =====================================================
# GOOGLE LOGIN (MOCK)
# POST /api/login/google
# =====================================================

# =====================================================
# GOOGLE LOGIN (INITIATE)
# POST /api/login/google
# =====================================================
@auth_routes.route("/login/google", methods=["POST"])
def google_login():
    from config import GOOGLE_CLIENT_ID
    
    redirect_uri = "http://127.0.0.1:5000/api/login/google/callback"
    scope = "openid email profile"
    
    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={redirect_uri}&"
        f"response_type=code&"
        f"scope={scope}&"
        f"access_type=offline&"
        f"prompt=consent"
    )
    
    return jsonify({
        "success": True, 
        "auth_url": auth_url
    })


# =====================================================
# GOOGLE LOGIN (CALLBACK)
# GET /api/login/google/callback
# =====================================================
@auth_routes.route("/login/google/callback", methods=["GET"])
def google_callback():
    try:
        import requests
        from config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
        
        # print(f"--- [DEBUG] Google Callback Received ---")
        code = request.args.get("code")
        # print(f"[DEBUG] Code: {code}")

        if not code:
            print("[ERROR] No code provided")
            return jsonify({"success": False, "message": "Authorization code missing"}), 400
            
        # Exchange code for token
        token_url = "https://oauth2.googleapis.com/token"
        token_data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": "http://127.0.0.1:5000/api/login/google/callback",
            "grant_type": "authorization_code"
        }
        
        # print(f"[DEBUG] Exchanging code for token...")
        res = requests.post(token_url, data=token_data)
        # print(f"[DEBUG] Token Response: {res.status_code} - {res.text}")
        
        # Check for errors in token response
        if res.status_code != 200:
             return jsonify({"success": False, "message": f"Google Token Error: {res.text}"}), 400

        res_json = res.json()
        access_token = res_json.get("access_token")
        
        if not access_token:
             print("[ERROR] Failed to get access token")
             return jsonify({"success": False, "message": "Failed to get access token"}), 400
             
        # Get User Info
        user_info_res = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        user_info = user_info_res.json()
        
        email = user_info.get("email")
        # google_id = user_info.get("id")
        first_name = user_info.get("given_name", "GoogleUser")
        last_name = user_info.get("family_name", "")
        
        # Check if user exists or create new
        conn = db()
        cur = conn.cursor()
        
        cur.execute("SELECT id, role, status FROM users WHERE email=?", (email,))
        user = cur.fetchone()
        
        if user:
            user_id, role, status = user
            if status != "active":
                conn.close()
                return jsonify({"success": False, "message": "Account blocked"}), 403
        else:
            # Create new user
            cur.execute("""
                INSERT INTO users (first_name, last_name, email, password, role, status, created_at)
                VALUES (?, ?, ?, ?, 'user', 'active', datetime('now'))
            """, (first_name, last_name, email, "GOOGLE_AUTH"))
            conn.commit()
            user_id = cur.lastrowid
            role = "user"
            
        conn.close()
        
        # Log Google Login
        print(f"[DEBUG] Logging login for User ID: {user_id}, Email: {email}")
        from utils.logger import log_login
        log_login(user_id, email, request.remote_addr, "Success (Google)")

        # Generate Token
        jwt_token = generate_token(user_id, email, role)
        
        # Redirect to frontend with token
        # We redirect to login.html first because that's where the logic to save the token to localStorage resides.
        frontend_url = "http://127.0.0.1:5512/frontend/login.html"  # FIXED PORT 5512
             
        redirect_url = f"{frontend_url}?token={jwt_token}&role={role}"
        
        # print(f"[DEBUG] Redirecting to: {redirect_url}")
        return redirect(redirect_url)

    except Exception as e:
        import traceback
        trace = traceback.format_exc()
        print(f"[CRITICAL ERROR] {trace}")
@auth_routes.route("/test/log", methods=["GET"])
def test_log():
    try:
        conn = db()
        cur = conn.cursor()
        
        # Count before
        cur.execute("SELECT COUNT(*) FROM login_logs")
        count_before = cur.fetchone()[0]
        
        from utils.logger import log_login
        # Mock user_id=1 (assuming admin exists)
        log_login(1, "test@securenet.com", "127.0.0.1", "Success (Manual Test)")
        
        # Count after
        cur.execute("SELECT COUNT(*) FROM login_logs")
        count_after = cur.fetchone()[0]
        
        # Get latest log
        cur.execute("SELECT * FROM login_logs ORDER BY id DESC LIMIT 1")
        latest_log = dict(cur.fetchone()) if cur.fetchone() else None

        # Check for ANY Google Log
        cur.execute("SELECT * FROM login_logs WHERE status = 'Success (Google)' ORDER BY id DESC LIMIT 1")
        google_log = dict(cur.fetchone()) if cur.fetchone() else "No Google Logs Found"
        
        conn.close()
        
        return jsonify({
            "success": True, 
            "message": "Manual log attempt finished",
            "count_before": count_before,
            "count_after": count_after,
            "latest_log": latest_log,
            "latest_google_log": google_log
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500