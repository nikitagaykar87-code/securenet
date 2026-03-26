import re
import json
from flask import Blueprint, request, jsonify
import zxcvbn
import random
from utils.logger import log_detection
from utils.jwt_utils import decode_token
from flask import request


password_bp = Blueprint("password_bp", __name__)


# -----------------------------
#  DARKNET EXPOSURE SIMULATOR
# -----------------------------
def darknet_scan_simulator(password):
    weak_patterns = ["123", "qwerty", "password", "abcd", "0000"]
    if any(p in password.lower() for p in weak_patterns):
        return {
            "exposed": True,
            "details": "Password appears in common leaked password patterns."
        }
    return {"exposed": False, "details": "No known leak patterns found."}


# -----------------------------
# NIST + OWASP POLICY CHECKS
# -----------------------------
def policy_validation(password):
    issues = []

    if len(password) < 12:
        issues.append("NIST recommends 12+ characters.")
    if not re.search(r"[A-Z]", password):
        issues.append("Add uppercase letters.")
    if not re.search(r"[a-z]", password):
        issues.append("Add lowercase letters.")
    if not re.search(r"[0-9]", password):
        issues.append("Add digits.")
    if not re.search(r"[\W_]", password):
        issues.append("Add symbols (@,#,$,%,&).")

    return issues


# -----------------------------
#  STRONG PASSWORD GENERATOR
# -----------------------------
def generate_strong_password():
    import string
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(16))


# -----------------------------
# MAIN STRENGTH ANALYZER
# -----------------------------
def analyze_password(password):
    z = zxcvbn.zxcvbn(password)

    score_map = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
    strength_label = score_map[z["score"]]

    crack_time = z["crack_times_display"]["offline_fast_hashing_1e10_per_second"]

    policy_issues = policy_validation(password)
    darknet_result = darknet_scan_simulator(password)

    return {
        "score": z["score"] * 20,            # convert 0-4 → 0-100
        "label": strength_label,
        "crack_time": crack_time,
        "policy_issues": policy_issues,
        "darknet": darknet_result,
        "suggested_password": generate_strong_password(),
        "tips": z["feedback"]["suggestions"] or ["Good password! No major issues."]
    }


# -----------------------------
# API ENDPOINT
# -----------------------------
@password_bp.route("/password/analyze", methods=["POST"])
def analyze_api():
    data = request.json
    password = data.get("password", "")

    if not password:
        return jsonify({"success": False, "error": "Password missing"}), 400

    result = analyze_password(password)
    result = analyze_password(password)

    # --- PROFESSIONAL LOGGING & ALERTS ---
    try:
        from utils.logger import log_password_scan, create_security_alert
        user_email = random.choice(DEFAULT_GUEST_EMAILS)
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            decoded = decode_token(token)
            if decoded:
                user_email = decoded.get("email", random.choice(DEFAULT_GUEST_EMAILS))
        
        # 1. Log Detailed Analysis
        log_password_scan(
            user_email,
            result["score"],
            result["label"],
            result["crack_time"],
            result["policy_issues"]
        )

        # 2. Create Security Alert for Weak Passwords
        if result["score"] <= 40:  # Very Weak or Weak
            create_security_alert(
                user_email,
                "Weak Password Policy",
                "Medium" if result["score"] == 40 else "High",
                f"User analyzed a {result['label']} password. Estimated crack time: {result['crack_time']}."
            )
            
        log_detection(user_email, "Password Analyzer")
    except Exception as log_err:
        print(f"Logging failed: {log_err}")

    return jsonify({
        "success": True,
        "analysis": result
    })

