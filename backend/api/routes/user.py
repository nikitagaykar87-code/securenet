from flask import Blueprint, request, jsonify
import sqlite3
from datetime import datetime
from config import DATABASE

user_routes = Blueprint("user_routes", __name__)


def db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# --------------------------
# LOG DETECTOR USAGE
# POST /api/log/detector
# --------------------------
@user_routes.route("/log/detector", methods=["POST"])
def log_detector():
    data = request.get_json(silent=True) or {}
    
    detector = data.get("detector", "Unknown")
    user_email = data.get("user", "guest")
    
    # Get email from token if available
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        from utils.jwt_utils import decode_token
        token = auth_header.split(" ")[1]
        decoded = decode_token(token)
        if decoded:
            user_email = decoded.get("email", user_email)
    
    conn = db()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            INSERT INTO detection_logs (user_email, detector_name, time)
            VALUES (?, ?, ?)
        """, (
            user_email,
            detector,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Logged successfully"
        })
    
    except Exception as e:
        conn.close()
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


# --------------------------
# LOG QUIZ SCORE
# POST /api/log/quiz
# --------------------------
@user_routes.route("/log/quiz", methods=["POST"])
def log_quiz():
    data = request.get_json(silent=True) or {}
    
    quiz_name = data.get("quiz_name", "Unknown")
    score = data.get("score", 0)
    total = data.get("total", 5)
    user_email = data.get("user", "guest")
    
    # Get email from token if available
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        from utils.jwt_utils import decode_token
        token = auth_header.split(" ")[1]
        decoded = decode_token(token)
        if decoded:
            user_email = decoded.get("email", user_email)
    
    conn = db()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            INSERT INTO quiz_scores (user_email, quiz_name, score, total_questions, time)
            VALUES (?, ?, ?, ?, ?)
        """, (
            user_email,
            quiz_name,
            score,
            total,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Quiz score logged successfully"
        })
    
    except Exception as e:
        conn.close()
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


# --------------------------
# GET CURRENT USER PROFILE
# GET /api/me
# --------------------------
@user_routes.route("/me", methods=["GET"])
def get_current_user():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"success": False, "message": "Missing token"}), 401

    from utils.jwt_utils import decode_token
    token = auth_header.split(" ")[1]
    decoded = decode_token(token)

    if not decoded:
        return jsonify({"success": False, "message": "Invalid token"}), 401

    user_id = decoded.get("user_id")
    email = decoded.get("email")

    conn = db()
    cur = conn.cursor()

    # 1. Get User Details
    cur.execute("""
        SELECT first_name, last_name, email, contact, dob, gender, role, created_at
        FROM users
        WHERE id = ?
    """, (user_id,))
    
    user_row = cur.fetchone()
    
    if not user_row:
        conn.close()
        return jsonify({"success": False, "message": "User not found"}), 404

    user_data = dict(user_row)

    # 2. Get Recent Quiz Scores
    cur.execute("""
        SELECT quiz_name, score, total_questions, time
        FROM quiz_scores
        WHERE user_email = ?
        ORDER BY time DESC
        LIMIT 5
    """, (email,))
    
    quiz_rows = cur.fetchall()
    quiz_history = [dict(row) for row in quiz_rows]

    # 3. Get Login History (Last 3)
    cur.execute("""
        SELECT ip_address, login_time, status
        FROM login_logs
        WHERE user_id = ? AND status LIKE 'Success%'
        ORDER BY login_time DESC
        LIMIT 3
    """, (user_id,))
    
    login_rows = cur.fetchall()
    login_history = [dict(row) for row in login_rows]

    conn.close()

    return jsonify({
        "success": True,
        "user": user_data,
        "quiz_history": quiz_history,
        "login_history": login_history
    })


# --------------------------
# LOG USER ACTIVITY
# POST /api/activity/log
# --------------------------
@user_routes.route("/activity/log", methods=["POST"])
def log_activity():
    data = request.get_json(silent=True) or {}
    action = data.get("action", "Unknown Action")
    
    # Get email from token if available
    try:
        import random
        from config import DEFAULT_GUEST_EMAILS
        auth_header = request.headers.get("Authorization")
        user_email = random.choice(DEFAULT_GUEST_EMAILS)
        if auth_header and auth_header.startswith("Bearer "):
            from utils.jwt_utils import decode_token
            token = auth_header.split(" ")[1]
            decoded = decode_token(token)
            if decoded:
                user_email = decoded.get("email", random.choice(DEFAULT_GUEST_EMAILS))
    except:
        user_email = "error_guest@example.com" # Fallback if imports or random choice fails
        
    ip_address = request.remote_addr
    
    conn = db()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            INSERT INTO activity_logs (user_email, action, ip_address, timestamp)
            VALUES (?, ?, ?, datetime('now'))
        """, (user_email, action, ip_address))
        
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "message": "Activity logged"})
        
    except Exception as e:
        conn.close()
        return jsonify({"success": False, "message": str(e)}), 500



