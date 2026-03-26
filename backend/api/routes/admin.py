from flask import Blueprint, jsonify
import sqlite3
from config import DATABASE
from utils.auth_middleware import jwt_required

admin_routes = Blueprint("admin_routes", __name__)


def db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# --------------------------
# ADMIN STATS
# GET /api/admin/stats
# --------------------------
@admin_routes.route("/admin/stats", methods=["GET"])
@jwt_required(role="admin")
def admin_stats():
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM users WHERE status='active'")
    active_users = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM users WHERE status='blocked'")
    blocked_users = cur.fetchone()[0]

    conn.close()

    return jsonify({
        "success": True,
        "total_users": total_users,
        "active_users": active_users,
        "blocked_users": blocked_users
    })


# --------------------------
# GET ALL USERS
# GET /api/admin/users
# --------------------------
@admin_routes.route("/admin/users", methods=["GET"])
@jwt_required(role="admin")
def get_users():
    conn = db()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, first_name, last_name, email, contact, role, status
        FROM users
        ORDER BY id DESC
    """)
    rows = cur.fetchall()
    conn.close()

    users = [{
        "id": r["id"],
        "name": f"{r['first_name'] or ''} {r['last_name'] or ''}".strip() or "Unknown User",
        "email": r["email"],
        "contact": r["contact"],
        "role": r["role"],
        "status": r["status"]
    } for r in rows]

    return jsonify({
        "success": True,
        "users": users
    })


# --------------------------
# BLOCK USER
# POST /api/admin/user/block/<id>
# --------------------------
@admin_routes.route("/admin/user/block/<int:user_id>", methods=["POST"])
@jwt_required(role="admin")
def block_user(user_id):
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT role FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return jsonify({"success": False, "message": "User not found"}), 404

    if row["role"] == "admin":
        conn.close()
        return jsonify({
            "success": False,
            "message": "Admin account cannot be blocked"
        }), 403

    cur.execute(
        "UPDATE users SET status='blocked' WHERE id=?",
        (user_id,)
    )
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "User blocked"})


# --------------------------
# ACTIVATE USER
# POST /api/admin/user/activate/<id>
# --------------------------
@admin_routes.route("/admin/user/activate/<int:user_id>", methods=["POST"])
@jwt_required(role="admin")
def activate_user(user_id):
    conn = db()
    cur = conn.cursor()

    cur.execute(
        "UPDATE users SET status='active' WHERE id=?",
        (user_id,)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "User activated"
    })


# --------------------------
# DELETE USER
# DELETE /api/admin/user/delete/<id>
# --------------------------
@admin_routes.route("/admin/user/delete/<int:user_id>", methods=["DELETE"])
@jwt_required(role="admin")
def delete_user(user_id):
    conn = db()
    cur = conn.cursor()

    cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "User deleted"
    })


# --------------------------
# GET DETECTOR LOGS
# GET /api/admin/logs
# --------------------------
@admin_routes.route("/admin/logs", methods=["GET"])
@jwt_required(role="admin")
def get_detector_logs():
    from flask import request as req
    
    detector = req.args.get("detector", "")
    email = req.args.get("email", "")
    
    conn = db()
    cur = conn.cursor()
    
    query = "SELECT * FROM detection_logs WHERE 1=1"
    params = []
    
    if detector and detector != "all":
        query += " AND detector_name = ?"
        params.append(detector)
    
    if email:
        query += " AND user_email LIKE ?"
        params.append(f"%{email}%")
    
    query += " ORDER BY id DESC"
    
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    
    logs = [{
        "id": r["id"],
        "user_email": r["user_email"],
        "detector": r["detector_name"],
        "time": r["time"]
    } for r in rows]
    
    return jsonify({
        "success": True,
        "logs": logs
    })


# --------------------------
# GET DETAILED CALL LOGS
# GET /api/admin/detailed-logs/call
# --------------------------
@admin_routes.route("/admin/detailed-logs/call", methods=["GET"])
@jwt_required(role="admin")
def get_detailed_call_logs():
    conn = db()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_email, phone_number, carrier, country, risk_level, score, timestamp FROM call_logs ORDER BY id DESC LIMIT 100")
        rows = cur.fetchall()
        logs = [dict(row) for row in rows]
        return jsonify({"success": True, "logs": logs})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()

# --------------------------
# GET DETAILED SMS LOGS
# GET /api/admin/detailed-logs/sms
# --------------------------
@admin_routes.route("/admin/detailed-logs/sms", methods=["GET"])
@jwt_required(role="admin")
def get_detailed_sms_logs():
    conn = db()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_email, sender, message_snippet, risk_score, ai_analysis, timestamp FROM sms_logs ORDER BY id DESC LIMIT 100")
        rows = cur.fetchall()
        logs = [dict(row) for row in rows]
        return jsonify({"success": True, "logs": logs})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()

# --------------------------
# GET DETAILED URL LOGS
# GET /api/admin/detailed-logs/url
# --------------------------
@admin_routes.route("/admin/detailed-logs/url", methods=["GET"])
@jwt_required(role="admin")
def get_detailed_url_logs():
    conn = db()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_email, url, scan_source, risk_score, status, timestamp FROM url_scan_logs ORDER BY id DESC LIMIT 100")
        rows = cur.fetchall()
        logs = [dict(row) for row in rows]
        return jsonify({"success": True, "logs": logs})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()

# --------------------------
# GET SECURITY ALERTS
# GET /api/admin/alerts
# --------------------------
@admin_routes.route("/admin/alerts", methods=["GET"])
@jwt_required(role="admin")
def get_security_alerts():
    conn = db()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM security_alerts ORDER BY id DESC LIMIT 100")
        rows = cur.fetchall()
        alerts = [dict(row) for row in rows]
        return jsonify({"success": True, "alerts": alerts})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()



# --------------------------
# GET API METRICS
# GET /api/admin/api-metrics
# --------------------------
@admin_routes.route("/admin/api-metrics", methods=["GET"])
@jwt_required(role="admin")
def get_api_metrics():
    conn = db()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute("SELECT api_name, COUNT(*) as calls, SUM(tokens_used) as total_tokens, AVG(response_time_ms) as avg_latency FROM api_usage_metrics GROUP BY api_name")
        rows = cur.fetchall()
        metrics = [dict(row) for row in rows]
        return jsonify({"success": True, "metrics": metrics})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()

# --------------------------
# GET PASSWORD SCAN LOGS
# GET /api/admin/password-logs
# --------------------------
@admin_routes.route("/admin/password-logs", methods=["GET"])
@jwt_required(role="admin")
def get_password_logs():
    conn = db()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM password_scan_logs ORDER BY id DESC LIMIT 100")
        rows = cur.fetchall()
        logs = [dict(row) for row in rows]
        return jsonify({"success": True, "logs": logs})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()

# --------------------------
# GET WEBSITE SCAN LOGS
# GET /api/admin/website-logs
# --------------------------
@admin_routes.route("/admin/website-logs", methods=["GET"])
@jwt_required(role="admin")
def get_website_logs():
    conn = db()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM website_scan_logs ORDER BY id DESC LIMIT 100")
        rows = cur.fetchall()
        logs = [dict(row) for row in rows]
        return jsonify({"success": True, "logs": logs})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()




# --------------------------
# GET QUIZ SCORES
# GET /api/admin/quiz-scores
# --------------------------
@admin_routes.route("/admin/quiz-scores", methods=["GET"])
@jwt_required(role="admin")
def get_quiz_scores():
    from flask import request as req
    email = req.args.get("email", "")
    
    conn = db()
    cur = conn.cursor()
    
    query = "SELECT * FROM quiz_scores WHERE 1=1"
    params = []
    
    if email:
        query += " AND user_email LIKE ?"
        params.append(f"%{email}%")
    
    query += " ORDER BY id DESC LIMIT 100"
    
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    
    scores = [{
        "id": r["id"],
        "user_email": r["user_email"],
        "quiz_name": r["quiz_name"],
        "score": r["score"],
        "total": r["total_questions"],
        "time": r["time"]
    } for r in rows]
    
    return jsonify({
        "success": True,
        "scores": scores
    })


# --------------------------
# GET LOGIN LOGS
# GET /api/admin/login-logs
# --------------------------
@admin_routes.route("/admin/login-logs", methods=["GET"])
@jwt_required(role="admin")
def get_login_logs():
    print("--- [DEBUG] Fetching Login Logs ---")
    from flask import request as req
    
    email = req.args.get("email", "")
    
    conn = db()
    cur = conn.cursor()
    
    query = "SELECT * FROM login_logs WHERE 1=1"
    params = []
    
    if email:
        query += " AND email LIKE ?"
        params.append(f"%{email}%")
    
    query += " ORDER BY id DESC LIMIT 100"
    
    print(f"[DEBUG] Query: {query}")
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    
    print(f"[DEBUG] Found {len(rows)} logs")

    logs = [{
        "id": r["id"],
        "email": r["email"],
        "status": r["status"],
        "ip": r["ip_address"],
        "time": r["login_time"]
    } for r in rows]
    
    return jsonify({
        "success": True,
        "logs": logs
    })


# --------------------------
# ANALYTICS: DETECTOR USAGE
# GET /api/admin/analytics/detectors
# --------------------------
@admin_routes.route("/admin/analytics/detectors", methods=["GET"])
@jwt_required(role="admin")
def get_detector_stats():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT detector_name, COUNT(*) as count FROM detection_logs GROUP BY detector_name ORDER BY count DESC")
    rows = cur.fetchall()
    conn.close()
    
    data = {row["detector_name"]: row["count"] for row in rows}
    return jsonify({"success": True, "data": data})





# --------------------------
# ANALYTICS: LOGIN STATS
# GET /api/admin/analytics/login-stats
# --------------------------
@admin_routes.route("/admin/analytics/login-stats", methods=["GET"])
@jwt_required(role="admin")
def get_login_stats():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT status, COUNT(*) as count FROM login_logs GROUP BY status")
    rows = cur.fetchall()
    conn.close()
    
    data = {row["status"]: row["count"] for row in rows}
    return jsonify({"success": True, "data": data})


# --------------------------
# ANALYTICS: QUIZ PERFORMANCE
# GET /api/admin/analytics/quiz-performance
# --------------------------
@admin_routes.route("/admin/analytics/quiz-performance", methods=["GET"])
@jwt_required(role="admin")
def get_quiz_stats():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT quiz_name, AVG(CAST(score AS FLOAT) / total_questions * 100) as avg_score 
        FROM quiz_scores 
        GROUP BY quiz_name
    """)
    rows = cur.fetchall()
    conn.close()
    
    data = {row["quiz_name"]: round(row["avg_score"], 1) for row in rows}
    return jsonify({"success": True, "data": data})


# --------------------------
# ANALYTICS: RECENT USERS
# GET /api/admin/analytics/recent-users
# --------------------------
@admin_routes.route("/admin/analytics/recent-users", methods=["GET"])
@jwt_required(role="admin")
def get_recent_users():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT first_name, last_name, email, status FROM users ORDER BY id DESC LIMIT 5")
    rows = cur.fetchall()
    conn.close()
    
    users = [{
        "name": f"{r['first_name'] or ''} {r['last_name'] or ''}".strip() or "Unknown User",
        "email": r["email"],
        "status": r["status"]
    } for r in rows]
    
    return jsonify({"success": True, "data": users})


# --------------------------
# ANALYTICS: USER GROWTH
# GET /api/admin/analytics/user-growth
# --------------------------
@admin_routes.route("/admin/analytics/user-growth", methods=["GET"])
@jwt_required(role="admin")
def get_user_growth():
    conn = db()
    cur = conn.cursor()
    
    # Group by Month (YYYY-MM)
    cur.execute("""
        SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count 
        FROM users 
        WHERE created_at IS NOT NULL
        GROUP BY month 
        ORDER BY month ASC
        LIMIT 12
    """)
    rows = cur.fetchall()
    conn.close()
    
    data = {row["month"]: row["count"] for row in rows}
    return jsonify({"success": True, "data": data})