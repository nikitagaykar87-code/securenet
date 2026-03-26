import sqlite3
from datetime import datetime
from config import DATABASE

def log_detection(user_email, detector_name):
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO detection_logs (user_email, detector_name, time)
            VALUES (?, ?, ?)
        """, (
            user_email,
            detector_name,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Log Error: {e}")

def log_login(user_id, email, ip_address, status):
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO login_logs (user_id, email, ip_address, status, login_time)
            VALUES (?, ?, ?, ?, ?)
        """, (
            user_id,
            email,
            ip_address,
            status,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Login Log Error: {e}")

# --- PROFESSIONAL SECURITY LOGGING ---

def create_security_alert(user_email, threat_type, severity, description):
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO security_alerts (user_email, threat_type, severity, description)
            VALUES (?, ?, ?, ?)
        """, (user_email, threat_type, severity, description))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Alert Error: {e}")

def log_detailed_email(user_email, domain, breach_count, spf, dmarc, score):
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO detailed_email_logs (user_email, sender_domain, breach_count, spf_check, dmarc_check, risk_score)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_email, domain, breach_count, spf, dmarc, score))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Email Log Error: {e}")

def log_detailed_qr(user_email, url, content_type, risk_status):
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO qr_scan_logs (user_email, embedded_url, content_type, risk_status)
            VALUES (?, ?, ?, ?)
        """, (user_email, url, content_type, risk_status))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"QR Log Error: {e}")

def log_api_usage(api_name, user_email, tokens=0, latency=0, status=200):
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO api_usage_metrics (api_name, user_email, tokens_used, response_time_ms, status_code)
            VALUES (?, ?, ?, ?, ?)
        """, (api_name, user_email, tokens, latency, status))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"API Metric Error: {e}")

def log_password_scan(user_email, strength_score, strength_label, crack_time, policy_issues):
    """Logs a detailed password strength analysis."""
    try:
        import json
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO password_scan_logs (user_email, strength_score, strength_label, crack_time, policy_issues)
            VALUES (?, ?, ?, ?, ?)
        """, (user_email, strength_score, strength_label, crack_time, json.dumps(policy_issues)))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Password Log Error: {e}")

def log_website_scan(user_email, site_url, risk_score, vt_malicious, ipqs_risk, ssl_grade):
    """Logs a detailed website/link scanner result."""
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO website_scan_logs (user_email, site_url, risk_score, vt_malicious, ipqs_risk, ssl_grade)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_email, site_url, risk_score, vt_malicious, ipqs_risk, ssl_grade))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Website Log Error: {e}")

def log_detailed_call(user_email, phone_number, carrier, country, risk_level, score):
    """Logs a detailed phone call analysis."""
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO call_logs (user_email, phone_number, carrier, country, risk_level, score)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_email, phone_number, carrier, country, risk_level, score))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Call Log Error: {e}")

def log_detailed_sms(user_email, sender, message_snippet, risk_score, ai_analysis):
    """Logs a detailed SMS analysis."""
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO sms_logs (user_email, sender, message_snippet, risk_score, ai_analysis)
            VALUES (?, ?, ?, ?, ?)
        """, (user_email, sender, message_snippet, risk_score, ai_analysis))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"SMS Log Error: {e}")

def log_detailed_url(user_email, url, scan_source, risk_score, status):
    """Logs a detailed URL scan from the extension."""
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO url_scan_logs (user_email, url, scan_source, risk_score, status)
            VALUES (?, ?, ?, ?, ?)
        """, (user_email, url, scan_source, risk_score, status))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"URL Scan Log Error: {e}")


