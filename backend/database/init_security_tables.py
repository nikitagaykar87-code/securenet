import sqlite3
import hashlib
from datetime import datetime

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_tables(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # 1. USERS TABLE
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT,
            last_name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            contact TEXT,
            dob TEXT,
            gender TEXT,
            role TEXT,
            status TEXT DEFAULT 'active',
            created_at TEXT,
            ban_reason TEXT
        )
    """)

    # 2. DETECTION LOGS
    cur.execute("""
        CREATE TABLE IF NOT EXISTS detection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            detector_name TEXT,
            time TEXT
        )
    """)

    # 3. ACTIVITY LOGS
    cur.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            action TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 4. LOGIN LOGS
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email TEXT,
            ip_address TEXT,
            status TEXT,
            login_time TEXT
        )
    """)

    # 5. QUIZ SCORES
    cur.execute("""
        CREATE TABLE IF NOT EXISTS quiz_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            quiz_name TEXT,
            score INTEGER,
            total_questions INTEGER,
            time TEXT
        )
    """)

    # 🚸 INITIAL ADMIN GEN
    admin_email = "securenet1121@gmail.com"
    cur.execute("SELECT id FROM users WHERE email = ?", (admin_email,))
    if not cur.fetchone():
        admin_pass = hash_password("admin123")
        cur.execute("""
            INSERT INTO users (first_name, last_name, email, password, role, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ("System", "Admin", admin_email, admin_pass, "admin", "active", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    conn.commit()
    conn.close()
    print(f"✅ Database initialized at {db_path}")
