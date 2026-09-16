import os
import sqlite3
import time
import uuid
import json
import secrets
import hashlib
import hmac
import smtplib
from email.message import EmailMessage
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, allow_headers=["Content-Type", "X-User-ID", "X-Auth-Token"])

DB_NAME = os.getenv("DMS_DB", "gov_dms_v4.db")
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "300"))
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "28800"))

ROLE_LEVELS = {
    "Admin": 3,
    "Supervisor": 2,
    "Investigator": 1,
    "External Witness": 0
}

ROLE_PERMISSIONS = {
    "Admin": ["dashboard", "users", "documents", "cases", "custody", "audit", "settings"],
    "Supervisor": ["dashboard", "documents", "cases", "custody", "audit"],
    "Investigator": ["dashboard", "documents", "cases", "custody"],
    "External Witness": ["dashboard", "documents"]
}

STATUSES = [
    "Draft", "Submitted", "Under Investigation", "Under Review",
    "Approved", "Rejected", "Archived", "Sealed"
]

ALLOWED_ROLES = list(ROLE_LEVELS.keys())


def now_ms():
    return int(time.time() * 1000)


def get_db():
    conn = sqlite3.connect(DB_NAME, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn


def add_column(conn, table, column, definition):
    cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    conn = get_db()
    try:
        c = conn.cursor()

        c.execute("""CREATE TABLE IF NOT EXISTS Users (
            id TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            must_change INTEGER DEFAULT 1,
            is_approved INTEGER DEFAULT 0
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS Documents (
            id TEXT PRIMARY KEY,
            filename TEXT,
            category TEXT,
            mimeType TEXT,
            uploader TEXT,
            timestamp INTEGER,
            originalHash TEXT,
            data TEXT,
            salt TEXT,
            iv TEXT,
            expires_at INTEGER DEFAULT 0,
            signature TEXT,
            public_key TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS Audit (
            id TEXT PRIMARY KEY,
            timestamp INTEGER,
            user TEXT,
            action TEXT,
            details TEXT,
            reason TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS PasswordResetRequests (
            id TEXT PRIMARY KEY,
            badge_id TEXT NOT NULL,
            reason TEXT,
            timestamp INTEGER,
            status TEXT DEFAULT 'PENDING'
        )""")

        # Additive migrations keep the original project database usable.
        for col, definition in [
            ("email", "TEXT DEFAULT ''"),
            ("full_name", "TEXT DEFAULT ''"),
            ("department", "TEXT DEFAULT ''"),
            ("phone", "TEXT DEFAULT ''"),
            ("account_status", "TEXT DEFAULT 'ACTIVE'"),
            ("last_login", "INTEGER DEFAULT 0"),
            ("failed_logins", "INTEGER DEFAULT 0"),
            ("locked_until", "INTEGER DEFAULT 0"),
            ("created_at", "INTEGER DEFAULT 0"),
            ("twofa_enabled", "INTEGER DEFAULT 1"),
            ("twofa_secret", "TEXT DEFAULT ''")
        ]:
            add_column(conn, "Users", col, definition)

        for col, definition in [
            ("case_id", "TEXT DEFAULT ''"),
            ("fir_number", "TEXT DEFAULT ''"),
            ("title", "TEXT DEFAULT ''"),
            ("department", "TEXT DEFAULT ''"),
            ("location", "TEXT DEFAULT ''"),
            ("priority", "TEXT DEFAULT 'Normal'"),
            ("classification", "TEXT DEFAULT 'Official'"),
            ("status", "TEXT DEFAULT 'Submitted'"),
            ("version", "INTEGER DEFAULT 1"),
            ("parent_id", "TEXT DEFAULT ''"),
            ("created_by", "TEXT DEFAULT ''"),
            ("updated_at", "INTEGER DEFAULT 0"),
            ("updated_by", "TEXT DEFAULT ''"),
            ("tags", "TEXT DEFAULT ''")
        ]:
            add_column(conn, "Documents", col, definition)

        c.execute("""CREATE TABLE IF NOT EXISTS DocumentVersions (
            id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            filename TEXT,
            category TEXT,
            mimeType TEXT,
            uploader TEXT,
            timestamp INTEGER,
            originalHash TEXT,
            data TEXT,
            salt TEXT,
            iv TEXT,
            expires_at INTEGER DEFAULT 0,
            signature TEXT,
            public_key TEXT,
            change_note TEXT DEFAULT '',
            created_by TEXT,
            created_at INTEGER
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS Cases (
            id TEXT PRIMARY KEY,
            case_number TEXT UNIQUE,
            fir_number TEXT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            department TEXT DEFAULT '',
            lead_investigator TEXT DEFAULT '',
            priority TEXT DEFAULT 'Normal',
            status TEXT DEFAULT 'Open',
            classification TEXT DEFAULT 'Official',
            created_by TEXT,
            created_at INTEGER,
            updated_at INTEGER
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS CustodyEvents (
            id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            from_user TEXT DEFAULT '',
            to_user TEXT DEFAULT '',
            reason TEXT DEFAULT '',
            location TEXT DEFAULT '',
            document_hash TEXT DEFAULT '',
            timestamp INTEGER,
            previous_event_hash TEXT DEFAULT '',
            event_hash TEXT DEFAULT ''
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS Sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at INTEGER,
            expires_at INTEGER,
            ip_address TEXT DEFAULT '',
            user_agent TEXT DEFAULT ''
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS OTPRequests (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at INTEGER,
            attempts INTEGER DEFAULT 0,
            used INTEGER DEFAULT 0,
            created_at INTEGER
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS SecurityAlerts (
            id TEXT PRIMARY KEY,
            timestamp INTEGER,
            user TEXT,
            severity TEXT,
            event TEXT,
            details TEXT,
            resolved INTEGER DEFAULT 0
        )""")

        # Existing databases may have the old plaintext admin. On first run it is
        # retained for compatibility and upgraded after a successful login.
        c.execute("""INSERT OR IGNORE INTO Users
            (id, password, role, must_change, is_approved, email, full_name,
             department, account_status, created_at, twofa_enabled)
            VALUES ('ADMIN-01', 'admin', 'Admin', 0, 1, '', 'System Administrator',
                    'Administration', 'ACTIVE', ?, 0)""", (now_ms(),))

        conn.commit()
    finally:
        conn.close()


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return "pbkdf2$310000$" + salt.hex() + "$" + digest.hex()


def verify_password(stored, password):
    if stored.startswith("pbkdf2$"):
        try:
            _, iterations, salt_hex, digest_hex = stored.split("$", 3)
            actual = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
            ).hex()
            return hmac.compare_digest(actual, digest_hex)
        except Exception:
            return False
    # Legacy compatibility for the original project. Successful authentication
    # is immediately upgraded to PBKDF2.
    return hmac.compare_digest(stored, password)


def make_token():
    return secrets.token_urlsafe(32)


def make_otp():
    return f"{secrets.randbelow(1000000):06d}"


def send_otp_email(email, user_id, otp):
    host = os.getenv("SMTP_HOST", "")
    port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    sender = os.getenv("SMTP_FROM", smtp_user)
    if not host or not sender:
        return False, "SMTP is not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD and SMTP_FROM."

    msg = EmailMessage()
    msg["Subject"] = "Secure DMS verification code"
    msg["From"] = sender
    msg["To"] = email
    msg.set_content(
        f"Secure DMS\n\nHello {user_id},\n\nYour verification code is {otp}.\n"
        f"It expires in {OTP_TTL_SECONDS // 60} minutes.\n\nIf you did not request this code, contact an administrator."
    )
    try:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls()
            if smtp_user:
                server.login(smtp_user, smtp_password)
            server.send_message(msg)
        return True, "Verification code sent to registered email."
    except Exception as exc:
        return False, f"Email delivery failed: {exc}"


def get_user(user_id):
    if not user_id:
        return None
    conn = get_db()
    try:
        return conn.execute("SELECT * FROM Users WHERE id=?", (user_id,)).fetchone()
    finally:
        conn.close()


def get_user_role(user_id):
    row = get_user(user_id)
    if row and row["is_approved"] == 1 and row["account_status"] == "ACTIVE":
        return row["role"]
    return None


def require_role(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user_id = request.headers.get("X-User-ID")
            role = get_user_role(user_id)
            if role not in roles:
                return jsonify({"status": "error", "message": "Unauthorized access"}), 403
            request.current_user = user_id
            request.current_role = role
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user_id = request.headers.get("X-User-ID")
        token = request.headers.get("X-Auth-Token")
        if not user_id or not token:
            return jsonify({"status": "error", "message": "Authentication required"}), 401
        conn = get_db()
        try:
            session = conn.execute(
                "SELECT * FROM Sessions WHERE token=? AND user_id=? AND expires_at>?",
                (token, user_id, now_ms())
            ).fetchone()
        finally:
            conn.close()
        if not session or not get_user_role(user_id):
            return jsonify({"status": "error", "message": "Session expired or invalid"}), 401
        request.current_user = user_id
        request.current_role = get_user_role(user_id)
        return fn(*args, **kwargs)
    return wrapper


def audit_event(user, action, details, reason="Routine Operations"):
    conn = get_db()
    try:
        audit_id = f"LOG-{uuid.uuid4().hex[:12].upper()}"
        conn.execute(
            "INSERT INTO Audit VALUES (?, ?, ?, ?, ?, ?)",
            (audit_id, now_ms(), user or "SYSTEM", action, details, reason or "Routine Operations")
        )
        conn.commit()
    finally:
        conn.close()


def create_security_alert(user, severity, event, details):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO SecurityAlerts VALUES (?, ?, ?, ?, ?, ?, 0)",
            (f"ALT-{uuid.uuid4().hex[:10].upper()}", now_ms(), user or "SYSTEM", severity, event, details)
        )
        conn.commit()
    finally:
        conn.close()


def custody_event(document_id, actor, action, reason="", from_user="", to_user="", location="", document_hash=""):
    conn = get_db()
    try:
        previous = conn.execute(
            "SELECT event_hash FROM CustodyEvents WHERE document_id=? ORDER BY timestamp DESC LIMIT 1",
            (document_id,)
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else ""
        ts = now_ms()
        event_id = f"CST-{uuid.uuid4().hex[:12].upper()}"
        material = "|".join([
            event_id, document_id, actor, action, from_user, to_user, reason,
            location, document_hash, str(ts), previous_hash
        ])
        event_hash = hashlib.sha256(material.encode()).hexdigest()
        conn.execute(
            """INSERT INTO CustodyEvents
            (id, document_id, actor, action, from_user, to_user, reason, location,
             document_hash, timestamp, previous_event_hash, event_hash)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (event_id, document_id, actor, action, from_user, to_user, reason,
             location, document_hash, ts, previous_hash, event_hash)
        )
        conn.commit()
    finally:
        conn.close()
    audit_event(actor, f"CUSTODY_{action.upper()}", f"Document {document_id}; custody event {event_id}", reason)


@app.route("/register", methods=["POST"])
@app.route("/api/register", methods=["POST"])
def register():
    data = request.json or {}
    badge_id = str(data.get("badge_id", "")).strip().upper()
    password = data.get("password", "")
    email = str(data.get("email", "")).strip()
    full_name = str(data.get("full_name", "")).strip()
    department = str(data.get("department", "")).strip()
    requested_role = data.get("role", "Investigator")

    if not badge_id or not password or not email:
        return jsonify({"status": "error", "message": "Badge ID, password and email are required"}), 400
    if requested_role not in ALLOWED_ROLES:
        return jsonify({"status": "error", "message": "Invalid role"}), 400

    needs_approval = requested_role in ["Admin", "Supervisor"]
    approved = 0 if needs_approval else 1
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO Users
            (id, password, role, must_change, is_approved, email, full_name,
             department, account_status, created_at, twofa_enabled)
             VALUES (?, ?, ?, 1, ?, ?, ?, ?, 'ACTIVE', ?, 1)""",
            (badge_id, hash_password(password), requested_role, approved, email,
             full_name, department, now_ms())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({"status": "error", "message": "Badge ID already exists"}), 400
    finally:
        conn.close()

    audit_event("SYSTEM", "USER_REGISTERED", f"{badge_id} requested role {requested_role}")
    return jsonify({
        "status": "success",
        "message": f"{requested_role} registration submitted." +
                   (" Awaiting Admin approval." if needs_approval else " You may log in.")
    })


@app.route("/login", methods=["POST"])
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    badge_id = str(data.get("badge_id", "")).strip().upper()
    password = data.get("password", "")
    user = get_user(badge_id)

    if not user:
        audit_event(badge_id or "UNKNOWN", "LOGIN_FAILED", "Unknown account")
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    if user["account_status"] == "SUSPENDED":
        return jsonify({"status": "error", "message": "Account is suspended. Contact an administrator."}), 403
    if user["locked_until"] and user["locked_until"] > now_ms():
        return jsonify({"status": "error", "message": "Account temporarily locked due to failed attempts."}), 423
    if not verify_password(user["password"], password):
        conn = get_db()
        try:
            failures = user["failed_logins"] + 1
            locked = now_ms() + 15 * 60 * 1000 if failures >= 5 else 0
            conn.execute("UPDATE Users SET failed_logins=?, locked_until=? WHERE id=?", (failures, locked, badge_id))
            conn.commit()
        finally:
            conn.close()
        audit_event(badge_id, "LOGIN_FAILED", f"Failed credentials; attempt {failures}")
        if failures >= 5:
            create_security_alert(badge_id, "HIGH", "ACCOUNT_LOCKED", "Five failed login attempts")
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    if not user["is_approved"]:
        return jsonify({"status": "error", "message": "Account pending administrative approval"}), 403

    # Upgrade legacy plaintext password after successful authentication.
    if not user["password"].startswith("pbkdf2$"):
        conn = get_db()
        try:
            conn.execute("UPDATE Users SET password=? WHERE id=?", (hash_password(password), badge_id))
            conn.commit()
        finally:
            conn.close()

    conn = get_db()
    try:
        conn.execute(
            "UPDATE Users SET failed_logins=0, locked_until=0, last_login=? WHERE id=?",
            (now_ms(), badge_id)
        )
        conn.commit()
    finally:
        conn.close()

    otp = make_otp()
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()
    otp_id = f"OTP-{uuid.uuid4().hex[:12].upper()}"
    expires = now_ms() + OTP_TTL_SECONDS * 1000
    conn = get_db()
    try:
        conn.execute("INSERT INTO OTPRequests VALUES (?, ?, ?, ?, 0, 0, ?)",
                     (otp_id, badge_id, otp_hash, expires, now_ms()))
        conn.commit()
    finally:
        conn.close()

    if user["twofa_enabled"]:
        sent, msg = send_otp_email(user["email"], badge_id, otp)
        if not sent:
            # Demo fallback can be explicitly enabled for local college-project testing.
            if os.getenv("DEMO_2FA", "false").lower() == "true":
                return jsonify({"status": "2fa_required", "otp_id": otp_id,
                                "message": "SMTP unavailable. DEMO_2FA is enabled.",
                                "dev_code": otp, "email_hint": user["email"][-12:]})
            return jsonify({"status": "error", "message": msg}), 503
        audit_event(badge_id, "2FA_CODE_SENT", f"Verification code sent to {user['email']}")
        return jsonify({"status": "2fa_required", "otp_id": otp_id,
                        "message": "Verification code sent to your registered email.",
                        "email_hint": user["email"][-12:]})

    token = make_token()
    conn = get_db()
    try:
        conn.execute("INSERT INTO Sessions VALUES (?, ?, ?, ?, ?, ?)",
                     (token, badge_id, now_ms(), now_ms() + SESSION_TTL_SECONDS * 1000,
                      request.remote_addr or "", request.headers.get("User-Agent", "")[:300]))
        conn.commit()
    finally:
        conn.close()
    audit_event(badge_id, "LOGIN_SUCCESS", "Password authentication successful")
    return jsonify({"status": "success", "token": token, "role": user["role"],
                    "must_change": bool(user["must_change"])})


@app.route("/verify-2fa", methods=["POST"])
@app.route("/api/verify-2fa", methods=["POST"])
def verify_2fa():
    data = request.json or {}
    badge_id = str(data.get("badge_id", "")).strip().upper()
    otp_id = data.get("otp_id")
    code = str(data.get("code", "")).strip()

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM OTPRequests WHERE id=? AND user_id=? AND used=0",
            (otp_id, badge_id)
        ).fetchone()
        if not row or row["expires_at"] < now_ms() or row["attempts"] >= 5:
            return jsonify({"status": "error", "message": "Invalid or expired verification code"}), 401
        actual = hashlib.sha256(code.encode()).hexdigest()
        if not hmac.compare_digest(actual, row["otp_hash"]):
            conn.execute("UPDATE OTPRequests SET attempts=attempts+1 WHERE id=?", (otp_id,))
            conn.commit()
            return jsonify({"status": "error", "message": "Incorrect verification code"}), 401

        conn.execute("UPDATE OTPRequests SET used=1 WHERE id=?", (otp_id,))
        token = make_token()
        conn.execute("INSERT INTO Sessions VALUES (?, ?, ?, ?, ?, ?)",
                     (token, badge_id, now_ms(), now_ms() + SESSION_TTL_SECONDS * 1000,
                      request.remote_addr or "", request.headers.get("User-Agent", "")[:300]))
        conn.commit()
        user = conn.execute("SELECT role, must_change FROM Users WHERE id=?", (badge_id,)).fetchone()
    finally:
        conn.close()

    audit_event(badge_id, "LOGIN_SUCCESS", "Password + email 2FA authentication successful")
    return jsonify({"status": "success", "token": token, "role": user["role"],
                    "must_change": bool(user["must_change"])})


@app.route("/logout", methods=["POST"])
@require_auth
def logout():
    token = request.headers.get("X-Auth-Token")
    conn = get_db()
    try:
        conn.execute("DELETE FROM Sessions WHERE token=?", (token,))
        conn.commit()
    finally:
        conn.close()
    audit_event(request.current_user, "LOGOUT", "Session terminated")
    return jsonify({"status": "success"})


@app.route("/me", methods=["GET"])
@require_auth
def me():
    u = get_user(request.current_user)
    return jsonify({
        "id": u["id"], "role": u["role"], "email": u["email"], "full_name": u["full_name"],
        "department": u["department"], "phone": u["phone"], "account_status": u["account_status"],
        "twofa_enabled": bool(u["twofa_enabled"]), "last_login": u["last_login"],
        "created_at": u["created_at"], "permissions": ROLE_PERMISSIONS.get(u["role"], [])
    })


@app.route("/admin/users", methods=["GET"])
@require_role("Admin")
def admin_users():
    conn = get_db()
    try:
        rows = conn.execute("""SELECT id, role, email, full_name, department, phone,
            is_approved, account_status, last_login, failed_logins, locked_until,
            created_at, twofa_enabled FROM Users ORDER BY created_at DESC""").fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/users/<user_id>", methods=["PATCH"])
@require_role("Admin")
def update_user(user_id):
    data = request.json or {}
    target = get_user(user_id)
    if not target:
        return jsonify({"status": "error", "message": "User not found"}), 404

    role = data.get("role", target["role"])
    status = data.get("account_status", target["account_status"])
    if role not in ALLOWED_ROLES or status not in ["ACTIVE", "SUSPENDED"]:
        return jsonify({"status": "error", "message": "Invalid role or account status"}), 400
    if user_id == request.current_user and (role != "Admin" or status != "ACTIVE"):
        return jsonify({"status": "error", "message": "You cannot remove your own Admin access or suspend your own account"}), 400

    conn = get_db()
    try:
        conn.execute("""UPDATE Users SET role=?, email=?, full_name=?, department=?, phone=?,
            account_status=?, is_approved=?, twofa_enabled=? WHERE id=?""",
            (role, data.get("email", target["email"]), data.get("full_name", target["full_name"]),
             data.get("department", target["department"]), data.get("phone", target["phone"]),
             status, int(data.get("is_approved", target["is_approved"])),
             int(data.get("twofa_enabled", target["twofa_enabled"])), user_id))
        conn.commit()
    finally:
        conn.close()
    audit_event(request.current_user, "USER_UPDATED", f"Updated {user_id}: role={role}, status={status}")
    return jsonify({"status": "success", "message": "User updated"})


@app.route("/admin/users/<user_id>/unlock", methods=["POST"])
@require_role("Admin")
def unlock_user(user_id):
    conn = get_db()
    try:
        conn.execute("UPDATE Users SET failed_logins=0, locked_until=0 WHERE id=?", (user_id,))
        conn.commit()
    finally:
        conn.close()
    audit_event(request.current_user, "USER_UNLOCKED", f"Unlocked {user_id}")
    return jsonify({"status": "success"})


@app.route("/admin/pending_users", methods=["GET"])
@require_role("Admin")
def get_pending_users():
    conn = get_db()
    try:
        rows = conn.execute("SELECT id, role, email, full_name, department, created_at FROM Users WHERE is_approved=0").fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/approve_user", methods=["POST"])
@require_role("Admin")
def approve_user():
    data = request.json or {}
    target = data.get("target_badge_id") or data.get("badge_id")
    approved = bool(data.get("approved", True))
    conn = get_db()
    try:
        if approved:
            conn.execute("UPDATE Users SET is_approved=1 WHERE id=?", (target,))
        else:
            conn.execute("UPDATE Users SET account_status='SUSPENDED' WHERE id=?", (target,))
        conn.commit()
    finally:
        conn.close()
    audit_event(request.current_user, "USER_APPROVED" if approved else "USER_REJECTED",
                f"{target} {'approved' if approved else 'rejected'}")
    return jsonify({"status": "success", "message": "User approval updated"})


@app.route("/admin/pending_resets", methods=["GET"])
@require_role("Admin")
def get_pending_resets():
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id request_id, badge_id, reason, timestamp FROM PasswordResetRequests WHERE status='PENDING'"
        ).fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/forgot_password", methods=["POST"])
def forgot_password():
    data = request.json or {}
    badge_id = str(data.get("badge_id", "")).strip().upper()
    reason = data.get("reason", "Forgotten Password")
    if not badge_id:
        return jsonify({"status": "error", "message": "Badge ID is required"}), 400
    if not get_user(badge_id):
        return jsonify({"status": "error", "message": "Badge ID not found"}), 404
    req_id = f"RST-{uuid.uuid4().hex[:12].upper()}"
    conn = get_db()
    try:
        conn.execute("INSERT INTO PasswordResetRequests VALUES (?, ?, ?, ?, 'PENDING')",
                     (req_id, badge_id, reason, now_ms()))
        conn.commit()
    finally:
        conn.close()
    audit_event(badge_id, "PASSWORD_RESET_REQUESTED", f"Request {req_id}", reason)
    return jsonify({"status": "success", "message": "Password reset request submitted."})


@app.route("/admin/reset_password", methods=["POST"])
@require_role("Admin")
def admin_reset_password():
    data = request.json or {}
    badge_id = data.get("badge_id")
    approved = bool(data.get("approved", True))
    conn = get_db()
    try:
        if approved:
            new_password = data.get("new_password")
            if not new_password:
                return jsonify({"status": "error", "message": "New password required"}), 400
            conn.execute("UPDATE Users SET password=?, must_change=1 WHERE id=?",
                         (hash_password(new_password), badge_id))
            conn.execute("UPDATE PasswordResetRequests SET status='APPROVED' WHERE badge_id=? AND status='PENDING'",
                         (badge_id,))
        else:
            conn.execute("UPDATE PasswordResetRequests SET status='REJECTED' WHERE badge_id=? AND status='PENDING'",
                         (badge_id,))
        conn.commit()
    finally:
        conn.close()
    audit_event(request.current_user, "PASSWORD_RESET_APPROVED" if approved else "PASSWORD_RESET_REJECTED",
                f"Password reset for {badge_id}")
    return jsonify({"status": "success"})


@app.route("/upload", methods=["POST"])
@require_auth
def upload():
    data = request.json or {}
    required = ["id", "filename", "category", "mimeType", "originalHash", "data", "salt", "iv"]
    if any(not data.get(k) for k in required):
        return jsonify({"status": "error", "message": "Incomplete document payload"}), 400

    # Never trust uploader supplied by the browser.
    doc_id = data["id"]
    ts = int(data.get("timestamp", now_ms()))
    metadata = {
        "case_id": data.get("case_id", ""),
        "fir_number": data.get("fir_number", ""),
        "title": data.get("title", data.get("filename", "")),
        "department": data.get("department", ""),
        "location": data.get("location", ""),
        "priority": data.get("priority", "Normal"),
        "classification": data.get("classification", "Official"),
        "status": data.get("status", "Submitted"),
        "tags": data.get("tags", "")
    }

    conn = get_db()
    try:
        conn.execute("""INSERT INTO Documents
            (id, filename, category, mimeType, uploader, timestamp, originalHash, data,
             salt, iv, expires_at, signature, public_key, case_id, fir_number, title,
             department, location, priority, classification, status, version, parent_id,
             created_by, updated_at, updated_by, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, '', ?, ?, ?, ?)""",
            (doc_id, data["filename"], data["category"], data["mimeType"], request.current_user,
             ts, data["originalHash"], data["data"], data["salt"], data["iv"],
             data.get("expires_at", 0), data.get("signature", ""), data.get("public_key", ""),
             metadata["case_id"], metadata["fir_number"], metadata["title"], metadata["department"],
             metadata["location"], metadata["priority"], metadata["classification"], metadata["status"],
             request.current_user, ts, request.current_user, metadata["tags"]))
        conn.execute("""INSERT INTO DocumentVersions
            (id, document_id, version, filename, category, mimeType, uploader, timestamp,
             originalHash, data, salt, iv, expires_at, signature, public_key, change_note,
             created_by, created_at)
            VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (f"VER-{uuid.uuid4().hex[:12].upper()}", doc_id, data["filename"], data["category"],
             data["mimeType"], request.current_user, ts, data["originalHash"], data["data"],
             data["salt"], data["iv"], data.get("expires_at", 0), data.get("signature", ""),
             data.get("public_key", ""), "Initial evidence ingestion", request.current_user, ts))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({"status": "error", "message": "Document ID already exists"}), 409
    finally:
        conn.close()

    custody_event(doc_id, request.current_user, "INGESTED", "Initial evidence ingestion",
                  to_user=request.current_user, document_hash=data["originalHash"])
    return jsonify({"status": "success", "id": doc_id, "version": 1})


@app.route("/documents", methods=["GET"])
@require_auth
def get_documents():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    category = request.args.get("category", "").strip()
    classification = request.args.get("classification", "").strip()
    case_id = request.args.get("case_id", "").strip()
    uploader = request.args.get("uploader", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    clauses, params = [], []
    if q:
        like = f"%{q}%"
        clauses.append("""(id LIKE ? OR filename LIKE ? OR category LIKE ? OR uploader LIKE ?
            OR case_id LIKE ? OR fir_number LIKE ? OR title LIKE ? OR department LIKE ?
            OR originalHash LIKE ? OR tags LIKE ?)""")
        params += [like] * 10
    for field, value in [("status", status), ("category", category),
                         ("classification", classification), ("case_id", case_id), ("uploader", uploader)]:
        if value:
            clauses.append(f"{field}=?")
            params.append(value)
    if date_from:
        clauses.append("timestamp>=?")
        params.append(int(float(date_from)))
    if date_to:
        clauses.append("timestamp<=?")
        params.append(int(float(date_to)))

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM Documents" + where + " ORDER BY timestamp DESC", params).fetchall()
    finally:
        conn.close()

    current = now_ms()
    out = []
    for r in rows:
        d = dict(r)
        d["is_expired"] = bool(r["expires_at"] and current > r["expires_at"])
        d.pop("data", None)
        d.pop("salt", None)
        d.pop("iv", None)
        out.append(d)
    return jsonify(out)


@app.route("/documents/<doc_id>", methods=["GET"])
@require_auth
def get_document(doc_id):
    conn = get_db()
    try:
        r = conn.execute("SELECT * FROM Documents WHERE id=?", (doc_id,)).fetchone()
    finally:
        conn.close()
    if not r:
        return jsonify({"status": "error", "message": "Document not found"}), 404
    d = dict(r)
    d["is_expired"] = bool(r["expires_at"] and now_ms() > r["expires_at"])
    return jsonify(d)


@app.route("/documents/<doc_id>/metadata", methods=["PATCH"])
@require_role("Admin", "Supervisor", "Investigator")
def update_document_metadata(doc_id):
    data = request.json or {}
    conn = get_db()
    try:
        old = conn.execute("SELECT * FROM Documents WHERE id=?", (doc_id,)).fetchone()
        if not old:
            return jsonify({"status": "error", "message": "Document not found"}), 404
        fields = ["category", "case_id", "fir_number", "title", "department", "location",
                  "priority", "classification", "status", "expires_at", "tags"]
        updates, params = [], []
        for field in fields:
            if field in data:
                updates.append(f"{field}=?")
                params.append(data[field])
        if not updates:
            return jsonify({"status": "error", "message": "No metadata supplied"}), 400
        updates += ["updated_at=?", "updated_by=?"]
        params += [now_ms(), request.current_user, doc_id]
        conn.execute("UPDATE Documents SET " + ", ".join(updates) + " WHERE id=?", params)
        conn.commit()
    finally:
        conn.close()
    custody_event(doc_id, request.current_user, "METADATA_UPDATED",
                  data.get("change_note", "Document metadata/status updated"),
                  document_hash=old["originalHash"])
    return jsonify({"status": "success"})


@app.route("/documents/<doc_id>/version", methods=["POST"])
@require_role("Admin", "Supervisor", "Investigator")
def create_document_version(doc_id):
    data = request.json or {}
    conn = get_db()
    try:
        old = conn.execute("SELECT * FROM Documents WHERE id=?", (doc_id,)).fetchone()
        if not old:
            return jsonify({"status": "error", "message": "Document not found"}), 404
        version = old["version"] + 1
        ts = now_ms()
        conn.execute("""INSERT INTO DocumentVersions
            (id, document_id, version, filename, category, mimeType, uploader, timestamp,
             originalHash, data, salt, iv, expires_at, signature, public_key, change_note,
             created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (f"VER-{uuid.uuid4().hex[:12].upper()}", doc_id, version,
             data.get("filename", old["filename"]), data.get("category", old["category"]),
             data.get("mimeType", old["mimeType"]), request.current_user, ts,
             data["originalHash"], data["data"], data["salt"], data["iv"],
             data.get("expires_at", old["expires_at"]), data.get("signature", old["signature"]),
             data.get("public_key", old["public_key"]), data.get("change_note", ""),
             request.current_user, ts))
        conn.execute("""UPDATE Documents SET filename=?, category=?, mimeType=?, uploader=?,
            timestamp=?, originalHash=?, data=?, salt=?, iv=?, expires_at=?, signature=?,
            public_key=?, version=?, updated_at=?, updated_by=? WHERE id=?""",
            (data.get("filename", old["filename"]), data.get("category", old["category"]),
             data.get("mimeType", old["mimeType"]), request.current_user, ts, data["originalHash"],
             data["data"], data["salt"], data["iv"], data.get("expires_at", old["expires_at"]),
             data.get("signature", old["signature"]), data.get("public_key", old["public_key"]),
             version, ts, request.current_user, doc_id))
        conn.commit()
    finally:
        conn.close()
    custody_event(doc_id, request.current_user, "VERSION_CREATED",
                  data.get("change_note", f"Version {version} created"),
                  document_hash=data["originalHash"])
    return jsonify({"status": "success", "version": version})


@app.route("/documents/<doc_id>/versions", methods=["GET"])
@require_auth
def document_versions(doc_id):
    conn = get_db()
    try:
        rows = conn.execute("""SELECT id, document_id, version, filename, category, mimeType,
            uploader, timestamp, originalHash, expires_at, signature, public_key,
            change_note, created_by, created_at FROM DocumentVersions
            WHERE document_id=? ORDER BY version DESC""", (doc_id,)).fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/documents/<doc_id>/status", methods=["PATCH"])
@require_role("Admin", "Supervisor", "Investigator")
def document_status(doc_id):
    data = request.json or {}
    status = data.get("status")
    if status not in STATUSES:
        return jsonify({"status": "error", "message": "Invalid document status"}), 400
    conn = get_db()
    try:
        row = conn.execute("SELECT originalHash, status FROM Documents WHERE id=?", (doc_id,)).fetchone()
        if not row:
            return jsonify({"status": "error", "message": "Document not found"}), 404
        conn.execute("UPDATE Documents SET status=?, updated_at=?, updated_by=? WHERE id=?",
                     (status, now_ms(), request.current_user, doc_id))
        conn.commit()
    finally:
        conn.close()
    custody_event(doc_id, request.current_user, "STATUS_CHANGED",
                  f"{row['status']} -> {status}. {data.get('reason', '')}",
                  document_hash=row["originalHash"])
    return jsonify({"status": "success"})


@app.route("/documents/<doc_id>/access", methods=["POST"])
@require_auth
def document_access(doc_id):
    data = request.json or {}
    reason = str(data.get("reason", "")).strip()
    if not reason:
        return jsonify({"status": "error", "message": "Legal/custody justification is required"}), 400
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM Documents WHERE id=?", (doc_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"status": "error", "message": "Document not found"}), 404
    if row["expires_at"] and now_ms() > row["expires_at"]:
        custody_event(doc_id, request.current_user, "ACCESS_DENIED", "Expired document access attempt",
                      document_hash=row["originalHash"])
        create_security_alert(request.current_user, "MEDIUM", "EXPIRED_DOCUMENT_ACCESS",
                              f"Attempted access to {doc_id}")
        return jsonify({"status": "error", "message": "Document access has expired"}), 403

    custody_event(doc_id, request.current_user, "VIEWED", reason,
                  to_user=request.current_user, document_hash=row["originalHash"])
    return jsonify({"status": "success", "data": row["data"], "salt": row["salt"], "iv": row["iv"],
                    "mimeType": row["mimeType"], "filename": row["filename"],
                    "originalHash": row["originalHash"], "signature": row["signature"],
                    "public_key": row["public_key"]})


@app.route("/documents/<doc_id>/custody", methods=["GET"])
@require_role("Admin", "Supervisor")
def get_custody(doc_id):
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM CustodyEvents WHERE document_id=? ORDER BY timestamp ASC",
                            (doc_id,)).fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/documents/<doc_id>/custody/transfer", methods=["POST"])
@require_role("Admin", "Supervisor")
def transfer_custody(doc_id):
    data = request.json or {}
    to_user = str(data.get("to_user", "")).strip().upper()
    reason = str(data.get("reason", "")).strip()
    location = str(data.get("location", "")).strip()
    if not to_user or not reason:
        return jsonify({"status": "error", "message": "Recipient and reason are required"}), 400
    if not get_user_role(to_user):
        return jsonify({"status": "error", "message": "Recipient is not an active approved user"}), 400
    conn = get_db()
    try:
        row = conn.execute("SELECT originalHash FROM Documents WHERE id=?", (doc_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"status": "error", "message": "Document not found"}), 404
    custody_event(doc_id, request.current_user, "TRANSFERRED", reason,
                  from_user=request.current_user, to_user=to_user,
                  location=location, document_hash=row["originalHash"])
    return jsonify({"status": "success"})


@app.route("/audit", methods=["GET"])
@require_role("Admin", "Supervisor")
def get_audit():
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM Audit ORDER BY timestamp DESC LIMIT 500").fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/security-alerts", methods=["GET"])
@require_role("Admin", "Supervisor")
def security_alerts():
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM SecurityAlerts ORDER BY timestamp DESC LIMIT 200").fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/cases", methods=["GET"])
@require_auth
def list_cases():
    q = request.args.get("q", "").strip()
    conn = get_db()
    try:
        if q:
            like = f"%{q}%"
            rows = conn.execute("""SELECT * FROM Cases
                WHERE case_number LIKE ? OR fir_number LIKE ? OR title LIKE ?
                OR department LIKE ? OR lead_investigator LIKE ?
                ORDER BY updated_at DESC""", (like, like, like, like, like)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM Cases ORDER BY updated_at DESC").fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/cases", methods=["POST"])
@require_role("Admin", "Supervisor", "Investigator")
def create_case():
    data = request.json or {}
    title = str(data.get("title", "")).strip()
    if not title:
        return jsonify({"status": "error", "message": "Case title is required"}), 400
    ts = now_ms()
    case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
    case_number = data.get("case_number") or f"CASE/{time.strftime('%Y')}/{secrets.randbelow(90000)+10000}"
    conn = get_db()
    try:
        conn.execute("""INSERT INTO Cases
            (id, case_number, fir_number, title, description, department, lead_investigator,
             priority, status, classification, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (case_id, case_number, data.get("fir_number", ""), title, data.get("description", ""),
             data.get("department", ""), data.get("lead_investigator", request.current_user),
             data.get("priority", "Normal"), data.get("status", "Open"),
             data.get("classification", "Official"), request.current_user, ts, ts))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({"status": "error", "message": "Case number already exists"}), 409
    finally:
        conn.close()
    audit_event(request.current_user, "CASE_CREATED", f"{case_number}: {title}")
    return jsonify({"status": "success", "case_id": case_id, "case_number": case_number})


@app.route("/cases/<case_id>", methods=["PATCH"])
@require_role("Admin", "Supervisor", "Investigator")
def update_case(case_id):
    data = request.json or {}
    allowed = ["fir_number", "title", "description", "department", "lead_investigator",
               "priority", "status", "classification"]
    updates, params = [], []
    for f in allowed:
        if f in data:
            updates.append(f"{f}=?")
            params.append(data[f])
    if not updates:
        return jsonify({"status": "error", "message": "No changes supplied"}), 400
    updates.append("updated_at=?")
    params.append(now_ms())
    params.append(case_id)
    conn = get_db()
    try:
        conn.execute("UPDATE Cases SET " + ", ".join(updates) + " WHERE id=?", params)
        conn.commit()
    finally:
        conn.close()
    audit_event(request.current_user, "CASE_UPDATED", f"Updated {case_id}")
    return jsonify({"status": "success"})


@app.route("/dashboard", methods=["GET"])
@require_auth
def dashboard():
    conn = get_db()
    try:
        total_docs = conn.execute("SELECT COUNT(*) n FROM Documents").fetchone()["n"]
        active_docs = conn.execute(
            "SELECT COUNT(*) n FROM Documents WHERE expires_at=0 OR expires_at>?", (now_ms(),)
        ).fetchone()["n"]
        expired_docs = total_docs - active_docs
        total_users = conn.execute("SELECT COUNT(*) n FROM Users").fetchone()["n"]
        active_users = conn.execute(
            "SELECT COUNT(*) n FROM Users WHERE is_approved=1 AND account_status='ACTIVE'"
        ).fetchone()["n"]
        total_cases = conn.execute("SELECT COUNT(*) n FROM Cases").fetchone()["n"]
        open_cases = conn.execute("SELECT COUNT(*) n FROM Cases WHERE status!='Closed'").fetchone()["n"]
        custody = conn.execute("SELECT COUNT(*) n FROM CustodyEvents").fetchone()["n"]
        alerts = conn.execute("SELECT COUNT(*) n FROM SecurityAlerts WHERE resolved=0").fetchone()["n"]
        pending = conn.execute("SELECT COUNT(*) n FROM Users WHERE is_approved=0").fetchone()["n"]

        categories = conn.execute(
            "SELECT category label, COUNT(*) value FROM Documents GROUP BY category ORDER BY value DESC"
        ).fetchall()
        statuses = conn.execute(
            "SELECT status label, COUNT(*) value FROM Documents GROUP BY status ORDER BY value DESC"
        ).fetchall()
        case_statuses = conn.execute(
            "SELECT status label, COUNT(*) value FROM Cases GROUP BY status ORDER BY value DESC"
        ).fetchall()
        activity = conn.execute("""
            SELECT strftime('%Y-%m-%d', datetime(timestamp/1000,'unixepoch')) day, COUNT(*) value
            FROM Audit GROUP BY day ORDER BY day DESC LIMIT 14
        """).fetchall()
    finally:
        conn.close()

    return jsonify({
        "cards": {
            "total_documents": total_docs, "active_documents": active_docs,
            "expired_documents": expired_docs, "total_users": total_users,
            "active_users": active_users, "total_cases": total_cases,
            "open_cases": open_cases, "custody_events": custody,
            "security_alerts": alerts, "pending_users": pending
        },
        "document_categories": [dict(x) for x in categories],
        "document_statuses": [dict(x) for x in statuses],
        "case_statuses": [dict(x) for x in case_statuses],
        "activity": list(reversed([dict(x) for x in activity]))
    })


@app.route("/system/verify-integrity", methods=["GET"])
@require_role("Admin", "Supervisor")
def verify_integrity():
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM CustodyEvents ORDER BY document_id, timestamp ASC").fetchall()
        checked = 0
        broken = []
        current_doc = None
        previous = ""
        for r in rows:
            if r["document_id"] != current_doc:
                current_doc = r["document_id"]
                previous = ""
            material = "|".join([
                r["id"], r["document_id"], r["actor"], r["action"], r["from_user"],
                r["to_user"], r["reason"], r["location"], r["document_hash"],
                str(r["timestamp"]), r["previous_event_hash"]
            ])
            expected = hashlib.sha256(material.encode()).hexdigest()
            if r["previous_event_hash"] != previous or not hmac.compare_digest(expected, r["event_hash"]):
                broken.append(r["id"])
            previous = r["event_hash"]
            checked += 1
    finally:
        conn.close()
    return jsonify({"status": "success", "checked": checked, "broken_events": broken,
                    "integrity_ok": not broken})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "database": DB_NAME, "time": now_ms()})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "8000")), debug=False, use_reloader=False)
