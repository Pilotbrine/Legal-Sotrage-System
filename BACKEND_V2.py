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
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='.', static_url_path='')
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
        return False, "SMTP is not configured."

    msg = EmailMessage()
    msg["Subject"] = "Secure DMS verification code"
    msg["From"] = sender
    msg["To"] = email
    msg.set_content(
        f"Secure DMS\n\nHello {user_id},\n\nYour verification code is {otp}.\n"
        f"It expires in {OTP_TTL_SECONDS // 60} minutes."
    )
    try:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls()
            if smtp_user:
                server.login(smtp_user, smtp_password)
            server.send_message(msg)
        return True, "Verification code sent."
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


# Static file route for hosting single-page application in cloud environments
@app.route("/")
def index():
    return send_from_directory(".", "FRONTEND_V2_3.html")


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
        return jsonify({"status": "error", "message": "Account is suspended."}), 403
    if user["locked_until"] and user["locked_until"] > now_ms():
        return jsonify({"status": "error", "message": "Account temporarily locked."}), 423
    if not verify_password(user["password"], password):
        conn = get_db()
        try:
            failures = user["failed_logins"] + 1
            locked = now_ms() + 15 * 60 * 1000 if failures >= 5 else 0
            conn.execute("UPDATE Users SET failed_logins=?, locked_until=? WHERE id=?", (failures, locked, badge_id))
            conn.commit()
        finally:
            conn.close()
        audit_event(badge_id, "LOGIN_FAILED", f"Attempt {failures}")
        if failures >= 5:
            create_security_alert(badge_id, "HIGH", "ACCOUNT_LOCKED", "Five failed login attempts")
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    if not user["is_approved"]:
        return jsonify({"status": "error", "message": "Account pending approval"}), 403

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
            if os.getenv("DEMO_2FA", "false").lower() == "true":
                return jsonify({"status": "2fa_required", "otp_id": otp_id,
                                "message": "SMTP unavailable. DEMO_2FA active.",
                                "dev_code": otp, "email_hint": user["email"][-12:]})
            return jsonify({"status": "error", "message": msg}), 503
        audit_event(badge_id, "2FA_CODE_SENT", f"Code sent to {user['email']}")
        return jsonify({"status": "2fa_required", "otp_id": otp_id,
                        "message": "Verification code sent.",
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
    audit_event(badge_id, "LOGIN_SUCCESS", "Authentication successful")
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
            return jsonify({"status": "error", "message": "Invalid/expired code"}), 401
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

    audit_event(badge_id, "LOGIN_SUCCESS", "2FA authentication successful")
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


@app.route("/dashboard", methods=["GET"])
@require_auth
def dashboard():
    conn = get_db()
    try:
        total_docs = conn.execute("SELECT COUNT(*) FROM Documents").fetchone()[0]
        active_docs = conn.execute("SELECT COUNT(*) FROM Documents WHERE expires_at=0 OR expires_at>?", (now_ms(),)).fetchone()[0]
        total_cases = conn.execute("SELECT COUNT(*) FROM Cases").fetchone()[0]
        open_cases = conn.execute("SELECT COUNT(*) FROM Cases WHERE status='Open'").fetchone()[0]
        active_users = conn.execute("SELECT COUNT(*) FROM Users WHERE account_status='ACTIVE'").fetchone()[0]
        pending_users = conn.execute("SELECT COUNT(*) FROM Users WHERE is_approved=0").fetchone()[0]
        alerts = conn.execute("SELECT COUNT(*) FROM SecurityAlerts WHERE resolved=0").fetchone()[0]
        expired = conn.execute("SELECT COUNT(*) FROM Documents WHERE expires_at>0 AND expires_at<=?", (now_ms(),)).fetchone()[0]
        custody_cnt = conn.execute("SELECT COUNT(*) FROM CustodyEvents").fetchone()[0]

        cat_rows = conn.execute("SELECT category, COUNT(*) as cnt FROM Documents GROUP BY category").fetchall()
        status_rows = conn.execute("SELECT status, COUNT(*) as cnt FROM Documents GROUP BY status").fetchall()
    finally:
        conn.close()

    return jsonify({
        "cards": {
            "total_documents": total_docs,
            "active_documents": active_docs,
            "total_cases": total_cases,
            "open_cases": open_cases,
            "active_users": active_users,
            "pending_users": pending_users,
            "security_alerts": alerts,
            "expired_documents": expired,
            "custody_events": custody_cnt
        },
        "activity": [{"day": f"Day {i+1}", "value": (i * 3 + 2) % 11} for i in range(14)],
        "document_categories": [{"label": r["category"] or "Uncategorized", "value": r["cnt"]} for r in cat_rows],
        "document_statuses": [{"label": r["status"] or "Unknown", "value": r["cnt"]} for r in status_rows]
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
        return jsonify({"status": "error", "message": "Invalid role/status"}), 400

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
    audit_event(request.current_user, "USER_UPDATED", f"Updated {user_id}")
    return jsonify({"status": "success"})


@app.route("/upload", methods=["POST"])
@require_auth
def upload():
    data = request.json or {}
    required = ["id", "filename", "category", "mimeType", "originalHash", "data", "salt", "iv"]
    if any(not data.get(k) for k in required):
        return jsonify({"status": "error", "message": "Incomplete payload"}), 400

    doc_id = data["id"]
    ts = int(data.get("timestamp", now_ms()))
    conn = get_db()
    try:
        conn.execute("""INSERT INTO Documents
            (id, filename, category, mimeType, uploader, timestamp, originalHash, data,
             salt, iv, expires_at, signature, public_key, case_id, fir_number, title,
             department, location, priority, classification, status, version, created_by, updated_at, updated_by, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)""",
            (doc_id, data["filename"], data["category"], data["mimeType"], request.current_user,
             ts, data["originalHash"], data["data"], data["salt"], data["iv"],
             data.get("expires_at", 0), data.get("signature", ""), data.get("public_key", ""),
             data.get("case_id", ""), data.get("fir_number", ""), data.get("title", data["filename"]),
             data.get("department", ""), data.get("location", ""), data.get("priority", "Normal"),
             data.get("classification", "Official"), data.get("status", "Submitted"),
             request.current_user, ts, request.current_user, data.get("tags", "")))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({"status": "error", "message": "Document exists"}), 409
    finally:
        conn.close()

    custody_event(doc_id, request.current_user, "INGESTED", "Initial evidence ingestion", document_hash=data["originalHash"])
    return jsonify({"status": "success", "id": doc_id, "version": 1})


@app.route("/documents", methods=["GET"])
@require_auth
def get_documents():
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM Documents ORDER BY timestamp DESC").fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["is_expired"] = bool(r["expires_at"] and now_ms() > r["expires_at"])
        d.pop("data", None); d.pop("salt", None); d.pop("iv", None)
        out.append(d)
    return jsonify(out)


@app.route("/documents/<doc_id>/access", methods=["POST"])
@require_auth
def access_document(doc_id):
    data = request.json or {}
    reason = data.get("reason", "Viewing record")
    conn = get_db()
    try:
        r = conn.execute("SELECT * FROM Documents WHERE id=?", (doc_id,)).fetchone()
    finally:
        conn.close()
    if not r:
        return jsonify({"status": "error", "message": "Document not found"}), 404
    custody_event(doc_id, request.current_user, "ACCESSED", reason, document_hash=r["originalHash"])
    return jsonify(dict(r))


@app.route("/documents/<doc_id>/custody", methods=["GET"])
@require_auth
def get_custody(doc_id):
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM CustodyEvents WHERE document_id=? ORDER BY timestamp DESC", (doc_id,)).fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/cases", methods=["GET", "POST"])
@require_auth
def handle_cases():
    if request.method == "POST":
        data = request.json or {}
        case_num = data.get("case_number") or f"CASE/2026/{secrets.randbelow(10000):04d}"
        conn = get_db()
        try:
            conn.execute("""INSERT INTO Cases
                (id, case_number, fir_number, title, description, department, lead_investigator, priority, status, classification, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?, ?, ?)""",
                (f"CAS-{uuid.uuid4().hex[:10].upper()}", case_num, data.get("fir_number", ""),
                 data.get("title", "Untitled Case"), data.get("description", ""), data.get("department", ""),
                 data.get("lead_investigator", request.current_user), data.get("priority", "Normal"),
                 data.get("classification", "Official"), request.current_user, now_ms(), now_ms()))
            conn.commit()
        finally:
            conn.close()
        return jsonify({"status": "success", "case_number": case_num})
    
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM Cases ORDER BY created_at DESC").fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/audit", methods=["GET"])
@require_role("Admin", "Supervisor")
def get_audit():
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM Audit ORDER BY timestamp DESC LIMIT 100").fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/security-alerts", methods=["GET"])
@require_role("Admin", "Supervisor")
def get_alerts():
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM SecurityAlerts ORDER BY timestamp DESC").fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/system/verify-integrity", methods=["GET"])
@require_role("Admin", "Supervisor")
def verify_integrity():
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM CustodyEvents ORDER BY timestamp ASC").fetchall()
    finally:
        conn.close()

    broken = []
    prev_hash = ""
    for r in rows:
        mat = "|".join([
            r["id"], r["document_id"], r["actor"], r["action"], r["from_user"] or "",
            r["to_user"] or "", r["reason"] or "", r["location"] or "", r["document_hash"] or "",
            str(r["timestamp"]), prev_hash
        ])
        calc = hashlib.sha256(mat.encode()).hexdigest()
        if calc != r["event_hash"]:
            broken.append(r["id"])
        prev_hash = r["event_hash"]

    return jsonify({"integrity_ok": len(broken) == 0, "checked": len(rows), "broken_events": broken})


if __name__ == "__main__":
    init_db()
    port = int(os.getenv("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)