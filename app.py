import os
import re
import json
import time
import sqlite3
import secrets
import logging
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import defaultdict

import bcrypt
import requests
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List

# ----------------------------
# Logging
# ----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("ahad-co-app")

# ----------------------------
# Paths / Config
# ----------------------------
BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "index.html"
STATIC_DIR = BASE_DIR / "static"

DB_PATH = Path(os.getenv("DB_PATH", str(BASE_DIR / "database.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", "10"))
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
VALID_ENTRY_TYPES = {"phone", "email", "code", "link", "note", "password", "secret_file", "file"}

# ----------------------------
# App
# ----------------------------
app = FastAPI(title="Ahad Co Auth System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# ----------------------------
# Simple in-memory rate limiter
# ----------------------------
RATE_LIMIT_WINDOW = 300
RATE_LIMIT_MAX_ATTEMPTS = 6
_attempts = defaultdict(list)


def rate_limit(key: str):
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    _attempts[key] = [t for t in _attempts[key] if t > window_start]
    if len(_attempts[key]) >= RATE_LIMIT_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many attempts. Please try again in a few minutes.")
    _attempts[key].append(now)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def parse_device(user_agent: str) -> str:
    ua = (user_agent or "").lower()
    if "android" in ua:
        os_name = "Android"
    elif "iphone" in ua or "ipad" in ua:
        os_name = "iOS"
    elif "windows" in ua:
        os_name = "Windows"
    elif "mac os" in ua or "macintosh" in ua:
        os_name = "macOS"
    elif "linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Unknown OS"

    if "chrome" in ua and "edg" not in ua:
        browser = "Chrome"
    elif "firefox" in ua:
        browser = "Firefox"
    elif "safari" in ua and "chrome" not in ua:
        browser = "Safari"
    elif "edg" in ua:
        browser = "Edge"
    else:
        browser = "Browser"

    return f"{browser} on {os_name}"


# ----------------------------
# Models
# ----------------------------
class UserSignup(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserVerify(BaseModel):
    username: str
    otp: str


class UserLogin(BaseModel):
    username: str
    password: str


class ResendOTP(BaseModel):
    username: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class VerifyResetOTP(BaseModel):
    email: EmailStr
    otp: str


class ResetPassword(BaseModel):
    email: EmailStr
    otp: str
    new_password: str


class LinkItem(BaseModel):
    label: str
    url: str


class ProfileUpdate(BaseModel):
    phone: Optional[str] = None
    custom_code: Optional[str] = None
    links: Optional[List[LinkItem]] = None


class VaultEntryCreate(BaseModel):
    type: str
    label: str
    value: str


class VaultEntryUpdate(BaseModel):
    id: int
    type: Optional[str] = None
    label: Optional[str] = None
    value: Optional[str] = None


class VaultEntryDelete(BaseModel):
    id: int


class SessionRevoke(BaseModel):
    session_id: int


class AccountDelete(BaseModel):
    password: str


class TwoFactorSetup(BaseModel):
    enable: bool


class TwoFactorVerify(BaseModel):
    code: str
    temp_token: Optional[str] = None


# ----------------------------
# DB Helpers
# ----------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_utc_str() -> str:
    return now_utc().isoformat()


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password TEXT NOT NULL,
            otp TEXT,
            otp_created_at TEXT,
            is_verified INTEGER NOT NULL DEFAULT 0,
            reset_otp TEXT,
            reset_otp_created_at TEXT,
            reset_verified INTEGER NOT NULL DEFAULT 0,
            role TEXT NOT NULL DEFAULT 'user',
            phone TEXT,
            custom_code TEXT,
            links TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Ensure role column exists if upgrading an existing DB
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    except sqlite3.OperationalError:
        pass

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            device_info TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            label TEXT NOT NULL,
            value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_2fa (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            secret TEXT,
            is_enabled INTEGER NOT NULL DEFAULT 0,
            backup_codes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            ip_address TEXT,
            device_info TEXT,
            location TEXT,
            success INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # User preferences/settings
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_preferences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            theme TEXT DEFAULT 'dark',
            language TEXT DEFAULT 'en',
            timezone TEXT DEFAULT 'UTC',
            notifications_enabled INTEGER DEFAULT 1,
            email_notifications INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # User notes/diary
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            color TEXT DEFAULT '#7C6CF6',
            pinned INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # Bookmarks
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_bookmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            description TEXT,
            category TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # Categories/Tags
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            icon TEXT DEFAULT '📁',
            color TEXT DEFAULT '#7C6CF6',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # API Keys
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            last_used TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # Activity/Audit Log
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # Notifications
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    conn.commit()
    conn.close()
    logger.info("Database initialized at: %s", DB_PATH)


init_db()


def validate_username(username: str) -> str:
    username = username.strip()
    if not USERNAME_REGEX.fullmatch(username):
        raise HTTPException(status_code=400, detail="Username must be 3-30 characters (letters, numbers, _, ., - only).")
    return username


def validate_password(password: str) -> str:
    password = password.strip()
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")
    if len(password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password is too long (max 72 characters).")
    return password


def generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def generate_token() -> str:
    return secrets.token_hex(32)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_session(user_id: int, request: Request) -> str:
    token = generate_token()
    device_info = parse_device(request.headers.get("user-agent", ""))
    ip = client_ip(request)
    current_time = now_utc_str()

    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO sessions (user_id, token, device_info, ip_address, created_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, token, device_info, ip, current_time, current_time))
        conn.commit()
    finally:
        conn.close()

    return token


def send_email(receiver_email: str, subject: str, otp: str, username: str, purpose: str):
    brevo_api_key = os.getenv("BREVO_API_KEY", "").strip()
    sender_email = os.getenv("SENDER_EMAIL", "").strip()
    sender_name = os.getenv("SENDER_NAME", "Ahad Co").strip()

    if not brevo_api_key or not sender_email:
        logger.error("BREVO_API_KEY or SENDER_EMAIL missing.")
        raise HTTPException(status_code=500, detail="Email service is not configured.")

    headers = {"accept": "application/json", "api-key": brevo_api_key, "content-type": "application/json"}

    html_content = f"""
    <html>
      <body style="font-family: Arial, sans-serif; line-height:1.6; background:#0B0C14; padding:24px;">
        <div style="max-width:420px;margin:0 auto;background:#14152a;border-radius:16px;padding:28px;color:#F5F5FA;">
          <h2 style="color:#7C6CF6;margin-top:0;">{purpose}</h2>
          <p>Hello <b>{username}</b>,</p>
          <p>Your verification code is:</p>
          <div style="font-size:32px;font-weight:bold;letter-spacing:6px;color:#2FD9C4;text-align:center;
                      background:rgba(255,255,255,0.06);padding:16px;border-radius:12px;margin:16px 0;">
            {otp}
          </div>
          <p style="color:#A0A0B2;font-size:13px;">This code expires in {OTP_EXPIRY_MINUTES} minutes.
          If you did not request this, you can safely ignore this email.</p>
          <p style="color:#A0A0B2;font-size:12px;margin-top:24px;">— Ahad Co</p>
        </div>
      </body>
    </html>
    """

    payload = {
        "sender": {"name": sender_name, "email": sender_email},
        "to": [{"email": receiver_email}],
        "subject": subject,
        "textContent": f"Hello {username},\n\nYour code is: {otp}\n\nExpires in {OTP_EXPIRY_MINUTES} minutes.",
        "htmlContent": html_content
    }

    try:
        response = requests.post(BREVO_API_URL, json=payload, headers=headers, timeout=20)
        logger.info("Brevo status: %s", response.status_code)
        if response.status_code not in (200, 201, 202):
            raise HTTPException(status_code=500, detail="Failed to send email. Please try again.")
    except requests.RequestException:
        logger.exception("Brevo request failed")
        raise HTTPException(status_code=500, detail="Email service is temporarily unavailable.")


def get_current_user_and_session(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated. Please sign in.")

    token = authorization.split(" ", 1)[1].strip()
    conn = get_db_connection()
    try:
        session_row = conn.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
        if not session_row:
            raise HTTPException(status_code=401, detail="Session expired. Please sign in again.")

        user_row = conn.execute("SELECT * FROM users WHERE id = ?", (session_row["user_id"],)).fetchone()
        if not user_row:
            raise HTTPException(status_code=401, detail="Account not found.")

        conn.execute("UPDATE sessions SET last_seen = ? WHERE id = ?", (now_utc_str(), session_row["id"]))
        conn.commit()

        return user_row, session_row
    finally:
        conn.close()


def require_role(allowed_roles: List[str]):
    """FastAPI dependency to enforce role-based access control (RBAC)."""
    def role_checker(authorization: Optional[str] = Header(None)):
        user_row, session_row = get_current_user_and_session(authorization)
        user_role = user_row["role"] if "role" in user_row.keys() else "user"
        if user_role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Forbidden: You do not have sufficient privileges for this action.")
        return user_row, session_row
    return role_checker


# ----------------------------
# Static / Health
# ----------------------------
@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
def read_index():
    if not INDEX_FILE.exists():
        raise HTTPException(status_code=404, detail="index.html not found.")
    return FileResponse(INDEX_FILE)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "brevo_api_key_set": bool(os.getenv("BREVO_API_KEY", "").strip()),
        "sender_email_set": bool(os.getenv("SENDER_EMAIL", "").strip()),
    }


# ----------------------------
# Signup / Verify (auto-login) / Resend
# ----------------------------
@app.post("/signup")
def signup(user: UserSignup, request: Request):
    rate_limit(f"{client_ip(request)}:signup")

    username = validate_username(user.username)
    email = str(user.email).strip().lower()
    password = validate_password(user.password)

    otp = generate_otp()
    hashed_pw = hash_password(password)
    current_time = now_utc_str()

    conn = get_db_connection()
    cursor = conn.cursor()
    inserted_user_id = None

    try:
        existing = cursor.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
        ).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="Username or email is already taken.")

        cursor.execute("""
            INSERT INTO users (username, email, password, otp, otp_created_at,
                is_verified, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?)
        """, (username, email, hashed_pw, otp, current_time, current_time, current_time))
        conn.commit()
        inserted_user_id = cursor.lastrowid

        send_email(email, "Verify your Ahad Co account", otp, username, "Email Verification")
        return {"message": "Account created. Check your email for the verification code."}

    except HTTPException:
        if inserted_user_id:
            cursor.execute("DELETE FROM users WHERE id = ?", (inserted_user_id,))
            conn.commit()
        raise
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username or email is already taken.")
    finally:
        conn.close()


@app.post("/resend-otp")
def resend_otp(payload: ResendOTP, request: Request):
    username = validate_username(payload.username)
    rate_limit(f"{client_ip(request)}:resend:{username}")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        row = cursor.execute("SELECT id, email, is_verified FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Account not found.")
        if row["is_verified"] == 1:
            return {"message": "Account is already verified."}

        new_otp = generate_otp()
        current_time = now_utc_str()
        cursor.execute("UPDATE users SET otp=?, otp_created_at=?, updated_at=? WHERE id=?",
                        (new_otp, current_time, current_time, row["id"]))
        conn.commit()

        send_email(row["email"], "Your new verification code", new_otp, username, "Email Verification")
        return {"message": "A new code has been sent to your email."}
    finally:
        conn.close()


@app.post("/verify")
def verify_otp(user: UserVerify, request: Request):
    username = validate_username(user.username)
    otp = user.otp.strip()
    rate_limit(f"{client_ip(request)}:verify:{username}")

    if not otp.isdigit() or len(otp) != 6:
        raise HTTPException(status_code=400, detail="Code must be 6 digits.")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        row = cursor.execute(
            "SELECT id, otp, otp_created_at, is_verified, username FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Account not found.")

        if row["is_verified"] == 0:
            db_otp = row["otp"]
            otp_created_at = row["otp_created_at"]
            if not db_otp or not otp_created_at:
                raise HTTPException(status_code=400, detail="No active code found. Please resend.")

            created_time = datetime.fromisoformat(otp_created_at)
            if now_utc() > created_time + timedelta(minutes=OTP_EXPIRY_MINUTES):
                raise HTTPException(status_code=400, detail="Code has expired. Please resend.")
            if db_otp != otp:
                raise HTTPException(status_code=400, detail="Incorrect code.")

            cursor.execute("""
                UPDATE users SET is_verified=1, otp=NULL, otp_created_at=NULL, updated_at=?
                WHERE id=?
            """, (now_utc_str(), row["id"]))
            conn.commit()

        # Auto-login: create a session immediately after successful verification
        token = create_session(row["id"], request)
        return {"message": "Verification successful!", "token": token, "username": row["username"]}
    finally:
        conn.close()


# ----------------------------
# Login / Logout / Sessions
# ----------------------------
@app.post("/login")
def login(user: UserLogin, request: Request):
    identifier = user.username.strip()
    rate_limit(f"{client_ip(request)}:login:{identifier.lower()}")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if "@" in identifier:
            row = cursor.execute(
                "SELECT id, username, password, is_verified FROM users WHERE email = ?", (identifier.lower(),)
            ).fetchone()
        else:
            row = cursor.execute(
                "SELECT id, username, password, is_verified FROM users WHERE username = ?", (identifier,)
            ).fetchone()

        if not row or not verify_password(user.password, row["password"]):
            raise HTTPException(status_code=400, detail="Incorrect username/email or password.")
        if row["is_verified"] == 0:
            raise HTTPException(status_code=400, detail="Please verify your email before signing in.")
    finally:
        conn.close()

    token = create_session(row["id"], request)
    return {"message": "Login successful!", "username": row["username"], "token": token}


@app.post("/logout")
def logout(authorization: Optional[str] = Header(None)):
    _, session_row = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_row["id"],))
        conn.commit()
        return {"message": "Logged out successfully."}
    finally:
        conn.close()


@app.get("/sessions")
def list_sessions(authorization: Optional[str] = Header(None)):
    user, current_session = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT id, device_info, ip_address, created_at, last_seen FROM sessions WHERE user_id = ? ORDER BY last_seen DESC",
            (user["id"],)
        ).fetchall()
        return {
            "sessions": [
                {
                    "id": r["id"],
                    "device_info": r["device_info"],
                    "ip_address": r["ip_address"],
                    "created_at": r["created_at"],
                    "last_seen": r["last_seen"],
                    "is_current": r["id"] == current_session["id"]
                } for r in rows
            ]
        }
    finally:
        conn.close()


@app.post("/sessions/revoke")
def revoke_session(payload: SessionRevoke, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id FROM sessions WHERE id = ? AND user_id = ?", (payload.session_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Session not found.")
        conn.execute("DELETE FROM sessions WHERE id = ?", (payload.session_id,))
        conn.commit()
        return {"message": "Session logged out."}
    finally:
        conn.close()


# ----------------------------
# Forgot Password
# ----------------------------
@app.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, request: Request):
    email = str(payload.email).strip().lower()
    rate_limit(f"{client_ip(request)}:forgot:{email}")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        row = cursor.execute("SELECT id, username FROM users WHERE email = ?", (email,)).fetchone()
        if not row:
            return {"message": "If this email exists, a reset code has been sent."}

        otp = generate_otp()
        current_time = now_utc_str()
        cursor.execute("""
            UPDATE users SET reset_otp=?, reset_otp_created_at=?, reset_verified=0, updated_at=?
            WHERE id=?
        """, (otp, current_time, current_time, row["id"]))
        conn.commit()

        send_email(email, "Reset your Ahad Co password", otp, row["username"], "Password Reset")
        return {"message": "If this email exists, a reset code has been sent."}
    finally:
        conn.close()


@app.post("/verify-reset-otp")
def verify_reset_otp(payload: VerifyResetOTP, request: Request):
    email = str(payload.email).strip().lower()
    otp = payload.otp.strip()
    rate_limit(f"{client_ip(request)}:resetverify:{email}")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        row = cursor.execute(
            "SELECT id, reset_otp, reset_otp_created_at FROM users WHERE email = ?", (email,)
        ).fetchone()
        if not row or not row["reset_otp"]:
            raise HTTPException(status_code=400, detail="Please request a reset code first.")

        created_time = datetime.fromisoformat(row["reset_otp_created_at"])
        if now_utc() > created_time + timedelta(minutes=OTP_EXPIRY_MINUTES):
            raise HTTPException(status_code=400, detail="Code has expired. Please request a new one.")
        if row["reset_otp"] != otp:
            raise HTTPException(status_code=400, detail="Incorrect code.")

        cursor.execute("UPDATE users SET reset_verified=1, updated_at=? WHERE id=?", (now_utc_str(), row["id"]))
        conn.commit()
        return {"message": "Code verified. You can now set a new password."}
    finally:
        conn.close()


@app.post("/reset-password")
def reset_password(payload: ResetPassword, request: Request):
    email = str(payload.email).strip().lower()
    new_password = validate_password(payload.new_password)
    rate_limit(f"{client_ip(request)}:resetpw:{email}")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        row = cursor.execute(
            "SELECT id, reset_otp, reset_verified FROM users WHERE email = ?", (email,)
        ).fetchone()
        if not row or row["reset_verified"] != 1 or row["reset_otp"] != payload.otp.strip():
            raise HTTPException(status_code=400, detail="Please verify the reset code first.")

        hashed_pw = hash_password(new_password)
        cursor.execute("""
            UPDATE users SET password=?, reset_otp=NULL, reset_otp_created_at=NULL,
                reset_verified=0, updated_at=?
            WHERE id=?
        """, (hashed_pw, now_utc_str(), row["id"]))
        # Reset password -> log out of all devices for safety
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (row["id"],))
        conn.commit()
        return {"message": "Password updated successfully. Please sign in again."}
    finally:
        conn.close()


# ----------------------------
# Profile
# ----------------------------
@app.get("/profile")
def get_profile(authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    links = json.loads(user["links"]) if user["links"] else []
    return {
        "username": user["username"],
        "email": user["email"],
        "phone": user["phone"],
        "custom_code": user["custom_code"],
        "links": links,
        "created_at": user["created_at"],
    }


@app.post("/profile/update")
def update_profile(payload: ProfileUpdate, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        phone = payload.phone if payload.phone is not None else user["phone"]
        custom_code = payload.custom_code if payload.custom_code is not None else user["custom_code"]
        links_json = json.dumps([l.dict() for l in payload.links]) if payload.links is not None else user["links"]

        conn.execute("""
            UPDATE users SET phone=?, custom_code=?, links=?, updated_at=?
            WHERE id=?
        """, (phone, custom_code, links_json, now_utc_str(), user["id"]))
        conn.commit()
        return {"message": "Profile updated successfully."}
    finally:
        conn.close()


# ----------------------------
# Data Vault (multiple phone/email/code/link/note entries)
# ----------------------------
@app.get("/vault")
def list_vault(authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT id, type, label, value, created_at, updated_at FROM vault_entries WHERE user_id = ? ORDER BY created_at DESC",
            (user["id"],)
        ).fetchall()
        return {"entries": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.post("/vault/add")
def add_vault_entry(payload: VaultEntryCreate, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    entry_type = payload.type.strip().lower()
    if entry_type not in VALID_ENTRY_TYPES:
        raise HTTPException(status_code=400, detail="Invalid entry type.")
    label = payload.label.strip()
    value = payload.value.strip()
    if not label or not value:
        raise HTTPException(status_code=400, detail="Label and value are required.")

    conn = get_db_connection()
    try:
        current_time = now_utc_str()
        cursor = conn.execute("""
            INSERT INTO vault_entries (user_id, type, label, value, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user["id"], entry_type, label, value, current_time, current_time))
        conn.commit()
        return {"message": "Entry added.", "id": cursor.lastrowid}
    finally:
        conn.close()


@app.post("/vault/update")
def update_vault_entry(payload: VaultEntryUpdate, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM vault_entries WHERE id = ? AND user_id = ?", (payload.id, user["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Entry not found.")

        entry_type = payload.type.strip().lower() if payload.type else row["type"]
        if entry_type not in VALID_ENTRY_TYPES:
            raise HTTPException(status_code=400, detail="Invalid entry type.")
        label = payload.label.strip() if payload.label is not None else row["label"]
        value = payload.value.strip() if payload.value is not None else row["value"]

        conn.execute("""
            UPDATE vault_entries SET type=?, label=?, value=?, updated_at=? WHERE id=?
        """, (entry_type, label, value, now_utc_str(), payload.id))
        conn.commit()
        return {"message": "Entry updated."}
    finally:
        conn.close()


@app.post("/vault/delete")
def delete_vault_entry(payload: VaultEntryDelete, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id FROM vault_entries WHERE id = ? AND user_id = ?", (payload.id, user["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Entry not found.")
        conn.execute("DELETE FROM vault_entries WHERE id = ?", (payload.id,))
        conn.commit()
        return {"message": "Entry deleted."}
    finally:
        conn.close()


# ----------------------------
# Account Deletion
# ----------------------------
@app.post("/account/delete")
def delete_account(payload: AccountDelete, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    if not verify_password(payload.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect password.")

    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM vault_entries WHERE user_id = ?", (user["id"],))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
        conn.execute("DELETE FROM users WHERE id = ?", (user["id"],))
        conn.commit()
        return {"message": "Account deleted permanently."}
    finally:
        conn.close()


# ----------------------------
# Two-Factor Authentication (2FA)
# ----------------------------
@app.get("/2fa/status")
def get_2fa_status(authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM user_2fa WHERE user_id = ?", (user["id"],)).fetchone()
        if not row:
            return {"enabled": False, "backup_codes_count": 0}
        return {
            "enabled": bool(row["is_enabled"]),
            "backup_codes_count": len(json.loads(row["backup_codes"] or "[]"))
        }
    finally:
        conn.close()


@app.post("/2fa/setup")
def setup_2fa(payload: TwoFactorSetup, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        current_time = now_utc_str()
        
        if payload.enable:
            # Generate new TOTP secret
            secret = pyotp.random_base32()
            
            # Generate backup codes
            backup_codes = [secrets.token_hex(8) for _ in range(8)]
            
            # Store temporarily (not enabled yet)
            conn.execute("""
                INSERT OR REPLACE INTO user_2fa (user_id, secret, is_enabled, backup_codes, created_at, updated_at)
                VALUES (?, ?, 0, ?, ?, ?)
            """, (user["id"], secret, json.dumps(backup_codes), current_time, current_time))
            conn.commit()
            
            # Generate QR code
            totp = pyotp.TOTP(secret)
            uri = totp.provisioning_uri(name=user["username"], issuer_name="Ahad Co")
            
            # Generate QR image
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            qr_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return {
                "secret": secret,
                "qr_code": f"data:image/png;base64,{qr_base64}",
                "backup_codes": backup_codes,
                "message": "Scan the QR code with your authenticator app"
            }
        else:
            # Disable 2FA
            conn.execute("DELETE FROM user_2fa WHERE user_id = ?", (user["id"],))
            conn.commit()
            return {"message": "2FA disabled successfully"}
    finally:
        conn.close()


@app.post("/2fa/verify-setup")
def verify_2fa_setup(payload: TwoFactorVerify, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM user_2fa WHERE user_id = ?", (user["id"],)).fetchone()
        if not row or not row["secret"]:
            raise HTTPException(status_code=400, detail="2FA setup not initiated")
        
        if row["is_enabled"]:
            raise HTTPException(status_code=400, detail="2FA is already enabled")
        
        totp = pyotp.TOTP(row["secret"])
        if not totp.verify(payload.code):
            raise HTTPException(status_code=400, detail="Invalid verification code")
        
        # Enable 2FA
        conn.execute("UPDATE user_2fa SET is_enabled=1, updated_at=? WHERE user_id=?", 
                     (now_utc_str(), user["id"]))
        conn.commit()
        
        return {"message": "2FA enabled successfully!"}
    finally:
        conn.close()


@app.post("/2fa/verify-login")
def verify_2fa_login(payload: TwoFactorVerify, authorization: Optional[str] = Header(None)):
    """Verify 2FA code during login when 2FA is enabled"""
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM user_2fa WHERE user_id = ?", (user["id"],)).fetchone()
        if not row or not row["is_enabled"]:
            raise HTTPException(status_code=400, detail="2FA not enabled")
        
        # Check if it's a backup code
        backup_codes = json.loads(row["backup_codes"] or "[]")
        if payload.code in backup_codes:
            # Remove used backup code
            backup_codes.remove(payload.code)
            conn.execute("UPDATE user_2fa SET backup_codes=? WHERE user_id=?", 
                         (json.dumps(backup_codes), user["id"]))
            conn.commit()
            return {"message": "Backup code accepted", "backup_codes_remaining": len(backup_codes)}
        
        # Verify TOTP
        totp = pyotp.TOTP(row["secret"])
        if not totp.verify(payload.code):
            raise HTTPException(status_code=400, detail="Invalid 2FA code")
        
        return {"message": "2FA verified successfully"}
    finally:
        conn.close()


# ----------------------------
# Login History
# ----------------------------
@app.get("/login-history")
def get_login_history(authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        rows = conn.execute("""
            SELECT ip_address, device_info, location, success, created_at 
            FROM login_history 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 20
        """, (user["id"],)).fetchall()
        return {"history": [dict(r) for r in rows]}
    finally:
        conn.close()


# ----------------------------
# API Keys (for developers)
# ----------------------------
class APIKeyCreate(BaseModel):
    name: str


class APIKeyRevoke(BaseModel):
    key_id: int


class NoteCreate(BaseModel):
    title: str
    content: str
    color: Optional[str] = "#7C6CF6"


class NoteUpdate(BaseModel):
    id: int
    title: Optional[str] = None
    content: Optional[str] = None
    color: Optional[str] = None
    pinned: Optional[bool] = None


class NoteDelete(BaseModel):
    id: int


class BookmarkCreate(BaseModel):
    title: str
    url: str
    description: Optional[str] = None
    category: Optional[str] = None


class BookmarkUpdate(BaseModel):
    id: int
    title: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None


class BookmarkDelete(BaseModel):
    id: int


class PasswordGeneratorRequest(BaseModel):
    length: int = 16
    include_uppercase: bool = True
    include_numbers: bool = True
    include_symbols: bool = True


class CategoryCreate(BaseModel):
    name: str
    icon: Optional[str] = "📁"
    color: Optional[str] = "#7C6CF6"


class CategoryUpdate(BaseModel):
    id: int
    name: Optional[str] = None
    icon: Optional[str] = None
    color: Optional[str] = None


class CategoryDelete(BaseModel):
    id: int


class UserPreferencesUpdate(BaseModel):
    theme: Optional[str] = None
    language: Optional[str] = None
    timezone: Optional[str] = None
    notifications_enabled: Optional[bool] = None
    email_notifications: Optional[bool] = None


class ActivityLogEntry(BaseModel):
    action: str
    details: Optional[str] = None


@app.get("/api-keys")
def list_api_keys(authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT id, name, last_used, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
            (user["id"],)
        ).fetchall()
        return {"keys": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.post("/api-keys")
def create_api_key(payload: APIKeyCreate, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    key = f"ahad_{secrets.token_hex(24)}"
    key_hash = hash_password(key)
    current_time = now_utc_str()
    
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "INSERT INTO api_keys (user_id, name, key_hash, created_at) VALUES (?, ?, ?, ?)",
            (user["id"], payload.name, key_hash, current_time)
        )
        conn.commit()
        return {"message": "API key created", "key": key, "id": cursor.lastrowid}
    finally:
        conn.close()


@app.post("/api-keys/revoke")
def revoke_api_key(payload: APIKeyRevoke, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id FROM api_keys WHERE id = ? AND user_id = ?", 
                          (payload.key_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="API key not found")
        conn.execute("DELETE FROM api_keys WHERE id = ?", (payload.key_id,))
        conn.commit()
        return {"message": "API key revoked"}
    finally:
        conn.close()


# ================================
# NOTES / DIARY
# ================================
@app.get("/notes")
def list_notes(authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM user_notes WHERE user_id = ? ORDER BY pinned DESC, updated_at DESC",
            (user["id"],)
        ).fetchall()
        return {"notes": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.post("/notes")
def create_note(payload: NoteCreate, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    current_time = now_utc_str()
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "INSERT INTO user_notes (user_id, title, content, color, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (user["id"], payload.title, payload.content, payload.color, current_time, current_time)
        )
        conn.commit()
        return {"message": "Note created", "id": cursor.lastrowid}
    finally:
        conn.close()


@app.put("/notes")
def update_note(payload: NoteUpdate, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM user_notes WHERE id = ? AND user_id = ?", 
                          (payload.id, user["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Note not found")
        
        title = payload.title if payload.title is not None else row["title"]
        content = payload.content if payload.content is not None else row["content"]
        color = payload.color if payload.color is not None else row["color"]
        pinned = 1 if payload.pinned else 0
        
        conn.execute(
            "UPDATE user_notes SET title=?, content=?, color=?, pinned=?, updated_at=? WHERE id=?",
            (title, content, color, pinned, now_utc_str(), payload.id)
        )
        conn.commit()
        return {"message": "Note updated"}
    finally:
        conn.close()


@app.delete("/notes")
def delete_note(payload: NoteDelete, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id FROM user_notes WHERE id = ? AND user_id = ?", 
                          (payload.id, user["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Note not found")
        conn.execute("DELETE FROM user_notes WHERE id = ?", (payload.id,))
        conn.commit()
        return {"message": "Note deleted"}
    finally:
        conn.close()


# ================================
# BOOKMARKS
# ================================
@app.get("/bookmarks")
def list_bookmarks(authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM user_bookmarks WHERE user_id = ? ORDER BY created_at DESC",
            (user["id"],)
        ).fetchall()
        return {"bookmarks": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.post("/bookmarks")
def create_bookmark(payload: BookmarkCreate, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    current_time = now_utc_str()
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "INSERT INTO user_bookmarks (user_id, title, url, description, category, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user["id"], payload.title, payload.url, payload.description, payload.category, current_time, current_time)
        )
        conn.commit()
        return {"message": "Bookmark created", "id": cursor.lastrowid}
    finally:
        conn.close()


@app.put("/bookmarks")
def update_bookmark(payload: BookmarkUpdate, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM user_bookmarks WHERE id = ? AND user_id = ?", 
                          (payload.id, user["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Bookmark not found")
        
        title = payload.title if payload.title is not None else row["title"]
        url = payload.url if payload.url is not None else row["url"]
        description = payload.description if payload.description is not None else row["description"]
        category = payload.category if payload.category is not None else row["category"]
        
        conn.execute(
            "UPDATE user_bookmarks SET title=?, url=?, description=?, category=?, updated_at=? WHERE id=?",
            (title, url, description, category, now_utc_str(), payload.id)
        )
        conn.commit()
        return {"message": "Bookmark updated"}
    finally:
        conn.close()


@app.delete("/bookmarks")
def delete_bookmark(payload: BookmarkDelete, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id FROM user_bookmarks WHERE id = ? AND user_id = ?", 
                          (payload.id, user["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Bookmark not found")
        conn.execute("DELETE FROM user_bookmarks WHERE id = ?", (payload.id,))
        conn.commit()
        return {"message": "Bookmark deleted"}
    finally:
        conn.close()


# ================================
# CATEGORIES / TAGS
# ================================
@app.get("/categories")
def list_categories(authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM user_categories WHERE user_id = ? ORDER BY name",
            (user["id"],)
        ).fetchall()
        return {"categories": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.post("/categories")
def create_category(payload: CategoryCreate, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    current_time = now_utc_str()
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "INSERT INTO user_categories (user_id, name, icon, color, created_at) VALUES (?, ?, ?, ?, ?)",
            (user["id"], payload.name, payload.icon, payload.color, current_time)
        )
        conn.commit()
        return {"message": "Category created", "id": cursor.lastrowid}
    finally:
        conn.close()


@app.put("/categories")
def update_category(payload: CategoryUpdate, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM user_categories WHERE id = ? AND user_id = ?", 
                          (payload.id, user["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Category not found")
        
        name = payload.name if payload.name is not None else row["name"]
        icon = payload.icon if payload.icon is not None else row["icon"]
        color = payload.color if payload.color is not None else row["color"]
        
        conn.execute(
            "UPDATE user_categories SET name=?, icon=?, color=? WHERE id=?",
            (name, icon, color, payload.id)
        )
        conn.commit()
        return {"message": "Category updated"}
    finally:
        conn.close()


@app.delete("/categories")
def delete_category(payload: CategoryDelete, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id FROM user_categories WHERE id = ? AND user_id = ?", 
                          (payload.id, user["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Category not found")
        conn.execute("DELETE FROM user_categories WHERE id = ?", (payload.id,))
        conn.commit()
        return {"message": "Category deleted"}
    finally:
        conn.close()


# ================================
# USER PREFERENCES
# ================================
@app.get("/preferences")
def get_preferences(authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM user_preferences WHERE user_id = ?", (user["id"],)).fetchone()
        if not row:
            return {"theme": "dark", "language": "en", "timezone": "UTC", 
                   "notifications_enabled": True, "email_notifications": True}
        return dict(row)
    finally:
        conn.close()


@app.put("/preferences")
def update_preferences(payload: UserPreferencesUpdate, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    current_time = now_utc_str()
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM user_preferences WHERE user_id = ?", (user["id"],)).fetchone()
        
        if row:
            theme = payload.theme if payload.theme is not None else row["theme"]
            language = payload.language if payload.language is not None else row["language"]
            timezone = payload.timezone if payload.timezone is not None else row["timezone"]
            notifications = 1 if payload.notifications_enabled else 0 if payload.notifications_enabled is not None else row["notifications_enabled"]
            email_notif = 1 if payload.email_notifications else 0 if payload.email_notifications is not None else row["email_notifications"]
            
            conn.execute(
                "UPDATE user_preferences SET theme=?, language=?, timezone=?, notifications_enabled=?, email_notifications=?, updated_at=? WHERE user_id=?",
                (theme, language, timezone, notifications, email_notif, current_time, user["id"])
            )
        else:
            conn.execute(
                "INSERT INTO user_preferences (user_id, theme, language, timezone, notifications_enabled, email_notifications, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (user["id"], payload.theme or "dark", payload.language or "en", payload.timezone or "UTC",
                 1 if payload.notifications_enabled else 0, 1 if payload.email_notifications else 0, current_time, current_time)
            )
        conn.commit()
        return {"message": "Preferences updated"}
    finally:
        conn.close()


# ================================
# PASSWORD GENERATOR
# ================================
@app.post("/generate-password")
def generate_password(payload: PasswordGeneratorRequest, authorization: Optional[str] = Header(None)):
    import string
    
    chars = ""
    if payload.include_uppercase:
        chars += string.ascii_uppercase
    if payload.include_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if payload.include_numbers:
        chars += string.digits
    chars += string.ascii_lowercase
    
    if not chars:
        chars = string.ascii_lowercase
    
    password = ''.join(secrets.choice(chars) for _ in range(payload.length))
    
    return {"password": password, "length": payload.length}


# ================================
# NOTIFICATIONS
# ================================
@app.get("/notifications")
def list_notifications(authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50",
            (user["id"],)
        ).fetchall()
        return {"notifications": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.post("/notifications/read")
def mark_notification_read(notification_id: int, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        conn.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?", 
                    (notification_id, user["id"]))
        conn.commit()
        return {"message": "Notification marked as read"}
    finally:
        conn.close()


@app.post("/notifications/read-all")
def mark_all_read(authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        conn.execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (user["id"],))
        conn.commit()
        return {"message": "All notifications marked as read"}
    finally:
        conn.close()


@app.delete("/notifications")
def delete_notification(notification_id: int, authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM notifications WHERE id=? AND user_id=?", (notification_id, user["id"]))
        conn.commit()
        return {"message": "Notification deleted"}
    finally:
        conn.close()


# ================================
# ACTIVITY LOG
# ================================
@app.get("/activity-log")
def get_activity_log(authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM activity_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 100",
            (user["id"],)
        ).fetchall()
        return {"activities": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.post("/activity-log")
def log_activity(payload: ActivityLogEntry, authorization: Optional[str] = Header(None), request: Request = None):
    user, _ = get_current_user_and_session(authorization)
    current_time = now_utc_str()
    ip = client_ip(request) if request else "unknown"
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO activity_log (user_id, action, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?)",
            (user["id"], payload.action, payload.details, ip, current_time)
        )
        conn.commit()
        return {"message": "Activity logged"}
    finally:
        conn.close()


# ================================
# STATS / DASHBOARD DATA
# ================================
@app.get("/stats")
def get_user_stats(authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        notes_count = conn.execute(
            "SELECT COUNT(*) as count FROM user_notes WHERE user_id = ?", (user["id"],)
        ).fetchone()["count"]
        
        bookmarks_count = conn.execute(
            "SELECT COUNT(*) as count FROM user_bookmarks WHERE user_id = ?", (user["id"],)
        ).fetchone()["count"]
        
        vault_count = conn.execute(
            "SELECT COUNT(*) as count FROM vault_entries WHERE user_id = ?", (user["id"],)
        ).fetchone()["count"]
        
        sessions_count = conn.execute(
            "SELECT COUNT(*) as count FROM sessions WHERE user_id = ?", (user["id"],)
        ).fetchone()["count"]
        
        return {
            "notes": notes_count,
            "bookmarks": bookmarks_count,
            "vault_entries": vault_count,
            "active_sessions": sessions_count,
            "member_since": user["created_at"]
        }
    finally:
        conn.close()


# ================================
# EXPORT / IMPORT DATA
# ================================
@app.get("/export-data")
def export_user_data(authorization: Optional[str] = Header(None)):
    user, _ = get_current_user_and_session(authorization)
    conn = get_db_connection()
    try:
        user_data = {
            "username": user["username"],
            "email": user["email"],
            "phone": user["phone"],
            "custom_code": user["custom_code"],
            "links": json.loads(user["links"]) if user["links"] else [],
            "created_at": user["created_at"]
        }
        
        notes = conn.execute("SELECT * FROM user_notes WHERE user_id = ?", (user["id"],)).fetchall()
        bookmarks = conn.execute("SELECT * FROM user_bookmarks WHERE user_id = ?", (user["id"],)).fetchall()
        vault = conn.execute("SELECT * FROM vault_entries WHERE user_id = ?", (user["id"],)).fetchall()
        
        return {
            "user": user_data,
            "notes": [dict(n) for n in notes],
            "bookmarks": [dict(b) for b in bookmarks],
            "vault": [dict(v) for v in vault],
            "exported_at": now_utc_str()
        }
    finally:
        conn.close()
