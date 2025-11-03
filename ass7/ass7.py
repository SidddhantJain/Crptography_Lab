"""
Assignment 7: Secure Website Demo (Password Protection Techniques)

This Flask app demonstrates multiple defenses against password cracking:
- Strong password hashing using scrypt (salted) + optional pepper (env SECRET_PEPPER)
- Password policy enforcement (length/complexity)
- Account lockout after repeated failures
- Per-IP rate limiting on login attempts
- Optional TOTP (Google Authenticator) 2FA
- CSRF tokens on forms
- Secure session cookie settings; basic security headers (CSP, X-Frame-Options)

Run (dev):
  pip install flask
  python ass7.py
  # open http://127.0.0.1:5000

Note: For demo simplicity, templates are inline via render_template_string and a local SQLite database is used.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import string
import time
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template_string,
    session,
    make_response,
    flash,
)

APP_SECRET = os.environ.get("FLASK_SECRET", "dev-secret-change-me")
PEPPER = os.environ.get("SECRET_PEPPER", "dev-pepper-change-me").encode("utf-8")
DB_PATH = os.path.join(os.path.dirname(__file__), "ass7.db")

# scrypt params (tune up for production; ensure they are not too slow for the demo)
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32

# login limits
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
RATE_LIMIT_MAX_PER_MINUTE = 10

app = Flask(__name__)
app.secret_key = APP_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # set True when serving over HTTPS
)

# in-memory per-IP rate limiter buckets: {ip: [timestamps]}
rate_buckets: Dict[str, List[float]] = {}


# --------------- Utilities ---------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            pw_hash BLOB NOT NULL,
            salt BLOB NOT NULL,
            totp_secret TEXT,
            created_at INTEGER NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    return conn


def csrf_token() -> str:
    tok = session.get("csrf_token")
    if not tok:
        tok = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii")
        session["csrf_token"] = tok
    return tok


def check_csrf():
    token = session.get("csrf_token")
    form_tok = request.form.get("csrf_token")
    if not token or not form_tok or not hmac.compare_digest(token, form_tok):
        raise ValueError("CSRF token invalid")


def password_policy_ok(pw: str) -> Tuple[bool, List[str]]:
    issues = []
    if len(pw) < 12:
        issues.append("Password must be at least 12 characters long")
    if not any(c.islower() for c in pw):
        issues.append("Include at least one lowercase letter")
    if not any(c.isupper() for c in pw):
        issues.append("Include at least one uppercase letter")
    if not any(c.isdigit() for c in pw):
        issues.append("Include at least one digit")
    specials = set("!@#$%^&*()-_=+[]{};:'\",.<>/?|`~")
    if not any(c in specials for c in pw):
        issues.append("Include at least one special character")
    return (len(issues) == 0, issues)


def hash_password(password: str, salt: bytes) -> bytes:
    # Combine password with a global pepper; pepper should be stored outside DB
    pw_bytes = password.encode("utf-8") + PEPPER
    dk = hashlib.scrypt(pw_bytes, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)
    return dk


def verify_password(password: str, salt: bytes, stored_hash: bytes) -> bool:
    test = hash_password(password, salt)
    return hmac.compare_digest(test, stored_hash)


# --------------- TOTP (RFC 6238) ---------------

def base32_secret(nbytes: int = 20) -> str:
    return base64.b32encode(os.urandom(nbytes)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = 6, algo=hashlib.sha1) -> int:
    # decode base32
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32 + pad, casefold=True)
    msg = counter.to_bytes(8, "big")
    h = hmac.new(key, msg, algo).digest()
    # dynamic truncation
    o = h[-1] & 0x0F
    code = ((h[o] & 0x7F) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]
    return code % (10 ** digits)


def totp_now(secret_b32: str, step: int = 30, digits: int = 6, t: int | None = None) -> int:
    if t is None:
        t = int(time.time())
    counter = t // step
    return _hotp(secret_b32, counter, digits)


def totp_verify(secret_b32: str, code: str, window: int = 1) -> bool:
    try:
        val = int(code)
    except Exception:
        """
        Assignment 7 launcher

        This wrapper simply runs the secure Flask app implemented in `secure_site.py`.
        Keeping a thin launcher avoids code duplication and fixes earlier merge issues.
        Run:
          python ass7.py
        Then open http://127.0.0.1:5000
        """

        from secure_site import app

        if __name__ == "__main__":
            app.run(debug=True)

