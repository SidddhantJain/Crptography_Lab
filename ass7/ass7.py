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
        return False
    now = int(time.time())
    for w in range(-window, window + 1):
        if totp_now(secret_b32, t=now + w * 30) == val:
            return True
    return False


def otpauth_uri(account: str, issuer: str, secret_b32: str) -> str:
    label = f"{issuer}:{account}"
    return f"otpauth://totp/{label}?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


# --------------- Rate limiting ---------------

def rate_limit_ok(ip: str) -> bool:
    now = time.time()
    bucket = rate_buckets.setdefault(ip, [])
    # remove entries older than 60 seconds
    rate_buckets[ip] = [ts for ts in bucket if now - ts < 60.0]
    if len(rate_buckets[ip]) >= RATE_LIMIT_MAX_PER_MINUTE:
        return False
    rate_buckets[ip].append(now)
    return True


# --------------- Security headers ---------------
@app.after_request
def add_security_headers(resp):
    csp = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    resp.headers.setdefault("Content-Security-Policy", csp)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    return resp


""" Templates (simple wrapper) """
BASE_HTML = """
<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>{{ title or 'Secure Site Demo' }}</title>
    <style>
        body { font-family: system-ui, Arial, sans-serif; margin: 2rem; }
        nav a { margin-right: 1rem; }
        .box { max-width: 560px; padding: 1rem; border: 1px solid #ddd; border-radius: 8px; }
        .ok { color: #0a0; } .err { color: #a00; }
        label { display:block; margin-top: 0.7rem; }
        input[type=text], input[type=password], input[type=number] { width: 100%; padding: .5rem; }
        button { padding: .5rem 1rem; margin-top: 1rem; }
        .flash { margin: .5rem 0; padding: .5rem; border-radius: 4px; }
        .flash.error { background:#ffe0e0; }
        .flash.info { background:#e0f4ff; }
        code { word-break: break-all; }
    </style>
    </head>
    <body>
        <nav>
            <a href=\"{{ url_for('home') }}\">Home</a>
            {% if session.get('user') %}
                <a href=\"{{ url_for('profile') }}\">Profile</a>
                <a href=\"{{ url_for('logout') }}\">Logout</a>
            {% else %}
                <a href=\"{{ url_for('register') }}\">Register</a>
                <a href=\"{{ url_for('login') }}\">Login</a>
            {% endif %}
        </nav>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for cat,msg in messages %}
                    <div class=\"flash {{ 'error' if cat=='error' else 'info' }}\">{{ msg }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {{ body|safe }}
    </body>
</html>
"""

def render_page(title: str, body_html: str):
        return render_template_string(BASE_HTML, title=title, body=body_html)


# --------------- Routes ---------------
@app.route("/login", methods=["GET", "POST"])
def login():
    require_totp = False
    if request.method == "POST":
        try:
            check_csrf()
        except Exception:
            flash("Invalid CSRF token", "error")
            return redirect(url_for("login"))
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?")
        if not rate_limit_ok(ip):
            flash("Too many attempts. Please slow down.", "error")
            return redirect(url_for("login"))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        totp_code = request.form.get("totp")
        with get_db() as db:
            cur = db.execute(
                "SELECT pw_hash, salt, totp_secret, failed_attempts, locked_until FROM users WHERE username=?",
                (username,),
            )
            row = cur.fetchone()
            if not row:
                flash("Invalid username or password", "error")
                return redirect(url_for("login"))
            pw_hash, salt, totp_secret, failed, locked_until = row
            now = int(time.time())
            if locked_until and now < locked_until:
                flash(f"Account locked. Try again in {locked_until - now} seconds.", "error")
                return redirect(url_for("login"))
            if not verify_password(password, salt, pw_hash):
                failed += 1
                locked = locked_until
                if failed >= MAX_FAILED_ATTEMPTS:
                    locked = now + LOCKOUT_MINUTES * 60
                    failed = 0
                db.execute(
                    "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
                    (failed, locked or 0, username),
                )
                db.commit()
                flash("Invalid username or password", "error")
                return redirect(url_for("login"))
            if totp_secret:
                require_totp = True
                if not totp_code or not totp_verify(totp_secret, totp_code):
                    flash("TOTP code required/invalid", "error")
                    body = f"""
                    <div class=\"box\">\n                      <h3>Login</h3>
                      <form method=\"post\">\n                        <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf_token()}\"/>
                        <label>Username
                          <input required name=\"username\" type=\"text\" value=\"{username}\"/>
                        </label>
                        <label>Password
                          <input required name=\"password\" type=\"password\"/>
                        </label>
                        <label>Authenticator code (TOTP)
                          <input name=\"totp\" type=\"text\" pattern=\"\\d{{6}}\"/>
                        </label>
                        <button type=\"submit\">Login</button>
                      </form>
                    </div>
                    """
                    return render_page("Login", body)
            db.execute(
                "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
                (0, 0, username),
            )
            db.commit()
            session["user"] = username
            flash("Logged in", "info")
            return redirect(url_for("home"))
    body = f"""
    <div class=\"box\">\n      <h3>Login</h3>
      <form method=\"post\">\n        <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf_token()}\"/>
        <label>Username
          <input required name=\"username\" type=\"text\"/>
        </label>
        <label>Password
          <input required name=\"password\" type=\"password\"/>
        </label>
        {"" if not require_totp else "<label>Authenticator code (TOTP) <input name=\\\"totp\\\" type=\\\"text\\\" pattern=\\\"\\\\d{6}\\\"/></label>"}
        <button type=\"submit\">Login</button>
      </form>
    </div>
    """
    return render_page("Login", body)
                rem = locked_until - now
                flash(f"Account locked. Try again in {rem} seconds.", "error")
                return redirect(url_for("login"))

            if not verify_password(password, salt, pw_hash):
                failed += 1
                locked = locked_until
                if failed >= MAX_FAILED_ATTEMPTS:
                    locked = now + LOCKOUT_MINUTES * 60
                    failed = 0  # reset counter after lock
                db.execute(
                    "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
                    (failed, locked or 0, username),
                )
                db.commit()
                flash("Invalid username or password", "error")
                return redirect(url_for("login"))

            # password ok; check TOTP if set
            if totp_secret:
                require_totp = True
                if not totp_code or not totp_verify(totp_secret, totp_code):
                    flash("TOTP code required/invalid", "error")
                                        # re-render login with TOTP prompt
                                        body = f"""
                                        <div class=\"box\">
                                            <h3>Login</h3>
                                            <form method=\"post\">
                                                <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf_token()}\"/>
                                                <label>Username
                                                    <input required name=\"username\" type=\"text\" value=\"{username}\"/>
                                                </label>
                                                <label>Password
                                                    <input required name=\"password\" type=\"password\"/>
                                                </label>
                                                <label>Authenticator code (TOTP)
                                                    <input name=\"totp\" type=\"text\" pattern=\"\\d{{6}}\"/>
                                                </label>
                                                <button type=\"submit\">Login</button>
                                            </form>
                                        </div>
                                        """
                                        return render_page("Login", body)

            # success
            db.execute(
                "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
                (0, 0, username),
            )
            db.commit()
            session["user"] = username
            flash("Logged in", "info")
            return redirect(url_for("home"))

        # GET or initial render
        body = f"""
        <div class=\"box\">
            <h3>Login</h3>
            <form method=\"post\">
                <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf_token()}\"/>
                <label>Username
                    <input required name=\"username\" type=\"text\"/>
                </label>
                <label>Password
                    <input required name=\"password\" type=\"password\"/>
                </label>
                {"" if not require_totp else "<label>Authenticator code (TOTP) <input name=\\\"totp\\\" type=\\\"text\\\" pattern=\\\"\\\\d{6}\\\"/></label>"}
                <button type=\"submit\">Login</button>
            </form>
        </div>
        """
        return render_page("Login", body)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("home"))


@app.route("/profile")
def profile():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    with get_db() as db:
        cur = db.execute("SELECT totp_secret FROM users WHERE username=?", (user,))
        row = cur.fetchone()
        totp_secret = row[0] if row else None
        body = f"""
        <div class=\"box\">
            <h3>Profile</h3>
            <p>User: <b>{user}</b></p>
            {('<p class=\\"ok\\">TOTP 2FA is <b>enabled</b>.</p>'
                '<form method=\\"post\\" action=\\"' + url_for('disable_totp') + '\\">'
                '<input type=\\"hidden\\" name=\\"csrf_token\\" value=\\"' + csrf_token() + '\\"/>'
                '<button type=\\"submit\\">Disable TOTP</button>'
                '</form>') if totp_secret else
             ('<p class=\\"err\\">TOTP 2FA is <b>disabled</b>.</p>'
                '<form method=\\"post\\" action=\\"' + url_for('enable_totp') + '\\">'
                '<input type=\\"hidden\\" name=\\"csrf_token\\" value=\\"' + csrf_token() + '\\"/>'
                '<button type=\\"submit\\">Enable TOTP</button>'
                '</form>')}
        </div>
        """
        return render_page("Profile", body)


@app.route("/enable_totp", methods=["POST"])
def enable_totp():
    try:
        check_csrf()
    except Exception:
        flash("Invalid CSRF token", "error")
        return redirect(url_for("profile"))
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    secret = base32_secret()
    with get_db() as db:
        db.execute("UPDATE users SET totp_secret=? WHERE username=?", (secret, user))
        db.commit()
    uri = otpauth_uri(user, "SecureDemo", secret)
    flash("TOTP enabled. Add the secret to your Authenticator app.", "info")
    body = f"""
    <div class=\"box\">
        <h3>Profile</h3>
        <p>User: <b>{user}</b></p>
        <p class=\"ok\">TOTP 2FA is <b>enabled</b>.</p>
        <form method=\"post\" action=\"{url_for('disable_totp')}\">
            <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf_token()}\"/>
            <button type=\"submit\">Disable TOTP</button>
        </form>
        <hr>
        <p>Scan this in your Authenticator app, or add manually:</p>
        <p><code>{uri}</code></p>
        <p>Secret: <code>{secret}</code></p>
    </div>
    """
    return render_page("Profile", body)


@app.route("/disable_totp", methods=["POST"])
def disable_totp():
    try:
        check_csrf()
    except Exception:
        flash("Invalid CSRF token", "error")
        return redirect(url_for("profile"))
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    with get_db() as db:
        db.execute("UPDATE users SET totp_secret=NULL WHERE username=?", (user,))
        db.commit()
    flash("TOTP disabled", "info")
    return redirect(url_for("profile"))


if __name__ == "__main__":
    app.run(debug=True)
