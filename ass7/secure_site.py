"""
Secure Website Demo (Password Protection Techniques)

Features:
- Password hashing with scrypt (salt + pepper)
- Password policy enforcement
- Account lockout after N failed attempts
- Per-IP login rate limiting (simple in-memory)
- Optional TOTP 2FA
- CSRF tokens
- Basic security headers

Run:
  pip install flask
  python secure_site.py
"""
import os
import time
import hmac
import base64
import sqlite3
import hashlib
from typing import List, Tuple, Dict
from flask import Flask, request, redirect, url_for, session, flash, render_template

APP_SECRET = os.environ.get("FLASK_SECRET", "dev-secret-change-me")
PEPPER = os.environ.get("SECRET_PEPPER", "dev-pepper-change-me").encode()
DB = os.path.join(os.path.dirname(__file__), "secure_site.db")

SCRYPT_N, SCRYPT_R, SCRYPT_P, DKLEN = 2**14, 8, 1, 32
MAX_FAILED, LOCK_MIN = 5, 15
RATE_MAX_PER_MIN = 10

app = Flask(__name__)
app.secret_key = APP_SECRET
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=False)

rate_buckets: Dict[str, List[float]] = {}

def page(template: str, **kwargs):
        return render_template(template, **kwargs)

@app.after_request
def headers(r):
    r.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
    r.headers.setdefault("X-Frame-Options", "DENY")
    r.headers.setdefault("X-Content-Type-Options", "nosniff")
    return r

# DB setup

def db():
    conn = sqlite3.connect(DB)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users(
      username TEXT PRIMARY KEY,
      pw_hash BLOB NOT NULL,
      salt BLOB NOT NULL,
      totp_secret TEXT,
      created_at INTEGER NOT NULL,
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until INTEGER NOT NULL DEFAULT 0
    )""")
    return conn

# CSRF

def csrf_token():
    t = session.get('csrf_token')
    if not t:
        t = base64.urlsafe_b64encode(os.urandom(24)).decode()
        session['csrf_token'] = t
    return t

def csrf_check():
    if not hmac.compare_digest(session.get('csrf_token',''), request.form.get('csrf_token','')):
        raise ValueError('bad csrf')

# Security helpers

def policy_ok(pw: str) -> Tuple[bool, List[str]]:
    issues = []
    if len(pw) < 12: issues.append('Min length 12')
    if not any(c.islower() for c in pw): issues.append('Add lowercase')
    if not any(c.isupper() for c in pw): issues.append('Add uppercase')
    if not any(c.isdigit() for c in pw): issues.append('Add a digit')
    if not any(c in "!@#$%^&*()-_=+[]{};:'\",.<>/?|`~" for c in pw): issues.append('Add a special char')
    return (not issues, issues)

def scrypt_hash(pw: str, salt: bytes) -> bytes:
    return hashlib.scrypt((pw.encode()+PEPPER), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=DKLEN)

def verify_pw(pw: str, salt: bytes, ref: bytes) -> bool:
    return hmac.compare_digest(scrypt_hash(pw, salt), ref)

# Simple TOTP
import struct
import time as _t

def b32_secret(n=20):
    return base64.b32encode(os.urandom(n)).decode().rstrip('=')

def totp(secret_b32: str, step=30, digits=6, t=None):
    if t is None: t = int(_t.time())
    counter = t//step
    pad = '='*((8-len(secret_b32)%8)%8)
    key = base64.b32decode(secret_b32+pad, casefold=True)
    msg = struct.pack('>Q', counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = ((h[o] & 0x7F)<<24) | (h[o+1]<<16) | (h[o+2]<<8) | h[o+3]
    return code % (10**digits)

def totp_ok(secret_b32: str, code: str, window=1) -> bool:
    try: v = int(code)
    except: return False
    now = int(_t.time())
    return any(totp(secret_b32, t=now + k*30) == v for k in range(-window, window+1))

# Rate limit

def rate_ok(ip: str) -> bool:
    now = time.time()
    b = rate_buckets.setdefault(ip, [])
    rate_buckets[ip] = [ts for ts in b if now-ts < 60]
    if len(rate_buckets[ip]) >= RATE_MAX_PER_MIN:
        return False
    rate_buckets[ip].append(now)
    return True

# Routes

@app.route('/')
def home():
        return page('home.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        try: csrf_check()
        except: flash('Invalid CSRF token','error'); return redirect(url_for('register'))
        u = request.form.get('username','').strip()
        p = request.form.get('password','')
        ok, issues = policy_ok(p)
        if not ok:
            for i in issues: flash(i,'error')
            return redirect(url_for('register'))
        salt = os.urandom(16)
        ph = scrypt_hash(p, salt)
        with db() as c:
            try:
                c.execute('INSERT INTO users(username,pw_hash,salt,created_at) VALUES(?,?,?,?)',(u,ph,salt,int(time.time())))
                c.commit()
            except sqlite3.IntegrityError:
                flash('Username exists','error'); return redirect(url_for('register'))
        flash('Registered. Please login.','info')
        return redirect(url_for('login'))
    return page('register.html', csrf_token=csrf_token())

@app.route('/login', methods=['GET','POST'])
def login():
    require_totp = False
    if request.method == 'POST':
        try: csrf_check()
        except: flash('Invalid CSRF token','error'); return redirect(url_for('login'))
        ip = request.headers.get('X-Forwarded-For', request.remote_addr or '?')
        if not rate_ok(ip): flash('Too many attempts, slow down','error'); return redirect(url_for('login'))
        u = request.form.get('username','').strip()
        p = request.form.get('password','')
        code = request.form.get('totp')
        with db() as c:
            r = c.execute('SELECT pw_hash,salt,totp_secret,failed_attempts,locked_until FROM users WHERE username=?',(u,)).fetchone()
            if not r: flash('Invalid username or password','error'); return redirect(url_for('login'))
            pw_hash,salt,totp_secret,failed,locked_until = r
            now = int(time.time())
            if locked_until and now < locked_until:
                flash(f'Account locked. Try again in {locked_until-now} seconds.','error'); return redirect(url_for('login'))
            if not verify_pw(p, salt, pw_hash):
                failed += 1
                locked = locked_until
                if failed >= MAX_FAILED:
                    locked = now + LOCK_MIN*60
                    failed = 0
                c.execute('UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?',(failed, locked or 0, u)); c.commit()
                flash('Invalid username or password','error'); return redirect(url_for('login'))
            if totp_secret:
                require_totp = True
                if not code or not totp_ok(totp_secret, code):
                    flash('TOTP code required/invalid','error')
                    return page('login.html', csrf_token=csrf_token(), require_totp=True, prefill_user=u)
            c.execute('UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?',(0,0,u)); c.commit()
            session['user'] = u
            flash('Logged in','info'); return redirect(url_for('home'))
        return page('login.html', csrf_token=csrf_token(), require_totp=require_totp)

@app.route('/logout')
def logout():
    session.clear(); flash('Logged out','info'); return redirect(url_for('home'))

@app.route('/profile')
def profile():
    u = session.get('user')
    if not u: return redirect(url_for('login'))
    with db() as c:
        r = c.execute('SELECT totp_secret FROM users WHERE username=?',(u,)).fetchone()
        totp_secret = r[0] if r else None
    return page('profile.html', user=u, totp_enabled=bool(totp_secret), csrf_token=csrf_token())

@app.route('/enable_totp', methods=['POST'])
def enable_totp():
    try: csrf_check()
    except: flash('Invalid CSRF token','error'); return redirect(url_for('profile'))
    u = session.get('user')
    if not u: return redirect(url_for('login'))
    secret = b32_secret()
    with db() as c:
        c.execute('UPDATE users SET totp_secret=? WHERE username=?',(secret,u)); c.commit()
    uri = f"otpauth://totp/SecureDemo:{u}?secret={secret}&issuer=SecureDemo&algorithm=SHA1&digits=6&period=30"
    flash('TOTP enabled','info')
    return page('profile.html', user=u, totp_enabled=True, csrf_token=csrf_token(), uri=uri, secret=secret)

@app.route('/disable_totp', methods=['POST'])
def disable_totp():
    try: csrf_check()
    except: flash('Invalid CSRF token','error'); return redirect(url_for('profile'))
    u = session.get('user')
    if not u: return redirect(url_for('login'))
    with db() as c:
        c.execute('UPDATE users SET totp_secret=NULL WHERE username=?',(u,)); c.commit()
    flash('TOTP disabled','info')
    return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(debug=True)
