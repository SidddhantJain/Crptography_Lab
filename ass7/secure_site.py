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
from flask import Flask, request, redirect, url_for, session, flash, render_template_string

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

BASE = """
<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1">
<title>{{title}}</title>
<style>body{font-family:system-ui,Arial;margin:2rem}nav a{margin-right:1rem}.box{max-width:560px;padding:1rem;border:1px solid #ddd;border-radius:8px}.ok{color:#090}.err{color:#900}label{display:block;margin-top:.7rem}input[type=text],input[type=password]{width:100%;padding:.5rem}button{padding:.5rem 1rem;margin-top:1rem}.flash{margin:.5rem 0;padding:.5rem;border-radius:4px}.error{background:#ffe0e0}.info{background:#e0f4ff}</style>
</head><body>
<nav>
  <a href="{{url_for('home')}}">Home</a>
  {% if session.get('user') %}
    <a href="{{url_for('profile')}}">Profile</a>
    <a href="{{url_for('logout')}}">Logout</a>
  {%else%}
    <a href="{{url_for('register')}}">Register</a>
    <a href="{{url_for('login')}}">Login</a>
  {%endif%}
</nav>
{% for cat,msg in get_flashed_messages(with_categories=True) %}
  <div class="flash {{cat}}">{{msg}}</div>
{% endfor %}
{{body|safe}}
</body></html>
"""

def page(title: str, body: str):
    return render_template_string(BASE, title=title, body=body)

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
    body = """
    <div class=box>
      <h2>Secure Website Demo</h2>
      <p>Demonstrates: scrypt password hashing with salt+pepper, password policy, rate limiting, lockout, and optional TOTP 2FA.</p>
    </div>
    """
    return page('Secure Site', body)

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
    body = f"""
    <div class=box>
      <h3>Create Account</h3>
      <form method=post>
        <input type=hidden name=csrf_token value="{csrf_token()}">
        <label>Username<input required name=username type=text minlength=3 maxlength=64></label>
        <label>Password<input required name=password type=password minlength=12></label>
        <button type=submit>Register</button>
      </form>
    </div>
    """
    return page('Register', body)

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
                    body = f"""
                    <div class=box>
                      <h3>Login</h3>
                      <form method=post>
                        <input type=hidden name=csrf_token value="{csrf_token()}">
                        <label>Username<input required name=username type=text value="{u}"></label>
                        <label>Password<input required name=password type=password></label>
                        <label>Authenticator code (TOTP)<input name=totp type=text pattern="\d{{6}}"></label>
                        <button type=submit>Login</button>
                      </form>
                    </div>
                    """
                    return page('Login', body)
            c.execute('UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?',(0,0,u)); c.commit()
            session['user'] = u
            flash('Logged in','info'); return redirect(url_for('home'))
    body = f"""
    <div class=box>
      <h3>Login</h3>
      <form method=post>
        <input type=hidden name=csrf_token value="{csrf_token()}">
        <label>Username<input required name=username type=text></label>
        <label>Password<input required name=password type=password></label>
        {'' if not require_totp else '<label>Authenticator code (TOTP)<input name=totp type=text pattern="\\d{6}"></label>'}
        <button type=submit>Login</button>
      </form>
    </div>
    """
    return page('Login', body)

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
    body = f"""
    <div class=box>
      <h3>Profile</h3>
      <p>User: <b>{u}</b></p>
      {('<p class=ok>TOTP 2FA is <b>enabled</b>.</p>'
        f'<form method=post action="{url_for('disable_totp')}"><input type=hidden name=csrf_token value="{csrf_token()}"><button type=submit>Disable TOTP</button></form>') if totp_secret else
       ('<p class=err>TOTP 2FA is <b>disabled</b>.</p>'
        f'<form method=post action="{url_for('enable_totp')}"><input type=hidden name=csrf_token value="{csrf_token()}"><button type=submit>Enable TOTP</button></form>')}
    </div>
    """
    return page('Profile', body)

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
    body = f"""
    <div class=box>
      <h3>Profile</h3>
      <p>User: <b>{u}</b></p>
      <p class=ok>TOTP 2FA is <b>enabled</b>.</p>
      <form method=post action="{url_for('disable_totp')}"><input type=hidden name=csrf_token value="{csrf_token()}"><button type=submit>Disable TOTP</button></form>
      <hr>
      <p>Add this to your Authenticator app:</p>
      <code>{uri}</code>
      <p>Secret: <code>{secret}</code></p>
    </div>
    """
    flash('TOTP enabled','info')
    return page('Profile', body)

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
