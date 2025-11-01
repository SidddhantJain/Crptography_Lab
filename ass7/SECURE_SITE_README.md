# Secure Website Demo (secure_site.py)

A minimal Flask website demonstrating layered protections against password cracking.

## Security Features

- Strong password storage: scrypt with per-user random salt + global pepper (SECRET_PEPPER)
- Password policy: minimum length 12; requires upper/lower/digit/special
- Throttling: per-IP login rate limiting (10/minute)
- Account lockout: 5 failed attempts → 15 minutes lock
- Optional 2FA: TOTP (Google Authenticator compatible)
- CSRF tokens on all POST forms
- Security headers: CSP, X-Frame-Options, X-Content-Type-Options
- Session cookie flags: HttpOnly, SameSite=Lax (set Secure=True on HTTPS)

## Run locally

```powershell
# from the repository root
python .\secure_site.py
# Open http://127.0.0.1:5000
```

If Flask is missing, install it into your environment:

```powershell
python -m pip install flask
```

## Try it

1. Register a user (strong password required)
2. Login
   - Try a few wrong passwords to see rate-limiting and lockout behavior
3. Enable TOTP on the Profile page
   - Add the displayed otpauth:// URI to an authenticator app
   - Logout and login again with the 6-digit code

## Hardening tips

- Serve behind HTTPS and set `SESSION_COOKIE_SECURE=True`
- Increase scrypt parameters (N, r, p) according to server capacity
- Store the pepper (`SECRET_PEPPER`) in environment or a key vault, never in the database
- Consider adding CAPTCHA after repeated failures and a breach check (HIBP k-anonymity) during registration
