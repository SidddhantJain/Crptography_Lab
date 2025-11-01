# Assignment 8: Secure Image Transmission

This assignment implements a practical, hybrid-crypto package for sending images securely over an unsecured network.

- Confidentiality: AES-256-GCM
- Key transport: RSA-OAEP (SHA-256) or Password-wrapped via AES-KW + scrypt
- Integrity/authenticity: RSA-PSS (SHA-256) signature over a canonicalized manifest
- Replay protection: message_id + timestamp and a local receive log
- Optional compression: DEFLATE before encryption

## Files
- `ass8.py` – CLI tool to generate keys, send (encrypt+sign), and receive (verify+decrypt) packages
- `keys/` – generated RSA keypairs (PEM)
- `receive_log.db` – local SQLite DB used to detect replays

## Setup

- Python 3.13 (venv already configured in this repo)
- One-time dependency install (already handled automatically):
  - `cryptography`

If you need to reinstall manually:

```powershell
# Optional: only if you ever need to reinstall
dotnet --version > $null 2>&1; if ($LASTEXITCODE -ne 0) { Write-Host "(Info) dotnet SDK is not required, continuing..." }
D:/Siddhant/projects/Crptography_Lab/.venv/Scripts/python.exe -m pip install --upgrade pip
D:/Siddhant/projects/Crptography_Lab/.venv/Scripts/python.exe -m pip install cryptography
```

## Usage (PowerShell)

```powershell
# 0) Generate keys for Alice and Bob
D:/Siddhant/projects/Crptography_Lab/.venv/Scripts/python.exe ./ass8/ass8.py gen-keys --who Alice
D:/Siddhant/projects/Crptography_Lab/.venv/Scripts/python.exe ./ass8/ass8.py gen-keys --who Bob

# 1) Alice sends an image to Bob
D:/Siddhant/projects/Crptography_Lab/.venv/Scripts/python.exe ./ass8/ass8.py send --sender Alice --receiver Bob --in ./path/to/image.png --out ./out.ass8pkg --compress

# 2) Bob receives the package
D:/Siddhant/projects/Crptography_Lab/.venv/Scripts/python.exe ./ass8/ass8.py receive --sender Alice --receiver Bob --in ./out.ass8pkg --out ./received.png --max-skew 86400

# (Optional) Password-based wrapping (no RSA needed for transport)
D:/Siddhant/projects/Crptography_Lab/.venv/Scripts/python.exe ./ass8/ass8.py send --sender Alice --receiver Bob --in ./path/to/image.png --out ./out_pass.ass8pkg --password "CorrectHorseBatteryStaple"
D:/Siddhant/projects/Crptography_Lab/.venv/Scripts/python.exe ./ass8/ass8.py receive --sender Alice --receiver Bob --in ./out_pass.ass8pkg --out ./received_pass.png --password "CorrectHorseBatteryStaple"
```

Notes:
- The manifest is JSON (UTF-8). Binary fields are base64.
- The signature is computed over a canonicalized JSON (sorted keys, compact separators) excluding the `signature` field.
- Replay detection is enforced per (sender, receiver, message_id). Delete `receive_log.db` to reset.

## Algorithm identifiers
- sym: `AES-256-GCM`
- wrap: `RSA-OAEP-SHA256`
- sig: `RSA-PSS-SHA256`

## Threat model & mitigations
- Eavesdropping: prevented by AES-GCM
- Tampering: prevented by AEAD and RSA-PSS signature
- Key theft in transit: mitigated by RSA-OAEP wrapping to receiver’s public key
- Replay: detected via message_id + timestamp persisted in SQLite
- MIME confusion: manifest carries mimetype and original filename (not enforced at runtime)

## Troubleshooting
- If you see an error about missing `cryptography`, reinstall with the commands above.
- If clocks differ a lot between sender and receiver, set `--max-skew 0` (disables time window) or increase it.
- If you change user names, regenerate matching keys under `ass8/keys`.
- In password mode, RSA signature is optional. If the sender’s RSA private key is present, a detached signature will be added; otherwise, the package is purely symmetric.
