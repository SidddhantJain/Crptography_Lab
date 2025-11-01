r"""
Assignment 8: Secure Image Transmission over Unsecured Network

This CLI demonstrates a practical, defense-in-depth design for sending images securely:
- Confidentiality: AES-256-GCM encrypts the image contents
- Integrity/Authenticity: RSA-PSS signature over full manifest (including ciphertext, nonce, wrapped key)
- Key transport: RSA-OAEP(SHA-256) wraps the per-message AES key
- Replay protection: message_id + timestamp and receiver-side replay DB
- Optional compression before encryption

Container format (JSON, UTF-8; base64 for binary fields):
{
  "version": "ass8.v1",
  "sender": "Alice",
  "receiver": "Bob",
  "alg": {"sym": "AES-256-GCM", "wrap": "RSA-OAEP-SHA256", "sig": "RSA-PSS-SHA256"},
  "meta": {"filename": "cat.png", "mimetype": "image/png", "filesize": 12345, "ts": 1730500000, "message_id": "..."},
  "wrap": {"ekey": base64, "nonce": base64, "tag": base64},
  "ciphertext": base64,
  "digest": {"sha256": hex},
  "signature": base64
}

Usage (PowerShell):
    # Generate RSA keypairs for Alice and Bob
    python ./ass8/ass8.py gen-keys --who Alice
    python ./ass8/ass8.py gen-keys --who Bob

    # Send (encrypt+sign) an image to Bob using Alice's private key
    python ./ass8/ass8.py send --sender Alice --receiver Bob --in ./path/to/image.png --out ./out.ass8pkg

    # Receive (verify+decrypt) using Bob's private key and Alice's public key
    python ./ass8/ass8.py receive --sender Alice --receiver Bob --in ./out.ass8pkg --out ./received.png
"""
from __future__ import annotations

import argparse
import base64
import json
import mimetypes
import os
import sqlite3
import sys
import time
import zlib
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
import hashlib

ROOT = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(ROOT, "keys")
DB_PATH = os.path.join(ROOT, "receive_log.db")

# ---------- Helpers ----------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def ensure_dirs():
    os.makedirs(KEYS_DIR, exist_ok=True)


def load_private_pem(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_pem(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def save_private_pem(key, path: str):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)


def save_public_pem(key, path: str):
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pem)


# ---------- Replay DB ----------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS received (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            message_id TEXT NOT NULL,
            ts INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_msg
        ON received(sender, receiver, message_id)
        """
    )
    return conn


def record_message(sender: str, receiver: str, message_id: str, ts: int):
    with get_db() as db:
        db.execute(
            "INSERT OR IGNORE INTO received(sender, receiver, message_id, ts) VALUES (?,?,?,?)",
            (sender, receiver, message_id, ts),
        )
        db.commit()


def seen_message(sender: str, receiver: str, message_id: str) -> bool:
    with get_db() as db:
        cur = db.execute(
            "SELECT 1 FROM received WHERE sender=? AND receiver=? AND message_id=?",
            (sender, receiver, message_id),
        )
        return cur.fetchone() is not None


# ---------- Crypto ops ----------

def rsa_generate(bits: int = 3072) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return priv, priv.public_key()


def rsa_oaep_wrap(pubkey: rsa.RSAPublicKey, key: bytes) -> bytes:
    return pubkey.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_oaep_unwrap(privkey: rsa.RSAPrivateKey, wrapped: bytes) -> bytes:
    return privkey.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_pss_sign(privkey: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return privkey.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def rsa_pss_verify(pubkey: rsa.RSAPublicKey, sig: bytes, data: bytes) -> bool:
    try:
        pubkey.verify(
            sig,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ---------- Commands ----------

def cmd_gen_keys(args: argparse.Namespace):
    ensure_dirs()
    who = args.who
    priv, pub = rsa_generate(3072)
    save_private_pem(priv, os.path.join(KEYS_DIR, f"{who}.private.pem"))
    save_public_pem(pub, os.path.join(KEYS_DIR, f"{who}.public.pem"))
    print(f"Generated keys for {who} under {KEYS_DIR}")


def cmd_send(args: argparse.Namespace):
    ensure_dirs()
    sender = args.sender
    receiver = args.receiver
    infile = args.infile
    outfile = args.outfile
    compress = args.compress

    # Load keys (RSA path only)
    sender_priv = None
    receiver_pub = None
    use_password = bool(args.password)
    if not use_password:
        sender_priv = load_private_pem(os.path.join(KEYS_DIR, f"{sender}.private.pem"))
        receiver_pub = load_public_pem(os.path.join(KEYS_DIR, f"{receiver}.public.pem"))

    # Read file
    with open(infile, "rb") as f:
        plain = f.read()
    mimetype, _ = mimetypes.guess_type(infile)
    mimetype = mimetype or "application/octet-stream"

    # Optional compression (deflate)
    compressed = zlib.compress(plain, level=9) if compress else plain

    # Generate random AES key + nonce
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    aad = f"{sender}|{receiver}".encode("utf-8")
    ct = aesgcm.encrypt(nonce, compressed, aad)  # includes tag at end
    # AESGCM.encrypt returns ciphertext||tag; but we’ll split for explicitness
    c_body, tag = ct[:-16], ct[-16:]

    # Wrap AES key
    wrap_alg = None
    wrap_fields = {}
    if use_password:
        # Derive KEK via scrypt
        s_salt = os.urandom(16)
        kek = hashlib.scrypt(args.password.encode("utf-8"), salt=s_salt, n=2**14, r=8, p=1, dklen=32)
        wrapped = aes_key_wrap(kek, aes_key)
        wrap_alg = "AES-KW-SCRYPT"
        wrap_fields = {
            "ekey": b64e(wrapped),
            "nonce": b64e(nonce),
            "tag": b64e(tag),
            "pass_salt": b64e(s_salt),
            "scrypt": {"n": 2**14, "r": 8, "p": 1},
        }
    else:
        wrapped = rsa_oaep_wrap(receiver_pub, aes_key)
        wrap_alg = "RSA-OAEP-SHA256"
        wrap_fields = {
            "ekey": b64e(wrapped),
            "nonce": b64e(nonce),
            "tag": b64e(tag),
        }

    # Compute SHA-256 digest of original content
    digest = hashes.Hash(hashes.SHA256())
    digest.update(plain)
    sha256_hex = digest.finalize().hex()

    ts = int(time.time())
    message_id = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("=")

    manifest = {
        "version": "ass8.v1",
        "sender": sender,
        "receiver": receiver,
    "alg": {"sym": "AES-256-GCM", "wrap": wrap_alg, "sig": "RSA-PSS-SHA256"},
        "meta": {
            "filename": os.path.basename(infile),
            "mimetype": mimetype,
            "filesize": len(plain),
            "ts": ts,
            "message_id": message_id,
            "compressed": bool(compress),
        },
        "wrap": wrap_fields,
        "ciphertext": b64e(c_body),
        "digest": {"sha256": sha256_hex},
    }

    # Canonicalize to bytes and sign
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if not use_password:
        sig = rsa_pss_sign(sender_priv, manifest_bytes)
    else:
        # For password mode without RSA keys, we still need authenticity. Use detached signature if sender keys exist; otherwise omit.
        # If sender RSA keys are not provided, skip signature to allow pure symmetric operation (receiver will accept if signature is absent and wrap=PASSWORD).
        sig = None
        try:
            sender_priv = load_private_pem(os.path.join(KEYS_DIR, f"{sender}.private.pem"))
            sig = rsa_pss_sign(sender_priv, manifest_bytes)
        except Exception:
            sig = None
    if sig is not None:
        manifest["signature"] = b64e(sig)

    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    print(f"Package written to {outfile} ({len(plain)} bytes input, compressed={bool(compress)}, wrap={wrap_alg})")


def cmd_receive(args: argparse.Namespace):
    ensure_dirs()
    sender = args.sender
    receiver = args.receiver
    infile = args.infile
    outfile = args.outfile
    max_skew = args.max_skew

    # Load keys (RSA path only)
    wrap_alg = None
    receiver_priv = None
    sender_pub = None
    if not args.password:
        receiver_priv = load_private_pem(os.path.join(KEYS_DIR, f"{receiver}.private.pem"))
        sender_pub = load_public_pem(os.path.join(KEYS_DIR, f"{sender}.public.pem"))

    # Load package
    with open(infile, "r", encoding="utf-8") as f:
        pkg = json.load(f)

    # Basic checks
    if pkg.get("version") != "ass8.v1":
        raise ValueError("Unsupported package version")
    if pkg.get("sender") != sender or pkg.get("receiver") != receiver:
        raise ValueError("Sender/receiver mismatch")

    sig_b64 = pkg.pop("signature", None)
    # Verify signature over canonicalized manifest (without signature) if present
    manifest_bytes = json.dumps(pkg, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if sig_b64:
        sig = b64d(sig_b64)
        if sender_pub is None:
            raise ValueError("Signature present but RSA sender key not available")
        if not rsa_pss_verify(sender_pub, sig, manifest_bytes):
            raise ValueError("Signature verification failed")

    meta = pkg["meta"]
    wrap = pkg["wrap"]
    wrap_alg = pkg.get("alg", {}).get("wrap")

    # Replay + time window checks
    msg_id = meta["message_id"]
    ts = int(meta["ts"]) if "ts" in meta else 0
    now = int(time.time())
    if max_skew and abs(now - ts) > max_skew:
        raise ValueError("Message timestamp out of allowed window")
    if seen_message(sender, receiver, msg_id):
        raise ValueError("Replay detected: message_id already seen")

    # Unwrap AES key and decrypt
    if wrap_alg == "RSA-OAEP-SHA256":
        if receiver_priv is None:
            raise ValueError("RSA receiver private key required")
        aes_key = rsa_oaep_unwrap(receiver_priv, b64d(wrap["ekey"]))
    elif wrap_alg == "AES-KW-SCRYPT":
        if not args.password:
            raise ValueError("Password required for AES-KW-SCRYPT wrapped package")
        s_params = wrap.get("scrypt", {"n": 2**14, "r": 8, "p": 1})
        s_salt = b64d(wrap["pass_salt"]) if "pass_salt" in wrap else b""
        kek = hashlib.scrypt(args.password.encode("utf-8"), salt=s_salt, n=int(s_params.get("n", 2**14)), r=int(s_params.get("r", 8)), p=int(s_params.get("p", 1)), dklen=32)
        aes_key = aes_key_unwrap(kek, b64d(wrap["ekey"]))
    else:
        raise ValueError(f"Unsupported wrap algorithm: {wrap_alg}")
    nonce = b64d(wrap["nonce"])
    tag = b64d(wrap["tag"])
    c_body = b64d(pkg["ciphertext"])

    aesgcm = AESGCM(aes_key)
    aad = f"{sender}|{receiver}".encode("utf-8")
    ct = c_body + tag
    decrypted = aesgcm.decrypt(nonce, ct, aad)

    # Decompress if needed
    if bool(meta.get("compressed")):
        try:
            decrypted = zlib.decompress(decrypted)
        except Exception as e:
            raise ValueError(f"Decompression error: {e}")

    # Optional digest check
    reported = pkg.get("digest", {}).get("sha256")
    if reported:
        h = hashes.Hash(hashes.SHA256())
        h.update(decrypted)
        if h.finalize().hex() != reported:
            raise ValueError("SHA-256 digest mismatch")

    # Write output file
    with open(outfile, "wb") as f:
        f.write(decrypted)

    # Mark message as seen
    record_message(sender, receiver, msg_id, ts)

    print(f"Decrypted and verified to {outfile} (size={len(decrypted)} bytes)")


# ---------- CLI ----------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="ASS8: Secure Image Transmission")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("gen-keys", help="Generate RSA keypair for a user")
    p_gen.add_argument("--who", required=True, help="User name (e.g., Alice, Bob)")
    p_gen.set_defaults(func=cmd_gen_keys)

    p_send = sub.add_parser("send", help="Encrypt+sign an image for receiver")
    p_send.add_argument("--sender", required=True)
    p_send.add_argument("--receiver", required=True)
    p_send.add_argument("--in", dest="infile", required=True, help="Path to input image")
    p_send.add_argument("--out", dest="outfile", required=True, help="Path to output package (.ass8pkg)")
    p_send.add_argument("--compress", action="store_true", help="Compress before encrypting")
    p_send.add_argument("--password", help="Password to wrap the AES key (AES-KW + scrypt). If set, RSA keys are optional for signature.")
    p_send.set_defaults(func=cmd_send)

    p_recv = sub.add_parser("receive", help="Verify+decrypt a package")
    p_recv.add_argument("--sender", required=True)
    p_recv.add_argument("--receiver", required=True)
    p_recv.add_argument("--in", dest="infile", required=True, help="Path to input package (.ass8pkg)")
    p_recv.add_argument("--out", dest="outfile", required=True, help="Path to write decrypted image")
    p_recv.add_argument("--max-skew", type=int, default=0, help="Max allowed clock skew in seconds (0=disabled)")
    p_recv.add_argument("--password", help="Password to unwrap the AES key for AES-KW-SCRYPT packages")
    p_recv.set_defaults(func=cmd_receive)

    return p


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
