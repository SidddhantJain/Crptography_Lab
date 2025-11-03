"""
Assignment 6: Confidentiality (RSA), Integrity (Hash), and Non-Repudiation (Digital Signature)

Interactive Python demo where user X sends a confidential message to user Y.
- Confidentiality: hybrid encryption (AES-GCM) with the AES key wrapped using RSA-OAEP (Y's public key)
- Integrity + Non-repudiation: RSA-PSS signature by X on the message; Y verifies using X's public key
- Hashing: show SHA-256 (default), SHA-1, or MD5 digest at sender and receiver for demonstrative integrity check
- MITM Z: can see only the RSA-wrapped key, nonce, ciphertext, and tag; cannot recover plaintext or signature without private keys

Run:
  python ass6.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympad, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


# -------------------- Helpers --------------------

def gen_rsa_keypair(bits: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return priv, priv.public_key()


def pubkey_fingerprint(pub: rsa.RSAPublicKey) -> str:
    # SHA-256 hash of DER SubjectPublicKeyInfo
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    h = hashes.Hash(hashes.SHA256())
    h.update(der)
    return h.finalize().hex()[:32]  # short fingerprint


def choose_hash_algo(choice: str) -> hashes.HashAlgorithm:
    ch = (choice or "").strip().lower()
    if ch in ("2", "sha1", "sha-1"):
        return hashes.SHA1()
    if ch in ("3", "md5"):
        return hashes.MD5()
    return hashes.SHA256()  # default


def hash_bytes(data: bytes, algo: hashes.HashAlgorithm) -> str:
    h = hashes.Hash(algo)
    h.update(data)
    return h.finalize().hex()


def sign_message(priv: rsa.RSAPrivateKey, message: bytes, algo: hashes.HashAlgorithm) -> bytes:
    # RSA-PSS with MGF1 and the chosen hash; sign over the raw message
    return priv.sign(
        message,
        asympad.PSS(mgf=asympad.MGF1(hashes.SHA256()), salt_length=asympad.PSS.MAX_LENGTH),
        algo,
    )


def verify_signature(pub: rsa.RSAPublicKey, message: bytes, signature: bytes, algo: hashes.HashAlgorithm) -> bool:
    try:
        pub.verify(
            signature,
            message,
            asympad.PSS(mgf=asympad.MGF1(hashes.SHA256()), salt_length=asympad.PSS.MAX_LENGTH),
            algo,
        )
        return True
    except Exception:
        return False


def aes_gcm_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    # AESGCM returns ct||tag at end, but cryptography returns combined? In AESGCM, the tag is appended to ct.
    # We will split last 16 bytes as tag.
    tag = ct[-16:]
    body = ct[:-16]
    return nonce, body, tag


def aes_gcm_decrypt(nonce: bytes, body: bytes, tag: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    ct = body + tag
    return aesgcm.decrypt(nonce, ct, None)


def rsa_wrap(pub: rsa.RSAPublicKey, data: bytes) -> bytes:
    return pub.encrypt(
        data,
        asympad.OAEP(mgf=asympad.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def rsa_unwrap(priv: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return priv.decrypt(
        data,
        asympad.OAEP(mgf=asympad.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


# -------------------- Envelope --------------------

def build_payload(message: str, signature: bytes, hash_algo_name: str, sender_pub_pem: bytes) -> bytes:
    obj = {
        "msg": message,
        "sig_b64": base64.b64encode(signature).decode("ascii"),
        "hash_algo": hash_algo_name,
        "sender_pub_pem": sender_pub_pem.decode("ascii"),
    }
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def parse_payload(data: bytes) -> Tuple[str, bytes, str, bytes]:
    obj = json.loads(data.decode("utf-8"))
    message = obj["msg"]
    signature = base64.b64decode(obj["sig_b64"])  # bytes
    hash_algo_name = obj["hash_algo"]
    sender_pub_pem = obj["sender_pub_pem"].encode("ascii")
    return message, signature, hash_algo_name, sender_pub_pem


def serialize_wire(rsa_wrapped_key: bytes, nonce: bytes, body: bytes, tag: bytes) -> bytes:
    # Simple length-prefix binary: [2B klen][k][12B nonce][2B blen][body][16B tag]
    if len(rsa_wrapped_key) > 65535 or len(body) > 65535:
        # For simplicity; in real systems use full framing/protocols
        raise ValueError("Data too large for demo framing")
    return (
        len(rsa_wrapped_key).to_bytes(2, "big")
        + rsa_wrapped_key
        + nonce
        + len(body).to_bytes(2, "big")
        + body
        + tag
    )


def parse_wire(blob: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    klen = int.from_bytes(blob[:2], "big")
    off = 2
    k = blob[off : off + klen]
    off += klen
    nonce = blob[off : off + 12]
    off += 12
    blen = int.from_bytes(blob[off : off + 2], "big")
    off += 2
    body = blob[off : off + blen]
    off += blen
    tag = blob[off : off + 16]
    return k, nonce, body, tag


# -------------------- Interactive demo --------------------

def run_full_demo():
    print("=== Assignment 6: Confidentiality (RSA), Integrity (Hash), Non-Repudiation (Signature) ===\n")

    # Choose hash algorithm
    if sys.stdin.isatty():
        print("Choose hash algorithm for display + signature (default SHA-256):")
        print("  1) SHA-256")
        print("  2) SHA-1")
        print("  3) MD5")
        choice = input("Enter choice [1/2/3, default=1]: ").strip()
    else:
        choice = "1"
    hash_algo = choose_hash_algo(choice)
    hash_name = {hashes.SHA256: "sha256", hashes.SHA1: "sha1", hashes.MD5: "md5"}[type(hash_algo)]

    # Enter message
    if sys.stdin.isatty():
        msg = input("\n[X] Enter message to send to Y: ")
    else:
        msg = "Hello from X to Y"

    # Generate RSA keypairs for X (sender) and Y (recipient)
    print("\n[SETUP] Generating RSA 2048-bit keys for X and Y...")
    x_priv, x_pub = gen_rsa_keypair(2048)
    y_priv, y_pub = gen_rsa_keypair(2048)
    print(f"[SETUP] X public key fingerprint: {pubkey_fingerprint(x_pub)}")
    print(f"[SETUP] Y public key fingerprint: {pubkey_fingerprint(y_pub)}")

    # Show sender hash (demonstrative integrity summary)
    sender_digest = hash_bytes(msg.encode("utf-8"), hash_algo)
    print(f"\n[X] {hash_name.upper()} digest of message: {sender_digest}")

    # Sign message with X's private key (RSA-PSS)
    signature = sign_message(x_priv, msg.encode("utf-8"), hash_algo)
    print(f"[X] Signature (base64): {base64.b64encode(signature).decode('ascii')[:60]}...")

    # Build payload with message, signature, hash algo name, and X public key (for Y to verify)
    x_pub_pem = x_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload = build_payload(msg, signature, hash_name, x_pub_pem)

    # Confidentiality: encrypt payload with AES-GCM under random key; wrap key with Y's RSA-OAEP
    sym_key = os.urandom(32)
    nonce, body, tag = aes_gcm_encrypt(payload, sym_key)
    wrapped_key = rsa_wrap(y_pub, sym_key)

    # Wire blob (what MITM would see)
    blob = serialize_wire(wrapped_key, nonce, body, tag)
    print("\n[NETWORK] Transmitting encrypted blob (visible to Z/MITM):")
    print(f"  wrapped_key (len={len(wrapped_key)}): {wrapped_key.hex()[:64]}...")
    print(f"  nonce: {nonce.hex()}")
    print(f"  body  (len={len(body)}): {body.hex()[:64]}...")
    print(f"  tag: {tag.hex()}")

    # Receiver Y decrypts
    print("\n[Y] Decrypting...")
    w2, n2, b2, t2 = parse_wire(blob)
    sym2 = rsa_unwrap(y_priv, w2)
    data = aes_gcm_decrypt(n2, b2, t2, sym2)

    # Parse payload
    r_msg, r_sig, r_hash_name, r_sender_pub_pem = parse_payload(data)
    r_hash_algo = choose_hash_algo({"sha256": "1", "sha1": "2", "md5": "3"}[r_hash_name])

    # Verify signature and recompute hash
    x_pub_recv = serialization.load_pem_public_key(r_sender_pub_pem)
    ok_sig = verify_signature(x_pub_recv, r_msg.encode("utf-8"), r_sig, r_hash_algo)
    recv_digest = hash_bytes(r_msg.encode("utf-8"), r_hash_algo)

    print(f"[Y] Decrypted message: {r_msg}")
    print(f"[Y] {r_hash_name.upper()} digest (recomputed): {recv_digest}")
    print(f"[Y] Signature valid (non-repudiation): {ok_sig}")

    if recv_digest == sender_digest and ok_sig:
        print("\nResult: Confidentiality preserved; integrity and non-repudiation verified.")
    else:
        print("\nResult: Verification failed (integrity/signature mismatch).")


if __name__ == "__main__":
    import sys, base64

    def encrypt_text_once():
        # Wrapper that runs the full flow and prints the wire blob in base64 for convenience
        print("\n--- Encrypt + Sign Message ---")
        run_full_demo()  # already prints internals; keeping simple for demo scope

    if sys.stdin.isatty():
        while True:
            print("\n=== Assignment 6 Menu ===")
            print("1) Run full confidentiality+integrity+signature demo")
            print("2) Quit")
            ch = input("> ").strip()
            if ch == "1":
                encrypt_text_once()
            elif ch == "2":
                break
            else:
                print("Invalid choice.")
    else:
        run_full_demo()
