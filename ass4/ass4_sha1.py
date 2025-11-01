"""
Simple SHA-1 Integrity Demo (Python)

This is the same as ass5.py but saved under an "ass4"-prefixed name
as requested. It:
- Reads a message (interactive when TTY; uses a default message otherwise)
- Computes sender SHA-1
- Simulates receiver recomputing and checking integrity
- Demonstrates tampering by flipping a bit in the first character

Run:
  python ass4_sha1.py
"""

from __future__ import annotations

import sys
import hashlib


def sha1_hex(message: str) -> str:
    return hashlib.sha1(message.encode("utf-8")).hexdigest()


def main():
    print("=== Simple SHA-1 Demo (ASS4) ===\n")

    if sys.stdin.isatty():
        msg = input("Enter message to send: ")
    else:
        msg = "Hello"  # fallback when not interactive

    digest = sha1_hex(msg)
    print(f"\n[SENDER] Message: {msg}")
    print(f"[SENDER] SHA-1 digest: {digest}")

    received = msg
    recvd_digest = sha1_hex(received)
    print(f"\n[RECEIVER] Received message: {received}")
    print(f"[RECEIVER] Recomputed digest: {recvd_digest}")

    if recvd_digest == digest:
        print("\nResult: Hashes match — integrity verified.")
    else:
        print("\nResult: Hash mismatch — message altered or corrupted.")

    print(f"\nNow demonstrating tampering: sender digest remains {digest}")
    if received:
        # Flip the lowest bit of the first Unicode code point
        first = received[0]
        tampered_first = chr(ord(first) ^ 0x01)
        tampered = tampered_first + received[1:]
    else:
        tampered = received

    print(f"[ATTACKER] Tampered message: {tampered}")
    print(f"[RECEIVER] Digest of tampered: {sha1_hex(tampered)}")
    print("=> Different digest shows tampering detected.")


if __name__ == "__main__":
    main()
