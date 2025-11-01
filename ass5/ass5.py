"""
Assignment 5: Hash-based Integrity Demo (Python)

Aim: Demonstrate how a message transmitted over a network can be integrity-checked
using a cryptographic hash (SHA-1 or SHA-256). The program is interactive: it
lets you choose the hash algorithm, enter a message, and optionally simulate
tampering to observe detection via changed digest.

Run:
    python ass5.py
"""

from __future__ import annotations

import sys
import hashlib


def compute_hash(message: str, algo: str) -> str:
    data = message.encode("utf-8")
    if algo.lower() in ("sha1", "sha-1"):
        return hashlib.sha1(data).hexdigest()
    elif algo.lower() in ("sha256", "sha-256"):
        return hashlib.sha256(data).hexdigest()
    else:
        raise ValueError("Unsupported algorithm; choose 'sha1' or 'sha256'")


def main():
    print("=== Assignment 5: Hash Integrity Demo (SHA-1 / SHA-256) ===\n")

    # Choose algorithm
    if sys.stdin.isatty():
        print("Choose hash algorithm:")
        print("  1) SHA-1 (160-bit)")
        print("  2) SHA-256 (256-bit)")
        choice = input("Enter choice [1/2, default=1]: ").strip()
        algo = "sha256" if choice == "2" else "sha1"
    else:
        algo = "sha1"  # fallback

    # Enter message
    if sys.stdin.isatty():
        msg = input("\nEnter message to send: ")
    else:
        msg = "Hello"  # fallback when non-interactive

    # Sender computes digest
    sender_digest = compute_hash(msg, algo)
    print(f"\n[SENDER] Message: {msg}")
    print(f"[SENDER] {algo.upper()} digest: {sender_digest}")

    # "Network transmission"
    transmitted = msg
    print("\n[NETWORK] Transmitting message...")

    # Receiver computes digest
    receiver_digest = compute_hash(transmitted, algo)
    print(f"\n[RECEIVER] Received message: {transmitted}")
    print(f"[RECEIVER] Recomputed {algo.upper()} digest: {receiver_digest}")

    if receiver_digest == sender_digest:
        print("\nResult: Hashes match — integrity verified.")
    else:
        print("\nResult: Hash mismatch — message altered or corrupted.")

    # Optional tampering demo
    tamper = "n"
    if sys.stdin.isatty():
        tamper = input("\nSimulate tampering? [y/N]: ").strip().lower()
    if tamper == "y":
        if transmitted:
            first = transmitted[0]
            tampered_first = chr(ord(first) ^ 0x01)  # flip 1 bit
            tampered = tampered_first + transmitted[1:]
        else:
            tampered = transmitted
        print(f"\n[ATTACKER] Tampered message: {tampered}")
        tampered_digest = compute_hash(tampered, algo)
        print(f"[RECEIVER] Digest of tampered: {tampered_digest}")
        print("=> Different digest shows tampering detected.")


if __name__ == "__main__":
    main()
