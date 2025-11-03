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
import hmac


def compute_hash(message: str, algo: str) -> str:
    data = message.encode("utf-8")
    if algo.lower() in ("sha1", "sha-1"):
        return hashlib.sha1(data).hexdigest()
    elif algo.lower() in ("sha256", "sha-256"):
        return hashlib.sha256(data).hexdigest()
    else:
        raise ValueError("Unsupported algorithm; choose 'sha1' or 'sha256'")


def hmac_hex(message: str, key: str, algo: str) -> str:
    data = message.encode("utf-8")
    k = key.encode("utf-8")
    if algo.lower().startswith("sha256"):
        d = hmac.new(k, data, hashlib.sha256).hexdigest()
    else:
        d = hmac.new(k, data, hashlib.sha1).hexdigest()
    return d


def run_hash_demo():
    print("=== Assignment 5: Hash Integrity Demo (SHA-1 / SHA-256) ===\n")
    # Choose algorithm
    print("Choose hash algorithm:")
    print("  1) SHA-1 (160-bit)")
    print("  2) SHA-256 (256-bit)")
    choice = input("Enter choice [1/2, default=1]: ").strip()
    algo = "sha256" if choice == "2" else "sha1"

    msg = input("\nEnter message to send: ")

    sender_digest = compute_hash(msg, algo)
    print(f"\n[SENDER] Message: {msg}")
    print(f"[SENDER] {algo.upper()} digest: {sender_digest}")

    transmitted = msg
    print("\n[NETWORK] Transmitting message...")

    receiver_digest = compute_hash(transmitted, algo)
    print(f"\n[RECEIVER] Received message: {transmitted}")
    print(f"[RECEIVER] Recomputed {algo.upper()} digest: {receiver_digest}")

    if receiver_digest == sender_digest:
        print("\nResult: Hashes match — integrity verified.")
    else:
        print("\nResult: Hash mismatch — message altered or corrupted.")

    tamper = input("\nSimulate tampering? [y/N]: ").strip().lower()
    if tamper == "y":
        if transmitted:
            first = transmitted[0]
            tampered_first = chr(ord(first) ^ 0x01)
            tampered = tampered_first + transmitted[1:]
        else:
            tampered = transmitted
        print(f"\n[ATTACKER] Tampered message: {tampered}")
        tampered_digest = compute_hash(tampered, algo)
        print(f"[RECEIVER] Digest of tampered: {tampered_digest}")
        print("=> Different digest shows tampering detected.")


def run_verify_digest():
    print("=== Verify Digest ===")
    algo = input("Algorithm [sha1/sha256, default=sha1]: ").strip().lower() or "sha1"
    msg = input("Message: ")
    digest = input("Expected digest (hex): ").strip()
    calc = compute_hash(msg, algo)
    print("Calculated:", calc)
    print("Match:", calc.lower() == digest.lower())


def run_hmac_demo():
    print("=== HMAC Sign/Verify (SHA-1 / SHA-256) ===")
    algo = input("Algorithm [sha1/sha256, default=sha256]: ").strip().lower() or "sha256"
    key = input("Shared secret key: ")
    msg = input("Message to authenticate: ")
    tag = hmac_hex(msg, key, algo)
    print(f"\n[SENDER] HMAC-{algo.upper()} tag: {tag}")
    v = input("Verify now? [Y/n]: ").strip().lower()
    if v in ("", "y", "yes"):
        msg2 = input("[RECEIVER] Enter received message (or press Enter to reuse): ")
        if not msg2:
            msg2 = msg
        tag2 = input("[RECEIVER] Enter received tag (hex) (or press Enter to reuse): ")
        if not tag2:
            tag2 = tag
        calc = hmac_hex(msg2, key, algo)
        print("Calculated:", calc)
        print("Valid:", hmac.compare_digest(calc.lower(), tag2.lower()))


def main():
    if sys.stdin.isatty():
        while True:
            print("\n=== Assignment 5 Menu ===")
            print("1) Hash integrity demo (sender/receiver)")
            print("2) Verify a digest")
            print("3) HMAC sign/verify")
            print("4) Quit")
            ch = input("> ").strip()
            if ch == "1":
                run_hash_demo()
            elif ch == "2":
                run_verify_digest()
            elif ch == "3":
                run_hmac_demo()
            elif ch == "4":
                break
            else:
                print("Invalid choice.")
    else:
        # Non-interactive fallback: run original demo quickly
        algo = "sha1"
        msg = "Hello"
        sender_digest = compute_hash(msg, algo)
        receiver_digest = compute_hash(msg, algo)
        print(f"[SENDER] {algo.upper()} digest: {sender_digest}")
        print(f"[RECEIVER] digest: {receiver_digest}")
        print("Integrity:", sender_digest == receiver_digest)


if __name__ == "__main__":
    main()
