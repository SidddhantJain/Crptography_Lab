"""
Diffie–Hellman Key Exchange (DH) with Man-In-The-Middle (MITM) demonstration.

This script shows:
  1) A normal DH key exchange between Alice and Bob, deriving the same shared key.
  2) A MITM attack where Eve intercepts and substitutes public keys, creating two
     different shared secrets (Alice–Eve and Eve–Bob). Eve can then read/alter messages.

No external dependencies. Symmetric encryption is a didactic XOR stream derived
from SHA-256(shared_secret) repeated, for easy visibility.

Run:
  python ass4.py           # run both demos (clean then MITM)
  python ass4.py --clean   # only clean DH demo
  python ass4.py --mitm    # only MITM demo

Note: This demo uses a small prime p=23 and generator g=5 for clarity.
      Do NOT use small parameters in real cryptography.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Tuple


# -------------------- Simple DH primitives --------------------

@dataclass
class DHParams:
    p: int  # prime modulus
    g: int  # generator (primitive root modulo p)


@dataclass
class DHKeyPair:
    priv: int
    pub: int


def dh_generate_keypair(params: DHParams, priv: int | None = None) -> DHKeyPair:
    """Generate a DH keypair.
    If priv is provided, use it (for reproducibility). Else pick random in [2, p-2]."""
    p, g = params.p, params.g
    if priv is None:
        # Avoid 0/1 and p-1 corner cases
        priv = secrets.randbelow(p - 3) + 2
    pub = pow(g, priv, p)
    return DHKeyPair(priv=priv, pub=pub)


def dh_compute_shared(params: DHParams, priv: int, other_pub: int) -> int:
    """Compute the shared secret s = other_pub^priv mod p."""
    return pow(other_pub, priv, params.p)


# -------------------- Toy symmetric (XOR) using SHA-256(shared) --------------------

def kdf_from_shared(shared: int) -> bytes:
    # Derive 32 bytes from the integer shared secret
    return hashlib.sha256(shared.to_bytes((shared.bit_length() + 7) // 8 or 1, 'big')).digest()


def xor_stream(data: bytes, key_material: bytes) -> bytes:
    # Repeat key bytes as needed and XOR
    if not key_material:
        raise ValueError("empty key_material")
    km = (key_material * (len(data) // len(key_material) + 1))[: len(data)]
    return bytes(a ^ b for a, b in zip(data, km))


def encrypt_message(msg: str, shared: int) -> bytes:
    km = kdf_from_shared(shared)
    return xor_stream(msg.encode('utf-8'), km)


def decrypt_message(ct: bytes, shared: int) -> str:
    km = kdf_from_shared(shared)
    pt = xor_stream(ct, km)
    return pt.decode('utf-8', errors='replace')


# -------------------- Demonstrations --------------------

SMALL_PARAMS = DHParams(p=23, g=5)  # do not use in production


def demo_clean(params: DHParams = SMALL_PARAMS) -> None:
    print("=== CLEAN DIFFIE–HELLMAN EXCHANGE ===")
    print(f"Public parameters: p={params.p}, g={params.g}")

    alice = dh_generate_keypair(params)
    bob = dh_generate_keypair(params)

    print(f"Alice picks a={alice.priv}, sends A=g^a mod p={alice.pub}")
    print(f"Bob   picks b={bob.priv}, sends B=g^b mod p={bob.pub}")

    s_alice = dh_compute_shared(params, alice.priv, bob.pub)
    s_bob = dh_compute_shared(params, bob.priv, alice.pub)

    print(f"Alice computes s=(B)^a mod p={s_alice}")
    print(f"Bob   computes s=(A)^b mod p={s_bob}")
    print("Shared secrets equal:", s_alice == s_bob)

    msg = "Hello Bob, this is Alice."
    ct = encrypt_message(msg, s_alice)
    rec = decrypt_message(ct, s_bob)
    print(f"Alice → Bob: CT={ct.hex()}  (Bob decrypts) → '{rec}'")
    print()


def demo_mitm(params: DHParams = SMALL_PARAMS) -> None:
    print("=== MAN-IN-THE-MIDDLE (MITM) ATTACK DEMO ===")
    print(f"Public parameters: p={params.p}, g={params.g}")

    # Honest parties generate keypairs
    alice = dh_generate_keypair(params)
    bob = dh_generate_keypair(params)

    # Eve (attacker) generates her own private/public keys for each side
    eve_for_alice = dh_generate_keypair(params)
    eve_for_bob = dh_generate_keypair(params)

    print(f"Alice picks a={alice.priv}, forms A={alice.pub} (intercepted by Eve)")
    print(f"Bob   picks b={bob.priv}, forms B={bob.pub} (intercepted by Eve)")

    # Eve substitutes:
    # - To Bob, Eve sends her own public value EA instead of A
    # - To Alice, Eve sends her own public value EB instead of B
    EA = eve_for_alice.pub
    EB = eve_for_bob.pub
    print(f"Eve sends to Bob: EA={EA} (pretending to be Alice)")
    print(f"Eve sends to Alice: EB={EB} (pretending to be Bob)")

    # Shared secrets now:
    # Alice thinks shared is s_AE = (EB)^a
    # Bob   thinks shared is s_BE = (EA)^b
    # Eve knows both via her private keys with each side.
    s_AE = dh_compute_shared(params, alice.priv, EB)
    s_BE = dh_compute_shared(params, bob.priv, EA)
    s_eve_with_alice = dh_compute_shared(params, eve_for_bob.priv, alice.pub)
    s_eve_with_bob = dh_compute_shared(params, eve_for_alice.priv, bob.pub)

    print(f"Alice's shared (with Eve): s_AE={s_AE}")
    print(f"Bob's   shared (with Eve): s_BE={s_BE}")
    print(f"Eve's shared with Alice:  {s_eve_with_alice}")
    print(f"Eve's shared with Bob:    {s_eve_with_bob}")

    # Alice sends a message "to Bob"; encrypted under s_AE (unknown to Bob)
    msg1 = "Hi Bob, it's Alice!"
    ct1 = encrypt_message(msg1, s_AE)
    print(f"Alice → (Eve) → Bob: CT1={ct1.hex()}")

    # Eve can decrypt using s_eve_with_alice (equals s_AE)
    e1 = decrypt_message(ct1, s_eve_with_alice)
    print(f"Eve decrypts CT1 with s_eve_with_alice → '{e1}'")

    # Eve can re-encrypt the same message (or modified) to Bob using s_eve_with_bob
    fwd1 = encrypt_message(e1, s_eve_with_bob)
    rec1 = decrypt_message(fwd1, s_BE)
    print(f"Eve → Bob (re-encrypted): {fwd1.hex()}  (Bob decrypts) → '{rec1}'")

    # Bob replies "to Alice"; Bob uses s_BE (unknown to Alice)
    msg2 = "Hi Alice, got your message!"
    ct2 = encrypt_message(msg2, s_BE)
    print(f"Bob  → (Eve) → Alice: CT2={ct2.hex()}")

    # Eve decrypts using s_eve_with_bob, then re-encrypts under s_eve_with_alice for Alice
    e2 = decrypt_message(ct2, s_eve_with_bob)
    print(f"Eve decrypts CT2 with s_eve_with_bob → '{e2}'")

    fwd2 = encrypt_message(e2, s_eve_with_alice)
    rec2 = decrypt_message(fwd2, s_AE)
    print(f"Eve → Alice (re-encrypted): {fwd2.hex()}  (Alice decrypts) → '{rec2}'")
    print()


def main():
    parser = argparse.ArgumentParser(description="DH + MITM demonstration")
    parser.add_argument("--clean", action="store_true", help="Run clean DH demo only")
    parser.add_argument("--mitm", action="store_true", help="Run MITM demo only")
    args = parser.parse_args()

    if args.clean and args.mitm:
        demo_clean()
        demo_mitm()
    elif args.clean:
        demo_clean()
    elif args.mitm:
        demo_mitm()
    else:
        demo_clean()
        demo_mitm()


if __name__ == "__main__":
    main()
