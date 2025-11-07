from typing import Tuple

def power_mod(base: int, exp: int, mod: int) -> int:
    ans = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            ans = (ans * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return ans


def xor_cipher(text: str, key: int) -> str:
    k = key & 0xFF
    return ''.join(chr(ord(c) ^ k) for c in text)


def show_hex(s: str) -> str:
    return ''.join(f"{ord(c):02X}" for c in s)


def normal_flow(p: int, g: int, a_priv: int, b_priv: int) -> None:
    a_pub = power_mod(g, a_priv, p)
    b_pub = power_mod(g, b_priv, p)
    print(f" Alice's public key = {a_pub}")
    print(f" Bob's public key = {b_pub}\n")

    print("*** Normal (Honest) Communication ***")
    a_shared = power_mod(b_pub, a_priv, p)
    b_shared = power_mod(a_pub, b_priv, p)
    print(f"Alice's shared key = {a_shared}")
    print(f"Bob's shared key = {b_shared}")
    print("Do they match? ", "YES" if a_shared == b_shared else "NO", "\n")

    message = input("Enter a short message to send: ")
    encrypted = xor_cipher(message, a_shared)
    decrypted = xor_cipher(encrypted, b_shared)

    print("\nMessage exchange example (XOR encryption):")
    print(f" Original message: {message}")
    print(f" Encrypted text: {show_hex(encrypted)}")
    print(f" Decrypted text: {decrypted}\n")


def mitm_flow(p: int, g: int, a_priv: int, b_priv: int, a_pub: int, b_pub: int) -> None:
    print("*** Man-in-the-Middle Simulation ***")
    e1 = int(input("Enter Eve's secret for Alice: "))
    e2 = int(input("Enter Eve's secret for Bob: "))

    print("\nIntercepting keys...")
    eve_to_bob = power_mod(g, e2, p)
    eve_to_alice = power_mod(g, e1, p)
    print(f"Eve sends fake key to Bob: {eve_to_bob}")
    print(f"Eve sends fake key to Alice: {eve_to_alice}\n")

    a_fake_shared = power_mod(eve_to_alice, a_priv, p)
    b_fake_shared = power_mod(eve_to_bob, b_priv, p)
    eve_key_with_alice = power_mod(a_pub, e1, p)
    eve_key_with_bob = power_mod(b_pub, e2, p)

    print("After interception:")
    print(f" Alice's key = {a_fake_shared}")
    print(f" Bob's key = {b_fake_shared}")
    print(f" Eve's key with Alice = {eve_key_with_alice}")
    print(f" Eve's key with Bob = {eve_key_with_bob}")
    print("Do Alice and Bob share same key? ", "YES" if a_fake_shared == b_fake_shared else "NO", "\n")

    alice_msg = input("Enter a message Alice sends: ")
    msg_from_alice = xor_cipher(alice_msg, a_fake_shared)
    print(f"Alice sends (encrypted hex): {show_hex(msg_from_alice)}")

    eve_read = xor_cipher(msg_from_alice, eve_key_with_alice)
    print(f"Eve reads message: {eve_read}")

    eve_forward = xor_cipher(eve_read, eve_key_with_bob)
    print(f"Eve forwards to Bob (re-encrypted hex): {show_hex(eve_forward)}")

    bob_read = xor_cipher(eve_forward, b_fake_shared)
    print(f"Bob decrypts and reads: {bob_read}\n")


def main() -> None:
    p = int(input("Enter prime number (p): "))
    g = int(input("Enter generator value (g): "))
    a_priv = int(input("Enter Alice's secret key: "))
    b_priv = int(input("Enter Bob's secret key: "))
    print(f"\nPublic values: p = {p}, g = {g}\n")

    print("Calculating public keys...")
    a_pub = power_mod(g, a_priv, p)
    b_pub = power_mod(g, b_priv, p)

    print("Choose mode:")
    print(" 1. Normal exchange")
    print(" 2. With attacker (MITM simulation)")
    option = int(input("Select (1 or 2): "))

    if option == 1:
        normal_flow(p, g, a_priv, b_priv)
    else:
        mitm_flow(p, g, a_priv, b_priv, a_pub, b_pub)


if __name__ == "__main__":
    main()
