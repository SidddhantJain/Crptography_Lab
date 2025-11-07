def gcd(a: int, b: int) -> int:
    
    while b != 0:
        a, b = b, a % b
    return a

def is_prime(x: int) -> bool:
    if x < 2:
        return False
    if x % 2 == 0:
        return x == 2
    d = 3
    while d * d <= x:
        if x % d == 0:
            return False
        d += 2
    return True


def mod_inverse(e: int, phi: int) -> int:
   
    for i in range(1, phi):
        if (e * i) % phi == 1:
            return i
    return 0


def mod_exp(base: int, exp: int, mod: int) -> int:
   
    result = 1
    base %= mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp //= 2
        base = (base * base) % mod
    return result


def main() -> None:
    # Input primes p, q (>5) with basic validation
    while True:
        try:
            p = int(input("Enter prime number p (>5): ").strip())
            q = int(input("Enter prime number q (>5): ").strip())
        except ValueError:
            print("Please enter valid integers for p and q.\n")
            continue

        if p <= 5 or q <= 5:
            print("Both p and q must be > 5.\n")
            continue
        if not is_prime(p) or not is_prime(q):
            print("Both p and q must be prime.\n")
            continue
        if p == q:
            print("p and q should be distinct primes.\n")
            continue
        break

    n = p * q
    phi = (p - 1) * (q - 1)
    print(f"n = {n}, phi = {phi}")

    # Read e until coprime with phi and in (1, phi)
    while True:
        try:
            e = int(input("Enter public key e (1 < e < phi) coprime with phi: ").strip())
        except ValueError:
            print("Please enter an integer for e.\n")
            continue
        if 1 < e < phi and gcd(e, phi) == 1:
            d = mod_inverse(e, phi)
            if d != 0:
                break
        print("Invalid e! Try again.\n")

    print(f"Private key d = {d}")

    # Read plaintext, force uppercase and A-Z only
    while True:
        message = input("Enter plaintext message (A-Z only): ").strip().upper()
        if all('A' <= ch <= 'Z' for ch in message):
            break
        print("Message must contain only letters A-Z (no spaces/symbols).\n")

    # Encrypt: each letter as m in [0,25]
    cipher: list[int] = []
    print("\nCiphertext: ", end="")
    for ch in message:
        m = ord(ch) - ord('A')
        c = mod_exp(m, e, n)
        cipher.append(c)
        print(f"{c} ", end="")
    print()

    # Decrypt
    print("Decrypted message: ", end="")
    for c in cipher:
        m = mod_exp(c, d, n)
        print(chr(m + ord('A')), end="")
    print()


if __name__ == "__main__":
    main()
