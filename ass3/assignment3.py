
def rail_fence_encrypt(text: str, rails: int) -> str:
    if rails <= 1 or rails >= len(text):
        return text
    rows = ["" for _ in range(rails)]
    r, dr = 0, 1
    for ch in text:
        rows[r] += ch
        r += dr
        if r == 0 or r == rails - 1:
            dr *= -1
    return "".join(rows)

def rail_fence_decrypt(cipher: str, rails: int) -> str:
    if rails <= 1 or rails >= len(cipher):
        return cipher
    # pattern of row indices
    pattern = []
    r, dr = 0, 1
    for _ in cipher:
        pattern.append(r)
        r += dr
        if r == 0 or r == rails - 1:
            dr *= -1
    # count chars per row
    counts = [pattern.count(i) for i in range(rails)]
    # slice cipher string into rows
    rows = []
    idx = 0
    for c in counts:
        rows.append(list(cipher[idx:idx+c]))
        idx += c
    # rebuild
    out = []
    for row_index in pattern:
        out.append(rows[row_index].pop(0))
    return "".join(out)

def encrypt(s: str, rails: int) -> str:
    if not s:
        return ""
    first = s[0]
    rev = s[::-1]
    rf = rail_fence_encrypt(rev, rails)
    xor_bytes = [(ord(c) ^ ord(first)) for c in rf]
    hex_part = ''.join(f"{b:02x}" for b in xor_bytes)
    return first + hex_part

def decrypt(ct: str, rails: int) -> str:
    if not ct:
        return ""
    first = ct[0]
    hex_part = ct[1:]
    # split hex into bytes
    rf_xor = ''.join(chr(int(hex_part[i:i+2], 16) ^ ord(first)) for i in range(0, len(hex_part), 2))
    rev = rail_fence_decrypt(rf_xor, rails)
    original = rev[::-1]
    return original

def main() -> None:
    s = input("Enter a string: ")
    rails = int(input("Enter number of rails (e.g. 3): "))
    enc = encrypt(s, rails)
    dec = decrypt(enc, rails)
    print(f"Encrypted (first char + hex): {enc}")
    print(f"Decrypted: {dec}")

if __name__ == "__main__":
    main()
