"""
Key-Routed Cipher Framework (18-char key design)

Design summary:
- One shared 18-character key is used for both encryption and decryption.
- For ENCRYPTION:
  • Use the first 4 characters (key[0:4]) to select the cipher technique.
  • Use the middle 10 characters (key[4:14]) to derive cipher parameters.
  • The last 4 characters (key[14:18]) should also map to the same cipher id
    (so that reversing the key for decryption selects the same cipher).

- For DECRYPTION:
  • Conceptually, the key sent to the receiver is reversed.
  • We implement that by internally reversing the provided key: decrypt() will
    reverse the key and then use its first 4 characters (original last 4) to
    select the cipher, and use the (reversed) middle 10 to derive parameters.
  • If the front-4 and back-4 codes map to different ciphers, we raise an error
    to surface a key-design mismatch.

Supported cipher names (mapped by a deterministic function from a 4-char code):
  0: HILL      (2x2 Hill cipher, letters A-Z)
  1: AFFINE    (Affine cipher mod 26)
  2: RAIL      (Rail Fence transposition)
  3: COLUMNAR  (Columnar transposition)
  4: ROUTE     (Route transposition - simple snake/zigzag)
  5: ADFGVX    (Simplified ADFGVX: Polybius 6x6 + columnar)
  6: VERNAM    (XOR stream, byte-wise using PRNG seeded from key)
  7: OTP       (One-Time Pad style stream from key; same as Vernam here)

Notes:
- This is a practical reference implementation to match the conceptual key design.
- Text ciphers (Hill/Affine/Rail/Columnar/Route/ADFGVX) operate on A-Z only; we
  normalize by removing non-letters and uppercasing. Vernam/OTP work on bytes
  and return hex strings for interoperability.
"""

from __future__ import annotations

import math
import random
import string
from dataclasses import dataclass
from typing import List, Tuple

import hashlib


ALPHA = string.ascii_uppercase


def _only_letters_up(s: str) -> str:
    return "".join(ch for ch in s.upper() if ch in ALPHA)


def _bytes_xor(data: bytes, keystream: bytes) -> bytes:
    return bytes(b ^ keystream[i % len(keystream)] for i, b in enumerate(data))


def _prng_from_seed(seed_bytes: bytes) -> random.Random:
    # deterministic PRNG (do NOT use for real security)
    seed_int = int.from_bytes(hashlib.sha256(seed_bytes).digest(), "big")
    rnd = random.Random(seed_int)
    return rnd


# -------------------- Key parsing and cipher routing --------------------

CIPHERS = [
    "HILL",
    "AFFINE",
    "RAIL",
    "COLUMNAR",
    "ROUTE",
    "ADFGVX",
    "VERNAM",
    "OTP",
]


def _code_to_cipher_id(code4: str) -> int:
    # Map any 4-char code to a cipher id 0..7 deterministically
    total = sum(ord(c) for c in code4)
    return total % len(CIPHERS)


@dataclass
class ParsedKey:
    original: str
    enc_cipher_id: int
    dec_cipher_id: int
    params_enc: bytes  # 10 middle chars as bytes (encryption side)
    params_dec: bytes  # 10 middle chars of reversed key (decryption side)


def parse_key_for_encrypt(key18: str) -> ParsedKey:
    if len(key18) != 18:
        raise ValueError("Key must be exactly 18 characters long")
    k = key18
    front4 = k[:4]
    back4 = k[-4:]
    enc_id = _code_to_cipher_id(front4)
    dec_id = _code_to_cipher_id(back4)  # must match enc_id conceptually
    middle10 = k[4:14].encode("utf-8")
    # For decrypt (conceptually reversed key): params will be reversed middle
    krev = k[::-1]
    params_dec = krev[4:14].encode("utf-8")
    return ParsedKey(k, enc_id, dec_id, middle10, params_dec)


def parse_key_for_decrypt(key18: str) -> ParsedKey:
    if len(key18) != 18:
        raise ValueError("Key must be exactly 18 characters long")
    # Conceptually the key is reversed before decryption selection.
    k = key18[::-1]
    front4 = k[:4]
    back4 = k[-4:]
    dec_id = _code_to_cipher_id(front4)
    enc_id = _code_to_cipher_id(back4)  # should match
    middle10 = k[4:14].encode("utf-8")
    # For completeness, original (non-reversed) middle extracted too
    original_middle10 = key18[4:14].encode("utf-8")
    return ParsedKey(key18, enc_id, dec_id, original_middle10, middle10)


def _derive_ints_from_params(params: bytes, count: int, mod: int) -> List[int]:
    h = hashlib.sha256(params).digest()
    ints = []
    pos = 0
    while len(ints) < count:
        if pos >= len(h):
            h = hashlib.sha256(h + params).digest()
            pos = 0
        val = h[pos]
        ints.append(val % mod)
        pos += 1
    return ints


# -------------------- Individual cipher implementations --------------------

# Affine cipher (A->0..25), E(x)= (a*x+b) mod 26 ; D(y)= a_inv*(y-b) mod 26
def _egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def _modinv(a, m):
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m


def affine_encrypt(plaintext: str, params: bytes) -> str:
    text = _only_letters_up(plaintext)
    # derive a in {1..25} coprime with 26, and b in {0..25}
    a_candidates = [n for n in range(1, 26, 2) if n % 13 != 0]  # coprime with 26
    a_index = _derive_ints_from_params(params, 1, len(a_candidates))[0]
    a = a_candidates[a_index]
    b = _derive_ints_from_params(params[::-1], 1, 26)[0]
    res = []
    for ch in text:
        x = ord(ch) - 65
        y = (a * x + b) % 26
        res.append(chr(y + 65))
    return "".join(res)


def affine_decrypt(ciphertext: str, params: bytes) -> str:
    text = _only_letters_up(ciphertext)
    a_candidates = [n for n in range(1, 26, 2) if n % 13 != 0]
    a_index = _derive_ints_from_params(params, 1, len(a_candidates))[0]
    a = a_candidates[a_index]
    ainv = _modinv(a, 26)
    b = _derive_ints_from_params(params[::-1], 1, 26)[0]
    res = []
    for ch in text:
        y = ord(ch) - 65
        x = (ainv * (y - b)) % 26
        res.append(chr(x + 65))
    return "".join(res)


# Rail Fence (standard zig-zag)
def rail_encrypt(plaintext: str, params: bytes) -> str:
    text = _only_letters_up(plaintext)
    rails = max(2, 2 + _derive_ints_from_params(params, 1, 6)[0])  # 2..7
    rows = ["" for _ in range(rails)]
    r, dr = 0, 1
    for ch in text:
        rows[r] += ch
        r += dr
        if r == rails - 1 or r == 0:
            dr *= -1
    return "".join(rows)


def rail_decrypt(ciphertext: str, params: bytes) -> str:
    text = _only_letters_up(ciphertext)
    rails = max(2, 2 + _derive_ints_from_params(params, 1, 6)[0])
    # mark positions
    n = len(text)
    marks = [[False] * n for _ in range(rails)]
    r, dr = 0, 1
    for i in range(n):
        marks[r][i] = True
        r += dr
        if r == rails - 1 or r == 0:
            dr *= -1
    # fill rows
    idx = 0
    # prepare matrix with placeholders for n columns
    rows = [[None] * n for _ in range(rails)]
    for rr in range(rails):
        for c in range(n):
            if marks[rr][c]:
                rows[rr][c] = text[idx]
                idx += 1
    # read zig-zag
    res = []
    r, dr = 0, 1
    for i in range(n):
        res.append(rows[r][i])
        r += dr
        if r == rails - 1 or r == 0:
            dr *= -1
    return "".join(res)


# Columnar transposition
def _column_order_from_key(key_str: str) -> List[int]:
    # derive a pseudo-keyword from params (letters only)
    kw = _only_letters_up(key_str)
    if not kw:
        kw = "KEY"
    # order by alphabetical order with stable index
    pairs = sorted([(ch, i) for i, ch in enumerate(kw)])
    order = [None] * len(kw)
    for rank, (_ch, i) in enumerate(pairs):
        order[i] = rank
    return order


def columnar_encrypt(plaintext: str, params: bytes) -> str:
    text = _only_letters_up(plaintext)
    # create a key string from params hex
    key_str = hashlib.sha1(params).hexdigest()[:8].upper()
    order = _column_order_from_key(key_str)
    cols = len(order)
    # pad with X to fit
    pad_len = (-len(text)) % cols
    text_p = text + ("X" * pad_len)
    rows = [text_p[i : i + cols] for i in range(0, len(text_p), cols)]
    # read columns by the order
    out = []
    for col_rank in range(cols):
        col_idx = order.index(col_rank)
        for row in rows:
            out.append(row[col_idx])
    return "".join(out)


def columnar_decrypt(ciphertext: str, params: bytes) -> str:
    text = _only_letters_up(ciphertext)
    key_str = hashlib.sha1(params).hexdigest()[:8].upper()
    order = _column_order_from_key(key_str)
    cols = len(order)
    rows = math.ceil(len(text) / cols)
    # number of filled cells in each column
    col_heights = [rows] * cols
    extra = (rows * cols) - len(text)
    if extra:
        # last columns (by reading order) have one less char
        for i in range(1, extra + 1):
            col_heights[-i] -= 1
    # reconstruct columns from ciphertext
    columns = ["" for _ in range(cols)]
    idx = 0
    for col_rank in range(cols):
        col_idx = order.index(col_rank)
        h = col_heights[col_idx]
        columns[col_idx] = text[idx : idx + h]
        idx += h
    # read row-wise
    out = []
    for r in range(rows):
        for c in range(cols):
            if r < len(columns[c]):
                out.append(columns[c][r])
    return "".join(out).rstrip("X")


# Simple "Route" cipher: write into a rectangle with width W, read in zig-zag columns
def route_encrypt(plaintext: str, params: bytes) -> str:
    text = _only_letters_up(plaintext)
    W = max(3, 3 + _derive_ints_from_params(params, 1, 8)[0])  # width 3..10
    pad = (-len(text)) % W
    text_p = text + ("X" * pad)
    rows = [text_p[i : i + W] for i in range(0, len(text_p), W)]
    out = []
    # read column-wise with alternating direction (snake)
    for c in range(W):
        col = [row[c] for row in rows]
        if c % 2 == 1:
            col.reverse()
        out.extend(col)
    return "".join(out)


def route_decrypt(ciphertext: str, params: bytes) -> str:
    text = _only_letters_up(ciphertext)
    W = max(3, 3 + _derive_ints_from_params(params, 1, 8)[0])
    n = len(text)
    R = math.ceil(n / W)
    # determine column lengths
    col_lens = [R] * W
    # fill columns in snake order
    cols = []
    idx = 0
    for c in range(W):
        seg = text[idx : idx + col_lens[c]]
        idx += col_lens[c]
        if c % 2 == 1:
            seg = seg[::-1]
        cols.append(list(seg))
    # read row-wise
    out = []
    for r in range(R):
        for c in range(W):
            if r < len(cols[c]):
                out.append(cols[c][r])
    return "".join(out).rstrip("X")


# Hill cipher 2x2
def _matrix_mod_inv_2x2(M, mod=26):
    a, b, c, d = M[0][0], M[0][1], M[1][0], M[1][1]
    det = (a * d - b * c) % mod
    det_inv = _modinv(det, mod)
    inv = [[(d * det_inv) % mod, (-b * det_inv) % mod], [(-c * det_inv) % mod, (a * det_inv) % mod]]
    return inv


def _hill_key_from_params(params: bytes) -> List[List[int]]:
    vals = _derive_ints_from_params(params, 4, 26)
    # Ensure invertible by tweaking if needed
    for tweak in range(26):
        M = [[(vals[0] + tweak) % 26, vals[1]], [vals[2], vals[3]]]
        try:
            _matrix_mod_inv_2x2(M)
            return M
        except Exception:
            continue
    # fallback simple invertible matrix
    return [[3, 3], [2, 5]]


def hill_encrypt(plaintext: str, params: bytes) -> str:
    text = _only_letters_up(plaintext)
    if len(text) % 2 == 1:
        text += "X"
    M = _hill_key_from_params(params)
    out = []
    for i in range(0, len(text), 2):
        x1 = ord(text[i]) - 65
        x2 = ord(text[i + 1]) - 65
        y1 = (M[0][0] * x1 + M[0][1] * x2) % 26
        y2 = (M[1][0] * x1 + M[1][1] * x2) % 26
        out.append(chr(y1 + 65))
        out.append(chr(y2 + 65))
    return "".join(out)


def hill_decrypt(ciphertext: str, params: bytes) -> str:
    text = _only_letters_up(ciphertext)
    if len(text) % 2 == 1:
        text += "X"
    M = _hill_key_from_params(params)
    Minv = _matrix_mod_inv_2x2(M)
    out = []
    for i in range(0, len(text), 2):
        y1 = ord(text[i]) - 65
        y2 = ord(text[i + 1]) - 65
        x1 = (Minv[0][0] * y1 + Minv[0][1] * y2) % 26
        x2 = (Minv[1][0] * y1 + Minv[1][1] * y2) % 26
        out.append(chr(x1 + 65))
        out.append(chr(x2 + 65))
    return "".join(out).rstrip("X")


# Simplified ADFGVX: 6x6 Polybius with labels A,D,F,G,V,X + columnar transposition
LABELS = "ADFGVX"


def _polybius_square(params: bytes) -> str:
    base = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    # derive permutation
    h = hashlib.sha256(params).digest()
    order = list(range(len(base)))
    rnd = _prng_from_seed(h)
    rnd.shuffle(order)
    return "".join(base[i] for i in order)


def adfgvx_encrypt(plaintext: str, params: bytes) -> str:
    square = _polybius_square(params)
    text = _only_letters_up(plaintext)
    # expand to pairs
    pairs = []
    for ch in text:
        idx = square.find(ch)
        if idx < 0:
            continue
        r = idx // 6
        c = idx % 6
        pairs.append(LABELS[r] + LABELS[c])
    frac = "".join(pairs)
    # then columnar with params-derived key
    return columnar_encrypt(frac, params)


def adfgvx_decrypt(ciphertext: str, params: bytes) -> str:
    square = _polybius_square(params)
    frac = columnar_decrypt(_only_letters_up(ciphertext), params)
    out = []
    # read pairs
    for i in range(0, len(frac), 2):
        if i + 1 >= len(frac):
            break
        r = LABELS.find(frac[i])
        c = LABELS.find(frac[i + 1])
        if r < 0 or c < 0:
            continue
        idx = r * 6 + c
        out.append(square[idx])
    return "".join(out)


# Vernam / OTP: byte-wise XOR with PRNG keystream derived from params
def vernam_encrypt(plaintext: str, params: bytes) -> str:
    data = plaintext.encode("utf-8")
    rnd = _prng_from_seed(params)
    ks = bytes(rnd.randrange(0, 256) for _ in range(len(data)))
    ct = _bytes_xor(data, ks)
    return ct.hex()


def vernam_decrypt(cipher_hex: str, params: bytes) -> str:
    data = bytes.fromhex(cipher_hex)
    rnd = _prng_from_seed(params)
    ks = bytes(rnd.randrange(0, 256) for _ in range(len(data)))
    pt = _bytes_xor(data, ks)
    return pt.decode("utf-8", errors="replace")


# OTP identical to Vernam here (conceptual design)
otp_encrypt = vernam_encrypt
otp_decrypt = vernam_decrypt


# -------------------- Router --------------------

def _encrypt_by_id(cipher_id: int, plaintext: str, params: bytes) -> str:
    name = CIPHERS[cipher_id]
    if name == "HILL":
        return hill_encrypt(plaintext, params)
    if name == "AFFINE":
        return affine_encrypt(plaintext, params)
    if name == "RAIL":
        return rail_encrypt(plaintext, params)
    if name == "COLUMNAR":
        return columnar_encrypt(plaintext, params)
    if name == "ROUTE":
        return route_encrypt(plaintext, params)
    if name == "ADFGVX":
        return adfgvx_encrypt(plaintext, params)
    if name == "VERNAM":
        return vernam_encrypt(plaintext, params)
    if name == "OTP":
        return otp_encrypt(plaintext, params)
    raise ValueError("Unknown cipher id")


def _decrypt_by_id(cipher_id: int, ciphertext: str, params: bytes) -> str:
    name = CIPHERS[cipher_id]
    if name == "HILL":
        return hill_decrypt(ciphertext, params)
    if name == "AFFINE":
        return affine_decrypt(ciphertext, params)
    if name == "RAIL":
        return rail_decrypt(ciphertext, params)
    if name == "COLUMNAR":
        return columnar_decrypt(ciphertext, params)
    if name == "ROUTE":
        return route_decrypt(ciphertext, params)
    if name == "ADFGVX":
        return adfgvx_decrypt(ciphertext, params)
    if name == "VERNAM":
        return vernam_decrypt(ciphertext, params)
    if name == "OTP":
        return otp_decrypt(ciphertext, params)
    raise ValueError("Unknown cipher id")


def encrypt(message: str, key18: str) -> Tuple[str, str]:
    """Encrypt using the key-routing design.

    Returns (cipher_name, ciphertext).
    The caller must keep the same 18-char key for decryption (or send reversed key as per concept).
    """
    pk = parse_key_for_encrypt(key18)
    if pk.enc_cipher_id != pk.dec_cipher_id:
        # Surface mismatch early to help fix key design as per concept
        raise ValueError(
            f"Key front4 maps to {CIPHERS[pk.enc_cipher_id]}, but back4 maps to {CIPHERS[pk.dec_cipher_id]}. "
            "For the conceptual design, choose the last 4 chars so both map to the same cipher."
        )
    name = CIPHERS[pk.enc_cipher_id]
    ct = _encrypt_by_id(pk.enc_cipher_id, message, pk.params_enc)
    return name, ct


def decrypt(ciphertext: str, key18: str) -> Tuple[str, str]:
    """Decrypt using the key-routing design.

    Conceptually, the receiver uses the reversed key. We reverse internally and
    select the cipher from the reversed-key front4. Returns (cipher_name, plaintext).
    """
    pk = parse_key_for_decrypt(key18)
    if pk.enc_cipher_id != pk.dec_cipher_id:
        raise ValueError(
            f"Reversed-key front4 maps to {CIPHERS[pk.dec_cipher_id]}, but reversed-key back4 maps to {CIPHERS[pk.enc_cipher_id]}. "
            "Both ends should resolve to the same cipher id in this design."
        )
    name = CIPHERS[pk.dec_cipher_id]
    pt = _decrypt_by_id(pk.dec_cipher_id, ciphertext, pk.params_dec)
    return name, pt


if __name__ == "__main__":
    # Small demo to show routing works end-to-end.
    demo_key = "ABCDXXXXXXXXXXWXYZ"  # 18 chars; ensure front/back map same by coincidence or adjust
    print("Key:", demo_key)
    try:
        name, ct = encrypt("Meet at the bridge at nine.", demo_key)
    except ValueError as e:
        # If mismatch, tweak last four to match by brute force small tweak
        front_id = _code_to_cipher_id(demo_key[:4])
        tail = list(demo_key[-4:])
        found = False
        for a in ALPHA:
            for b in ALPHA:
                for c in ALPHA:
                    for d in ALPHA:
                        trial_tail = a + b + c + d
                        if _code_to_cipher_id(trial_tail) == front_id:
                            demo_key = demo_key[:14] + trial_tail
                            found = True
                            break
                    if found:
                        break
                if found:
                    break
            if found:
                break
        print("Adjusted key tail for demo:", demo_key)
        name, ct = encrypt("Meet at the bridge at nine.", demo_key)
    print("Cipher:", name)
    print("Ciphertext:", ct)
    name2, pt = decrypt(ct, demo_key)
    print("Decrypted (using reversed-key logic):", pt)
