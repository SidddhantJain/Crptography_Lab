"""
Authenticated key-routed cipher framework (18-char key, HMAC-derived selection/params)

Features
- One 18-character master key K (printable). Optionally reverse on decrypt (legacy mode).
- Hide cipher ID: cipher selected via HMAC-SHA256 over full key (no per-substring leak).
- Deterministic parameter derivation from HMAC-derived 64-bit seed.
- Integrity/authenticity: TAG = HMAC-SHA256(K_bytes, IV || CT). Verify before decryption.
- Wire format: IV(12 bytes) || CT (bytes) || TAG(32 bytes).

Supported ciphers (N=8)
  0: HILL (2x2, A..Z)
  1: AFFINE (mod 26)
  2: RAIL (Rail Fence)
  3: COLUMNAR (Columnar transposition, L=8)
  4: ROUTE (rows, cols, path∈{row-wise, column-wise, spiral, diagonal})
  5: ADFGVX (6x6 Polybius + columnar)
  6: VERNAM (byte XOR keystream from seed; NOT cryptographically secure)
  7: OTP (byte XOR with external one-time key; must be provided)

Classical text handling policy
- For length-preserving classical ciphers (HILL/AFFINE/RAIL/COLUMNAR/ROUTE):
  operate on letters A..Z only and preserve non-letters in place.
- For ADFGVX: operate on A..Z and digits 0..9 only; non-alphanumerics are removed
  from the processed stream (since fractionation changes length). They are not
  preserved in-place to avoid ambiguity.

Security note
- This is for educational purposes. Do NOT treat classical ciphers here as strong
  cryptography. If you need confidentiality, use modern AEAD (AES-GCM/ChaCha20-Poly1305).
"""

from __future__ import annotations

import base64
import hmac
import hashlib
import math
import os
import random
import string
from typing import List, Tuple, Sequence


ALPHA = string.ascii_uppercase
ADFGVX_LABELS = "ADFGVX"
ALNUM36 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

CIPHER_LIST = [
	"HILL",
	"AFFINE",
	"RAIL",
	"COLUMNAR",
	"ROUTE",
	"ADFGVX",
	"VERNAM",
	"OTP",
]


# -------------------- HMAC helpers and derivations --------------------

def hmac_sha256(key: bytes, data: bytes) -> bytes:
	return hmac.new(key, data, hashlib.sha256).digest()


def derive_core(K_bytes: bytes, N: int) -> Tuple[int, int, int]:
	"""Return (cipher_index, seed, iv_seed). Uses D1/D2/D3 from spec."""
	D1 = hmac_sha256(K_bytes, b"cipher_select")
	D2 = hmac_sha256(K_bytes, b"param_seed")
	D3 = hmac_sha256(K_bytes, b"iv_seed")
	cipher_index = int.from_bytes(D1[:4], "big") % N
	seed = int.from_bytes(D2[:8], "big")
	iv_seed = int.from_bytes(D3[:8], "big")
	return cipher_index, seed, iv_seed


def derive_col_key_letters(K_bytes: bytes, L: int, label: bytes) -> str:
	b = hmac_sha256(K_bytes, label)
	out = []
	for i in range(L):
		out.append(ALPHA[b[i % len(b)] % 26])
	return "".join(out)


def stable_order_from_key(key_str: str) -> List[int]:
	# Stable sort by (letter, index)
	pairs = sorted([(ch, i) for i, ch in enumerate(key_str)])
	order = [None] * len(key_str)
	for rank, (_ch, i) in enumerate(pairs):
		order[i] = rank
	return order


def expand_label_bytes(K_bytes: bytes, base_label: bytes, count: int) -> bytes:
	"""Deterministically expand label to count bytes by HMAC chaining."""
	out = bytearray()
	idx = 0
	cur = b""
	while len(out) < count:
		cur = hmac_sha256(K_bytes, base_label + idx.to_bytes(2, "big"))
		out.extend(cur)
		idx += 1
	return bytes(out[:count])


# -------------------- Classical helpers --------------------

def only_letters_up(s: str) -> str:
	return "".join(ch for ch in s.upper() if ch in ALPHA)


def preserve_nonletters_apply(text: str, transform_letters: callable) -> str:
	"""Apply transform_letters to the A..Z letters only; keep others in place."""
	letters = [ch for ch in text if ch.upper() in ALPHA]
	letters_up = [ch.upper() for ch in letters]
	processed = list(transform_letters("".join(letters_up)))
	# reinsert
	out = []
	it = iter(processed)
	for ch in text:
		if ch.upper() in ALPHA:
			out.append(next(it))
		else:
			out.append(ch)
	return "".join(out)


# -------------------- Key generation --------------------

def generate_key(length: int = 18) -> str:
	"""Generate a new random printable 18-character key (A-Z0-9)."""
	alphabet = string.ascii_uppercase + string.digits
	return "".join(random.choice(alphabet) for _ in range(length))


# -------------------- Affine cipher --------------------

def egcd(a: int, b: int) -> Tuple[int, int, int]:
	if b == 0:
		return (a, 1, 0)
	g, x1, y1 = egcd(b, a % b)
	return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, m: int) -> int:
	g, x, _ = egcd(a, m)
	if g != 1:
		raise ValueError("No modular inverse")
	return x % m


def affine_params_from_seed(seed: int) -> Tuple[int, int]:
	a = (seed >> 6) % 26
	b = seed % 26
	# fix a to be coprime with 26
	coprimes = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
	if math.gcd(a, 26) != 1:
		# choose first >= a mod 26 deterministically
		start = a % 26
		chosen = None
		for k in range(26):
			cand = (start + k) % 26
			if cand in coprimes:
				chosen = cand
				break
		if chosen is None:
			chosen = 1
		a = chosen
	return a, b


def affine_encrypt_letters(letters: str, a: int, b: int) -> str:
	out = []
	for ch in letters:
		x = ord(ch) - 65
		y = (a * x + b) % 26
		out.append(chr(y + 65))
	return "".join(out)


def affine_decrypt_letters(letters: str, a: int, b: int) -> str:
	ainv = modinv(a, 26)
	out = []
	for ch in letters:
		y = ord(ch) - 65
		x = (ainv * (y - b)) % 26
		out.append(chr(x + 65))
	return "".join(out)


# -------------------- Hill (2x2) --------------------

def hill_matrix_from_seed(seed: int) -> List[List[int]]:
	m00 = (seed >> 48) % 26
	m01 = (seed >> 36) % 26
	m10 = (seed >> 24) % 26
	m11 = (seed >> 12) % 26
	# ensure invertible: adjust m11 up to 26 times
	for _ in range(26):
		det = (m00 * m11 - m01 * m10) % 26
		if math.gcd(det, 26) == 1:
			return [[m00, m01], [m10, m11]]
		m11 = (m11 + 1) % 26
	raise ValueError("Hill key not invertible after repairs")


def mat_inv_2x2_mod26(M: List[List[int]]) -> List[List[int]]:
	a, b, c, d = M[0][0], M[0][1], M[1][0], M[1][1]
	det = (a * d - b * c) % 26
	det_inv = modinv(det, 26)
	return [[(d * det_inv) % 26, (-b * det_inv) % 26], [(-c * det_inv) % 26, (a * det_inv) % 26]]


def hill_encrypt_letters(letters: str, M: List[List[int]]) -> str:
	if len(letters) % 2 == 1:
		letters += "X"
	out = []
	for i in range(0, len(letters), 2):
		x1 = ord(letters[i]) - 65
		x2 = ord(letters[i + 1]) - 65
		y1 = (M[0][0] * x1 + M[0][1] * x2) % 26
		y2 = (M[1][0] * x1 + M[1][1] * x2) % 26
		out.append(chr(y1 + 65))
		out.append(chr(y2 + 65))
	return "".join(out)


def hill_decrypt_letters(letters: str, M: List[List[int]]) -> str:
	if len(letters) % 2 == 1:
		letters += "X"
	Minv = mat_inv_2x2_mod26(M)
	out = []
	for i in range(0, len(letters), 2):
		y1 = ord(letters[i]) - 65
		y2 = ord(letters[i + 1]) - 65
		x1 = (Minv[0][0] * y1 + Minv[0][1] * y2) % 26
		x2 = (Minv[1][0] * y1 + Minv[1][1] * y2) % 26
		out.append(chr(x1 + 65))
		out.append(chr(x2 + 65))
	return "".join(out).rstrip("X")


# -------------------- Rail Fence --------------------

def rail_params_from_seed(seed: int) -> int:
	return (seed % 11) + 2  # 2..12


def rail_encrypt_letters(letters: str, rails: int) -> str:
	rows = ["" for _ in range(rails)]
	r, dr = 0, 1
	for ch in letters:
		rows[r] += ch
		r += dr
		if r == rails - 1 or r == 0:
			dr *= -1
	return "".join(rows)


def rail_decrypt_letters(letters: str, rails: int) -> str:
	n = len(letters)
	if n == 0:
		return ""
	marks = [[False] * n for _ in range(rails)]
	r, dr = 0, 1
	for i in range(n):
		marks[r][i] = True
		r += dr
		if r == rails - 1 or r == 0:
			dr *= -1
	# fill rows
	rows = [[None] * n for _ in range(rails)]
	idx = 0
	for rr in range(rails):
		for c in range(n):
			if marks[rr][c]:
				rows[rr][c] = letters[idx]
				idx += 1
	# read zig-zag
	out = []
	r, dr = 0, 1
	for i in range(n):
		out.append(rows[r][i])
		r += dr
		if r == rails - 1 or r == 0:
			dr *= -1
	return "".join(out)


# -------------------- Columnar --------------------

def columnar_encrypt_letters(letters: str, key_str: str) -> str:
	"""Columnar transposition without padding (length-preserving).

	Fill rows left-to-right; last row may be short. Read columns by rank; for
	short columns (those with index >= rem) skip missing cells.
	"""
	order = stable_order_from_key(key_str)
	cols = len(order)
	if cols == 0:
		return letters
	n = len(letters)
	rows = (n + cols - 1) // cols
	rem = n % cols
	if rem == 0:
		rem = cols
	# build rows (last row may be short)
	matrix = []
	idx = 0
	for r in range(rows):
		row_len = cols if r < rows - 1 else rem
		matrix.append(letters[idx : idx + row_len])
		idx += row_len
	out = []
	for rank in range(cols):
		col_idx = order.index(rank)
		for r in range(rows):
			if r < rows - 1:
				# full rows
				out.append(matrix[r][col_idx])
			else:
				# last row has length rem
				if col_idx < rem:
					out.append(matrix[r][col_idx])
	return "".join(out)


def columnar_decrypt_letters(letters: str, key_str: str) -> str:
	"""Inverse of columnar_encrypt_letters without padding.

	Compute column heights based on n and cols: first rem columns (by column index)
	have height rows, others have rows-1. Slice ciphertext in rank order into columns,
	then read row-wise.
	"""
	order = stable_order_from_key(key_str)
	cols = len(order)
	if cols == 0:
		return letters
	n = len(letters)
	rows = (n + cols - 1) // cols
	rem = n % cols
	# When rem==0, all columns have equal height = rows
	col_heights = [rows if (rem == 0 or c < rem) else rows - 1 for c in range(cols)]
	columns = ["" for _ in range(cols)]
	idx = 0
	for rank in range(cols):
		col_idx = order.index(rank)
		h = col_heights[col_idx]
		columns[col_idx] = letters[idx : idx + h]
		idx += h
	out = []
	for r in range(rows):
		for c in range(cols):
			if r < len(columns[c]):
				out.append(columns[c][r])
	return "".join(out)


# -------------------- Route cipher --------------------

def route_params_from_seed(seed: int) -> Tuple[int, int, int]:
	rows = ((seed >> 8) % 6) + 2  # 2..7
	cols = ((seed >> 12) % 6) + 2  # 2..7
	path = seed % 4  # 0=row-wise,1=column-wise,2=spiral,3=diagonal
	return rows, cols, path


def path_positions(rows: int, cols: int, mode: int) -> List[Tuple[int, int]]:
	pos = []
	if mode == 0:  # row-wise
		for r in range(rows):
			for c in range(cols):
				pos.append((r, c))
	elif mode == 1:  # column-wise
		for c in range(cols):
			for r in range(rows):
				pos.append((r, c))
	elif mode == 2:  # spiral (clockwise)
		top, left, bottom, right = 0, 0, rows - 1, cols - 1
		while top <= bottom and left <= right:
			for c in range(left, right + 1):
				pos.append((top, c))
			top += 1
			for r in range(top, bottom + 1):
				pos.append((r, right))
			right -= 1
			if top <= bottom:
				for c in range(right, left - 1, -1):
					pos.append((bottom, c))
				bottom -= 1
			if left <= right:
				for r in range(bottom, top - 1, -1):
					pos.append((r, left))
				left += 1
	else:  # diagonal zig-zag (like matrix diags)
		for s in range(rows + cols - 1):
			r_start = 0 if s < cols else s - cols + 1
			r_end = min(s, rows - 1)
			diag = [(r, s - r) for r in range(r_start, r_end + 1) if 0 <= s - r < cols]
			if s % 2 == 0:
				diag.reverse()
			pos.extend(diag)
	return pos


def route_encrypt_letters(letters: str, rows: int, cols: int, path: int) -> str:
	"""Route encryption without padding (length-preserving).

	Fill row-major until letters exhausted; read along path but only for n positions.
	"""
	n = len(letters)
	grid = [[None] * cols for _ in range(rows)]
	idx = 0
	for r in range(rows):
		for c in range(cols):
			if idx < n:
				grid[r][c] = letters[idx]
				idx += 1
	out = []
	pos = path_positions(rows, cols, path)
	for (r, c) in pos[:n]:
		ch = grid[r][c]
		if ch is None:
			# if path hits beyond filled cells, skip
			continue
		out.append(ch)
	return "".join(out)


def route_decrypt_letters(letters: str, rows: int, cols: int, path: int) -> str:
	"""Inverse of route_encrypt_letters without padding.

	Place letters by path positions (first n positions), then read row-major.
	"""
	n = len(letters)
	grid = [[None] * cols for _ in range(rows)]
	pos = path_positions(rows, cols, path)[:n]
	it = iter(letters)
	for (r, c) in pos:
		grid[r][c] = next(it)
	out = []
	for r in range(rows):
		for c in range(cols):
			if grid[r][c] is not None:
				out.append(grid[r][c])
	return "".join(out)


# -------------------- ADFGVX --------------------

def adfgvx_square_from_key(K_bytes: bytes) -> str:
	# Stable sort of 36 symbols by expanded per-index byte
	weights = expand_label_bytes(K_bytes, b"adfgvx_map", 36)
	pairs = sorted((weights[i], i) for i in range(36))
	order = [idx for (_w, idx) in pairs]
	return "".join(ALNUM36[i] for i in order)


def adfgvx_fractionate(text: str, square: str) -> str:
	out = []
	for ch in text.upper():
		if ch not in ALNUM36:
			continue
		idx = square.find(ch)
		r = idx // 6
		c = idx % 6
		out.append(ADFGVX_LABELS[r])
		out.append(ADFGVX_LABELS[c])
	return "".join(out)


def adfgvx_defractionate(frac: str, square: str) -> str:
	out = []
	for i in range(0, len(frac), 2):
		if i + 1 >= len(frac):
			break
		r = ADFGVX_LABELS.find(frac[i])
		c = ADFGVX_LABELS.find(frac[i + 1])
		if r < 0 or c < 0:
			continue
		out.append(square[r * 6 + c])
	return "".join(out)


# -------------------- Vernam / OTP --------------------

def xor_bytes(a: bytes, b: bytes) -> bytes:
	return bytes(x ^ y for x, y in zip(a, b))


def vernam_keystream(seed: int, n: int) -> bytes:
	rnd = random.Random(seed & 0xFFFFFFFF)
	return bytes(rnd.randrange(0, 256) for _ in range(n))


# -------------------- Router (encrypt/decrypt) --------------------

def encrypt(
	K: str,
	plaintext: str,
	*,
	legacy_reverse: bool = False,
	deterministic_iv: bool = False,
	require_external_otp: bool = True,
	external_otp_key: bytes | None = None,
) -> Tuple[str, bytes]:
	"""Encrypt and return (cipher_name, BLOB_bytes) where BLOB = IV||CT||TAG.

	plaintext is a text string. Stream ciphers operate on UTF-8 bytes of this string.
	"""
	if len(K) < 18:
		# pad to 18 deterministically (documented policy)
		K = (K + ("#" * 18))[:18]
	elif len(K) > 18:
		K = K[:18]
	K_eff = K[::-1] if legacy_reverse else K
	K_bytes = K_eff.encode("utf-8")

	cipher_index, seed, iv_seed = derive_core(K_bytes, len(CIPHER_LIST))
	cipher_name = CIPHER_LIST[cipher_index]

	# IV
	if deterministic_iv:
		IV = hmac_sha256(K_bytes, b"iv_seed")[:12]
	else:
		IV = os.urandom(12)

	# Encrypt per cipher
	if cipher_name == "AFFINE":
		a, b = affine_params_from_seed(seed)
		ct_text = preserve_nonletters_apply(plaintext, lambda L: affine_encrypt_letters(L, a, b))
		CT = ct_text.encode("ascii", errors="ignore")
	elif cipher_name == "HILL":
		M = hill_matrix_from_seed(seed)
		ct_text = preserve_nonletters_apply(plaintext, lambda L: hill_encrypt_letters(L, M))
		CT = ct_text.encode("ascii", errors="ignore")
	elif cipher_name == "RAIL":
		rails = rail_params_from_seed(seed)
		ct_text = preserve_nonletters_apply(plaintext, lambda L: rail_encrypt_letters(L, rails))
		CT = ct_text.encode("ascii", errors="ignore")
	elif cipher_name == "COLUMNAR":
		key_str = derive_col_key_letters(K_bytes, 8, b"col_key")
		ct_text = preserve_nonletters_apply(plaintext, lambda L: columnar_encrypt_letters(L, key_str))
		CT = ct_text.encode("ascii", errors="ignore")
	elif cipher_name == "ROUTE":
		rows, cols, path = route_params_from_seed(seed)
		ct_text = preserve_nonletters_apply(plaintext, lambda L: route_encrypt_letters(L, rows, cols, path))
		CT = ct_text.encode("ascii", errors="ignore")
	elif cipher_name == "ADFGVX":
		square = adfgvx_square_from_key(K_bytes)
		frac = adfgvx_fractionate(plaintext, square)  # non-alnum dropped
		key_str = derive_col_key_letters(K_bytes, 8, b"adfgvx_col")
		ct_text = columnar_encrypt_letters(frac, key_str)
		CT = ct_text.encode("ascii")
	elif cipher_name == "VERNAM":
		data = plaintext.encode("utf-8")
		ks = vernam_keystream(seed, len(data))
		CT = xor_bytes(data, ks)
	elif cipher_name == "OTP":
		data = plaintext.encode("utf-8")
		if require_external_otp and external_otp_key is None:
			raise ValueError("OTP mode requires external_otp_key of same length as plaintext bytes")
		if external_otp_key is None or len(external_otp_key) != len(data):
			raise ValueError("external_otp_key length must equal plaintext byte length")
		CT = xor_bytes(data, external_otp_key)
	else:
		raise ValueError("Unknown cipher")

	TAG = hmac_sha256(K_bytes, IV + CT)
	BLOB = IV + CT + TAG
	return cipher_name, BLOB


def decrypt(
	K: str,
	blob: bytes,
	*,
	legacy_reverse: bool = False,
	require_external_otp: bool = True,
	external_otp_key: bytes | None = None,
) -> Tuple[str, str]:
	"""Decrypt BLOB and return (cipher_name, plaintext_str).
	Verifies TAG before decryption and raises on mismatch.
	"""
	if len(K) < 18:
		K = (K + ("#" * 18))[:18]
	elif len(K) > 18:
		K = K[:18]
	K_eff = K[::-1] if legacy_reverse else K
	K_bytes = K_eff.encode("utf-8")

	if len(blob) < 12 + 32:
		raise ValueError("Blob too short")
	IV = blob[:12]
	TAG = blob[-32:]
	CT = blob[12:-32]
	exp = hmac_sha256(K_bytes, IV + CT)
	if not hmac.compare_digest(TAG, exp):
		raise ValueError("Tag verification failed (wrong key or tampered data)")

	cipher_index, seed, _iv_seed = derive_core(K_bytes, len(CIPHER_LIST))
	cipher_name = CIPHER_LIST[cipher_index]

	if cipher_name == "AFFINE":
		a, b = affine_params_from_seed(seed)
		ct_text = CT.decode("ascii", errors="ignore")
		pt_text = preserve_nonletters_apply(ct_text, lambda L: affine_decrypt_letters(L, a, b))
		return cipher_name, pt_text
	elif cipher_name == "HILL":
		M = hill_matrix_from_seed(seed)
		ct_text = CT.decode("ascii", errors="ignore")
		pt_text = preserve_nonletters_apply(ct_text, lambda L: hill_decrypt_letters(L, M))
		return cipher_name, pt_text
	elif cipher_name == "RAIL":
		rails = rail_params_from_seed(seed)
		ct_text = CT.decode("ascii", errors="ignore")
		pt_text = preserve_nonletters_apply(ct_text, lambda L: rail_decrypt_letters(L, rails))
		return cipher_name, pt_text
	elif cipher_name == "COLUMNAR":
		key_str = derive_col_key_letters(K_bytes, 8, b"col_key")
		ct_text = CT.decode("ascii", errors="ignore")
		pt_text = preserve_nonletters_apply(ct_text, lambda L: columnar_decrypt_letters(L, key_str))
		return cipher_name, pt_text
	elif cipher_name == "ROUTE":
		rows, cols, path = route_params_from_seed(seed)
		ct_text = CT.decode("ascii", errors="ignore")
		pt_text = preserve_nonletters_apply(ct_text, lambda L: route_decrypt_letters(L, rows, cols, path))
		return cipher_name, pt_text
	elif cipher_name == "ADFGVX":
		square = adfgvx_square_from_key(K_bytes)
		key_str = derive_col_key_letters(K_bytes, 8, b"adfgvx_col")
		frac = CT.decode("ascii")
		mid = columnar_decrypt_letters(frac, key_str)
		pt_alnum = adfgvx_defractionate(mid, square)
		return cipher_name, pt_alnum
	elif cipher_name == "VERNAM":
		data = xor_bytes(CT, vernam_keystream(seed, len(CT)))
		return cipher_name, data.decode("utf-8", errors="replace")
	elif cipher_name == "OTP":
		if require_external_otp and external_otp_key is None:
			raise ValueError("OTP mode requires external_otp_key of same length as ciphertext bytes")
		if external_otp_key is None or len(external_otp_key) != len(CT):
			raise ValueError("external_otp_key length must equal ciphertext byte length in OTP mode")
		data = xor_bytes(CT, external_otp_key)
		return cipher_name, data.decode("utf-8", errors="replace")
	else:
		raise ValueError("Unknown cipher")


# -------------------- Demo --------------------

def _demo():
	K = generate_key(18)
	msg = "Meet at the bridge at nine."
	print("Generated key:", K)
	# Use random IV (recommended)
	name, blob = encrypt(K, msg)
	print("Cipher:", name)
	print("BLOB (hex):", blob.hex())
	name2, pt = decrypt(K, blob)
	print("Decrypted:", pt)


if __name__ == "__main__":
	import sys

	def interactive():
		print("=== Key-Routed Authenticated Cipher Demo ===")
		msg = input("Enter message to encrypt: ")
		K = generate_key(18)
		print(f"Generated key (keep it secret): {K}")
		# Encrypt with random IV (recommended)
		cipher, blob = encrypt(K, msg)
		IV, TAG, CT = blob[:12], blob[-32:], blob[12:-32]
		print(f"Cipher chosen: {cipher}")
		print(f"IV (hex):  {IV.hex()}")
		print(f"CT (hex):  {CT.hex()}")
		print(f"TAG (hex): {TAG.hex()}")
		# "send" for decryption
		cipher2, pt = decrypt(K, blob)
		print("Decrypted:", pt)

	try:
		if sys.stdin.isatty():
			interactive()
		else:
			_demo()
	except KeyboardInterrupt:
		pass

