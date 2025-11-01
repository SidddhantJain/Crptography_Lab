"""
RSA Performance Experiment

Aim: Estimate the time to i) Generate RSA key pair, ii) Encrypt an n-bit message,
iii) Decrypt an n-bit message, as a function of key size. We also vary message
sizes (n) within the OAEP input limit for each key size.

Outputs:
- Prints a concise on-screen summary
- Writes detailed CSV to rsa_bench_results.csv in this folder

Usage (PowerShell):
  # quick smoke test
  .venv\Scripts\python.exe ass2.py --keys 1024 2048 --keygen-trials 2 --ed-trials 10

  # fuller run (will take longer)
  .venv\Scripts\python.exe ass2.py --keys 1024 2048 3072 4096 --keygen-trials 5 --ed-trials 30

Notes:
- Encryption uses RSA-OAEP with SHA-256 (common modern setting).
- OAEP imposes a maximum message size of: k - 2*hLen - 2 bytes, where k is key size in bytes,
  and hLen=32 for SHA-256. We choose n-bit messages that fit this bound per key size.
"""

from __future__ import annotations

import argparse
import csv
import math
import statistics as stats
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import secrets


HASH_ALG = hashes.SHA256()
HASH_LEN = 32  # bytes for SHA-256


@dataclass
class OpStats:
	times_ms: List[float]

	@property
	def mean(self) -> float:
		return float(stats.mean(self.times_ms)) if self.times_ms else float("nan")

	@property
	def stdev(self) -> float:
		if len(self.times_ms) >= 2:
			return float(stats.stdev(self.times_ms))
		return 0.0


def max_oaep_message_bytes(key_bits: int, hash_len: int = HASH_LEN) -> int:
	k = key_bits // 8
	return max(0, k - 2 * hash_len - 2)


def choose_message_sizes_bytes(key_bits: int) -> List[int]:
	"""Choose a representative set of plaintext sizes (in bytes) that fit OAEP for key_bits.

	Uses a mix of small and larger sizes up to the OAEP maximum for the key.
	"""
	max_bytes = max_oaep_message_bytes(key_bits)
	# Base candidates (bytes). We'll filter to <= max_bytes and dedupe, keep ascending order.
	candidates = [8, 16, 24, 32, 48, 60, 64, 96, 128, 160, 192, 256, 384, 512, 768, 1024, 1536]
	sizes = [b for b in candidates if b <= max_bytes]
	# Ensure we have at least one size; if max is very small, pick max_bytes when >0
	if not sizes and max_bytes > 0:
		sizes = [max_bytes]
	return sizes


def gen_key(key_bits: int) -> rsa.RSAPrivateKey:
	return rsa.generate_private_key(public_exponent=65537, key_size=key_bits)


def rsa_encrypt(pub, data: bytes) -> bytes:
	return pub.encrypt(
		data,
		padding.OAEP(mgf=padding.MGF1(algorithm=HASH_ALG), algorithm=HASH_ALG, label=None),
	)


def rsa_decrypt(priv, ciphertext: bytes) -> bytes:
	return priv.decrypt(
		ciphertext,
		padding.OAEP(mgf=padding.MGF1(algorithm=HASH_ALG), algorithm=HASH_ALG, label=None),
	)


def time_once(fn) -> float:
	t0 = time.perf_counter()
	fn()
	t1 = time.perf_counter()
	return (t1 - t0) * 1000.0


def run_experiment(key_bits_list: List[int], keygen_trials: int, ed_trials: int) -> Tuple[List[Dict], List[str]]:
	"""Run experiments and return (rows, headers) for CSV."""
	rows: List[Dict] = []
	headers = [
		"timestamp",
		"key_bits",
		"op",
		"message_bits",
		"trials",
		"mean_ms",
		"stdev_ms",
		"oaep_max_msg_bits",
	]

	for key_bits in key_bits_list:
		print(f"\n▶ Measuring key={key_bits}-bit ...")

		# Key generation timing
		kg_times = []
		for _ in range(keygen_trials):
			kg_times.append(time_once(lambda: gen_key(key_bits)))
		kg_stats = OpStats(kg_times)
		rows.append(
			{
				"timestamp": datetime.utcnow().isoformat(),
				"key_bits": key_bits,
				"op": "keygen",
				"message_bits": 0,
				"trials": keygen_trials,
				"mean_ms": round(kg_stats.mean, 3),
				"stdev_ms": round(kg_stats.stdev, 3),
				"oaep_max_msg_bits": max_oaep_message_bytes(key_bits) * 8,
			}
		)
		print(f"  keygen: mean={kg_stats.mean:.1f} ms (n={keygen_trials})")

		# Use a single key for encryption/decryption tests to isolate op costs
		priv = gen_key(key_bits)
		pub = priv.public_key()

		max_bits = max_oaep_message_bytes(key_bits) * 8
		msg_sizes_bytes = choose_message_sizes_bytes(key_bits)
		if not msg_sizes_bytes:
			print("  (OAEP max message is 0 bytes with these settings; skipping E/D)")
			continue

		for m_bytes in msg_sizes_bytes:
			m_bits = m_bytes * 8
			# Prepare a random message within the allowed size
			msg = secrets.token_bytes(m_bytes)

			# Time encryption
			enc_times = []
			for _ in range(ed_trials):
				enc_times.append(time_once(lambda: rsa_encrypt(pub, msg)))
			enc_stats = OpStats(enc_times)
			rows.append(
				{
					"timestamp": datetime.utcnow().isoformat(),
					"key_bits": key_bits,
					"op": "encrypt",
					"message_bits": m_bits,
					"trials": ed_trials,
					"mean_ms": round(enc_stats.mean, 3),
					"stdev_ms": round(enc_stats.stdev, 3),
					"oaep_max_msg_bits": max_bits,
				}
			)

			# Create one ciphertext and time decryption on that
			ct = rsa_encrypt(pub, msg)
			dec_times = []
			for _ in range(ed_trials):
				dec_times.append(time_once(lambda: rsa_decrypt(priv, ct)))
			dec_stats = OpStats(dec_times)
			rows.append(
				{
					"timestamp": datetime.utcnow().isoformat(),
					"key_bits": key_bits,
					"op": "decrypt",
					"message_bits": m_bits,
					"trials": ed_trials,
					"mean_ms": round(dec_stats.mean, 3),
					"stdev_ms": round(dec_stats.stdev, 3),
					"oaep_max_msg_bits": max_bits,
				}
			)

			print(
				f"  m={m_bits:>5} bits | enc {enc_stats.mean:6.2f} ms | dec {dec_stats.mean:7.2f} ms (n={ed_trials})"
			)

	return rows, headers


def write_csv(rows: List[Dict], headers: List[str], path: str) -> None:
	with open(path, "w", newline="", encoding="utf-8") as f:
		w = csv.DictWriter(f, fieldnames=headers)
		w.writeheader()
		for r in rows:
			w.writerow(r)


def summarize(rows: List[Dict]) -> str:
	"""Return a human-readable summary and conclusions."""
	# Aggregate by key and op for a compact text summary
	from collections import defaultdict

	key_summary = defaultdict(lambda: {"keygen": None, "encrypt": [], "decrypt": []})
	for r in rows:
		k = r["key_bits"]
		if r["op"] == "keygen":
			key_summary[k]["keygen"] = (r["mean_ms"], r["stdev_ms"])
		elif r["op"] in ("encrypt", "decrypt"):
			key_summary[k][r["op"]].append((r["message_bits"], r["mean_ms"]))

	lines = []
	lines.append("\n=== Summary (means) ===")
	for k in sorted(key_summary.keys()):
		kg = key_summary[k]["keygen"]
		enc = key_summary[k]["encrypt"]
		dec = key_summary[k]["decrypt"]
		lines.append(f"Key {k}-bit:")
		if kg:
			lines.append(f"  KeyGen: ~{kg[0]} ms")
		if enc:
			enc_mean = stats.mean(m for _, m in enc)
			lines.append(f"  Encrypt: ~{enc_mean:.2f} ms (weak dependence on message size)")
		if dec:
			dec_mean = stats.mean(m for _, m in dec)
			lines.append(f"  Decrypt: ~{dec_mean:.2f} ms (much slower than encrypt, grows with key size)")

	# General conclusions
	lines.append("\n=== Conclusions ===")
	lines.append("1) Key generation time increases sharply with key size (approximately super-linear).")
	lines.append("2) Encryption time is relatively small and mostly independent of message size (with e=65537).")
	lines.append("3) Decryption time is significantly larger than encryption and grows with key size (CRT exponentiation).")
	lines.append(
		"4) With OAEP (SHA-256), the maximum single-block plaintext size is limited; larger payloads require hybrid encryption."
	)

	return "\n".join(lines)


def parse_args() -> argparse.Namespace:
	p = argparse.ArgumentParser(description="RSA timing experiment (keygen/encrypt/decrypt)")
	p.add_argument(
		"--keys",
		nargs="+",
		type=int,
		default=[1024, 2048],
		help="RSA key sizes to test (bits)",
	)
	p.add_argument("--keygen-trials", type=int, default=3, help="Trials for key generation timing")
	p.add_argument("--ed-trials", type=int, default=20, help="Trials for encrypt/decrypt timing")
	p.add_argument(
		"--out",
		type=str,
		default="rsa_bench_results.csv",
		help="CSV output path",
	)
	return p.parse_args()


def main():
	args = parse_args()
	rows, headers = run_experiment(args.keys, args.keygen_trials, args.ed_trials)
	write_csv(rows, headers, args.out)
	print(f"\n📄 Wrote results to {args.out}")
	print(summarize(rows))


if __name__ == "__main__":
	main()

