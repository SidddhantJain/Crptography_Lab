# Key‑Routed Authenticated Framework (ass3.py)

This document explains the full logic, data flow, parameters, and wire format of the 18‑character master‑key framework implemented in `ass3.py`. It includes compact parameter tables and flow diagrams for key selection, encryption, and decryption.

> Educational note: The classical ciphers herein are not cryptographically strong. The scheme authenticates ciphertexts and hides which cipher is used, but it is not a substitute for modern AEAD (AES‑GCM/ChaCha20‑Poly1305).

---

## Goals and design

- Single 18‑character printable master key K.
- Optionally preserve legacy mode: reverse key on decrypt (`legacy_reverse=True`).
- Hide cipher identity: select cipher via HMAC over the entire key (no substring leaks).
- Deterministically derive all cipher parameters from HMAC seed values.
- Provide authenticity/integrity via HMAC tag over IV || ciphertext.
- Simple wire format: `IV(12) || CT || TAG(32)`.

---

## Key handling and derivations

- Input key K (string). If not exactly 18 chars, it is deterministically padded/trimmed to 18.
- Legacy mode: on decryption (and optionally encryption) you may set `legacy_reverse=True` which uses `K' = reverse(K)` as key bytes for derivations.
- Key bytes: `K_bytes = (K or reverse(K)).encode('utf-8')`.

Core HMACs (KDF steps):
- `D1 = HMAC_SHA256(K_bytes, b"cipher_select")`
- `D2 = HMAC_SHA256(K_bytes, b"param_seed")`
- `D3 = HMAC_SHA256(K_bytes, b"iv_seed")`

Interpret:
- `cipher_index = int.from_bytes(D1[:4], 'big') % N`  (where N = number of ciphers)
- `seed = int.from_bytes(D2[:8], 'big')`              (64‑bit param seed)
- `iv_seed = int.from_bytes(D3[:8], 'big')`           (64‑bit IV seed for deterministic IV tests)

Cipher list (fixed order):
1. HILL
2. AFFINE
3. RAIL (Rail Fence)
4. COLUMNAR (Columnar transposition)
5. ROUTE (Route transposition)
6. ADFGVX (6×6 + columnar)
7. VERNAM (PRNG keystream XOR)
8. OTP (external one‑time pad)

---

## Compact parameter table

| Cipher    | Parameters derived                              | Exact formulas (from `seed`)                                                                 | Notes |
|-----------|--------------------------------------------------|----------------------------------------------------------------------------------------------|------|
| HILL 2×2  | Matrix `M = [[m00,m01],[m10,m11]]` mod 26       | `m00=(seed>>48)%26, m01=(seed>>36)%26, m10=(seed>>24)%26, m11=(seed>>12)%26`; if `det(M)` not invertible mod 26, increment `m11=(m11+1)%26` up to 26 until invertible | Letters A..Z, pad X inside math; wrapper preserves non‑letters in place |
| AFFINE    | `a∈Z26*`, `b∈Z26`                               | `a=(seed>>6)%26; b=seed%26`; if `gcd(a,26)!=1`, choose next coprime deterministically from `{1,3,5,7,9,11,15,17,19,21,23,25}` | Letters A..Z, wrapper preserves non‑letters |
| RAIL      | `rails`                                         | `rails=(seed%11)+2` → [2..12]                                                                | Letters A..Z, wrapper preserves non‑letters |
| COLUMNAR  | Column key (L=8)                                | `key_letters = HMAC(K, "col_key")[:8] → each byte %26 → A..Z`; stable sort by (letter,index) for ordering | Length‑preserving (no padding); wrapper preserves non‑letters |
| ROUTE     | Rows, Cols, Path                                 | `rows=((seed>>8)%6)+2`, `cols=((seed>>12)%6)+2` → [2..7]; `path=seed%4` in {row‑wise, column‑wise, spiral, diagonal} | Length‑preserving (no padding); wrapper preserves non‑letters |
| ADFGVX    | 6×6 square; column key (L=8)                    | Square: stable sort of 36 symbols using bytes from `HMAC(K,"adfgvx_map")`; column key: same as COLUMNAR via `HMAC(K,"adfgvx_col")` | Operates on A–Z0–9 only; non‑alphanumerics not preserved in place |
| VERNAM    | Keystream seed                                   | PRNG seeded with `seed & 0xFFFFFFFF`; XOR UTF‑8 bytes                                         | NOT crypto‑secure; deterministic |
| OTP       | External pad                                     | Must be provided, not derived from K                                                          | Requires OTP key same length as plaintext bytes |

Text handling policy:
- HILL/AFFINE/RAIL/COLUMNAR/ROUTE: transform A..Z letters only; non‑letters preserved in place. These transpositions are length‑preserving.
- ADFGVX: operates on A–Z0–9; other chars are dropped from the transformed stream (not preserved in place).
- VERNAM/OTP: operate on raw bytes of the UTF‑8 plaintext.

---

## Wire format and integrity

- IV: 12 bytes. Random by default; deterministic option available for testing: `IV = HMAC(K_bytes, b"iv_seed")[:12]`.
- Tag: `TAG = HMAC_SHA256(K_bytes, IV || CT)` (32 bytes).
- Wire format (blob): `BLOB = IV || CT || TAG`.
- Always verify tag before decryption. On mismatch → reject (tampering or wrong key).

---

## Diagrams

### Key and cipher selection

```mermaid
flowchart LR
  K[Master Key (18 chars)] -->|optional reverse on decrypt| Kb[Key bytes]
  Kb --> D1[HMAC(Kb, "cipher_select")]
  Kb --> D2[HMAC(Kb, "param_seed")]
  Kb --> D3[HMAC(Kb, "iv_seed")]
  D1 -->|int(D1[:4]) % N| IDX[cipher_index]
  IDX --> C{CIPHER_LIST[idx]}
  D2 --> SEED[64-bit seed]
  D3 --> IVSEED[64-bit iv_seed]
```

### Encryption flow

```mermaid
flowchart TD
  A[Plaintext P] --> B{legacy_reverse?}
  B -->|No| Kb1[Key bytes = K.encode()]
  B -->|Yes| Kb2[Key bytes = reverse(K).encode()]
  Kb1 --> D1E[HMAC(Kb, "cipher_select")]
  Kb1 --> D2E[HMAC(Kb, "param_seed")]
  Kb1 --> D3E[HMAC(Kb, "iv_seed")]
  D1E --> IDXE[Cipher index]
  D2E --> SEEDE[Param seed]
  D3E --> IVSEED[IV seed]
  IDXE --> CIPH{Select cipher}
  SEEDE --> PARAMS[Derive cipher params]
  CIPH --> ENC[Encrypt with params]
  IVSEED --> IVMODE{IV mode}
  IVMODE -->|Random| IVR[os.urandom(12)]
  IVMODE -->|Deterministic (testing)| IVD[HMAC(Kb, "iv_seed")[:12]]
  ENC --> CT[Ciphertext bytes]
  IVR --> TAGcalc
  IVD --> TAGcalc
  TAGcalc[Compute TAG = HMAC(Kb, IV||CT)] --> BLOB[BLOB = IV || CT || TAG]
  CT --> TAGcalc
  BLOB --> OUT[Transmit]
```

### Decryption flow

```mermaid
flowchart TD
  IN[BLOB = IV || CT || TAG] --> SPLIT[Split IV, CT, TAG]
  SPLIT --> B{legacy_reverse?}
  B -->|No| Kb1[Key bytes = K.encode()]
  B -->|Yes| Kb2[Key bytes = reverse(K).encode()]
  Kb1 --> TAGv[Recompute TAG' = HMAC(Kb, IV||CT)]
  Kb2 --> TAGv
  TAGv --> CHK{TAG' == TAG?}
  CHK -->|No| REJ[Reject: tampered/wrong key]
  CHK -->|Yes| D1D[HMAC(Kb, "cipher_select")]
  Kb1 --> D2D[HMAC(Kb, "param_seed")]
  Kb2 --> D2D
  D1D --> IDXD[cipher_index]
  D2D --> SEEDD[Param seed]
  IDXD --> CIPH{Select cipher}
  SEEDD --> PARAMSd[Derive params]
  CIPH --> DEC[Decrypt]
  DEC --> PT[Plaintext]
```

---

## API overview

`encrypt(K: str, plaintext: str, *, legacy_reverse=False, deterministic_iv=False, require_external_otp=True, external_otp_key: bytes|None=None) -> (cipher_name: str, blob: bytes)`

`decrypt(K: str, blob: bytes, *, legacy_reverse=False, require_external_otp=True, external_otp_key: bytes|None=None) -> (cipher_name: str, plaintext: str)`

- Returns the selected cipher name and either the wire blob (encrypt) or plaintext (decrypt).
- In OTP mode you must supply `external_otp_key` equal in length to plaintext bytes.

---

## CLI usage (interactive demo)

```powershell
python .\ass3.py
```
- Prompts for message.
- Always generates a fresh random 18‑char key (A–Z0–9).
- Prints: cipher chosen, IV (hex), CT (hex), TAG (hex).
- Immediately verifies and decrypts to show round‑trip.

---

## Examples

```python
from ass3 import encrypt, decrypt, generate_key

K = generate_key(18)
msg = "Meet at the bridge at nine."

# Encrypt (random IV)
cipher, blob = encrypt(K, msg)
print(cipher, blob.hex())

# Decrypt
cipher2, plain = decrypt(K, blob)
assert plain == msg

# Legacy reverse-on-decrypt
cipher3, blob2 = encrypt(K, msg, legacy_reverse=True)
cipher4, plain2 = decrypt(K, blob2, legacy_reverse=True)
assert plain2 == msg

# OTP mode
data = "secret".encode("utf-8")
otp_key = os.urandom(len(data))  # must be truly random and used once
_, blob3 = encrypt(K, "secret", require_external_otp=True, external_otp_key=otp_key)
_, back = decrypt(K, blob3, require_external_otp=True, external_otp_key=otp_key)
assert back == "secret"
```

---

## Error handling

- Tag verification failure: raises `ValueError("Tag verification failed ...")`.
- Hill matrix non‑invertible: deterministically repair `m11` up to 26 steps; else error.
- Affine `a` not coprime to 26: deterministically pick next coprime.
- OTP missing/length mismatch: raises clear error.

---

## Security considerations

- Cipher identity hidden by HMAC selection; partial key knowledge gives no leakage.
- Authenticity/integrity via HMAC over IV||CT; reject on mismatch.
- Classical ciphers remain educational; do not rely on them for strong confidentiality.
- Vernam PRNG keystream is deterministic and not cryptographically secure.
- OTP is only secure with truly random pads used exactly once; pads are not derived from K.

---

## File map

- `ass3.py` — full implementation (ciphers, routing, HMAC derivations, IV||CT||TAG).
- `ASS3_README.md` — this document.
