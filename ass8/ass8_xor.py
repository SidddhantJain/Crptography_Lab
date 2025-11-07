import os
import random


def xor_file(in_path: str, out_path: str, key_byte: int, chunk: int = 65536) -> None:
    if not os.path.isfile(in_path):
        raise FileNotFoundError(f"Input not found: {in_path}")
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(in_path, 'rb') as fi, open(out_path, 'wb') as fo:
        while True:
            data = fi.read(chunk)
            if not data:
                break
            fo.write(bytes(b ^ key_byte for b in data))


def make_permutation(n: int, seed: int):
    perm = list(range(n))
    rnd = random.Random(seed)
    for i in range(n - 1, 0, -1):
        j = rnd.randint(0, i)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def inverse_permutation(perm):
    n = len(perm)
    inv = [0] * n
    for i in range(n):
        inv[perm[i]] = i
    return inv


def permute_image(in_path: str, out_path: str, seed: int, mode: str) -> None:
    # Lazy imports so XOR mode doesn't require these packages
    import numpy as np
    from PIL import Image
    if not os.path.isfile(in_path):
        raise FileNotFoundError(f"Input not found: {in_path}")
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    img = Image.open(in_path).convert("RGBA")
    w, h = img.size
    n = w * h
    pixels = np.array(img).reshape(-1, 4)
    perm = make_permutation(n, seed)
    out = np.zeros_like(pixels)

    if mode == 'E':
        for i in range(n):
            out[perm[i]] = pixels[i]
    else:  # D
        inv = inverse_permutation(perm)
        for j in range(n):
            out[inv[j]] = pixels[j]

    Image.fromarray(out.reshape(h, w, 4), "RGBA").save(out_path)


def _abs_path(p: str) -> str:
    return p if os.path.isabs(p) else os.path.abspath(p)


def main():
    try:
        print("\n=== Image Transformer (XOR bytes or Permute pixels) ===")
        mode_type = input("Choose mode: XOR bytes (X) or Permute pixels (P): ").strip().upper()[:1]

        if mode_type == 'X':
            in_path = _abs_path(input("Enter image filename to encrypt/decrypt: ").strip())
            out_path = _abs_path(input("Enter output filename: ").strip())
            key_str = input("Enter single character key: ").strip()
            if not key_str:
                print("Key cannot be empty.")
                return
            key_byte = ord(key_str[0])
            xor_file(in_path, out_path, key_byte)
            print(f"Done. Wrote: {out_path}")

        elif mode_type == 'P':
            in_path = _abs_path(input("Enter image path: ").strip())
            out_path = _abs_path(input("Enter output filename: ").strip())
            k_str = input("Enter key (number or single char): ").strip()
            if k_str.isdigit():
                seed = int(k_str)
            else:
                seed = ord(k_str[0]) if k_str else 0
            ed = input("Encrypt (E) or Decrypt (D)? ").strip().upper()[:1]
            if ed not in ('E','D'):
                print("Invalid choice: use E or D.")
                return
            permute_image(in_path, out_path, seed, ed)
            print(f"Done. Wrote: {out_path}")

        else:
            print("Invalid mode. Choose X or P.")

    except Exception as ex:
        print(f"Error: {ex}")


if __name__ == "__main__":
    main()
