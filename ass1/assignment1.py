import random

# --- Compact classical ciphers (simple and basic) ---

def caesar(text, shift, mode='e'):
    k = shift if mode == 'e' else -shift
    return ''.join(chr((ord(c) + k) % 128) for c in text)

def mono(text, key, mode='e'):
    alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = key.upper()
    if len(key) != 26 or set(key) != set(alpha):
        print('Invalid key (need 26 unique A-Z).')
        return ''
    enc = dict(zip(alpha, key))
    dec = {v: k for k, v in enc.items()}
    m = enc if mode == 'e' else dec
    out = []
    for ch in text:
        u = ch.upper()
        out.append((m[u].lower() if ch.islower() else m[u]) if u in m else ch)
    return ''.join(out)

def vigenere(text, key, mode='e'):
    A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = ''.join([c for c in key.upper() if c.isalpha()])
    if not key:
        print('Key must be letters only.')
        return ''
    out, j = [], 0
    for ch in text:
        if ch.upper() in A:
            t = A.index(ch.upper())
            k = A.index(key[j % len(key)])
            s = (t + (k if mode == 'e' else -k)) % 26
            out.append(A[s].lower() if ch.islower() else A[s])
            j += 1
        else:
            out.append(ch)
    return ''.join(out)

def _pf_matrix(key):
    A = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    k = ''.join(dict.fromkeys((key.upper().replace('J','I') + A)))
    k = ''.join(c for c in k if c in A)[:25]
    pos = {k[i]: divmod(i, 5) for i in range(25)}
    return k, pos

def _pf_pairs(text, fill_x=True):
    s = ''.join(c for c in text.upper().replace('J','I') if c.isalpha())
    pairs = []
    i = 0
    while i < len(s):
        a = s[i]
        b = s[i+1] if i+1 < len(s) else 'X'
        if a == b and fill_x:
            pairs.append((a, 'X'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    return pairs

def playfair(text, key, mode='e'):
    k, pos = _pf_matrix(key)
    pairs = _pf_pairs(text, fill_x=(mode=='e'))
    out = []
    for a,b in pairs:
        r1,c1 = pos[a]; r2,c2 = pos[b]
        if r1 == r2:
            c1 = (c1 + (1 if mode=='e' else -1)) % 5
            c2 = (c2 + (1 if mode=='e' else -1)) % 5
        elif c1 == c2:
            r1 = (r1 + (1 if mode=='e' else -1)) % 5
            r2 = (r2 + (1 if mode=='e' else -1)) % 5
        else:
            c1, c2 = c2, c1
        out += [k[r1*5+c1], k[r2*5+c2]]
    return ''.join(out)

def rail_encrypt(text, rails):
    if rails <= 1: return text
    rows = [''] * rails; i = 0; d = 1
    for ch in text:
        rows[i] += ch; i += d
        if i == 0 or i == rails-1: d *= -1
    return ''.join(rows)

def rail_decrypt(cipher, rails):
    if rails <= 1: return cipher
    idx, i, d = [], 0, 1
    for _ in cipher:
        idx.append(i); i += d
        if i == 0 or i == rails-1: d *= -1
    counts = [idx.count(r) for r in range(rails)]
    parts, p = [], 0
    for c in counts:
        parts.append(list(cipher[p:p+c])); p += c
    res, ptr = [], [0]*rails
    for r in idx:
        res.append(parts[r][ptr[r]]); ptr[r] += 1
    return ''.join(res)

def vernam(text, key):
    if len(text) != len(key):
        print('Key length must equal text length.')
        return ''
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(text, key))


def main():
    while True:
        print('\n=== Simple Crypto Menu ===')
        print('1. Caesar')
        print('2. Monoalphabetic')
        print('3. Vigenere')
        print('4. Playfair')
        print('5. Rail Fence')
        print('6. Vernam (XOR)')
        print('0. Exit')
        ch = input('Choice: ').strip()

        if ch == '1':
            s = input('Text: ')
            try:
                k = int(input('Shift: '))
            except ValueError:
                print('Shift must be integer.'); continue
            m = input("Mode (e/d): ").lower()
            print('Result:', caesar(s, k, m))

        elif ch == '2':
            s = input('Text: ')
            key = input('26-letter key (blank=auto): ').upper()
            if not key:
                alpha = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ'); random.shuffle(alpha)
                key = ''.join(alpha); print('Key:', key)
            m = input('Mode (e/d): ').lower()
            print('Result:', mono(s, key, m))

        elif ch == '3':
            s = input('Text: ')
            key = input('Key (letters only): ')
            m = input('Mode (e/d): ').lower()
            print('Result:', vigenere(s, key, m))

        elif ch == '4':
            s = input('Text (letters only processed): ')
            key = input('Key: ')
            m = input('Mode (e/d): ').lower()
            print('Result:', playfair(s, key, m))

        elif ch == '5':
            s = input('Text: ')
            try:
                r = int(input('Rails (>1): '))
            except ValueError:
                print('Rails must be integer.'); continue
            m = input('Mode (e/d): ').lower()
            print('Result:', rail_encrypt(s, r) if m=='e' else rail_decrypt(s, r))

        elif ch == '6':
            s = input('Text: ')
            k = input('Key (same length): ')
            enc = vernam(s, k)
            if enc:
                print('Encrypted (hex):', ' '.join(f'{ord(c):02X}' for c in enc))
                print('Decrypted:', vernam(enc, k))

        elif ch == '0':
            print('Bye!'); break
        else:
            print('Invalid choice.')


if __name__ == '__main__':
    main()

