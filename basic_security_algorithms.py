import random
def rail_fence_encrypt(text, rails):
    if rails == 1:
        return text
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1  # 1: down, -1: up
    for char in text:
        fence[rail].append(char)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    result = ''.join(''.join(row) for row in fence)
    return result

def rail_fence_decrypt(cipher, rails):
    if rails == 1:
        return cipher
    # Create an empty fence
    fence = [['\n' for _ in range(len(cipher))] for _ in range(rails)]

    # Mark the places with '*'
    rail = 0
    direction = 1
    for i in range(len(cipher)):
        fence[rail][i] = '*'
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1

    # Fill the fence with cipher letters
    index = 0
    for r in range(rails):
        for c in range(len(cipher)):
            if fence[r][c] == '*' and index < len(cipher):
                fence[r][c] = cipher[index]
                index += 1

    # Read the fence to reconstruct the text
    result = []
    rail = 0
    direction = 1
    for i in range(len(cipher)):
        result.append(fence[rail][i])
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    return ''.join(result)


def generate_key():
    alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    shuffled = alphabet[:]
    random.shuffle(shuffled)
    return ''.join(shuffled)

def monoalphabetic_cipher(text, key, mode):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    text = text.upper()
    key = key.upper()

    if len(key) != 26 or set(key) != set(alphabet):
        print("Invalid key!")
        return ""

    if mode == 'e':
        mapping = {alphabet[i]: key[i] for i in range(26)}
    else:
        mapping = {key[i]: alphabet[i] for i in range(26)}

    result = ""
    for char in text:
        if char in mapping:
            result += mapping[char]
        else:
            result += char
    return result

def sorted_freq_letters(freq_dict):
    return sorted(freq_dict, key=freq_dict.get, reverse=True)

def prepare_playfair_key(key):
    key = key.upper().replace('J', 'I')  # Replace J with I as per Playfair rules
    seen = set()
    result = ""
    for char in key:
        if char.isalpha() and char not in seen:
            seen.add(char)
            result += char
    # Fill rest of alphabet (except J)
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":  
        if char not in seen:
            result += char
    # Create 5x5 matrix
    matrix = [list(result[i:i+5]) for i in range(0, 25, 5)]
    return matrix

def find_position(matrix, char):
    for i, row in enumerate(matrix):
        for j, c in enumerate(row):
            if c == char:
                return i, j
    return None

def process_text_playfair(text):
    # Prepare text: uppercase, replace J with I, remove non-alpha, create pairs
    text = text.upper().replace('J', 'I')
    text = ''.join(filter(str.isalpha, text))
    i = 0
    pairs = []
    while i < len(text):
        a = text[i]
        b = ''
        if i + 1 < len(text):
            b = text[i+1]
            if a == b:
                b = 'X'
                i += 1
            else:
                i += 2
        else:
            b = 'X'
            i += 1
        pairs.append((a, b))
    return pairs

def playfair_cipher(text, key, mode):
    matrix = prepare_playfair_key(key)
    pairs = process_text_playfair(text)
    result = ""
    for a, b in pairs:
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)
        if mode == 'e':  # encrypt
            if r1 == r2:
                # Same row
                result += matrix[r1][(c1 + 1) % 5]
                result += matrix[r2][(c2 + 1) % 5]
            elif c1 == c2:
                # Same column
                result += matrix[(r1 + 1) % 5][c1]
                result += matrix[(r2 + 1) % 5][c2]
            else:
                # Rectangle
                result += matrix[r1][c2]
                result += matrix[r2][c1]
        elif mode == 'd':  # decrypt
            if r1 == r2:
                # Same row
                result += matrix[r1][(c1 - 1) % 5]
                result += matrix[r2][(c2 - 1) % 5]
            elif c1 == c2:
                # Same column
                result += matrix[(r1 - 1) % 5][c1]
                result += matrix[(r2 - 1) % 5][c2]
            else:
                # Rectangle
                result += matrix[r1][c2]
                result += matrix[r2][c1]
        else:
            print("Invalid mode! Use 'e' or 'd'.")
            return ""
    return result


def caesar_cipher(text, shift, mode):
    result = ""
    for char in text:
        ascii_val = ord(char)
        if mode == 'e':
            shifted = (ascii_val + shift) % 128
        elif mode == 'd':
            shifted = (ascii_val - shift + 128) % 128
        else:
            print("Invalid Caesar mode! Use 'e' for encrypt or 'd' for decrypt.")
            return ""
        result += chr(shifted)
    return result

def display_ascii_values(text):
    return ' '.join(str(ord(c)) for c in text)

def vigenere_cipher(text, key, mode):
    text = text.upper()
    key = key.upper()
    result = ""
    key_length = len(key)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def shift_char(c, k, mode):
        if c not in alphabet:
            return c
        text_idx = alphabet.index(c)
        key_idx = alphabet.index(k)
        if mode == 'e':
            shifted_idx = (text_idx + key_idx) % 26
        elif mode == 'd':
            shifted_idx = (text_idx - key_idx) % 26
        else:
            return c
        return alphabet[shifted_idx]

    key_index = 0
    for char in text:
        if char in alphabet:
            result += shift_char(char, key[key_index % key_length], mode)
            key_index += 1
        else:
            result += char

    return result

def main():
    while True:
        print("\n=== Encryption Utility ===")  
        print("Select Algorithm:")
        print("0. Exit")
        print("Substitution Method ")
        print("1. Caesar Cipher (ASCII-level)")
        print("2. Monoalphabetic Cipher")
        print("3. PolyAlphabetical Cipher")
        print("4. Play Fair")
        print("Transposition Method")
        print("5. Rail Fense   ")
       

        algorithm_choice = input("Enter choice: ").strip()

        match algorithm_choice:
            case '1':
                print("\n--- Caesar Cipher ---")
                text = input("Enter text: ")
                try:
                    shift = int(input("Enter shift value (integer): "))
                except ValueError:
                    print("Shift must be an integer!")
                    continue
                mode = input("Enter mode ('e' for encrypt, 'd' for decrypt): ").lower()

                result = caesar_cipher(text, shift, mode)
                if result:
                    print("Result (ASCII values):", display_ascii_values(result))
                    print("Shifted Text (as characters):", result)

                    key = input("To exit enter '1', to decrypt the result enter '2', or to continue enter '0': ")
                    if key == '1':
                        break
                    elif key == '2':
                        decrypted = caesar_cipher(result, shift, 'd')
                        print("Decrypted ASCII Values:", display_ascii_values(decrypted))
                        print("Decrypted Text:", decrypted)

            case '2':
                print("\n--- Monoalphabetic Cipher ---")
                text = input("Enter text: ")
               
                key = input("Enter 26-letter substitution key (A-Z exactly once) or leave empty to auto-generate: ").upper()
               
                # If no key entered, generate a random one
                if not key:
                    alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                    random.shuffle(alphabet)
                    key = ''.join(alphabet)
                    print(f"Generated key: {key}")
               
                mode = input("Enter mode ('e' for encrypt, 'd' for decrypt): ").lower()

                result = monoalphabetic_cipher(text, key, mode)
                if result:
                    print("Result:", result)

                    key2 = input("To exit enter '1', to decrypt the result enter '2', or to continue enter '0': ")
                    if key2 == '1':
                        break
                    elif key2 == '2':
                        opposite_mode = 'd' if mode == 'e' else 'e'
                        decrypted = monoalphabetic_cipher(result, key, opposite_mode)
                        print("Decrypted Text:", decrypted)        \
           
            case '3':
                print("\n--- PolyAlphabetical Cipher ---")
                text = input("Enter text: ")
                key = input("Enter key (letters only): ").upper()
                if not key.isalpha():
                    print("Key must contain letters only!")
                    continue
                mode = input("Enter mode ('e' for encrypt, 'd' for decrypt): ").lower()

                # result = vigenere_cipher(text, key, mode)
                if result:
                    print("Result:", result)

                    key2 = input("To exit enter '1', to decrypt the result enter '2', or to continue enter '0': ")
                    if key2 == '1':
                        break
                    elif key2 == '2':
                        # decrypted = vigenere_cipher(result, key, 'd')
                        print("Decrypted Text:", decrypted)
            case '4':
                    print("\n--- Playfair Cipher ---")
                    text = input("Enter text: ")
                    key = input("Enter key (alphabetic only): ")
                    mode = input("Enter mode ('e' for encrypt, 'd' for decrypt): ").lower()
               
                    if not key.isalpha():
                        print("Key must be alphabetic only!")
                        break  # or continue depending on your main loop
               
                    if mode not in ['e', 'd']:
                        print("Invalid mode! Please enter 'e' or 'd'.")
                        break
               
                    result = playfair_cipher(text, key, mode)
                    if result:
                        print("Result:", result)
               
                        key_input = input("To exit enter '1', to decrypt the result enter '2', or to continue enter '0': ")
                        if key_input == '1':
                            break
                        elif key_input == '2':
                            if mode == 'e':
                                decrypted = playfair_cipher(result, key, 'd')
                                print("Decrypted Text:", decrypted)
                            else:
                                print("Already decrypted!")

               
           
            case '5':
                    print("\n--- Rail Fence Cipher ---")
                    text = input("Enter text: ")
                    try:
                        rails = int(input("Enter number of rails (integer > 1): "))
                        if rails < 2:
                            print("Number of rails must be greater than 1!")
                            break
                    except ValueError:
                        print("Number of rails must be an integer!")
                        break
               
                    mode = input("Enter mode ('e' for encrypt, 'd' for decrypt): ").lower()
                    if mode not in ['e', 'd']:
                        print("Invalid mode! Please enter 'e' or 'd'.")
                        break
               
                    if mode == 'e':
                        result = rail_fence_encrypt(text, rails)
                    else:
                        result = rail_fence_decrypt(text, rails)
               
                    print("Result:", result)
               
                    key_input = input("To exit enter '1', to switch mode enter '2', or to continue enter '0': ")
                    if key_input == '1':
                        break
                    elif key_input == '2':
                        # Switch mode and run again immediately (optional)
                        mode = 'd' if mode == 'e' else 'e'
                        if mode == 'e':
                            result = rail_fence_encrypt(text, rails)
                        else:
                            result = rail_fence_decrypt(text, rails)
                        print(f"Switched mode ({mode}):", result)
                           
            case '0':
                print("Exiting...")
                break

            case _:
                print("Invalid algorithm selection. Try again.")

if __name__ == "__main__":
    main()