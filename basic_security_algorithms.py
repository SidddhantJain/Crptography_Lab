import random

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
        print("1. Caesar Cipher (ASCII-level)")
        print("2. Monoalphabetic Cipher")
        print("3. PolyAlphabetical Cipher")
        

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


            case '0':
                print("Exiting...")
                break

            case _:
                print("Invalid algorithm selection. Try again.")

if __name__ == "__main__":
    main()
