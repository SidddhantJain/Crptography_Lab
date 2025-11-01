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
    
    # Create fence pattern to determine positions
    fence = [[None for _ in range(len(cipher))] for _ in range(rails)]
    
    # Mark positions where characters should go
    rail = 0
    direction = 1
    for i in range(len(cipher)):
        fence[rail][i] = True  # Mark this position
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    
    # Fill fence with cipher characters row by row
    cipher_index = 0
    for r in range(rails):
        for c in range(len(cipher)):
            if fence[r][c] is True:
                fence[r][c] = cipher[cipher_index]
                cipher_index += 1
    
    # Read fence in zigzag pattern to get original text
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
        if char.upper() in mapping:
            mapped_char = mapping[char.upper()]
            # Preserve original case
            if char.islower():
                result += mapped_char.lower()
            else:
                result += mapped_char
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

def process_text_playfair(text, for_decrypt=False):
    # Store original case information
    original_case = [(i, char.islower()) for i, char in enumerate(text) if char.isalpha()]
    
    # Prepare text: uppercase, replace J with I, remove non-alpha, create pairs
    processed_text = text.upper().replace('J', 'I')
    processed_text = ''.join(filter(str.isalpha, processed_text))
    
    if for_decrypt:
        # For decryption, just split into pairs without adding X
        pairs = []
        for i in range(0, len(processed_text), 2):
            if i + 1 < len(processed_text):
                pairs.append((processed_text[i], processed_text[i+1]))
            else:
                pairs.append((processed_text[i], 'X'))
        return pairs, original_case
    
    # For encryption, add X between duplicate letters and at end if needed
    i = 0
    pairs = []
    while i < len(processed_text):
        a = processed_text[i]
        b = ''
        if i + 1 < len(processed_text):
            b = processed_text[i+1]
            if a == b:
                b = 'X'
                i += 1
            else:
                i += 2
        else:
            b = 'X'
            i += 1
        pairs.append((a, b))
    return pairs, original_case

def playfair_cipher(text, key, mode):
    # Store original spacing for decryption
    original_spaces = []
    if mode == 'd':
        # For decryption, we don't have original spacing info, so just process as-is
        matrix = prepare_playfair_key(key)
        pairs, case_info = process_text_playfair(text, for_decrypt=True)
    else:
        # For encryption, store space positions
        for i, char in enumerate(text):
            if char == ' ':
                # Count only alphabetic characters before this space
                alpha_count = sum(1 for c in text[:i] if c.isalpha())
                original_spaces.append(alpha_count)
        
        matrix = prepare_playfair_key(key)
        pairs, case_info = process_text_playfair(text, for_decrypt=False)
    
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
    
    # Clean up result for decryption
    if mode == 'd':
        # Remove trailing X
        if result.endswith('X'):
            result = result[:-1]
        # Remove X padding between identical characters
        cleaned_result = ""
        i = 0
        while i < len(result):
            if (i > 0 and i < len(result) - 1 and 
                result[i] == 'X' and 
                result[i-1] == result[i+1]):
                i += 1
                continue
            cleaned_result += result[i]
            i += 1
        result = cleaned_result
        
        # Restore original case for decryption
        if mode == 'd' and case_info:
            final_result = ""
            result_idx = 0
            for orig_idx, was_lower in case_info:
                if result_idx < len(result):
                    if was_lower:
                        final_result += result[result_idx].lower()
                    else:
                        final_result += result[result_idx]
                    result_idx += 1
            # Add any remaining characters
            final_result += result[result_idx:]
            result = final_result
    
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

def PollyAlphabetic_cipher(text, key, mode):
    key = key.upper()
    result = ""
    key_length = len(key)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def shift_char(c, k, mode):
        if c.upper() not in alphabet:
            return c
        text_idx = alphabet.index(c.upper())
        key_idx = alphabet.index(k)
        if mode == 'e':
            shifted_idx = (text_idx + key_idx) % 26
        elif mode == 'd':
            shifted_idx = (text_idx - key_idx) % 26
        else:
            return c
        shifted_char = alphabet[shifted_idx]
        # Preserve original case
        if c.islower():
            return shifted_char.lower()
        else:
            return shifted_char

    key_index = 0
    for char in text:
        if char.upper() in alphabet:
            result += shift_char(char, key[key_index % key_length], mode)
            key_index += 1
        else:
            result += char

    return result

# Vernam Cipher Implementation
def vernam_cipher(text, key):
    # Vernam cipher requires key to be same length as text
    if len(text) != len(key):
        raise ValueError("Key must be the same length as text for Vernam cipher.")
    result = ""
    for t, k in zip(text, key):
        # XOR each character's ASCII value
        result += chr(ord(t) ^ ord(k))
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
        print("5. Rail Fence")
        print("6. Vernam Cipher (XOR/OTP)")
       

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
                        print("Decrypted Text:", decrypted)
           
            case '3':
                print("\n--- PolyAlphabetical Cipher ---")
                text = input("Enter text: ")
                key = input("Enter key (letters only): ").upper()
                if not key.isalpha():
                    print("Key must contain letters only!")
                    continue
                mode = input("Enter mode ('e' for encrypt, 'd' for decrypt): ").lower()

                result = PollyAlphabetic_cipher(text, key, mode)
                if result:
                    print("Result:", result)

                    key2 = input("To exit enter '1', to decrypt the result enter '2', or to continue enter '0': ")
                    if key2 == '1':
                        break
                    elif key2 == '2':
                        decrypted = PollyAlphabetic_cipher(result, key, 'd')
                        print("Decrypted Text:", decrypted)
            case '4':
                print("\n--- Playfair Cipher ---")
                text = input("Enter text: ")
                key = input("Enter key (alphabetic only): ")
                mode = input("Enter mode ('e' for encrypt, 'd' for decrypt): ").lower()

                if not key.isalpha():
                    print("Key must be alphabetic only!")
                    continue

                if mode not in ['e', 'd']:
                    print("Invalid mode! Please enter 'e' or 'd'.")
                    continue

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
                    mode = 'd' if mode == 'e' else 'e'
                    if mode == 'e':
                        switched_result = rail_fence_encrypt(result, rails)
                    else:
                        switched_result = rail_fence_decrypt(result, rails)
                    print(f"Switched mode ({mode}):", switched_result)
                
            case '6':
                print("\n--- Vernam Cipher (XOR/One-Time Pad) ---")
                v_text = input("Enter text (length N): ")
                v_key = input("Enter key (length N): ")
                if len(v_text) != len(v_key):
                    print("Key must be the same length as text!")
                else:
                    v_encrypted = vernam_cipher(v_text, v_key)
                    v_encrypted_hex = ' '.join(f"{ord(ch):02X}" for ch in v_encrypted)
                    print(f"Encrypted (hex): {v_encrypted_hex}")
                    v_decrypted = vernam_cipher(v_encrypted, v_key)
                    print(f"Decrypted: {v_decrypted}")
            case '0':
                print("Exiting...")
                break

            case _:
                print("Invalid algorithm selection. Try again.")

if __name__ == "__main__":
    main()

