def caesar_cipher(text, shift, mode):
    result = ""
    for char in text:
        ascii_val = ord(char)
        if mode == 'e':
            shifted = (ascii_val + shift) % 256
        elif mode == 'd':
            shifted = (ascii_val - shift + 256) % 256
        else:
            print("Invalid Caesar mode! Use 'e' for encrypt or 'd' for decrypt.")
            return ""
        result += chr(shifted)
    return result

def display_ascii_values(text):
    return ' '.join(str(ord(c)) for c in text)

def main():
    while True:
        print("\n=== Encryption Utility ===")
        print("Select Algorithm:")
        print("0.exit")
        print("1. Caesar Cipher (ASCII-level)")
        # Future options:
        # print("2. Vigenère Cipher")
        # print("3. XOR Cipher")
        algorithm_choice = input("Enter choice: ")

        if algorithm_choice == '1':
            print("\n--- Caesar Cipher ---")
            text = input("Enter text: ")
            shift = int(input("Enter shift value: "))
            mode = input("Enter mode ('e' for encrypt, 'd' for decrypt): ")

            result = caesar_cipher(text, shift, mode)
            print("Result (ASCII values):", display_ascii_values(result))
            print("Shifted Text (as characters):", result)

            key = input("To exit enter '1', to decrypt the result enter '2', or to continue enter '0': ")
            if key == '1':
                break
            elif key == '2':
                decrypted = caesar_cipher(result, shift, 'd')
                print("Decrypted ASCII Values:", display_ascii_values(decrypted))
                print("Decrypted Text:", decrypted)
        elif algorithm_choice == '0':
            break
        else:
            print("Invalid algorithm selection. Try again.")

if __name__ == "__main__":
    main()
