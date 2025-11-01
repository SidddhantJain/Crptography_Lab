#include <iostream>
#include <string>

using namespace std;

void caesar_cipher(string& text, int shift, char mode) {
    for (char& c : text) {
        unsigned char original = static_cast<unsigned char>(c);

        if (mode == 'e') {
            c = static_cast<char>((original + shift) % 256); // encrypt
        }
        else if (mode == 'd') {
            c = static_cast<char>((original - shift + 256) % 256); // decrypt
        }
        else {
            cerr << "Invalid Caesar mode! Use 'e' for encrypt or 'd' for decrypt.\n";
            return;
        }
    }
}

int main() {
    string text;
    int shift;
    char mode;
    int key;
    int algorithm_choice;

    while (true) {
        cout << "\n=== Encryption Utility ===\n";
        cout << "Select Algorithm:\n";
        cout << "1. Caesar Cipher (ASCII-level)\n";
        // Future: Add more like
        // cout << "2. Vigenère Cipher\n";
        // cout << "3. XOR Cipher\n";
        cout << "Enter choice: ";
        cin >> algorithm_choice;
        cin.ignore(numeric_limits<streamsize>::max(), '\n'); // flush buffer

        switch (algorithm_choice) {
            case 1: {  // Caesar Cipher
                cout << "\n--- Caesar Cipher ---\n";
                cout << "Enter text: ";
                getline(cin, text);

                cout << "Enter shift value: ";
                cin >> shift;

                cout << "Enter mode ('e' for encrypt, 'd' for decrypt): ";
                cin >> mode;

                caesar_cipher(text, shift, mode);

                cout << "Result (ASCII values): ";
                for (char c : text) {
                    cout << static_cast<int>(static_cast<unsigned char>(c)) << ' ';
                }
                cout << "\n";

                cout << "Shifted Text (as characters): " << text << "\n";

                cout << "To exit enter '1', to decrypt the result enter '2', or to continue enter '0': ";
                cin >> key;
                cin.ignore(numeric_limits<streamsize>::max(), '\n');

                if (key == 1) {
                    return 0;
                } else if (key == 2) {
                    caesar_cipher(text, shift, 'd');
                    cout << "Decrypted ASCII Values: ";
                    for (char c : text) {
                        cout << static_cast<int>(static_cast<unsigned char>(c)) << ' ';
                    }
                    cout << "\nDecrypted Text: " << text << "\n";
                }

                break;
            }

            default:
                cout << "Invalid algorithm selection. Try again.\n";
        }
    }

    return 0;
}
