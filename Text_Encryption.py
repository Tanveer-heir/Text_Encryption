def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def main():
    print("=== Text Encryption & Decryption Tool ===")
    while True:
        choice = input("Choose 1) Encrypt 2) Decrypt 3) Exit: ")
        if choice == '1':
            msg = input("Enter text to encrypt: ")
            s = int(input("Enter shift key (number): "))
            print("Encrypted text:", caesar_encrypt(msg, s))
        elif choice == '2':
            msg = input("Enter text to decrypt: ")
            s = int(input("Enter shift key (number): "))
            print("Decrypted text:", caesar_decrypt(msg, s))
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main()
