# Secure-File-Encryption-and-Decryption-Tool
This project focuses on encrypting and decrypting files to ensure data confidentiality. It uses the Advanced Encryption Standard (AES) algorithm with the CBC mode for strong encryption. The tool supports password-based encryption and includes a mechanism to generate secure encryption keys using a key derivation function (PBKDF2).
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Generate a secure encryption key
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt a file
def encrypt_file(input_file, password, output_file):
    salt = os.urandom(16)  # Generate a random salt
    key = generate_key(password, salt)
    iv = os.urandom(16)  # Generate a random initialization vector (IV)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Padding to make the plaintext a multiple of the block size
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length] * padding_length)
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Save the salt, IV, and ciphertext to the output file
    with open(output_file, 'wb') as f:
        f.write(salt + iv + ciphertext)

    print(f"File encrypted successfully: {output_file}")

# Decrypt a file
def decrypt_file(input_file, password, output_file):
    with open(input_file, 'rb') as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"File decrypted successfully: {output_file}")

# Main program
def main():
    print("Secure File Encryption and Decryption Tool")
    print("1. Encrypt a File")
    print("2. Decrypt a File")
    choice = input("Enter your choice (1/2): ")

    if choice == "1":
        input_file = input("Enter the path of the file to encrypt: ")
        password = input("Enter a password for encryption: ")
        output_file = input("Enter the path for the encrypted file: ")
        encrypt_file(input_file, password, output_file)
    elif choice == "2":
        input_file = input("Enter the path of the encrypted file: ")
        password = input("Enter the password for decryption: ")
        output_file = input("Enter the path for the decrypted file: ")
        decrypt_file(input_file, password, output_file)
    else:
        print("Invalid choice. Exiting.")

# Run the program
if __name__ == "__main__":
    main()
