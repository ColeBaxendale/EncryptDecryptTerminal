import os
import sys

from getpass import getpass
from fast_crypt.encryption import generate_key, encrypt_data, decrypt_data
from fast_crypt.github_auth import github_oauth, has_permission_to_decrypt

# Your cli.py code continues here...


def main():
    while True:
        print("\nFast-Crypt CLI")
        print("1. Exit")
        print("2. Encrypt a file")
        print("3. Decrypt a file")
        choice = input("Enter your choice: ")

        if choice == '1':
            print("Exiting Fast-Crypt.")
            break
        elif choice == '2':
            if github_oauth():
                file_path = input("Enter the path to the file you want to encrypt: ")
                if os.path.isfile(file_path):
                    # select_team_members()
                    key = generate_key()
                    with open(file_path, 'rb') as file:
                        data = file.read()
                    encrypted_data = encrypt_data(data, key)
                    with open(file_path + '.enc', 'wb') as file:
                        file.write(encrypted_data)
                    print(f"File '{file_path}' encrypted successfully.")
                else:
                    print("The specified file does not exist. Please try again.")
        elif choice == '3':
            if github_oauth():
                print("Permission to decrypt: Granted (Mock)")
                file_path = input("Enter the path to the file you want to decrypt: ")
                if os.path.isfile(file_path):
                    key = getpass("Enter the encryption key: ")
                    with open(file_path, 'rb') as file:
                        encrypted_data = file.read()
                    decrypted_data = decrypt_data(encrypted_data, key.encode())
                    with open(file_path.replace('.enc', ''), 'wb') as file:
                        file.write(decrypted_data)
                    print(f"File '{file_path}' decrypted successfully.")
                else:
                    print("The specified file does not exist. Please try again.")
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
