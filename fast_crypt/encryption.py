from cryptography.fernet import Fernet
from fast_crypt import github_auth

from fast_crypt.github_auth import has_permission_to_decrypt

def generate_key():
    return Fernet.generate_key()

def encrypt_data(data, key):
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data)
    return encrypted_data

def decrypt_data(file_path):
    if not github_auth():
        print("GitHub Authentication failed.")
        return

    if not has_permission_to_decrypt():
        print("You do not have permission to decrypt this file.")
        return

    # Here you would proceed with the decryption process
    print(f"Decrypting file: {file_path}")
    # Mock decryption, replace with actual decryption logic.
    print("File decrypted successfully and placed in directory.")