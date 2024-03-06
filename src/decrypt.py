from cryptography.fernet import Fernet

def decrypt_file(file_path, key):
    """Decrypts a file using a given key."""
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_path.replace('.enc', ''), 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)
