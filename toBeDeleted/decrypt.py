from cryptography.fernet import Fernet

def decrypt_file(file_path, key):
    """Decrypts a file using a given key."""
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    decrypted_file_path = file_path.replace('.enc', '.decrypted')
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)
