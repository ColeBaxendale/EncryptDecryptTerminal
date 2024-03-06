from cryptography.fernet import Fernet

def encrypt_file(file_path, key):
    """Encrypts a file using a given key."""
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        original_data = file.read()
    encrypted_data = fernet.encrypt(original_data)
    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
