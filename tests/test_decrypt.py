from src.encrypt import encrypt_file
from src.decrypt import decrypt_file
from cryptography.fernet import Fernet
import os

def test_encrypt_and_decrypt_file():
    # Setup - create a test file and a key
    test_filename = 'testfile.txt'
    test_content = b'This is a test.'
    key = Fernet.generate_key()

    # Write original content to the file
    with open(test_filename, 'wb') as f:
        f.write(test_content)

    # Encrypt the file
    encrypt_file(test_filename, key)
    
    # Ensure the encrypted file exists
    encrypted_file_path = test_filename + '.enc'
    assert os.path.exists(encrypted_file_path)

    # Decrypt the file
    decrypt_file(encrypted_file_path, key)

    # Read the decrypted content and verify it matches the original
    with open(test_filename, 'rb') as f:
        decrypted_content = f.read()
    
    assert decrypted_content == test_content

    # Cleanup - remove test files
    os.remove(test_filename)
    os.remove(encrypted_file_path)
