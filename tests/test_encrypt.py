from src.encrypt import encrypt_file
from cryptography.fernet import Fernet
import os

def test_encrypt_file_creates_encrypted_file():
    # Setup - create a test file and a key
    test_filename = 'testfile.txt'
    test_content = b'This is a test.'
    key = Fernet.generate_key()

    with open(test_filename, 'wb') as f:
        f.write(test_content)

    # Test encryption
    encrypt_file(test_filename, key)
    assert os.path.exists(test_filename + '.enc')

    # Cleanup - remove test files
    os.remove(test_filename)
    if os.path.exists(test_filename + '.enc'):
        os.remove(test_filename + '.enc')
