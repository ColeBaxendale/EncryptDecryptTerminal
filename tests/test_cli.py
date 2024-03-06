import os
import pytest
from src.encrypt import encrypt_file
from src.decrypt import decrypt_file
from cryptography.fernet import Fernet

@pytest.fixture
def tmp_dir(tmp_path):
    return tmp_path

def test_encrypt_decrypt(tmp_dir):
    # Generate Fernet key
    fernet_key = Fernet.generate_key()
    
    # Create a test file
    test_file_content = b'This is a test.'
    test_file_path = os.path.join(tmp_dir, 'testfile.txt')
    with open(test_file_path, 'wb') as f:
        f.write(test_file_content)
    
    # Encrypt the file
    encrypt_file(test_file_path, fernet_key)
    assert os.path.exists(test_file_path + '.enc')
    
    # Decrypt the file
    decrypt_file(test_file_path + '.enc', fernet_key)
    
    # Check if the decrypted file content matches the original content
    decrypted_file_path = test_file_path + '.decrypted'
    assert os.path.exists(decrypted_file_path)
    with open(decrypted_file_path, 'rb') as f:
        decrypted_content = f.read()
    assert decrypted_content == test_file_content
