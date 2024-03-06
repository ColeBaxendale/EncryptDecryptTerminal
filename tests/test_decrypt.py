# File: tests/test_decrypt.py

import os
import pytest
from src.encrypt import encrypt_file
from src.decrypt import decrypt_file
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken

def test_decrypt_file_with_correct_key(tmp_path):
    test_file = tmp_path / 'testfile.txt'
    content = b'This is a test.'
    key = Fernet.generate_key()
    
    test_file.write_bytes(content)
    encrypt_file(str(test_file), key)
    
    encrypted_file = str(test_file) + '.enc'
    decrypt_file(encrypted_file, key)
    
    decrypted_content = test_file.read_bytes()
    assert decrypted_content == content

def test_decrypt_file_with_incorrect_key(tmp_path):
    test_file = tmp_path / 'testfile.txt'
    content = b'This is a test.'
    key = Fernet.generate_key()
    wrong_key = Fernet.generate_key()
    
    test_file.write_bytes(content)
    encrypt_file(str(test_file), key)
    
    encrypted_file = str(test_file) + '.enc'
    with pytest.raises(InvalidToken):
        decrypt_file(encrypted_file, wrong_key)

def test_decrypt_nonexistent_file(tmp_path):
    nonexistent_file = tmp_path / 'nonexistent.enc'
    key = Fernet.generate_key()
    
    with pytest.raises(FileNotFoundError):
        decrypt_file(str(nonexistent_file), key)
