# File: tests/test_encrypt.py

import os
from src.encrypt import encrypt_file
from cryptography.fernet import Fernet

def test_encrypt_empty_file(tmp_path):
    empty_file = tmp_path / 'emptyfile.txt'
    empty_file.write_bytes(b'')
    key = Fernet.generate_key()
    
    encrypt_file(str(empty_file), key)
    
    encrypted_file = str(empty_file) + '.enc'
    assert os.path.exists(encrypted_file)
    assert os.path.getsize(encrypted_file) > 0  # Encrypted file should have some content even if the original file is empty

def test_encrypt_large_file(tmp_path):
    large_file = tmp_path / 'largefile.txt'
    large_file.write_bytes(b'0' * 10**6)  # 1MB of zeros
    key = Fernet.generate_key()
    
    encrypt_file(str(large_file), key)
    
    encrypted_file = str(large_file) + '.enc'
    assert os.path.exists(encrypted_file)
    # Encrypted file might be slightly larger than the original due to encryption overhead
    assert os.path.getsize(encrypted_file) > os.path.getsize(str(large_file))
