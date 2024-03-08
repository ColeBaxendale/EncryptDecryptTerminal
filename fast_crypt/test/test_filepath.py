import pytest
from unittest.mock import patch
from fast_crypt.file_path import file_path_prompt, does_exist  # Adjust the import path as necessary

def test_file_path_prompt_encrypt_existing_file(mocker):
    # Mock user input to simulate entering a valid file path, then simulate the file existing
    mocker.patch('builtins.input', return_value='.env')
    mocker.patch('os.path.exists', return_value=True)
    
    result = file_path_prompt("encrypt")
    assert result == '.env'

def test_file_path_prompt_decrypt_existing_encrypted_file(mocker):
    # Mock user input for decrypting an existing .enc file
    mocker.patch('builtins.input', return_value='.env.enc')
    mocker.patch('os.path.exists', return_value=True)
    
    # The expected result should be '.env', as the '.enc' is removed for decrypt actions
    result = file_path_prompt("decrypt")
    assert result == '.env' 

def test_does_exist_for_nonexistent_file():
    # Directly testing does_exist with a non-existent file
    assert does_exist('/path/to/nonexistent.txt', 'encrypt') is None

def test_does_exist_for_existing_file():
    with patch('os.path.exists', return_value=True):
        assert does_exist('/path/to/existing.txt', 'encrypt') == '/path/to/existing.txt'

def test_does_exist_for_existing_encrypted_file_decrypt_action():
    with patch('os.path.exists', return_value=True):
        # Test decrypting an existing .enc file
        assert does_exist('/path/to/file.enc', 'decrypt') == '/path/to/file'
