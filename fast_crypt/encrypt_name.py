from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

FIXED_SALT = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'
FIXED_IV = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
FIXED_KEY = "lv3AHtC/X<mdBe>x/[bLl-&DNRoU0/BDD6H&iF|,`GsRO{a}>))5rfL`/kDLFg#"

class AESEncryption:
    def __init__(self, key=FIXED_KEY, salt=FIXED_SALT, iv=FIXED_IV):
        self.salt = salt
        self.iv = iv
        self.key = self._derive_key(key, self.salt)

    def _derive_key(self, passphrase, salt, iterations=100000):
        """Derive a secret key from a given passphrase."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(passphrase.encode())

    def encrypt(self, plaintext):
        """Encrypt the plaintext using AES."""
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return urlsafe_b64encode(self.iv + ciphertext).decode()
