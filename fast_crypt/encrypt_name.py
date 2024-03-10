import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
from google.cloud import secretmanager


def access_secret(secret_name):
    project_id = "verdant-tempest-416615"  # replace with your GCP project ID
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    secret_value = response.payload.data.decode("UTF-8")
    return secret_value

def access_secret_and_decode(secret_name):
    secret_value = access_secret(secret_name)  # Fetch the secret as a UTF-8 string
    return base64.urlsafe_b64decode(secret_value)  # Decode from base64 to bytes

# Adjust how you access and handle these secrets
FIXED_SALT = access_secret_and_decode("FIXED_SALT")
FIXED_IV = access_secret_and_decode("FIXED_IV")
FIXED_KEY = access_secret_and_decode("FIXED_KEY")

print(FIXED_IV)
print(FIXED_SALT)
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
        passphrase_bytes = passphrase.encode('utf-8') if isinstance(passphrase, str) else passphrase
        return kdf.derive(passphrase_bytes)

    def encrypt(self, plaintext):
        """Encrypt the plaintext using AES."""
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return urlsafe_b64encode(self.iv + ciphertext).decode()
