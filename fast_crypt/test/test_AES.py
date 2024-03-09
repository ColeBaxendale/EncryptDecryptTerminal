import unittest

from fast_crypt.encrypt_name import AESEncryption


class TestAESEncryption(unittest.TestCase):
    def setUp(self):
        # Initialize your AESEncryption object here
        self.aes_encryption = AESEncryption()

    def test_encrypt_returns_string(self):
        # Test that encryption returns a base64 encoded string
        plaintext = "Test message"
        encrypted_text = self.aes_encryption.encrypt(plaintext)
        self.assertIsInstance(encrypted_text, str)

    def test_encrypt_deterministic_output(self):
        # Test that encryption of the same plaintext returns the same result
        # Important: This is specific to your use case with fixed IV and salt
        plaintext = "Deterministic message"
        encrypted_text1 = self.aes_encryption.encrypt(plaintext)
        encrypted_text2 = self.aes_encryption.encrypt(plaintext)
        self.assertEqual(encrypted_text1, encrypted_text2)

# Add more tests as needed

if __name__ == '__main__':
    unittest.main()
