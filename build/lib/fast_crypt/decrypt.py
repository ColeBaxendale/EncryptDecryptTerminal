import hashlib
import click
from cryptography.fernet import Fernet
from google.cloud import secretmanager

PROJECT_ID = 'verdant-tempest-416615'
def access_secret(secret_name):
    project_id = "verdant-tempest-416615"  # replace with your GCP project ID
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    secret_value = response.payload.data.decode("UTF-8")
    return secret_value

CLIENT_ID = access_secret("CLIENT_ID")
CLIENT_SECRET = access_secret("CLIENT_SECRET")

# Assuming the same PROJECT_ID and SERVICE_ACCOUNT_CREDENTIALS as before
class FileSecretsDecryptor:
    def __init__(self, project_id=PROJECT_ID):
        self.project_id = project_id
        self.client = secretmanager.SecretManagerServiceClient()


    def retrieve_secret_from_manager(self, secret_name):
        # Use SHA-256 to hash the secret name to ensure it matches the stored version
        hash_object = hashlib.sha256(secret_name.encode())
        hex_dig = hash_object.hexdigest()

        # Build the secret version name
        secret_version_name = f"projects/{self.project_id}/secrets/{hex_dig}/versions/latest"

        # Access the secret version
        response = self.client.access_secret_version(request={"name": secret_version_name})
        # Extract the payload as a bytes object
        payload = response.payload.data

        return payload.decode()

    def decrypt_file(self, encrypted_file_path, secret_name):
        # Retrieve the encryption key from Google Secret Manager
        key = self.retrieve_secret_from_manager(secret_name)

        # Initialize the Fernet cipher
        cipher = Fernet(key)

        # Read the encrypted content
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        # Decrypt the file data
        decrypted_data = cipher.decrypt(encrypted_data)

        # Write the decrypted data to a new file
        decrypted_file_path = encrypted_file_path[:-4]
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        click.echo(f"Decrypted file saved to: {decrypted_file_path}")