import hashlib
import click
from google.cloud import secretmanager
from cryptography.fernet import Fernet
from google.api_core.exceptions import AlreadyExists

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

class FileSecretsManager:
    def __init__(self, project_id=PROJECT_ID):
        self.project_id = project_id
        self.client = secretmanager.SecretManagerServiceClient()


    def encrypt_file_and_store_key(self, file_path, secret_name):
        # Generate a new Fernet encryption key
        key = Fernet.generate_key()
        cipher = Fernet(key)

        # Read the file content
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Encrypt the file data
        encrypted_data = cipher.encrypt(file_data)

        # Write the encrypted data to a new file
        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        # Use SHA-256 to hash the secret name to ensure it contains only letters or numbers
        hash_object = hashlib.sha256(secret_name.encode())
        hex_dig = hash_object.hexdigest()  # This is now a valid secret name for Google Secret Manager

        # Store the encryption key in Google Secret Manager
        self.store_key_in_secret_manager(key.decode(), hex_dig)

    def store_key_in_secret_manager(self, key, secret_name):
        parent = f"projects/{self.project_id}"
        secret_path = f"{parent}/secrets/{secret_name}"

        try:
            # Attempt to create the secret
            self.client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_name,
                    "secret": {"replication": {"automatic": {}}},
                }
            )
        except AlreadyExists:
            # If the secret already exists, log it and move on to adding a new version
            click.echo(f"Secret already exists, adding new version.")

        # Add a new version to the secret with the encryption key
        self.client.add_secret_version(
            request={
                "parent": secret_path,
                "payload": {"data": key.encode('UTF-8')},
            }
        )
        click.echo(f"Added new version to the secret")