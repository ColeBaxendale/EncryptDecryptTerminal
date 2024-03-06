import os
import click
import requests
from cryptography.fernet import Fernet

# GitHub API endpoint for user information
GITHUB_API_URL = 'https://api.github.com/user'

# Function to retrieve GitHub username using GitHub access token
def get_github_username(access_token):
    headers = {'Authorization': f'token {access_token}'}
    response = requests.get(GITHUB_API_URL, headers=headers)
    response.raise_for_status()
    return response.json()['login']

# Function to encrypt a file
def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        original_data = file.read()
    encrypted_data = fernet.encrypt(original_data)
    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

# Function to decrypt a file
def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_path.replace('.enc', ''), 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

@click.group()
def cli():
    """Simple CLI for encrypting and decrypting files."""
    pass

@cli.command()
@click.argument('file_path')
@click.option('--access-token', prompt='GitHub Access Token', help='GitHub access token for authentication.')
def encrypt(file_path, access_token):
    """Encrypts the specified file."""
    try:
        key = os.getenv("ENCRYPTION_KEY") or Fernet.generate_key()
        github_username = get_github_username(access_token)
        # Include GitHub username in encryption process
        key_with_username = f"{key.decode()}_{github_username}"
        encrypt_file(file_path, key_with_username)
        click.echo(f'{file_path} has been encrypted.')
    except Exception as e:
        click.echo(f'Error encrypting file: {e}')

@cli.command()
@click.argument('file_path')
@click.option('--access-token', prompt='GitHub Access Token', help='GitHub access token for authentication.')
def decrypt(file_path, access_token):
    """Decrypts the specified file."""
    try:
        # Retrieve GitHub username using the provided access token
        github_username = get_github_username(access_token)
        
        # Use the GitHub username to retrieve the encryption key
        key_with_username = get_encryption_key_for_user(github_username)
        
        # Decrypt the file using the retrieved encryption key
        decrypt_file(file_path, key_with_username)
        
        click.echo(f'{file_path} has been decrypted.')
    except Exception as e:
        click.echo(f'Error decrypting file: {e}')

if __name__ == '__main__':
    cli()
