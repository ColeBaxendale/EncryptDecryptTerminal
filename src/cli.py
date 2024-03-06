import click
from .encrypt import encrypt_file
from .decrypt import decrypt_file
from cryptography.fernet import Fernet
import os

# You might load the key from an environment variable or a file
key = os.getenv("ENCRYPTION_KEY", Fernet.generate_key())

@click.group()
def cli():
    """Simple CLI for encrypting and decrypting files."""
    pass

@cli.command()
@click.argument('file_path')
def encrypt(file_path):
    """Encrypts the specified file."""
    encrypt_file(file_path, key)
    click.echo(f'{file_path} has been encrypted.')

@cli.command()
@click.argument('file_path')
def decrypt(file_path):
    """Decrypts the specified file."""
    decrypt_file(file_path, key)
    click.echo(f'{file_path} has been decrypted.')

if __name__ == '__main__':
    cli()
