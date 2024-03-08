import sys
import click
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import subprocess
import base64
from cryptography.fernet import Fernet
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import nacl.encoding
import nacl.signing
import base64
import os

from fast_crypt.auth import authenticate
from fast_crypt.cli_update import get_current_repo



CLIENT_ID = '905746f3395ec758bef4'
CLIENT_SECRET = 'a619ae1daeb0e4ee51eb1d2ab3edd1cbdfdc1b9c'  # Securely manage this
REDIRECT_URI = 'http://localhost:3000/callback'
SCOPES = 'repo,user'

access_token = None

def menu():
    return click.prompt("\nChoose an option:\n0 - Exit\n1 - Encrypt a file\n2 - Decrypt a file", type=int)

@click.command()
def main():
    authenticated = authenticate()
    if not authenticated:
        click.echo("GitHub authentication failed. Exiting FastCrypt.")
        sys.exit(1)  # Exit the program with an error status
    repo_full_name = get_current_repo()         
    if not repo_full_name:
        click.echo("Failed to identify repository. Ensure you're within a git repository.")
        return
    print(repo_full_name)
    while True:
        choice = menu()
        if choice == 0:
            click.echo("FastCrypt Close.")
            break
        elif choice == 1:
            print('encrypt')
          
        elif choice == 2:
           print('decrypt')
        else:
            click.echo("Invalid choice. Please select again.")

if __name__ == "__main__":
    main()








