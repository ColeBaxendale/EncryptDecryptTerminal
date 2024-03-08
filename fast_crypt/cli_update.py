



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





def decrypt_file_with_key(repo_full_name, key, encrypted_file_path):
    # Create a Fernet cipher object using the fetched key
    cipher = Fernet(key)

    try:
        # Print the file path being decrypted
        print(f"Decrypting file: {encrypted_file_path}")

        # Read the encrypted file
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
        
        # Decrypt the data
        decrypted_data = cipher.decrypt(encrypted_data)

        # Write the decrypted data to a new file
        decrypted_file_path = encrypted_file_path[:-4]  # Remove the .enc extension
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f"File decrypted successfully. Decrypted file saved as: {decrypted_file_path}")
    except Exception as e:
        print(f"Error decrypting file: {e}")



def main():
    authenticate()
    repo_full_name = get_current_repo()
    if not repo_full_name:
        click.echo("Failed to identify repository. Ensure you're within a git repository.")
        return
    
    while True:
        choice = menu()
        if choice == 0:
            break
        elif choice == 1:
            file_path = file_path_prompt("encrypt")
            if file_path:
                encrypt_file_and_store_key(repo_full_name, file_path)
            else:
                click.echo("Operation cancelled.")
        elif choice == 2:
            file_path = file_path_prompt("decrypt")
            if file_path:
                # Generate the secret name based on the file path
                secret_name = "KEY_" + os.path.basename(file_path).replace('.', '_')
                
                key = fetch_key_from_google()
                if key:
                    # Perform decryption with the retrieved key
                   decrypt_file_with_key(repo_full_name, key, file_path + '.enc')

                else:
                    print("Failed to fetch decryption key from Git Secrets.")
            else:
                click.echo("Operation cancelled.")
        else:
            click.echo("Invalid choice. Please select again.")

if __name__ == "__main__":
    main()


