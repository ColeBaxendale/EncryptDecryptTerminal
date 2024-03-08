



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



def get_current_repo():
    try:
        remote_url = subprocess.check_output(["git", "config", "--get", "remote.origin.url"]).decode().strip()
        if "github.com" in remote_url:
            return remote_url.split("github.com/")[1].replace(".git", "")
    except Exception as e:
        click.echo(f"Error detecting repository: {e}")
    return None






def file_path_prompt(action):
    if action == "encrypt":
        prompt_message = "Enter the path to the file you want to encrypt (Enter 0 to cancel): "
    elif action == "decrypt":
        prompt_message = "Enter the path to the file you want to decrypt (Enter 0 to cancel): "
    else:
        return None

    while True:
        file_path = input(prompt_message)
        if file_path == "0":
            return None  # User chose to exit
        if os.path.exists(file_path):
            return file_path
        elif action == "decrypt" and file_path.endswith(".enc"):
            # Strip ".enc" extension for decryption files
            file_path = file_path[:-4]
            if os.path.exists(file_path):
                return file_path
            else:
                print("The decrypted file does not exist. Please try again.")
        else:
            print("The file does not exist. Please try again.")


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



    from http.server import BaseHTTPRequestHandler, HTTPServer
import webbrowser
import requests

CLIENT_ID = '905746f3395ec758bef4'
CLIENT_SECRET = 'a619ae1daeb0e4ee51eb1d2ab3edd1cbdfdc1b9c'  # Securely manage this
REDIRECT_URI = 'http://localhost:3000/callback'
SCOPES = 'repo,user'


def authenticate():
    try:
        auth_url = f"https://github.com/login/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPES}"
        webbrowser.open_new(auth_url)
        httpd = HTTPServer(('', 3000), OAuthCallbackHandler)
        httpd.handle_request()
        if access_token:
            return True  # Authentication successful
        else:
            return False  # Authentication failed, no access token
    except Exception as e:
        print(f"An error occurred during authentication: {e}")
        return False


class OAuthCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global access_token
        if self.path.startswith("/callback"):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            code = self.path.split('?code=')[1]
            access_token = exchange_code_for_token(code)
            message = "Authentication successful. You can close this window."
            self.wfile.write(message.encode())    

def exchange_code_for_token(code):
    url = 'https://github.com/login/oauth/access_token'
    headers = {'Accept': 'application/json'}
    payload = {
        'client_id': CLIENT_ID, 
        'client_secret': CLIENT_SECRET, 
        'code': code, 
        'redirect_uri': REDIRECT_URI
    }
    
    try:
        response = requests.post(url, data=payload, headers=headers)
        
        # Check if the request was successful
        if response.status_code == 200:
            return response.json().get('access_token')
        else:
            # Log the error or notify the user
            print(f"Failed to exchange code for token. Status code: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        # Handle network errors
        print(f"An error occurred while trying to exchange code for token: {e}")
        return None
    