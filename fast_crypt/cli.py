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

CLIENT_ID = '905746f3395ec758bef4'
CLIENT_SECRET = 'a619ae1daeb0e4ee51eb1d2ab3edd1cbdfdc1b9c'  # Securely manage this
REDIRECT_URI = 'http://localhost:3000/callback'
SCOPES = 'repo,user'

access_token = None

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
    payload = {'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET, 'code': code, 'redirect_uri': REDIRECT_URI}
    response = requests.post(url, data=payload, headers=headers)
    return response.json().get('access_token')

def authenticate():
    auth_url = f"https://github.com/login/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPES}"
    webbrowser.open_new(auth_url)
    httpd = HTTPServer(('', 3000), OAuthCallbackHandler)
    httpd.handle_request()

def get_current_repo():
    try:
        remote_url = subprocess.check_output(["git", "config", "--get", "remote.origin.url"]).decode().strip()
        if "github.com" in remote_url:
            return remote_url.split("github.com/")[1].replace(".git", "")
    except Exception as e:
        click.echo(f"Error detecting repository: {e}")
    return None

def get_repo_public_key(repo_full_name):
    url = f"https://api.github.com/repos/{repo_full_name}/actions/secrets/public-key"
    headers = {"Authorization": f"token {access_token}"}
    response = requests.get(url, headers=headers)
    
    try:
        response.raise_for_status()  # Raise an exception for 4xx or 5xx status codes
        response_data = response.json()
        return response_data["key_id"], response_data["key"]
    except requests.exceptions.HTTPError as err:
        print(f"HTTP Error: {err}")
        print(f"Response content: {response.content}")
        return None, None
    except KeyError as err:
        print(f"KeyError: {err}")
        print(f"Response content: {response.content}")
        return None, None

def encrypt_secret_for_github(public_key, secret_value):
    from nacl.public import PublicKey, SealedBox

    # Decode the GitHub public key from Base64
    public_key_bytes = base64.b64decode(public_key)

    # Use NaCl's SealedBox for encryption
    public_key = PublicKey(public_key_bytes)
    sealed_box = SealedBox(public_key)

    # Encrypt the secret
    encrypted = sealed_box.encrypt(secret_value)  # secret_value is already bytes

    # GitHub expects the encrypted value in Base64 encoding
    encrypted_base64 = base64.b64encode(encrypted)

    return encrypted_base64.decode()

def store_secret_in_github(repo_full_name, secret_name, encrypted_secret, key_id):
    try:
        url = f"https://api.github.com/repos/{repo_full_name}/actions/secrets/{secret_name}"
        headers = {
            "Authorization": f"token {access_token}",
            "Content-Type": "application/json"
        }
        data = json.dumps({
            "encrypted_value": encrypted_secret, 
            "key_id": key_id
        })
        response = requests.put(url, headers=headers, data=data)
        
        print("Secret storage request:", response.request.url)
        print("Request headers:", response.request.headers)
        print("Request body:", data)
        
        if response.status_code in [201, 204]:
            click.echo(f"Secret {secret_name} stored successfully.")
        else:
            click.echo(f"Failed to store the secret. Status: {response.status_code}")
            print("Response content:", response.content)
    except Exception as e:
        print(f"Error storing secret in GitHub: {e}")
        
def encrypt_file_and_store_key(repo_full_name, file_path):
    key = Fernet.generate_key()
    cipher = Fernet(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher.encrypt(file_data)
    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
    
    # Prepare the secret name based on the filename
    file_name = os.path.basename(file_path)
    secret_name = "KEY_" + file_name.replace('.', '_')
    print(secret_name)  # Print the secret name for debugging purposes
    
    key_id, public_key = get_repo_public_key(repo_full_name)
    encrypted_key_for_github = encrypt_secret_for_github(public_key, key)
    store_secret_in_github(repo_full_name, secret_name, encrypted_key_for_github, key_id)


def create_decrypt_workflow():
    workflow_dir = os.path.join('.github', 'workflows')
    if not os.path.exists(workflow_dir):
        os.makedirs(workflow_dir)
    
    workflow_file = os.path.join(workflow_dir, 'decrypt.yml')
    if not os.path.exists(workflow_file):
        with open(workflow_file, 'w') as f:
            f.write("""
name: Decrypt File

on:
  push:
    branches:
      - main

jobs:
  decrypt:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v2

      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.x'

      - name: Fetch encryption key from GitHub Secrets
        run: echo "::set-env name=ENCRYPTION_KEY::${{ secrets.ENCRYPTION_KEY }}"

      - name: Decrypt file
        run: python decrypt_file.py
          env:
            ENCRYPTION_KEY: ${{ secrets.ENCRYPTION_KEY }}
""")
        print("Decrypt workflow file created successfully.")
    else:
        print("Decrypt workflow file already exists.")


def fetch_key_from_git_secrets(repo_full_name, secret_name):
    # GitHub API endpoint to retrieve the secret value
    url = f"https://api.github.com/repos/{repo_full_name}/actions/secrets/{secret_name.upper()}"
    
    # HTTP request headers including authentication token
    headers = {
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Send GET request to retrieve the secret value
    response = requests.get(url, headers=headers)
    
    # Check if request was successful
    if response.status_code == 200:
        # Extract the secret value from the response
        secret_value = response.json().get("secret")
        print(f"Secret value retrieved successfully for secret {secret_name}: {secret_value}")
        print(f"Response content: {response.content}")
        return secret_value
    else:
        # Print error message if request fails
        print(f"Failed to retrieve secret {secret_name}. Status code: {response.status_code}")
        print(f"Response content: {response.content}")
        return None


def menu():
    return click.prompt("\nChoose an option:\n0 - Exit\n1 - Encrypt a file\n2 - Decrypt a file", type=int)

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
    
    # Create the decrypt workflow file
    create_decrypt_workflow()
    
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
                
                key = fetch_key_from_git_secrets(repo_full_name, secret_name)
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