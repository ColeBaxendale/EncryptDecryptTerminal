import os
import click
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import subprocess
import base64
from cryptography.fernet import Fernet

# Please make sure to securely configure your client ID and secret
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
    payload = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    response = requests.post(url, data=payload, headers=headers)
    token_json = response.json()
    return token_json.get('access_token')

def authenticate():
    auth_url = f"https://github.com/login/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPES}"
    webbrowser.open_new(auth_url)
    httpd = HTTPServer(('', 3000), OAuthCallbackHandler)
    httpd.handle_request()

def get_current_repo():
    try:
        remote_url = subprocess.check_output(["git", "config", "--get", "remote.origin.url"]).decode().strip()
        if "github.com" in remote_url:
            repo_full_name = remote_url.split("github.com/")[1].replace(".git", "")
            return repo_full_name
    except Exception as e:
        print(f"Error detecting repository: {e}")
        return None

def menu():
    choice = click.prompt("\nChoose an option:\n0 - Exit\n1 - Encrypt a file\n2 - Decrypt a file", type=int)
    return choice

def file_path_prompt(action):
    while True:
        file_path = click.prompt(f"Enter the path to the file you want to {action} (Enter 0 to cancel)", type=str)
        if file_path == "0":
            return None  # User chose to exit
        if os.path.exists(file_path):
            return file_path
        else:
            click.echo("The file does not exist. Please try again.")

def main():
    while True:
        choice = menu()
        if choice == 0:
            break
        elif choice == 1:
            authenticate()
            click.echo("Authentication process completed.")
            repo = get_current_repo()
            if repo:
                print(f"Working within repository: {repo}")
                file_path = file_path_prompt("encrypt")
                if file_path:
                    # Placeholder: Implement actual encryption and storage logic here
                    click.echo(f"Encrypting {file_path}")
                    break
                else:
                    click.echo("Encryption cancelled.")
            else:
                click.echo("Failed to identify repository. Ensure you're within a git repository.")
        elif choice == 2:
            authenticate()
            click.echo("Authentication process completed.")
            repo = get_current_repo()
            if repo:
                print(f"Working within repository: {repo}")
                file_path = file_path_prompt("decrypt")
                if file_path:
                    # Placeholder: Implement actual decryption logic here
                    click.echo(f"Decrypting {file_path}")
                    break
                else:
                    click.echo("Decryption cancelled.")
            else:
                click.echo("Failed to identify repository. Ensure you're within a git repository.")
        else:
            click.echo("Invalid choice. Please select again.")

if __name__ == "__main__":
    main()
