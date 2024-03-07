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





def main():
    while True:
        choice = menu()
        if choice == 0:
            break


        elif choice == 1:
            authenticate()
            click.echo("Authentication process completed.")
            repo = get_current_repo()
            print(repo)

            file_path = click.prompt("Enter the path to the file you want to encrypt", type=str)
            # encrypt_and_store_secret(file_path) function call goes here
            if file_path  and os.path.exists(file_path):
                print(file_path)



        elif choice == 2:
            authenticate()
            click.echo("Authentication process completed.")
            repo = get_current_repo()
            print(repo)

            # Assuming the user is already authenticated
            file_path = click.prompt("Enter the path to the file you want to decrypt", type=str)
            # decrypt_file(file_path) function call goes here
            if file_path  and os.path.exists(file_path):
                print(file_path)


        else:
            click.echo("Invalid choice. Please select again.")

if __name__ == "__main__":
    main()