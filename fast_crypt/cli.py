import click
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import requests

CLIENT_ID = '905746f3395ec758bef4'
CLIENT_SECRET = '1991f8c7a370187bf2fb6db5696e155324d427c3'  # Make sure to securely configure this
REDIRECT_URI = 'http://localhost:3000/callback'
SCOPES = 'repo,user'

# This global variable will store the access token once obtained
access_token = None

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global access_token
        if self.path.startswith("/callback"):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"Authentication successful. You can close this window.")
            
            # Extract the code from the URL
            code = self.path.split('?code=')[1]
            
            # Exchange the code for a token
            access_token = exchange_code_for_token(code)
            print(f"Access Token Obtained: {access_token}")  # For debugging purposes

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
    token_response = response.json()
    return token_response.get('access_token')

@click.command()
def authenticate():
    auth_url = f"https://github.com/login/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPES}"
    webbrowser.open_new(auth_url)
    # Start a temporary server to handle the callback
    httpd = HTTPServer(('', 3000), OAuthCallbackHandler)
    httpd.handle_request()

@click.command()
def some_authenticated_action():
    global access_token
    if access_token is None:
        click.echo("Please authenticate first using the 'authenticate' command.")
        return
    
    # Example: List user's repositories using the access token
    headers = {
        'Authorization': f'token {access_token}',
        'Accept': 'application/vnd.github.v3+json',
    }
    response = requests.get('https://api.github.com/user/repos', headers=headers)
    
    if response.ok:
        for repo in response.json():
            print(repo['full_name'])
    else:
        click.echo("Failed to list repositories.")

@click.group()
def cli():
    pass

cli.add_command(authenticate)
cli.add_command(some_authenticated_action)

if __name__ == "__main__":
    cli()
