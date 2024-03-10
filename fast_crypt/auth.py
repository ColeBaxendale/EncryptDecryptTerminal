from http.server import BaseHTTPRequestHandler, HTTPServer
import webbrowser
import click
import requests
from google.cloud import secretmanager

def access_secret(secret_name):
    project_id = "verdant-tempest-416615"  # replace with your GCP project ID
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    secret_value = response.payload.data.decode("UTF-8")
    return secret_value

CLIENT_ID = access_secret("CLIENT_ID")
CLIENT_SECRET = access_secret("CLIENT_SECRET")
REDIRECT_URI = 'http://localhost:3000/callback'
SCOPES = 'repo,user'

def authenticate():
    try:
        auth_url = f"https://github.com/login/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPES}"
        webbrowser.open_new(auth_url)
        httpd = HTTPServer(('', 3000), OAuthCallbackHandler)
        httpd.handle_request()
        if access_token:
            return access_token  # Authentication successful
        else:
            return False  # Authentication failed, no access token
    except Exception as e:
        click.echo(f"An error occurred during authentication: {e}")
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
            click.echo(f"Failed to exchange code for token. Status code: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        # Handle network errors
        click.echo(f"An error occurred while trying to exchange code for token: {e}")
        return None
    
def is_user_authorized(access_token, repo_full_name):
    headers = {"Authorization": f"token {access_token}"}
    # Assuming the authenticated user is the one making the request
    user_endpoint = f"https://api.github.com/user"
    user_response = requests.get(user_endpoint, headers=headers)
    
    if user_response.status_code == 200:
        username = user_response.json()["login"]
        permissions_endpoint = f"https://api.github.com/repos/{repo_full_name}/collaborators/{username}/permission"
        permissions_response = requests.get(permissions_endpoint, headers=headers)
        
        if permissions_response.status_code == 200:
            permission = permissions_response.json()["permission"]
            return permission in ["admin", "write"]
    return False