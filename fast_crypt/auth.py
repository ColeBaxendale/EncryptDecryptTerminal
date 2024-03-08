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
            return access_token  # Authentication successful
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
            access_token = exchange_code_for_token(code)  # Ensure this call successfully sets the token
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
            # Typical permission values include "admin", "write", "read", "none"
            return permission in ["admin", "write"]
    return False