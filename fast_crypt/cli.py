import click
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import requests

CLIENT_ID = '905746f3395ec758bef4'
CLIENT_SECRET = 'YOUR_CLIENT_SECRET'
REDIRECT_URI = 'http://localhost:3000/callback'
SCOPES = 'repo,user'

def handle_oauth_callback(server_class=HTTPServer, handler_class=BaseHTTPRequestHandler):
    server_address = ('', 3000)
    httpd = server_class(server_address, handler_class)
    httpd.handle_request()

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/callback"):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"Authentication successful. You can close this window.")
            # Extract the code from the URL
            code = self.path.split('?code=')[1]
            # Exchange the code for a token in the background
            threading.Thread(target=exchange_code_for_token, args=(code,)).start()

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
    access_token = response.json().get('access_token')
    # Here, use the access_token for authenticated API requests

@click.command()
def authenticate():
    auth_url = f"https://github.com/login/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPES}"
    webbrowser.open_new(auth_url)
    # Start a temporary server to handle the callback
    handle_oauth_callback(HTTPServer, RequestHandler)

@click.group()
def cli():
    pass

cli.add_command(authenticate)

if __name__ == "__main__":
    cli()
