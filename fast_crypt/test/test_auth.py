# test_auth.py
import requests_mock
from fast_crypt.auth import exchange_code_for_token, is_user_authorized

def test_exchange_code_for_token_success():
    with requests_mock.Mocker() as m:
        m.post('https://github.com/login/oauth/access_token', json={'access_token': 'testtoken'}, status_code=200)
        token = exchange_code_for_token('dummycode')
        assert token == 'testtoken'

def test_exchange_code_for_token_failure():
    with requests_mock.Mocker() as m:
        m.post('https://github.com/login/oauth/access_token', json={'error': 'bad_verification_code'}, status_code=400)
        token = exchange_code_for_token('wrongcode')
        assert token is None



ACCESS_TOKEN = "test_access_token"
REPO_FULL_NAME = "ColeBaxendale/EncryptDecryptTerminal"
USERNAME = "testuser"
PERMISSIONS_URL = f"https://api.github.com/repos/{REPO_FULL_NAME}/collaborators/{USERNAME}/permission"

def test_is_user_authorized_with_admin_permissions():
    with requests_mock.Mocker() as m:
        # Mock the user endpoint to return the username
        m.get("https://api.github.com/user", json={"login": USERNAME}, status_code=200)
        # Mock the permissions endpoint to return "admin" permissions
        m.get(PERMISSIONS_URL, json={"permission": "admin"}, status_code=200)

        authorized = is_user_authorized(ACCESS_TOKEN, REPO_FULL_NAME)
        assert authorized == True

def test_is_user_authorized_with_write_permissions():
    with requests_mock.Mocker() as m:
        m.get("https://api.github.com/user", json={"login": USERNAME}, status_code=200)
        m.get(PERMISSIONS_URL, json={"permission": "write"}, status_code=200)

        authorized = is_user_authorized(ACCESS_TOKEN, REPO_FULL_NAME)
        assert authorized == True

def test_is_user_authorized_with_read_permissions():
    with requests_mock.Mocker() as m:
        m.get("https://api.github.com/user", json={"login": USERNAME}, status_code=200)
        m.get(PERMISSIONS_URL, json={"permission": "read"}, status_code=200)

        authorized = is_user_authorized(ACCESS_TOKEN, REPO_FULL_NAME)
        assert authorized == False

def test_is_user_authorized_with_no_permissions():
    with requests_mock.Mocker() as m:
        m.get("https://api.github.com/user", json={"login": USERNAME}, status_code=200)
        # Simulate a scenario where the user does not have permissions
        m.get(PERMISSIONS_URL, json={"permission": "none"}, status_code=200)

        authorized = is_user_authorized(ACCESS_TOKEN, REPO_FULL_NAME)
        assert authorized == False

def test_is_user_authorized_failure():
    with requests_mock.Mocker() as m:
        # Simulate an error response for the user endpoint
        m.get("https://api.github.com/user", status_code=404)

        authorized = is_user_authorized(ACCESS_TOKEN, REPO_FULL_NAME)
        assert authorized == False