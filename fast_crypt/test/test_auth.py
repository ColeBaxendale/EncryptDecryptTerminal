# test_auth.py
import requests_mock
from fast_crypt.auth import exchange_code_for_token

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
