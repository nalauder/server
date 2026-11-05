"""Helpers for driving the OIDC single sign-on flow against the dev Keycloak from API tests."""
import html
import os
import re
import time
from urllib.parse import urlencode, urlsplit

import requests

from utils import get_hashtopolis_uri

OIDC_URI = get_hashtopolis_uri() + '/api/v2/auth/oidc'
DEFAULT_RETURN_TO = 'http://localhost:4200'

# The server container does not wait for Keycloak to come up, so give it time before deciding
DISCOVERY_WAIT_SECONDS = 60

# None until checked, then 'enabled', 'disabled' (not configured) or 'unreachable'
_status = None


def _provider_reachable(issuer):
    url = issuer.rstrip('/') + '/.well-known/openid-configuration'
    deadline = time.monotonic() + DISCOVERY_WAIT_SECONDS
    while True:
        try:
            if requests.get(url, timeout=5).status_code == 200:
                return True
        except requests.RequestException:
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(2)


def _in_ci():
    return os.environ.get('CI', '').strip().lower() not in ('', '0', 'false')


def oidc_enabled():
    """Whether the server under test is configured for SSO and its provider answers discovery.

    The tests run inside the server container, so the server's own settings are in our environment.
    The answer is cached, so only the first caller waits for the provider. When SSO is configured but
    the provider does not answer, the OIDC tests are skipped locally, but in CI (the CI variable is
    set) this raises, so a broken provider cannot let CI pass without running them.
    """
    global _status
    if _status is None:
        issuer = os.environ.get('HASHTOPOLIS_OIDC_ISSUER', '').strip()
        client_id = os.environ.get('HASHTOPOLIS_OIDC_CLIENT_ID', '').strip()
        if not (issuer and client_id):
            _status = 'disabled'
        else:
            _status = 'enabled' if _provider_reachable(issuer) else 'unreachable'
    if _status == 'unreachable' and _in_ci():
        raise RuntimeError('OIDC is configured but the provider is unreachable; '
                           'refusing to skip the OIDC tests in CI')
    return _status == 'enabled'


def start_login(session, return_to=DEFAULT_RETURN_TO):
    """Starts an SSO login; the oidcState cookie lands in the session. Returns the provider URL."""
    response = session.get(OIDC_URI + '/login?' + urlencode({'returnTo': return_to}), allow_redirects=False)
    assert response.status_code == 302, f'login: status={response.status_code} body={response.text}'
    return response.headers['Location']


def start_link(session, jwt, password):
    """Starts linking an identity to the user the JWT belongs to. Returns the provider URL."""
    response = session.post(OIDC_URI + '/link', json={'password': password},
                            headers={'Authorization': 'Bearer ' + jwt})
    assert response.status_code == 200, f'link: status={response.status_code} body={response.text}'
    return response.json()['authorizeUrl']


def provider_login(provider_url, username, password):
    """Signs in at Keycloak and returns the callback URL it redirects to.

    Uses a fresh session every time, so no provider SSO session carries over between calls.
    """
    provider = requests.Session()
    page = provider.get(provider_url)
    assert page.status_code == 200, f'provider page: status={page.status_code}'
    match = re.search(r'<form\b[^>]*\baction="([^"]+)"', page.text)
    assert match, 'no login form on the provider page'
    action = html.unescape(match.group(1))
    response = provider.post(action, data={'username': username, 'password': password, 'credentialId': ''},
                             allow_redirects=False)
    assert response.status_code == 302, f'provider login: status={response.status_code}'
    return response.headers['Location']


def hit_callback(session, callback_url):
    """Delivers the provider's redirect to the server under test, without following the result."""
    parts = urlsplit(callback_url)
    url = get_hashtopolis_uri() + parts.path + ('?' + parts.query if parts.query else '')
    return session.get(url, allow_redirects=False)
