import base64
import json
import os
import unittest
import uuid

import requests
from hashtopolis import Helper, User

from oidc_helpers import (DEFAULT_RETURN_TO, OIDC_URI, hit_callback, oidc_enabled, provider_login,
                          start_link, start_login)
from utils import BaseTest, get_hashtopolis_uri

AUTH_URI = get_hashtopolis_uri() + '/api/v2/auth/token'
REFRESH_URI = get_hashtopolis_uri() + '/api/v2/auth/refresh'
OAUTH_TOKEN_URI = get_hashtopolis_uri() + '/api/v2/auth/oauth-token'

ALICE = ('alice', 'alice-dev-pass')
BOB = ('bob', 'bob-dev-pass')
ISSUER = 'http://keycloak:8180/realms/hashtopolis'

STATE_COOKIE = 'oidcState'
REFRESH_COOKIE = 'refreshToken'


def _jwt_payload(token):
    payload_b64 = token.split('.')[1]
    payload_b64 += '=' * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


def _set_cookies(response):
    """All Set-Cookie headers of a response, as a list."""
    return response.raw.headers.getlist('Set-Cookie')


def _state_of(session):
    return session.cookies.get(STATE_COOKIE)


class OidcTest(BaseTest):
    @classmethod
    def setUpClass(cls):
        if not oidc_enabled():
            raise unittest.SkipTest('OIDC is not configured or the provider is unreachable')

    def make_user(self):
        """A fresh Hashtopolis user with a known password; removed (with its identities) in tearDown."""
        password = 'oidc-test-pass-' + uuid.uuid4().hex[:8]
        user = User(name='test-oidc-' + uuid.uuid4().hex[:12], email='oidc-user@example.test',
                    globalPermissionGroupId=1, isValid=True, sessionLifetime=3600)
        user.save()
        self.delete_after_test(user)
        Helper().set_user_password(user, password)
        return user, password

    def jwt_for(self, user, password):
        response = requests.post(AUTH_URI, auth=(user.name, password))
        self.assertEqual(response.status_code, 201, msg=response.text)
        return response.json()['token']

    def link(self, user, password, provider_user=ALICE):
        """Links a Keycloak identity to the user through the settings flow; returns the callback response."""
        session = requests.Session()
        url = start_link(session, self.jwt_for(user, password), password)
        return hit_callback(session, provider_login(url, *provider_user))

    def sso_login(self, provider_user=ALICE):
        session = requests.Session()
        url = start_login(session)
        return session, hit_callback(session, provider_login(url, *provider_user))

    def assertRedirect(self, response, location):
        self.assertEqual(response.status_code, 302, msg=response.text)
        self.assertEqual(response.headers['Location'], location)

    def test_config_public(self):
        response = requests.get(OIDC_URI + '/config')
        self.assertEqual(response.status_code, 200, msg=response.text)
        body = response.json()
        self.assertIs(body['enabled'], True)
        self.assertEqual(body['displayName'], 'Keycloak')
        self.assertIsInstance(body['localLoginEnabled'], bool)

    def test_login_rejects_untrusted_return_to(self):
        for return_to in ('https://evil.example.test', DEFAULT_RETURN_TO + '/somewhere', ''):
            response = requests.get(OIDC_URI + '/login', params={'returnTo': return_to}, allow_redirects=False)
            self.assertEqual(response.status_code, 400, msg=f'{return_to}: {response.text}')
            self.assertNotIn(STATE_COOKIE, ''.join(_set_cookies(response)))

    def test_link_requires_password(self):
        user, password = self.make_user()
        response = requests.post(OIDC_URI + '/link', json={'password': 'wrong-' + password},
                                 headers={'Authorization': 'Bearer ' + self.jwt_for(user, password)})
        self.assertEqual(response.status_code, 401, msg=response.text)
        self.assertNotIn(STATE_COOKIE, ''.join(_set_cookies(response)))

    def test_link_returns_to_the_calling_frontend(self):
        user, password = self.make_user()
        jwt = self.jwt_for(user, password)
        response = requests.post(OIDC_URI + '/link', json={'password': password},
                                 headers={'Authorization': 'Bearer ' + jwt, 'Origin': 'http://127.0.0.1:4200'})
        self.assertEqual(response.status_code, 200, msg=response.text)
        session = requests.Session()
        session.cookies.set(STATE_COOKIE, response.cookies.get(STATE_COOKIE))
        callback = hit_callback(session, provider_login(response.json()['authorizeUrl'], *ALICE))
        self.assertRedirect(callback, 'http://127.0.0.1:4200/account/acc-settings?sso=linked')

        cross_site = requests.post(OIDC_URI + '/link', json={'password': password},
                                   headers={'Authorization': 'Bearer ' + jwt, 'Origin': 'https://evil.example.test'})
        self.assertEqual(cross_site.status_code, 403, msg=cross_site.text)

    def test_link_needs_access_token(self):
        # The JWT middleware rejects it before the handler runs, as on every other authenticated route
        response = requests.post(OIDC_URI + '/link', json={'password': 'whatever'})
        self.assertEqual(response.json()['title'], 'Token not found.', msg=response.text)
        self.assertNotIn(STATE_COOKIE, ''.join(_set_cookies(response)))

    def test_link_then_login(self):
        user, password = self.make_user()

        linked = self.link(user, password)
        self.assertRedirect(linked, DEFAULT_RETURN_TO + '/account/acc-settings?sso=linked')

        session, response = self.sso_login()
        self.assertRedirect(response, DEFAULT_RETURN_TO + '/auth/sso')
        self.assertIsNotNone(session.cookies.get(REFRESH_COOKIE))

        refreshed = session.post(REFRESH_URI)
        self.assertEqual(refreshed.status_code, 201, msg=refreshed.text)
        self.assertEqual(_jwt_payload(refreshed.json()['token'])['userId'], user.id)

    def test_link_identity_owned_by_other_user(self):
        owner, owner_password = self.make_user()
        other, other_password = self.make_user()
        self.assertRedirect(self.link(owner, owner_password), DEFAULT_RETURN_TO + '/account/acc-settings?sso=linked')

        response = self.link(other, other_password)
        self.assertRedirect(response, DEFAULT_RETURN_TO + '/account/acc-settings?sso=error&reason=already_linked')

    def test_link_same_identity_twice_is_success(self):
        user, password = self.make_user()
        self.assertRedirect(self.link(user, password), DEFAULT_RETURN_TO + '/account/acc-settings?sso=linked')
        self.assertRedirect(self.link(user, password), DEFAULT_RETURN_TO + '/account/acc-settings?sso=linked')

    def test_unlinked_login_goes_to_link_required(self):
        session = requests.Session()
        url = start_login(session)
        login_state = _state_of(session)

        response = hit_callback(session, provider_login(url, *BOB))
        self.assertRedirect(response, DEFAULT_RETURN_TO + '/auth?sso=link-required')
        self.assertIn('oidcState=', ''.join(_set_cookies(response)))
        pending_state = _state_of(session)
        self.assertIsNotNone(pending_state)
        self.assertNotEqual(pending_state, login_state)
        self.assertIsNone(session.cookies.get(REFRESH_COOKIE))

    def test_disabled_user(self):
        user, password = self.make_user()
        self.assertRedirect(self.link(user, password), DEFAULT_RETURN_TO + '/account/acc-settings?sso=linked')
        user.isValid = False
        user.save()

        session, response = self.sso_login()
        self.assertRedirect(response, DEFAULT_RETURN_TO + '/auth?sso=error&reason=user_disabled')
        self.assertNotIn(REFRESH_COOKIE + '=', ''.join(_set_cookies(response)))
        self.assertIsNone(session.cookies.get(REFRESH_COOKIE))

    def test_replayed_callback(self):
        session = requests.Session()
        url = start_login(session)
        state = _state_of(session)
        callback = provider_login(url, *BOB)

        first = hit_callback(session, callback)
        self.assertRedirect(first, DEFAULT_RETURN_TO + '/auth?sso=link-required')

        # Same callback with the same cookie a second time
        replay = requests.get(get_hashtopolis_uri() + '/api/v2/auth/oidc/callback?' + callback.split('?', 1)[1],
                              cookies={STATE_COOKIE: state}, allow_redirects=False)
        self.assertRedirect(replay, DEFAULT_RETURN_TO + '/auth?sso=error&reason=expired')

    def test_callback_without_cookie(self):
        url = start_login(requests.Session())
        response = hit_callback(requests.Session(), provider_login(url, *BOB))
        self.assertRedirect(response, DEFAULT_RETURN_TO + '/auth?sso=error&reason=expired')
        self.assertNotIn(STATE_COOKIE, ''.join(_set_cookies(response)))

    def test_provider_error_parameter(self):
        session = requests.Session()
        start_login(session)
        response = session.get(OIDC_URI + '/callback',
                               params={'error': 'access_denied', 'state': _state_of(session)},
                               allow_redirects=False)
        self.assertRedirect(response, DEFAULT_RETURN_TO + '/auth?sso=error&reason=provider_error')

    def test_latest_of_two_logins_wins(self):
        user, password = self.make_user()
        self.assertRedirect(self.link(user, password), DEFAULT_RETURN_TO + '/account/acc-settings?sso=linked')

        # A double click: two logins in the same browser, the second overwrites the first one's cookie
        session = requests.Session()
        older_url = start_login(session)
        newer_url = start_login(session)

        # Completing the superseded attempt fails, but leaves the newer attempt's cookie in place
        older = hit_callback(session, provider_login(older_url, *ALICE))
        self.assertRedirect(older, DEFAULT_RETURN_TO + '/auth?sso=error&reason=expired')
        self.assertNotIn(STATE_COOKIE, ''.join(_set_cookies(older)))

        newer = hit_callback(session, provider_login(newer_url, *ALICE))
        self.assertRedirect(newer, DEFAULT_RETURN_TO + '/auth/sso')
        self.assertIsNotNone(session.cookies.get(REFRESH_COOKIE))

    def test_list_and_unlink_identities(self):
        owner, owner_password = self.make_user()
        other, other_password = self.make_user()
        self.assertRedirect(self.link(owner, owner_password), DEFAULT_RETURN_TO + '/account/acc-settings?sso=linked')
        self.assertRedirect(self.link(other, other_password, BOB), DEFAULT_RETURN_TO + '/account/acc-settings?sso=linked')
        owner_auth = {'Authorization': 'Bearer ' + self.jwt_for(owner, owner_password)}
        other_auth = {'Authorization': 'Bearer ' + self.jwt_for(other, other_password)}

        listed = requests.get(OIDC_URI + '/identities', headers=owner_auth)
        self.assertEqual(listed.status_code, 200, msg=listed.text)
        identities = listed.json()['identities']
        self.assertEqual(len(identities), 1)
        identity = identities[0]
        self.assertEqual(set(identity), {'id', 'label', 'issuer', 'createdAt', 'lastUsedAt'})
        self.assertEqual(identity['label'], 'alice')
        self.assertEqual(identity['issuer'], ISSUER)
        self.assertIsInstance(identity['createdAt'], int)
        self.assertIsNone(identity['lastUsedAt'])

        # Somebody else's identity looks like a missing one
        foreign = requests.delete(f"{OIDC_URI}/identities/{identity['id']}", headers=other_auth)
        self.assertEqual(foreign.status_code, 404, msg=foreign.text)

        deleted = requests.delete(f"{OIDC_URI}/identities/{identity['id']}", headers=owner_auth)
        self.assertEqual(deleted.status_code, 204, msg=deleted.text)
        self.assertEqual(requests.get(OIDC_URI + '/identities', headers=owner_auth).json(), {'identities': []})
        self.assertEqual(len(requests.get(OIDC_URI + '/identities', headers=other_auth).json()['identities']), 1)

    def test_login_updates_last_used(self):
        user, password = self.make_user()
        self.assertRedirect(self.link(user, password), DEFAULT_RETURN_TO + '/account/acc-settings?sso=linked')
        _, response = self.sso_login()
        self.assertRedirect(response, DEFAULT_RETURN_TO + '/auth/sso')

        auth = {'Authorization': 'Bearer ' + self.jwt_for(user, password)}
        identity = requests.get(OIDC_URI + '/identities', headers=auth).json()['identities'][0]
        self.assertIsInstance(identity['lastUsedAt'], int)

    def pending_session(self, provider_user=BOB):
        """A browser whose SSO login with an unlinked identity left a pending link behind."""
        session = requests.Session()
        url = start_login(session)
        response = hit_callback(session, provider_login(url, *provider_user))
        self.assertRedirect(response, DEFAULT_RETURN_TO + '/auth?sso=link-required')
        return session

    def link_pending(self, session, username, password):
        return session.post(OIDC_URI + '/link-pending', json={'username': username, 'password': password})

    def test_link_pending_links_and_logs_in(self):
        user, password = self.make_user()
        session = self.pending_session()

        response = self.link_pending(session, user.name, password)
        self.assertEqual(response.status_code, 204, msg=response.text)
        self.assertIsNotNone(session.cookies.get(REFRESH_COOKIE))
        self.assertIn(STATE_COOKIE + '=;', ''.join(_set_cookies(response)))

        refreshed = session.post(REFRESH_URI)
        self.assertEqual(refreshed.status_code, 201, msg=refreshed.text)
        self.assertEqual(_jwt_payload(refreshed.json()['token'])['userId'], user.id)

        # The identity is linked now, so the next SSO login goes straight in
        _, login = self.sso_login(BOB)
        self.assertRedirect(login, DEFAULT_RETURN_TO + '/auth/sso')
        auth = {'Authorization': 'Bearer ' + self.jwt_for(user, password)}
        identities = requests.get(OIDC_URI + '/identities', headers=auth).json()['identities']
        self.assertEqual([i['label'] for i in identities], ['bob'])

    def test_link_pending_wrong_password_can_retry(self):
        user, password = self.make_user()
        session = self.pending_session()

        wrong = self.link_pending(session, user.name, 'wrong-' + password)
        self.assertEqual(wrong.status_code, 401, msg=wrong.text)
        self.assertIsNone(session.cookies.get(REFRESH_COOKIE))
        unknown = self.link_pending(session, 'no-such-user-' + uuid.uuid4().hex[:8], password)
        self.assertEqual(unknown.status_code, 401, msg=unknown.text)

        retry = self.link_pending(session, user.name, password)
        self.assertEqual(retry.status_code, 204, msg=retry.text)

    def test_link_pending_without_cookie_401(self):
        user, password = self.make_user()
        response = requests.post(OIDC_URI + '/link-pending', json={'username': user.name, 'password': password})
        self.assertEqual(response.status_code, 401, msg=response.text)
        self.assertNotIn(REFRESH_COOKIE + '=', ''.join(_set_cookies(response)))

    def test_link_pending_needs_username_and_password(self):
        session = self.pending_session()
        response = session.post(OIDC_URI + '/link-pending', json={'username': 'someone'})
        self.assertEqual(response.status_code, 400, msg=response.text)

    def test_link_pending_single_use(self):
        user, password = self.make_user()
        session = self.pending_session()
        state = _state_of(session)
        self.assertEqual(self.link_pending(session, user.name, password).status_code, 204)

        # The state cookie was cleared, but a copy of it must not work a second time either
        replay = requests.post(OIDC_URI + '/link-pending', json={'username': user.name, 'password': password},
                               cookies={STATE_COOKIE: state})
        self.assertEqual(replay.status_code, 401, msg=replay.text)

    def test_link_pending_disabled_user_403_no_link(self):
        user, password = self.make_user()
        user.isValid = False
        user.save()
        session = self.pending_session()

        response = self.link_pending(session, user.name, password)
        self.assertEqual(response.status_code, 403, msg=response.text)
        self.assertIsNone(session.cookies.get(REFRESH_COOKIE))

        # Nothing was linked and the request is not used up: re-enabled, the same attempt now works
        user.isValid = True
        user.save()
        auth = {'Authorization': 'Bearer ' + self.jwt_for(user, password)}
        self.assertEqual(requests.get(OIDC_URI + '/identities', headers=auth).json(), {'identities': []})
        self.assertEqual(self.link_pending(session, user.name, password).status_code, 204)

    def test_link_pending_identity_owned_by_other_user_409(self):
        owner, owner_password = self.make_user()
        other, other_password = self.make_user()
        self.assertRedirect(self.link(owner, owner_password, BOB), DEFAULT_RETURN_TO + '/account/acc-settings?sso=linked')
        # BOB is linked, so a login would not be pending; start the pending request before the link instead
        session = requests.Session()
        url = start_login(session)
        callback = provider_login(url, *BOB)
        # Unlink, let the login become pending, then link the identity to the owner again
        auth = {'Authorization': 'Bearer ' + self.jwt_for(owner, owner_password)}
        identity = requests.get(OIDC_URI + '/identities', headers=auth).json()['identities'][0]
        requests.delete(f"{OIDC_URI}/identities/{identity['id']}", headers=auth)
        self.assertRedirect(hit_callback(session, callback), DEFAULT_RETURN_TO + '/auth?sso=link-required')
        self.assertRedirect(self.link(owner, owner_password, BOB), DEFAULT_RETURN_TO + '/account/acc-settings?sso=linked')

        response = self.link_pending(session, other.name, other_password)
        self.assertEqual(response.status_code, 409, msg=response.text)
        self.assertIsNone(session.cookies.get(REFRESH_COOKIE))

    def test_existing_oauth_token_endpoint_untouched(self):
        # Without /keys/jwks.json the dev server also prints a PHP warning before the problem JSON, which
        # sends the status line early; so compare the error text, which is what master answers with.
        response = requests.post(OAUTH_TOKEN_URI)
        expected = 'No jwt Token found in the Bearer header' if os.path.exists('/keys/jwks.json') \
            else 'No jwks.json found, upload the jwks public keys to /keys/jwks.json to use OIDC authentication'
        self.assertIn(expected, response.text)
        self.assertNotIn('refreshToken', ''.join(_set_cookies(response)))
