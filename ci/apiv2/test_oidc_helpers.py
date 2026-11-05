"""Checks how the OIDC API tests decide whether to run, without a server or provider."""
import pytest

import oidc_helpers


@pytest.fixture
def unreachable_provider(monkeypatch):
    """SSO is configured, but the provider never answers discovery."""
    monkeypatch.setenv('HASHTOPOLIS_OIDC_ISSUER', 'http://idp.example.test/realms/test')
    monkeypatch.setenv('HASHTOPOLIS_OIDC_CLIENT_ID', 'hashtopolis')
    monkeypatch.setattr(oidc_helpers, '_provider_reachable', lambda issuer: False)
    monkeypatch.setattr(oidc_helpers, '_status', None)


def test_unreachable_provider_skips_locally(unreachable_provider, monkeypatch):
    monkeypatch.delenv('CI', raising=False)
    assert oidc_helpers.oidc_enabled() is False


def test_unreachable_provider_fails_in_ci(unreachable_provider, monkeypatch):
    monkeypatch.setenv('CI', 'true')
    with pytest.raises(RuntimeError, match='unreachable'):
        oidc_helpers.oidc_enabled()
    # Every later caller fails too, rather than reading a cached "not enabled" and skipping
    with pytest.raises(RuntimeError, match='unreachable'):
        oidc_helpers.oidc_enabled()


def test_unconfigured_sso_skips_in_ci(monkeypatch):
    monkeypatch.setenv('CI', 'true')
    monkeypatch.delenv('HASHTOPOLIS_OIDC_ISSUER', raising=False)
    monkeypatch.setattr(oidc_helpers, '_status', None)
    assert oidc_helpers.oidc_enabled() is False
