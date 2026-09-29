"""LiveOktaClient transport behaviour, without network access."""
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import Settings
from app.integrations.okta.client import LiveOktaClient, OktaError

ORG = "https://example.okta.com"


class FakeResp:
    def __init__(self, status=200, body=None, headers=None, next_url=None, text=""):
        self.status_code, self._body, self.headers = status, body, headers or {}
        self.links = {"next": {"url": next_url}} if next_url else {}
        self.text = text

    def json(self):
        return self._body


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(("GET", url, params, headers))
        return self.responses.pop(0)

    def post(self, url, data=None, headers=None, timeout=None):
        self.calls.append(("POST", url, data, headers))
        return self.responses.pop(0)


def ssws_settings(**kw):
    return Settings(OKTA_SOURCE="live", OKTA_ORG_URL=ORG, OKTA_AUTH_MODE="ssws",
                    OKTA_API_TOKEN="00secret", _env_file=None, **kw)


def test_pagination_follows_link_header():
    fs = FakeSession([FakeResp(body=[{"id": 1}], next_url=f"{ORG}/api/v1/apps?after=1"),
                      FakeResp(body=[{"id": 2}])])
    apps = LiveOktaClient(ssws_settings(), fs).list_apps()
    assert [a["id"] for a in apps] == [1, 2]
    assert fs.calls[0][2] == {"limit": 200}
    assert fs.calls[1][2] is None            # params not re-sent on the cursor URL
    assert fs.calls[0][3]["Authorization"] == "SSWS 00secret"


def test_rate_limit_waits_for_reset(monkeypatch):
    slept = []
    monkeypatch.setattr(time, "sleep", lambda s: slept.append(s))
    reset = str(int(time.time()) + 3)
    fs = FakeSession([FakeResp(429, headers={"X-Rate-Limit-Reset": reset}), FakeResp(body=[])])
    assert LiveOktaClient(ssws_settings(), fs).list_groups() == []
    assert slept and 1 <= slept[0] <= 4


def test_gives_up_after_max_retries(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda s: None)
    fs = FakeSession([FakeResp(503)] * 3)
    with pytest.raises(OktaError):
        LiveOktaClient(ssws_settings(OKTA_MAX_RETRIES=2), fs).list_apps()


def test_client_error_is_raised_without_secret():
    fs = FakeSession([FakeResp(403, text='{"errorCode":"E0000006"}')])
    with pytest.raises(OktaError) as e:
        LiveOktaClient(ssws_settings(), fs).list_apps()
    assert "00secret" not in str(e.value) and "403" in str(e.value)


def test_oauth_private_key_jwt(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = tmp_path / "key.pem"
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    s = Settings(OKTA_SOURCE="live", OKTA_ORG_URL=ORG, OKTA_AUTH_MODE="oauth",
                 OKTA_CLIENT_ID="0oaSVC", OKTA_PRIVATE_KEY_PATH=str(pem), OKTA_PRIVATE_KEY_KID="k1",
                 _env_file=None)
    fs = FakeSession([FakeResp(body={"access_token": "tok", "expires_in": 3600}), FakeResp(body=[])])
    LiveOktaClient(s, fs).list_apps()
    _, url, data, _ = fs.calls[0]
    assert url == f"{ORG}/oauth2/v1/token"
    assert data["scope"] == "okta.apps.read okta.groups.read okta.users.read okta.logs.read"
    claims = jwt.decode(data["client_assertion"], key.public_key(), algorithms=["RS256"],
                        audience=f"{ORG}/oauth2/v1/token")
    assert claims["iss"] == claims["sub"] == "0oaSVC"
    assert jwt.get_unverified_header(data["client_assertion"])["kid"] == "k1"
    assert fs.calls[1][3]["Authorization"] == "Bearer tok"


def test_live_settings_validation():
    with pytest.raises(ValueError):
        Settings(OKTA_SOURCE="live", _env_file=None)
    with pytest.raises(ValueError):
        Settings(OKTA_SOURCE="live", OKTA_ORG_URL="http://insecure.okta.com", OKTA_AUTH_MODE="ssws",
                 OKTA_API_TOKEN="x", _env_file=None)
