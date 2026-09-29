"""Okta data sources.

Two implementations share one interface:

* LiveOktaClient - calls the Okta Management API (read-only scopes only).
* FileOktaSource - reads an offline export directory with the same JSON
  shapes. Use this when the customer's security team will not grant API
  access to the migration team: they run `flask okta-export` themselves and
  hand over the folder.

Export directory layout:
    apps.json
    groups.json
    apps/<appId>/groups.json
    apps/<appId>/users.json
    apps/<appId>/keys.json
    apps/<appId>/metadata.xml       (SAML apps only, optional)
    tenant/<kind>.json              (optional: policies, authenticators, group_rules,
                                     authorization_servers, inline_hooks, event_hooks, idps, network_zones)
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Iterator, Protocol

import jwt
import requests

from app.config import OktaAuthMode, Settings

log = logging.getLogger(__name__)

SAML_MODES = {"SAML_2_0", "SAML_1_1"}
OIDC_MODES = {"OPENID_CONNECT"}


class OktaError(Exception):
    pass


class UsageUnavailable(Exception):
    """System Log not readable (missing okta.logs.read) or not in the export."""


class TenantUnavailable(Exception):
    """A tenant object kind could not be read (missing scope / not in the export)."""
    def __init__(self, msg: str, status: str = "UNAVAILABLE"):
        super().__init__(msg)
        self.status = status


# Tenant-level object kinds -> (Management API path, read scope). All GET-only.
TENANT_KINDS: dict[str, tuple[str, str]] = {
    "policies": ("/api/v1/policies", "okta.policies.read"),
    "authenticators": ("/api/v1/authenticators", "okta.authenticators.read"),
    "group_rules": ("/api/v1/groups/rules", "okta.groups.read"),
    "authorization_servers": ("/api/v1/authorizationServers", "okta.authorizationServers.read"),
    "inline_hooks": ("/api/v1/inlineHooks", "okta.inlineHooks.read"),
    "event_hooks": ("/api/v1/eventHooks", "okta.eventHooks.read"),
    "idps": ("/api/v1/idps", "okta.idps.read"),
    "network_zones": ("/api/v1/zones", "okta.networkZones.read"),
}
POLICY_TYPES = ["OKTA_SIGN_ON", "ACCESS_POLICY", "MFA_ENROLL", "PASSWORD", "PROFILE_ENROLLMENT", "IDP_DISCOVERY"]


USAGE_FILTER = ('target.id eq "{app_id}" and (eventType eq "user.authentication.sso" '
                'or eventType sw "app.oauth2")')


class OktaSource(Protocol):
    def describe(self) -> str: ...
    def list_apps(self) -> list[dict]: ...
    def list_groups(self) -> list[dict]: ...
    def list_app_groups(self, app_id: str) -> list[dict]: ...
    def list_app_users(self, app_id: str) -> list[dict]: ...
    def list_app_keys(self, app_id: str) -> list[dict]: ...
    def get_app_metadata(self, app: dict) -> str | None: ...
    def list_app_usage_events(self, app_id: str, days: int, max_events: int) -> list[dict]: ...
    def list_tenant(self, kind: str) -> list[dict]: ...


# ---------------------------------------------------------------------------
class LiveOktaClient:
    """Read-only Okta Management API client.

    Handles Link-header pagination, 429 rate limiting (X-Rate-Limit-Reset),
    transient 5xx retries, and token caching for OAuth. Never logs secrets.
    """

    def __init__(self, settings: Settings, session: requests.Session | None = None):
        self.s = settings
        self.base = settings.okta_org
        self.http = session or requests.Session()
        self.http.headers.update({"Accept": "application/json",
                                  "User-Agent": "okta-pingfederate-migration-factory/0.1"})
        self._token: str | None = None
        self._token_exp: float = 0.0

    def describe(self) -> str:
        return self.base or ""

    # --- auth ------------------------------------------------------------
    def _auth_header(self) -> dict:
        if self.s.okta_auth_mode == OktaAuthMode.SSWS:
            return {"Authorization": f"SSWS {self.s.okta_api_token.get_secret_value()}"}
        if not self._token or time.time() > self._token_exp - 60:
            self._fetch_oauth_token()
        return {"Authorization": f"Bearer {self._token}"}

    def _fetch_oauth_token(self) -> None:
        token_url = f"{self.base}/oauth2/v1/token"
        key = Path(self.s.okta_private_key_path).read_text()
        now = int(time.time())
        headers = {"kid": self.s.okta_private_key_kid} if self.s.okta_private_key_kid else None
        assertion = jwt.encode(
            {"iss": self.s.okta_client_id, "sub": self.s.okta_client_id, "aud": token_url,
             "iat": now, "exp": now + 300, "jti": str(uuid.uuid4())},
            key, algorithm="RS256", headers=headers,
        )
        resp = self.http.post(token_url, timeout=self.s.okta_timeout_seconds, data={
            "grant_type": "client_credentials",
            "scope": self.s.okta_scopes,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
        }, headers={"Accept": "application/json"})
        if resp.status_code != 200:
            # Okta error bodies do not contain secrets; safe to surface.
            raise OktaError(f"OAuth token request failed ({resp.status_code}): {resp.text[:500]}")
        body = resp.json()
        self._token = body["access_token"]
        self._token_exp = time.time() + int(body.get("expires_in", 3600))

    # --- transport ---------------------------------------------------------
    def _request(self, url: str, params: dict | None = None,
                 accept: str = "application/json") -> requests.Response:
        attempt = 0
        while True:
            attempt += 1
            headers = {**self._auth_header(), "Accept": accept}
            resp = self.http.get(url, params=params, headers=headers,
                                 timeout=self.s.okta_timeout_seconds)
            if resp.status_code == 429 and attempt <= self.s.okta_max_retries:
                reset = resp.headers.get("X-Rate-Limit-Reset")
                wait = max(1.0, float(reset) - time.time()) if reset else 2.0 ** attempt
                log.warning("Okta rate limit hit on %s; sleeping %.1fs", url.split("?")[0], wait)
                time.sleep(min(wait, 60))
                continue
            if resp.status_code >= 500 and attempt <= self.s.okta_max_retries:
                time.sleep(min(2.0 ** attempt, 30))
                continue
            if resp.status_code == 401 and self.s.okta_auth_mode == OktaAuthMode.OAUTH and attempt == 1:
                self._token = None
                continue
            if resp.status_code >= 400:
                raise OktaError(f"GET {url.split('?')[0]} -> {resp.status_code}: {resp.text[:500]}")
            return resp

    def _paginate(self, path: str, params: dict | None = None) -> Iterator[dict]:
        url: str | None = f"{self.base}{path}"
        first = True
        while url:
            resp = self._request(url, params=params if first else None)
            first = False
            data = resp.json()
            if not isinstance(data, list):
                raise OktaError(f"Expected a list from {path}")
            yield from data
            url = resp.links.get("next", {}).get("url")

    # --- API ---------------------------------------------------------------
    def list_apps(self) -> list[dict]:
        return list(self._paginate("/api/v1/apps", {"limit": 200}))

    def list_groups(self) -> list[dict]:
        return list(self._paginate("/api/v1/groups", {"limit": 200, "expand": "stats,app"}))

    def list_app_groups(self, app_id: str) -> list[dict]:
        return list(self._paginate(f"/api/v1/apps/{app_id}/groups", {"limit": 200}))

    def list_app_users(self, app_id: str) -> list[dict]:
        return list(self._paginate(f"/api/v1/apps/{app_id}/users", {"limit": 500, "expand": "user"}))

    def list_app_keys(self, app_id: str) -> list[dict]:
        return self._request(f"{self.base}/api/v1/apps/{app_id}/credentials/keys").json()

    def get_app_metadata(self, app: dict) -> str | None:
        href = app.get("_links", {}).get("metadata", {}).get("href")
        url = href or f"{self.base}/api/v1/apps/{app['id']}/sso/saml/metadata"
        try:
            return self._request(url, accept="application/xml").text
        except OktaError as exc:
            log.warning("Could not fetch SAML metadata for %s: %s", app.get("id"), exc)
            return None

    def list_app_usage_events(self, app_id: str, days: int, max_events: int) -> list[dict]:
        """Sign-in events for one app from the System Log. The log API keeps
        returning a 'next' link (it is a polling API), so stop on a short page."""
        since = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - days * 86400))
        url: str | None = f"{self.base}/api/v1/logs"
        params = {"since": since, "limit": 1000, "sortOrder": "ASCENDING",
                  "filter": USAGE_FILTER.format(app_id=app_id)}
        events: list[dict] = []
        try:
            while url and len(events) < max_events:
                resp = self._request(url, params=params)
                params = None
                page = resp.json()
                events.extend(page)
                if len(page) < 1000:
                    break
                url = resp.links.get("next", {}).get("url")
        except OktaError as exc:
            if " 403" in str(exc) or "-> 403" in str(exc):
                raise UsageUnavailable("System Log not readable: grant okta.logs.read") from exc
            raise
        return events[:max_events]

    def list_tenant(self, kind: str) -> list[dict]:
        """Tenant-level objects. Policies carry their rules and authorization servers their
        scopes/claims/policies under "_embedded", so one export file per kind is enough."""
        if kind not in TENANT_KINDS:
            raise ValueError(f"Unknown tenant kind {kind}")
        path, scope = TENANT_KINDS[kind]
        unavailable = ("-> 400", "-> 401", "-> 403", "-> 404")
        try:
            if kind == "policies":
                out, failed = [], []
                for ptype in POLICY_TYPES:     # one type failing (e.g. Classic Engine) does not lose the others
                    try:
                        for p in self._paginate(path, {"type": ptype}):
                            p.setdefault("_embedded", {})["rules"] = list(self._paginate(f"{path}/{p['id']}/rules"))
                            out.append(p)
                    except OktaError as exc:
                        if not any(c in str(exc) for c in unavailable):
                            raise
                        failed.append(ptype)
                if failed and not out:
                    raise TenantUnavailable(f"policies: not readable (grant {scope})")
                return out
            items = list(self._paginate(path)) if kind != "authenticators" else self._request(f"{self.base}{path}").json()
            if kind == "authorization_servers":
                for a in items:
                    base = f"{path}/{a['id']}"
                    a.setdefault("_embedded", {}).update({
                        "scopes": list(self._paginate(f"{base}/scopes")),
                        "claims": list(self._paginate(f"{base}/claims")),
                        "policies": list(self._paginate(f"{base}/policies"))})
            return items
        except OktaError as exc:
            if any(c in str(exc) for c in unavailable):
                raise TenantUnavailable(f"{kind}: not readable (grant {scope}, or not available in this Okta "
                                        "edition)") from exc
            raise

    # --- export ---------------------------------------------------------------
    def export_to(self, out_dir: Path, saml_only_details: bool = True) -> dict:
        """Write a FileOktaSource-compatible export. Returns counts."""
        out_dir.mkdir(parents=True, exist_ok=True)
        apps = self.list_apps()
        _write_json(out_dir / "apps.json", apps)
        _write_json(out_dir / "groups.json", self.list_groups())
        detailed = 0
        for app in apps:
            mode = app.get("signOnMode")
            if saml_only_details and mode not in SAML_MODES | OIDC_MODES:
                continue
            d = out_dir / "apps" / app["id"]
            d.mkdir(parents=True, exist_ok=True)
            _write_json(d / "groups.json", self.list_app_groups(app["id"]))
            _write_json(d / "users.json", self.list_app_users(app["id"]))
            try:
                _write_json(d / "logs.json", self.list_app_usage_events(app["id"], 90, 20000))
            except UsageUnavailable:
                pass
            if mode in SAML_MODES:
                _write_json(d / "keys.json", self.list_app_keys(app["id"]))
                md = self.get_app_metadata(app)
                if md:
                    (d / "metadata.xml").write_text(md, encoding="utf-8")
            detailed += 1
        tenant = 0
        for kind in TENANT_KINDS:
            try:
                _write_json(out_dir / "tenant" / f"{kind}.json", self.list_tenant(kind))
                tenant += 1
            except TenantUnavailable as exc:
                log.warning("Export: %s", exc)
        return {"apps": len(apps), "detailed_apps": detailed, "tenant_kinds": tenant}


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


# ---------------------------------------------------------------------------
class FileOktaSource:
    def __init__(self, export_dir: Path):
        self.dir = Path(export_dir)
        if not (self.dir / "apps.json").exists():
            raise OktaError(f"No apps.json in export directory {self.dir}")

    def describe(self) -> str:
        return str(self.dir)

    def _load(self, *parts: str, default=None):
        p = self.dir.joinpath(*parts)
        if not p.exists():
            return [] if default is None else default
        return json.loads(p.read_text(encoding="utf-8"))

    def list_apps(self) -> list[dict]:
        return self._load("apps.json")

    def list_groups(self) -> list[dict]:
        return self._load("groups.json")

    def list_app_groups(self, app_id: str) -> list[dict]:
        return self._load("apps", app_id, "groups.json")

    def list_app_users(self, app_id: str) -> list[dict]:
        return self._load("apps", app_id, "users.json")

    def list_app_keys(self, app_id: str) -> list[dict]:
        return self._load("apps", app_id, "keys.json")

    def list_app_usage_events(self, app_id: str, days: int, max_events: int) -> list[dict]:
        p = self.dir / "apps" / app_id / "logs.json"
        if not p.exists():
            raise UsageUnavailable("No logs.json in the export for this app")
        return json.loads(p.read_text(encoding="utf-8"))[:max_events]

    def list_tenant(self, kind: str) -> list[dict]:
        if kind not in TENANT_KINDS:
            raise ValueError(f"Unknown tenant kind {kind}")
        p = self.dir / "tenant" / f"{kind}.json"
        if not p.exists():
            raise TenantUnavailable(f"{kind}: not in the export (tenant/{kind}.json)", status="NOT_EXPORTED")
        return json.loads(p.read_text(encoding="utf-8"))

    def get_app_metadata(self, app: dict) -> str | None:
        p = self.dir / "apps" / app["id"] / "metadata.xml"
        return p.read_text(encoding="utf-8") if p.exists() else None


def build_source(settings: Settings) -> OktaSource:
    from app.config import OktaSourceMode
    if settings.okta_source == OktaSourceMode.LIVE:
        return LiveOktaClient(settings)
    return FileOktaSource(settings.okta_export_dir)
