"""PingFederate Admin API - the ONLY code that writes to PingFederate.

Deliberately narrow:
* create an SP connection (POST /idp/spConnections) - nothing else. There is no
  update, no delete and no OAuth-client write in this class, on purpose.
* uses a separate write account (PF_WRITE_USER), never the read-only Auditor one.
* read helpers used by the dry run (does the entity ID exist, do referenced IDs exist).
Called only from app.services.pf_write after approval + dry run.
"""
from __future__ import annotations

from urllib.parse import quote

import requests

from app.config import Settings
from app.integrations.pingfederate.client import PfError


class PfWriter:
    def __init__(self, settings: Settings, session: requests.Session | None = None):
        if not settings.pf_write_enabled:
            raise PfError("PingFederate writes are disabled (PF_WRITE_ENABLED=false)")
        if not (settings.pf_admin_url and settings.pf_write_user and settings.pf_write_password):
            raise PfError("PF_ADMIN_URL, PF_WRITE_USER and PF_WRITE_PASSWORD are required to write")
        self.s = settings
        self.base = settings.pf_admin_url.rstrip("/")
        self.http = session or requests.Session()
        self.http.auth = (settings.pf_write_user, settings.pf_write_password.get_secret_value())
        self.http.headers.update({"X-XSRF-Header": "PingFederate", "Accept": "application/json",
                                  "Content-Type": "application/json"})
        self.verify = str(settings.pf_ca_bundle) if settings.pf_ca_bundle else True

    def describe(self) -> str:
        return self.base

    def _get(self, path: str, **params):
        return self.http.get(f"{self.base}{path}", params=params or None, timeout=self.s.pf_timeout_seconds,
                             verify=self.verify)

    def find_sp_connection(self, entity_id: str) -> dict | None:
        resp = self._get("/idp/spConnections", entityId=entity_id)
        if resp.status_code >= 400:
            raise PfError(f"GET /idp/spConnections -> {resp.status_code}: {resp.text[:300]}")
        body = resp.json()
        items = body.get("items", []) if isinstance(body, dict) else body
        return next((c for c in items if (c.get("entityId") or "") == entity_id), None)

    def ref_exists(self, path: str) -> bool:
        resp = self._get(path)
        if resp.status_code == 404:
            return False
        if resp.status_code >= 400:
            raise PfError(f"GET {path} -> {resp.status_code}: {resp.text[:300]}")
        return True

    def create_sp_connection(self, payload: dict) -> dict:
        if payload.get("active") is not False:
            raise PfError("Refusing to create an active connection; it must be created disabled")
        resp = self.http.post(f"{self.base}/idp/spConnections", json=payload, timeout=self.s.pf_timeout_seconds,
                              verify=self.verify)
        if resp.status_code >= 400:
            try:
                body = resp.json()
                msgs = [body.get("message") or ""] + [f"{e.get('fieldPath', '')}: {e.get('message', '')}"
                                                      for e in body.get("validationErrors") or []]
                detail = "; ".join(m for m in msgs if m)[:1500]
            except ValueError:
                detail = resp.text[:500]
            raise PfError(f"POST /idp/spConnections -> {resp.status_code}: {detail}")
        return resp.json()


def ref_paths(payload: dict) -> dict[str, str]:
    """Admin API paths of the objects an SP connection payload refers to."""
    out = {}
    sso = payload.get("spBrowserSso") or {}
    for m in sso.get("adapterMappings") or []:
        if (m.get("idpAdapterRef") or {}).get("id"):
            out["IdP adapter"] = f"/idp/adapters/{quote(m['idpAdapterRef']['id'], safe='')}"
        for src in m.get("attributeSources") or []:
            if (src.get("dataStoreRef") or {}).get("id"):
                out["LDAP data store"] = f"/dataStores/{quote(src['dataStoreRef']['id'], safe='')}"
    kp = ((payload.get("credentials") or {}).get("signingSettings") or {}).get("signingKeyPairRef") or {}
    if kp.get("id"):
        out["Signing key pair"] = f"/keyPairs/signing/{quote(kp['id'], safe='')}"
    return out
