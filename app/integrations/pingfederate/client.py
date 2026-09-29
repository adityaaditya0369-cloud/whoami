"""Read-only PingFederate sources (what is actually configured).

* LivePfClient  - PingFederate Admin API, GET only. Use an account with the
                  read-only "Auditor" admin role.
* FilePfSource  - export folder with the same JSON shapes:
                      sp_connections.json   (GET /idp/spConnections)
                      oauth_clients.json    (GET /oauth/clients)
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Protocol

import requests

from app.config import PfSourceMode, Settings

log = logging.getLogger(__name__)


class PfError(Exception):
    pass


class PfSource(Protocol):
    def describe(self) -> str: ...
    def list_sp_connections(self) -> list[dict]: ...
    def list_oauth_clients(self) -> list[dict]: ...


def _items(body) -> list[dict]:
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        return list(body.get("items") or [])
    raise PfError("Unexpected response shape from PingFederate")


class LivePfClient:
    def __init__(self, settings: Settings, session: requests.Session | None = None):
        self.s = settings
        self.base = settings.pf_admin_url.rstrip("/")
        self.http = session or requests.Session()
        self.http.auth = (settings.pf_admin_user, settings.pf_admin_password.get_secret_value())
        # PingFederate's Admin API requires this header on every call (CSRF protection).
        self.http.headers.update({"X-XSRF-Header": "PingFederate", "Accept": "application/json"})
        self.verify = str(settings.pf_ca_bundle) if settings.pf_ca_bundle else True

    def describe(self) -> str:
        return self.base

    def _get_all(self, path: str) -> list[dict]:
        out: list[dict] = []
        page, per_page = 1, 100
        while True:
            resp = self.http.get(f"{self.base}{path}", params={"page": page, "numberPerPage": per_page},
                                 timeout=self.s.pf_timeout_seconds, verify=self.verify)
            if resp.status_code >= 400:
                raise PfError(f"GET {path} -> {resp.status_code}: {resp.text[:300]}")
            body = resp.json()
            items = _items(body)
            out.extend(items)
            total = body.get("totalCount") if isinstance(body, dict) else None
            if not items or total is None or len(out) >= int(total) or len(items) < per_page:
                return out
            page += 1

    def list_sp_connections(self) -> list[dict]:
        return self._get_all("/idp/spConnections")

    def list_oauth_clients(self) -> list[dict]:
        return self._get_all("/oauth/clients")

    def export_to(self, out_dir: Path) -> dict:
        out_dir.mkdir(parents=True, exist_ok=True)
        sp, oc = self.list_sp_connections(), self.list_oauth_clients()
        (out_dir / "sp_connections.json").write_text(json.dumps({"items": sp}, indent=2), encoding="utf-8")
        (out_dir / "oauth_clients.json").write_text(json.dumps({"items": oc}, indent=2), encoding="utf-8")
        return {"sp_connections": len(sp), "oauth_clients": len(oc)}


class FilePfSource:
    def __init__(self, export_dir: Path):
        self.dir = Path(export_dir)
        if not self.dir.exists():
            raise PfError(f"PingFederate export folder not found: {self.dir}")

    def describe(self) -> str:
        return str(self.dir)

    def _load(self, name: str) -> list[dict]:
        p = self.dir / name
        return _items(json.loads(p.read_text(encoding="utf-8"))) if p.exists() else []

    def list_sp_connections(self) -> list[dict]:
        return self._load("sp_connections.json")

    def list_oauth_clients(self) -> list[dict]:
        return self._load("oauth_clients.json")


def build_pf_source(settings: Settings) -> PfSource | None:
    if settings.pf_source == PfSourceMode.LIVE:
        return LivePfClient(settings)
    if settings.pf_source == PfSourceMode.FILE:
        return FilePfSource(settings.pf_export_dir)
    return None
