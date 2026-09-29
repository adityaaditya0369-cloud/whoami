"""Okta app (expected) <-> PingFederate object (actual) reconciliation.

Match key: SAML = SP entity ID, OIDC = client ID. Catalog apps whose entity ID
Okta does not expose fall back to an exact (case-insensitive) name match.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db import Application, MigrationTask, PfObject

NOT_BUILT, MATCHES, DIFFERS = "NOT_BUILT", "MATCHES", "DIFFERS"
BUILD_STATUSES = ["BLOCKED", "READY_TO_BUILD", "BUILT_WITH_DIFFERENCES", "BUILT", "VERIFIED", "OUT_OF_SCOPE"]
BUILD_LABEL = {
    "BLOCKED": "Blocked", "READY_TO_BUILD": "Ready to build", "BUILT_WITH_DIFFERENCES": "Built - differs",
    "BUILT": "Built", "VERIFIED": "Verified", "OUT_OF_SCOPE": "Out of scope",
}


@dataclass
class Check:
    check: str
    expected: str
    actual: str
    ok: bool
    severity: str = "WARNING"     # CRITICAL for security-relevant gaps


@dataclass
class Recon:
    app: Application
    pf: PfObject | None
    status: str
    matched_by: str = ""
    checks: list[Check] = field(default_factory=list)

    @property
    def problems(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]


def _j(xs) -> str:
    return ", ".join(sorted(str(x) for x in xs)) or "—"


def expected_kind(app: Application) -> str | None:
    return "SP_CONNECTION" if app.is_saml else ("OAUTH_CLIENT" if app.is_oidc else None)


def expected_key(app: Application) -> str | None:
    if app.is_saml and app.saml:
        return app.saml.audience
    if app.is_oidc and app.oidc:
        return app.oidc.client_id
    return None


def _saml_checks(app: Application, pf: PfObject) -> list[Check]:
    s, d = app.saml, pf.details or {}
    codes = {f.code for f in app.findings}
    out = []
    exp_acs = {e.get("url") for e in (s.acs_endpoints or [])} or ({s.sso_acs_url} if s.sso_acs_url else set())
    got_acs = {e.get("url") for e in d.get("acs_urls") or []}
    if exp_acs:
        out.append(Check("ACS URLs", _j(exp_acs), _j(got_acs), exp_acs <= got_acs))
    exp_attr = {c.name for c in app.claims} | {"SAML_SUBJECT"}
    got_attr = set(d.get("attributes") or [])
    missing = exp_attr - got_attr
    out.append(Check("Attribute contract", _j(exp_attr), _j(got_attr) + (f" (missing: {_j(missing)})" if missing else ""),
                     not missing))
    if s.assertion_signed:
        out.append(Check("Sign assertion", "Yes", "Yes" if d.get("sign_assertions") else "No",
                         bool(d.get("sign_assertions"))))
    if "CUSTOM_IDP_ISSUER" in codes:
        out.append(Check("Virtual server ID", s.idp_issuer or "", _j(d.get("virtual_identities") or []),
                         s.idp_issuer in (d.get("virtual_identities") or [])))
    if "ISSUANCE_CRITERIA_REQUIRED" in codes:
        out.append(Check("Issuance criteria (access control)", "Required",
                         "Present" if d.get("has_issuance_criteria") else "None",
                         bool(d.get("has_issuance_criteria")), "CRITICAL"))
    if s.slo_enabled:
        out.append(Check("Single logout", s.slo_logout_url or "Enabled", _j(d.get("slo_urls") or []),
                         bool(d.get("slo_urls"))))
    return out


def _oidc_checks(app: Application, pf: PfObject) -> list[Check]:
    o, d = app.oidc, pf.details or {}
    out = []
    exp_r, got_r = set(o.redirect_uris or []), set(d.get("redirect_uris") or [])
    if exp_r:
        out.append(Check("Redirect URIs", _j(exp_r), _j(got_r), exp_r <= got_r))
    exp_g, got_g = set(o.grant_types or []), set(d.get("grant_types") or [])
    out.append(Check("Grant types", _j(exp_g), _j(got_g), exp_g == got_g or (
        "implicit" in exp_g and (exp_g - {"implicit"}) <= got_g)))   # moving off implicit is allowed
    want = {"client_secret_basic": "client_secret", "client_secret_post": "client_secret",
            "client_secret_jwt": "client_secret", "private_key_jwt": "private_key_jwt", "none": "none"}.get(
        o.token_endpoint_auth_method or "", o.token_endpoint_auth_method)
    out.append(Check("Client authentication", want or "—", d.get("client_auth") or "—", want == d.get("client_auth")))
    public = o.token_endpoint_auth_method == "none" or o.application_type in ("native", "browser")
    if public or o.pkce_required:
        out.append(Check("PKCE required", "Yes", "Yes" if d.get("pkce_required") else "No",
                         bool(d.get("pkce_required")), "CRITICAL" if public else "WARNING"))
    out.append(Check("Access control", "Authentication policy / issuance criteria",
                     "Verify in PingFederate policies (not on the client)", True, "INFO"))
    return out


def reconcile(session: Session) -> tuple[list[Recon], list[PfObject]]:
    """Returns (one Recon per in-scope app, PF objects not matched to any Okta app)."""
    objs = session.scalars(select(PfObject).where(PfObject.removed.is_(False))).all()
    by_key = {(o.kind, o.key): o for o in objs}
    by_name = {(o.kind, o.name.strip().lower()): o for o in objs}
    apps = session.scalars(select(Application).where(Application.removed_from_okta.is_(False))
                           .order_by(Application.label)).all()
    used: dict[int, str] = {}
    out: list[Recon] = []
    for a in apps:
        kind = expected_kind(a)
        if not kind:
            continue
        key = expected_key(a)
        pf, how = None, ""
        if key and (kind, key) in by_key:
            pf, how = by_key[(kind, key)], "entity ID" if kind == "SP_CONNECTION" else "client ID"
        elif (kind, a.label.strip().lower()) in by_name:
            pf, how = by_name[(kind, a.label.strip().lower())], "name"
        if pf is None:
            out.append(Recon(a, None, NOT_BUILT))
            continue
        if pf.id in used:   # e.g. prod and UAT Okta apps sharing one SP entity ID
            out.append(Recon(a, pf, DIFFERS, how, [Check(
                "Own SP connection", "A separate connection for this app",
                f"Already used by {used[pf.id]}", False, "CRITICAL")]))
            continue
        used[pf.id] = a.label
        checks = _saml_checks(a, pf) if a.is_saml and a.saml else (_oidc_checks(a, pf) if a.oidc else [])
        if not pf.active:
            checks.append(Check("Enabled", "Yes", "No", False))
        out.append(Recon(a, pf, DIFFERS if any(not c.ok for c in checks) else MATCHES, how, checks))
    return out, [o for o in objs if o.id not in used]


def build_status(app: Application, recon: Recon | None, tasks: dict[str, MigrationTask] | None = None) -> str:
    if app.state == "OUT_OF_SCOPE":
        return "OUT_OF_SCOPE"
    if tasks and tasks.get("VERIFY") and tasks["VERIFY"].status == "DONE":
        return "VERIFIED"
    if recon and recon.status == MATCHES:
        return "BUILT"
    if recon and recon.status == DIFFERS:
        return "BUILT_WITH_DIFFERENCES"
    return "BLOCKED" if app.blocked else "READY_TO_BUILD"
