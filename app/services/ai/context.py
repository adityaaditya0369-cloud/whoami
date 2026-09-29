"""Build the data sent to the model, and optionally mask it.

Never included: user names/emails/ids, certificates, raw Okta payloads, secrets.
With masking on, hostnames/URLs and group names become stable tokens
(host-1, group-3); the mapping stays local and is reversed on the output.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

from app.config import Settings
from app.models.db import Application, RiskScore


def build_context(app: Application, score: RiskScore | None, settings: Settings) -> dict:
    s = app.saml
    groups = [a for a in app.assignments if a.principal_type == "GROUP"]
    return {
        "application": {
            "label": app.label, "okta_catalog_name": app.okta_name,
            "type": "custom SAML" if app.is_custom_saml else "OIN catalog (partial config via API)",
            "okta_status": app.okta_status, "app_username_template": app.user_name_template,
            "assigned_users": app.user_count, "direct_user_assignments": app.direct_user_count,
            "assigned_groups": [g.principal_name or g.principal_id for g in groups],
            "business_owner_known": bool(app.business_owner),
            "business_criticality": app.business_criticality, "has_test_environment": app.has_test_environment,
        },
        "saml": None if s is None else {
            "config_completeness": s.config_completeness, "sp_entity_id": s.audience,
            "acs_url": s.sso_acs_url, "acs_endpoints": s.acs_endpoints,
            "name_id_template": s.name_id_template, "name_id_format": s.name_id_format,
            "name_id_pingfederate_source": f"{s.pf_nameid_source}: {s.pf_nameid_detail}",
            "response_signed": s.response_signed, "assertion_signed": s.assertion_signed,
            "signature_algorithm": s.signature_algorithm, "idp_issuer": s.idp_issuer,
            "slo_enabled": s.slo_enabled, "signed_authn_requests": s.sp_certificate_present,
            "default_relay_state": s.default_relay_state,
            "authn_context_class_ref": s.authn_context_class_ref,
            "catalog_app_settings": s.catalog_app_settings,
        },
        "claims": [{
            "name": c.name, "type": c.claim_type, "okta_values": c.values,
            "group_filter": f"{c.group_filter_type} {c.group_filter_value}" if c.claim_type == "GROUP" else None,
            "pingfederate_source": c.pf_source, "pingfederate_detail": c.pf_source_detail,
            "okta_only_groups_matched": c.matched_okta_native_groups or [],
        } for c in app.claims],
        "findings": [{"code": f.code, "severity": f.severity, "message": f.message}
                     for f in sorted(app.findings, key=lambda f: (f.severity, f.code))],
        "risk": None if score is None else {
            "rules_version": score.rules_version,
            "complexity": {"score": score.complexity_score, "level": score.complexity_level},
            "impact": {"score": score.impact_score, "level": score.impact_level},
            "overall_level": score.overall_level, "blocked": score.blocked, "blockers": score.blockers,
            "suggested_wave": score.suggested_wave, "breakdown": score.breakdown,
        },
        "target": {
            "product": "PingFederate (self-hosted)", "directory": settings.pf_directory_type.value,
            "ognl_allowed": settings.pf_ognl_allowed,
        },
    }


def context_hash(ctx: dict, provider: str, model: str | None, masked: bool) -> str:
    blob = json.dumps({"ctx": ctx, "p": provider, "m": model, "masked": masked}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


# --- masking --------------------------------------------------------------
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


class Masker:
    def __init__(self):
        self.forward: dict[str, str] = {}

    def _token(self, prefix: str, value: str) -> str:
        if value not in self.forward:
            n = sum(1 for t in self.forward.values() if t.startswith(prefix + "-")) + 1
            self.forward[value] = f"{prefix}-{n}"
        return self.forward[value]

    def _mask_str(self, s: str) -> str:
        def repl(m):
            u = urlsplit(m.group(0))
            host = self._token("host", u.hostname or "")
            return f"{u.scheme}://{host}{u.path}" if u.path else f"{u.scheme}://{host}"
        s = _URL_RE.sub(repl, s)
        # Parent domains of every host seen so far (catches e-mail addresses, URNs and bare host names).
        for real, tok in list(self.forward.items()):
            if tok.startswith("host-") and real.count(".") >= 1:
                self._token("domain", ".".join(real.split(".")[-2:]))
        for real, tok in sorted(self.forward.items(), key=lambda kv: -len(kv[0])):
            if not real:
                continue
            if tok.startswith("group-"):
                s = re.sub(rf"(?<![\w-]){re.escape(real)}(?![\w-])", tok, s)
            elif tok.startswith(("host-", "domain-")):
                s = re.sub(rf"(?<![\w.-]){re.escape(real)}(?![\w-])", tok, s, flags=re.IGNORECASE)
        return s

    def mask(self, ctx: dict) -> dict:
        # Group names first so they are replaced wherever they appear.
        for g in ctx["application"]["assigned_groups"]:
            self._token("group", g)
        for c in ctx["claims"]:
            for g in c.get("okta_only_groups_matched") or []:
                self._token("group", g)
        ctx = json.loads(json.dumps(ctx, default=str))
        ctx["application"]["label"] = self._token("app", ctx["application"]["label"])
        # Custom (AIW) app names embed the Okta org name, e.g. "acmecorp_wiki_1".
        if ctx["application"]["type"].startswith("custom"):
            ctx["application"]["okta_catalog_name"] = self._token("appname", ctx["application"]["okta_catalog_name"])
        return self._walk(ctx)

    def _walk(self, v):
        if isinstance(v, dict):
            return {k: self._walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [self._walk(x) for x in v]
        if isinstance(v, str):
            return self._mask_str(v)
        return v

    def unmask(self, v):
        if isinstance(v, dict):
            return {k: self.unmask(x) for k, x in v.items()}
        if isinstance(v, list):
            return [self.unmask(x) for x in v]
        if isinstance(v, str):
            for real, tok in sorted(self.forward.items(), key=lambda kv: -len(kv[1])):
                v = re.sub(rf"\b{re.escape(tok)}\b", real, v)
            return v
        return v
