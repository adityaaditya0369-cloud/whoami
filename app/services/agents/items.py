"""What each agent reviews: the deterministic rule results for one app, as items.

Every item carries the rule result (what the tool decided), the facts it was
based on, and a search query for the knowledge base. Agents review these;
they never produce the results themselves.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime

from app.config import Settings
from app.models.db import Application, Group, RiskScore
from app.services.readiness import pf_readiness


@dataclass
class Item:
    key: str
    label: str
    rule_result: str
    facts: dict = field(default_factory=dict)
    query: str = ""

    def as_context(self) -> dict:
        d = asdict(self)
        d.pop("query")
        return d


def _active_cert(app: Application):
    certs = [c for c in app.certificates if c.is_active_signing_key] or list(app.certificates)
    return max(certs, key=lambda c: c.not_after or datetime.min) if certs else None


def saml_items(app: Application, settings: Settings) -> list[Item]:
    s = app.saml
    codes = {f.code for f in app.findings}
    acs = s.acs_endpoints or ([{"url": s.sso_acs_url, "index": 0}] if s.sso_acs_url else [])
    items = [
        Item("entity_id", "SP entity ID (partner)",
             f"Partner entity ID = {s.audience}" if s.audience else "Unknown - take it from the vendor's SP metadata",
             {"okta_audience": s.audience, "config_completeness": s.config_completeness, "catalog_app": not app.is_custom_saml,
              "duplicate_entity_id": "DUPLICATE_SP_ENTITY_ID" in codes},
             f"SP entity ID audience partner {app.okta_name} {app.label}"),
        Item("acs", "Assertion consumer service (ACS) URLs",
             ("POST endpoints: " + ", ".join(f"[{e.get('index', 0)}] {e.get('url')}" for e in acs)) if acs
             else "Unknown - take ACS URLs from the vendor's SP metadata",
             {"endpoints": acs, "recipient": s.recipient, "destination": s.destination},
             f"ACS assertion consumer service URL recipient destination {app.label}"),
        Item("name_id_format", "NameID format",
             f"SAML_SUBJECT with format {s.name_id_format or 'unspecified'}",
             {"okta_format": s.name_id_format, "okta_template": s.name_id_template},
             "NameID format subject emailAddress unspecified persistent"),
        Item("signing", "Signing",
             f"Sign {'assertion' if s.assertion_signed else 'response'} with SHA-256 (RSA-SHA256)",
             {"okta_response_signed": s.response_signed, "okta_assertion_signed": s.assertion_signed,
              "okta_signature_algorithm": s.signature_algorithm, "okta_digest_algorithm": s.digest_algorithm},
             "signing signature assertion response SHA-256 SHA-1 algorithm certificate"),
        Item("issuer", "IdP issuer seen by the SP",
             (f"Virtual server ID '{s.idp_issuer}' (keeps the issuer the SP knows)" if "CUSTOM_IDP_ISSUER" in codes
              else f"New issuer: PingFederate entity ID {settings.pf_entity_id} (SP must be updated)"),
             {"okta_issuer": s.idp_issuer, "pf_entity_id": settings.pf_entity_id, "custom_issuer": "CUSTOM_IDP_ISSUER" in codes},
             "issuer IdP entity ID virtual server ID metadata"),
    ]
    cert = _active_cert(app)
    items.append(Item("certificate", "Okta signing certificate (rollback baseline)",
                      (f"Okta cert {cert.sha256_thumbprint or cert.kid} valid until {cert.not_after:%Y-%m-%d}; "
                       "kept for rollback, replaced by PingFederate's signing key") if cert and cert.not_after
                      else "No Okta signing certificate captured",
                      {"not_after": cert.not_after.isoformat() if cert and cert.not_after else None,
                       "key_size": cert.key_size if cert else None},
                      "signing certificate expiry rollover rollback"))
    if s.slo_enabled:
        items.append(Item("slo", "Single logout", f"Enable SLO profiles; SP logout URL {s.slo_logout_url}",
                          {"slo_url": s.slo_logout_url}, "single logout SLO"))
    if s.sp_certificate_present:
        items.append(Item("authn_requests", "Signed AuthnRequests",
                          "Import the SP signing certificate and require signed AuthnRequests",
                          {}, "signed AuthnRequest SP certificate"))
    if s.authn_context_class_ref and "NON_DEFAULT_AUTHN_CONTEXT" in codes:
        items.append(Item("authn_context", "Authentication context",
                          f"Map AuthnContextClassRef {s.authn_context_class_ref} in the authentication policy",
                          {"okta_value": s.authn_context_class_ref}, "AuthnContextClassRef authentication context MFA"))
    if s.default_relay_state:
        items.append(Item("relay_state", "Default RelayState",
                          f"Carry over default RelayState {s.default_relay_state}", {"value": s.default_relay_state},
                          "RelayState target resource IdP-initiated"))
    return items


def claims_items(app: Application, settings: Settings, ognl_allowed: bool | None = None) -> list[Item]:
    ognl = settings.pf_ognl_allowed if ognl_allowed is None else ognl_allowed
    s = app.saml
    items = [Item("nameid", "NameID (SAML_SUBJECT)",
                  f"{s.pf_nameid_source}: {s.pf_nameid_detail}",
                  {"okta_template": s.name_id_template, "format": s.name_id_format,
                   "app_username_template": app.user_name_template},
                  f"NameID subject {s.name_id_template or ''} {app.user_name_template or ''} username")]
    for c in app.claims:
        if c.claim_type != "EXPRESSION":
            continue
        items.append(Item(f"claim:{c.name}", f"Attribute '{c.name}'",
                          f"{c.pf_source}: {c.pf_source_detail}",
                          {"okta_values": c.values, "expression_kind": c.expression_kind,
                           "source_attributes": c.source_attributes, "functions": c.functions_used,
                           "missing_directory_inputs": c.pf_missing_inputs, "ognl_allowed": ognl,
                           "directory": settings.pf_directory_type.value},
                          f"attribute {c.name} {' '.join(c.values)} {' '.join(c.source_attributes or [])} mapping LDAP"))
    return items


def group_items(app: Application, settings: Settings, groups_by_id: dict[str, Group]) -> list[Item]:
    r = pf_readiness(app)
    okta_only = set(r["okta_only_groups"])
    items = []
    for a in app.assignments:
        if a.principal_type != "GROUP":
            continue
        g = groups_by_id.get(a.principal_id)
        name = a.principal_name or a.principal_id
        builtin = bool(g and g.group_type == "BUILT_IN")
        where = ("Okta built-in group (everyone)" if builtin else
                 "Okta-only group: create it in the directory and copy the members" if name in okta_only else
                 f"Already in the directory (imported from {g.source_app})" if g and g.source_app else
                 "Assumed to exist in the directory")
        items.append(Item(f"assigned_group:{name}", f"Assigned group '{name}'", where,
                          {"group_type": g.group_type if g else None, "source": g.source_app if g else None,
                           "members": g.member_count if g else None},
                          f"group {name} assignment directory Active Directory"))
    for c in app.claims:
        if c.claim_type != "GROUP":
            continue
        items.append(Item(f"group_claim:{c.name}", f"Group attribute '{c.name}'",
                          f"{c.pf_source}: {c.pf_source_detail}",
                          {"okta_filter": f"{c.group_filter_type} {c.group_filter_value}",
                           "matched_groups": c.matched_group_count, "sample": (c.matched_group_sample or [])[:8],
                           "okta_only_groups_matched": c.matched_okta_native_groups},
                          f"group claim {c.name} filter {c.group_filter_type} memberOf LDAP"))
    codes = {f.code for f in app.findings}
    items.append(Item("access_control", "Who may sign in",
                      ("Issuance criteria: members of a per-app directory group (created from the Okta assignments)"
                       if r["issuance_criteria"] else "No issuance criteria (everyone who can authenticate)"),
                      {"direct_user_assignments": app.direct_user_count, "assigned_users": app.user_count,
                       "issuance_criteria": r["issuance_criteria"], "direct_users_finding": "DIRECT_USER_ASSIGNMENTS" in codes},
                      "issuance criteria access control authorization group membership"))
    return items


def risk_items(app: Application, score: RiskScore | None) -> list[Item]:
    if score is None:
        return [Item("risk", "Risk score", "Not scored", {}, "risk")]
    items = [Item(f"rule:{b['rule']}", f"{b['dimension'].title()}: {b['rule']}", f"+{b['points']} points",
                  {"reason": b["reason"], "dimension": b["dimension"]}, f"{b['rule']} {b['reason']}")
             for b in score.breakdown]
    items.append(Item("wave", "Suggested wave", score.suggested_wave,
                      {"complexity": score.complexity_level, "impact": score.impact_level, "overall": score.overall_level,
                       "blocked": score.blocked, "blockers": score.blockers,
                       "business_criticality": app.business_criticality, "has_test_environment": app.has_test_environment,
                       "assigned_users": app.user_count, "usage_known": app.usage_known,
                       "active_users": app.usage_unique_users},
                      "wave pilot cutover schedule criticality test environment"))
    return items
