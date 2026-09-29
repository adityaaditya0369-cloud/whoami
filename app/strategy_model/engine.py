"""Deterministic strategy engine: feature detection, compatibility, decision and complexity.

For every Okta app and tenant object:
  1. detect which catalog features it uses (with the evidence that triggered each one),
  2. compatibility = the worst compatibility of those features,
  3. strategy = RETIRE > RETAIN > REDESIGN > TRANSFORM > RECREATE, from the rules below,
  4. an architect may override the strategy (audited, with a reason).

Nothing here calls an LLM. AI explains these results elsewhere; it never sets them.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from app.models.db import Application, TenantObject
from app.strategy_model.catalog import COMPAT_LEVEL, STRATEGIES, Capability, worst

PRECEDENCE = ["RETIRE", "RETAIN", "REDESIGN", "TRANSFORM", "RECREATE"]
COMPAT_WORD = {"EQUIVALENT": "equivalent", "PARTIAL": "partial", "NONE": "no equivalent"}
SWA_MODES = {"AUTO_LOGIN", "BROWSER_PLUGIN", "SECURE_PASSWORD_STORE", "BASIC_AUTH"}

# Finding codes (app/services/findings.py) -> catalog feature
FINDING_FEATURE = {
    "CLAIM_NEEDS_OGNL": "claims.expression", "NAMEID_NEEDS_OGNL": "claims.expression",
    "APPUSER_ATTRIBUTE_CLAIM": "claims.appuser", "GROUP_CLAIM": "claims.groups",
    "GROUP_CLAIM_OKTA_NATIVE_GROUPS": "groups.okta_only", "OKTA_NATIVE_GROUPS_ASSIGNED": "groups.okta_only",
    "NAMEID_IS_OKTA_USER_ID": "nameid.okta_user_id", "SLO_ENABLED": "saml.slo", "MULTIPLE_ACS": "saml.multiple_acs",
    "OIDC_IMPLICIT_GRANT": "app.oidc.implicit", "OIDC_WILDCARD_REDIRECT": "app.oidc.wildcard_redirect",
}
RETIRE_CODES = {"UNUSED_IN_WINDOW", "NO_ASSIGNMENTS"}
PROTOCOL_KEYS = {"app.saml", "app.saml.catalog", "app.oidc", "app.wsfed", "app.swa", "app.bookmark"}

# Complexity factors (from the strategy design): finding code -> factor
FACTOR_OF_CODE = {
    **{c: "Protocol" for c in ("OIDC_IMPLICIT_GRANT", "OIDC_PASSWORD_GRANT", "OIDC_PKCE_NOT_REQUIRED",
                               "SIGNED_AUTHN_REQUESTS", "SLO_ENABLED", "MULTIPLE_ACS", "NON_DEFAULT_AUTHN_CONTEXT",
                               "OIDC_REFRESH_TOKENS", "OIDC_WILDCARD_REDIRECT")},
    **{c: "Configuration" for c in ("CATALOG_APP_PARTIAL_CONFIG", "CUSTOM_IDP_ISSUER", "DUPLICATE_SP_ENTITY_ID",
                                    "NO_SIGNING_CERTIFICATE_FOUND", "OIDC_SCOPES_CLAIMS_NOT_ANALYSED",
                                    "OIDC_NEW_CLIENT_SECRET")},
    **{c: "Customization" for c in ("CLAIM_NEEDS_OGNL", "NAMEID_NEEDS_OGNL", "CUSTOM_APP_USERNAME")},
    **{c: "Data transformation" for c in ("APPUSER_ATTRIBUTE_CLAIM", "CLAIM_ATTRIBUTE_UNMAPPED",
                                          "NAMEID_ATTRIBUTE_UNMAPPED", "NAMEID_IS_OKTA_USER_ID", "GROUP_CLAIM",
                                          "GROUP_CLAIM_OKTA_NATIVE_GROUPS", "OKTA_NATIVE_GROUPS_ASSIGNED",
                                          "ASSIGNMENT_PROFILE_ATTRIBUTES", "UNRESOLVED_GROUP_ASSIGNMENTS")},
    **{c: "Security" for c in ("ISSUANCE_CRITERIA_REQUIRED", "OIDC_ACCESS_CONTROL_REQUIRED",
                               "DIRECT_USER_ASSIGNMENTS")},
}
IMPACT_FACTOR = {"BUSINESS_CRITICALITY": "Business criticality", "ACTIVE_USERS": "Users affected",
                 "ASSIGNED_USERS": "Users affected", "TEST_ENVIRONMENT": "Testing"}
FACTORS = ["Protocol", "Configuration", "Customization", "Data transformation", "Security",
           "Dependencies", "Business criticality", "Users affected", "Testing"]
LEVEL_LABEL = {"LOW": "Low", "MEDIUM": "Medium", "HIGH": "High", "CRITICAL": "Very high"}


@dataclass
class Hit:
    key: str
    evidence: str
    count: int = 1

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Decision:
    strategy: str | None
    compat_level: str | None
    reasons: list[dict] = field(default_factory=list)
    hits: list[Hit] = field(default_factory=list)
    prerequisites: list[Hit] = field(default_factory=list)


# --- feature detection ---------------------------------------------------------------------
def app_hits(app: Application, policies: dict[str, TenantObject]) -> tuple[list[Hit], list[Hit]]:
    """(app features, prerequisite features). Prerequisites are tenant-level designs the app relies on
    (its sign-in policy); they are planned once, before the wave, not per app."""
    hits: list[Hit] = []
    pre: list[Hit] = []
    mode = app.sign_on_mode or ""
    if app.is_saml:
        hits.append(Hit("app.saml" if app.is_custom_saml else "app.saml.catalog",
                        f"Sign-on mode {mode}" + ("" if app.is_custom_saml else " (OIN catalog app)")))
    elif app.is_oidc:
        grants = (app.oidc.grant_types if app.oidc else []) or []
        hits.append(Hit("app.oidc", f"OIDC client, grants: {', '.join(grants) or 'none'}"))
    elif mode == "WS_FEDERATION":
        hits.append(Hit("app.wsfed", "Sign-on mode WS_FEDERATION"))
    elif mode in SWA_MODES:
        hits.append(Hit("app.swa", f"Sign-on mode {mode} (password vaulting)"))
    elif mode == "BOOKMARK":
        hits.append(Hit("app.bookmark", "Bookmark app"))

    counts: dict[str, list[str]] = {}
    for f in app.findings:
        key = FINDING_FEATURE.get(f.code)
        if key:
            counts.setdefault(key, []).append(f.message)
    for key, msgs in counts.items():
        hits.append(Hit(key, msgs[0] if len(msgs) == 1 else f"{msgs[0]} (+{len(msgs) - 1} more)", len(msgs)))

    if app.auth_server_id:
        hits.append(Hit("app.oidc.custom_auth_server", f"Tokens from custom authorization server {app.auth_server_id}"))
    feats = set(app.okta_features or [])
    push = sorted(f for f in feats if f.startswith("PUSH_") or f == "GROUP_PUSH")
    if push:
        hits.append(Hit("app.provisioning", "Okta pushes users/groups to the app: " + ", ".join(push)))
    if "PROFILE_MASTERING" in feats:
        hits.append(Hit("app.profile_master", "The app is a profile source (profile mastering) for Okta users"))
    elif any(f.startswith("IMPORT_") for f in feats):
        hits.append(Hit("app.provisioning.import", "Okta imports users from the app"))
    if app.access_policy_id:
        pol = policies.get(app.access_policy_id)
        pa = (pol.attributes or {}) if pol is not None else {}
        if pol is not None and not pa.get("system"):
            detail = []
            if pa.get("requires_mfa"):
                detail.append("requires MFA")
            if pa.get("uses_device_conditions"):
                detail.append("device conditions")
            if pa.get("uses_network_zones"):
                detail.append("network zones")
            pre.append(Hit("app.access_policy", f"Sign-in policy '{pol.name}'" + (f" ({', '.join(detail)})" if detail else "")))
    return hits, pre


def tenant_hits(obj: TenantObject) -> list[Hit]:
    a = obj.attributes or {}
    k, st = obj.kind, (obj.subtype or "")
    if k == "policies":
        key = {"OKTA_SIGN_ON": "policy.global_session", "ACCESS_POLICY": "policy.app_access",
               "MFA_ENROLL": "policy.mfa_enroll", "PASSWORD": "policy.password",
               "PROFILE_ENROLLMENT": "policy.profile_enrollment", "IDP_DISCOVERY": "policy.idp_discovery"}.get(st)
        if not key:
            return []
        bits = [f"{a.get('rule_count', 0)} rule(s)"]
        for flag, label in (("requires_mfa", "MFA"), ("uses_network_zones", "network zones"),
                            ("uses_device_conditions", "device conditions"), ("uses_risk", "risk")):
            if a.get(flag):
                bits.append(label)
        if obj.app_ids:
            bits.append(f"{len(obj.app_ids)} app(s)")
        return [Hit(key, f"{st} policy: " + ", ".join(bits))]
    if k == "authenticators":
        key = {"okta_password": "auth.password", "okta_verify": "auth.okta_verify", "webauthn": "auth.webauthn",
               "phone_number": "auth.otp_channel", "okta_email": "auth.otp_channel"}.get(st, "auth.other")
        return [Hit(key, f"Authenticator {obj.name} ({st})")]
    if k == "group_rules":
        return [Hit("group_rule", f"Rule: {a.get('expression') or '?'} -> {len(a.get('target_groups') or [])} group(s)")]
    if k == "authorization_servers":
        if st == "default" and not (a.get("custom_scopes") or a.get("custom_claims") or a.get("policy_count")):
            return []
        bits = [f"{len(a.get('custom_scopes') or [])} custom scope(s)", f"{len(a.get('custom_claims') or [])} custom claim(s)"]
        if a.get("expression_claims"):
            bits.append(f"expression claims: {', '.join(a['expression_claims'])}")
        return [Hit("auth_server.custom", "; ".join(bits))]
    if k == "inline_hooks":
        key = "hook.token" if "tokens.transform" in st else ("hook.telephony" if "telephony" in st else "hook.user")
        return [Hit(key, f"Inline hook {st} -> {a.get('uri_host') or '?'}")]
    if k == "event_hooks":
        return [Hit("hook.event", f"{len(a.get('events') or [])} event type(s) -> {a.get('uri_host') or '?'}")]
    if k == "idps":
        return [Hit("idp.social" if a.get("social") else "idp.enterprise", f"{st} identity provider")]
    if k == "network_zones":
        if st == "DYNAMIC":
            return [Hit("zone.dynamic", f"Dynamic zone ({a.get('locations', 0)} location(s), {a.get('asns', 0)} ASN(s))")]
        return [Hit("zone.ip", f"IP zone, {a.get('gateways', 0)} range(s), usage {a.get('usage') or 'POLICY'}")]
    return []


# --- decisions ------------------------------------------------------------------------
def _pick(candidates: list[tuple[str, dict]]) -> tuple[str | None, list[dict]]:
    if not candidates:
        return None, []
    best = min((s for s, _ in candidates), key=PRECEDENCE.index)
    return best, [r for s, r in candidates if s == best] + [r for s, r in candidates if s != best]


def decide_app(app: Application, catalog: dict[str, Capability], policies: dict[str, TenantObject],
               override=None) -> Decision:
    hits, pre = app_hits(app, policies)
    cands: list[tuple[str, dict]] = []
    codes = {f.code for f in app.findings}
    if app.okta_status != "ACTIVE":
        cands.append(("RETIRE", {"rule": "APP_INACTIVE", "text": "Inactive in Okta: confirm with the owner, then retire"}))
    for c in sorted(codes & RETIRE_CODES):
        cands.append(("RETIRE", {"rule": c, "text": "No assigned users" if c == "NO_ASSIGNMENTS"
                                 else "Not used in the usage window: business validation, then retire"}))
    if app.blocked:
        cands.append(("RETAIN", {"rule": "BLOCKED", "text": "Blocked until an open decision is made: stays on Okta "
                                 "(temporary coexistence), migrates later"}))
    known = [h for h in hits if h.key in catalog]
    if not any(h.key in PROTOCOL_KEYS for h in hits):
        cands.append(("REDESIGN", {"rule": "UNKNOWN_SIGN_ON_MODE",
                                   "text": f"Sign-on mode {app.sign_on_mode} is not in the capability catalog: "
                                           "architecture review"}))
    for h in known:
        cap = catalog[h.key]
        cands.append((cap.strategy, {"rule": h.key, "text": f"{cap.okta_feature} → {cap.pf_capability} "
                                     f"({COMPAT_WORD[cap.compatibility]})", "evidence": h.evidence}))
    strategy, reasons = _pick(cands)
    compat = worst([catalog[h.key].compatibility for h in known])
    if override is not None:
        reasons = [{"rule": "OVERRIDE", "text": f"Override by {override.actor}: {override.reason}",
                    "rules_chose": strategy}] + reasons
        strategy = override.strategy
    return Decision(strategy, COMPAT_LEVEL.get(compat) if compat else None, reasons, hits, pre)


def decide_tenant(obj: TenantObject, catalog: dict[str, Capability]) -> Decision:
    hits = [h for h in tenant_hits(obj) if h.key in catalog]
    if (obj.status or "ACTIVE") != "ACTIVE":
        return Decision("RETIRE", None, [{"rule": "INACTIVE", "text": "Inactive in Okta: do not migrate"}], hits)
    if not hits:
        return Decision(None, None, [{"rule": "NOTHING_TO_MIGRATE", "text": "Nothing to migrate"}], [])
    cands = [(catalog[h.key].strategy, {"rule": h.key, "text": f"{catalog[h.key].okta_feature} → "
                                        f"{catalog[h.key].pf_capability}", "evidence": h.evidence}) for h in hits]
    strategy, reasons = _pick(cands)
    compat = worst([catalog[h.key].compatibility for h in hits])
    return Decision(strategy, COMPAT_LEVEL[compat], reasons, hits)


# --- complexity breakdown ----------------------------------------------------------------
def complexity_breakdown(risk_breakdown: list[dict], dependency_count: int) -> dict[str, int]:
    """Split the deterministic risk score into the strategy model's factors (display only; the
    risk engine stays the source of the score). Dependencies are shown alongside: 2 points per
    confirmed dependency, capped at 6, and not part of the risk score."""
    out = {f: 0 for f in FACTORS}
    for c in risk_breakdown or []:
        rule, pts = c.get("rule"), int(c.get("points") or 0)
        if c.get("dimension") == "COMPLEXITY":
            out[FACTOR_OF_CODE.get(rule, "Configuration")] += pts
        elif rule in IMPACT_FACTOR:
            out[IMPACT_FACTOR[rule]] += pts
    out["Dependencies"] = min(dependency_count * 2, 6)
    return out


assert set(PRECEDENCE) == set(STRATEGIES)
