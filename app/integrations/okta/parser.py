"""Pure functions: raw Okta JSON/XML -> validated domain models.

No I/O here, so everything is unit-testable against captured payloads.
"""
from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from defusedxml import ElementTree as SafeET

from app.integrations.okta.client import SAML_MODES
from app.models.domain import (
    TenantObjectModel,
    AcsEndpoint, AppGroupModel, AppModel, AppUserModel, CertificateModel, ClaimModel,
    ExpressionAnalysis, GroupModel, MetadataModel, OidcConfigModel, SamlConfigModel,
)

# --- Okta Expression Language analysis -------------------------------------
_ATTR_RE = re.compile(r"\b(user|appuser|appUser|app|org|idpuser)\.([A-Za-z_][A-Za-z0-9_]*)")
_DIRECT_RE = re.compile(r"^\s*(user|appuser|appUser|app|org|idpuser)\.[A-Za-z_][A-Za-z0-9_]*\s*$")
_LITERAL_RE = re.compile(r'^\s*"[^"]*"\s*$')
_FUNC_RE = re.compile(r"\b([A-Z][A-Za-z]*\.[a-zA-Z]+|isMemberOfGroup\w*|getFilteredGroups"
                      r"|hasWorkday\w*|user\.getGroups|getManager\w*|getAssistant\w*)\s*\(")


def analyse_expression(values: list[str]) -> ExpressionAnalysis:
    """Classify Okta EL values. DIRECT = plain attribute reference, which maps
    1:1 to a directory attribute in a PingFederate data store. COMPLEX = needs
    an OGNL expression in PingFederate, or the value pre-computed in the directory."""
    attrs: list[str] = []
    funcs: list[str] = []
    kinds = set()
    for v in values or []:
        v = v or ""
        attrs += [f"{a}.{b}" for a, b in _ATTR_RE.findall(v)]
        funcs += _FUNC_RE.findall(v)
        if _DIRECT_RE.match(v):
            kinds.add("DIRECT")
        elif _LITERAL_RE.match(v) or (not _ATTR_RE.search(v) and not _FUNC_RE.search(v)
                                       and "?" not in v and "+" not in v):
            kinds.add("LITERAL")
        else:
            kinds.add("COMPLEX")
            if "?" in v and ":" in v:
                funcs.append("<conditional>")
            if "+" in v:
                funcs.append("<concatenation>")
    kind = "COMPLEX" if "COMPLEX" in kinds or len(values or []) > 1 else (
        "DIRECT" if "DIRECT" in kinds else "LITERAL")
    return ExpressionAnalysis(kind=kind, source_attributes=sorted(set(attrs)),
                              functions_used=sorted(set(funcs)))


def match_group_filter(filter_type: str | None, filter_value: str | None,
                       group_names: list[str]) -> list[str]:
    """Which tenant groups a GROUP attribute statement filter would emit.
    Approximation of Okta semantics: STARTS_WITH/EQUALS/CONTAINS are
    case-insensitive, REGEX must match the whole name."""
    if not filter_type or filter_value is None:
        return []
    ft = filter_type.upper()
    fv = filter_value
    if ft == "REGEX":
        try:
            rx = re.compile(fv)
        except re.error:
            return []
        return [g for g in group_names if rx.fullmatch(g)]
    low = fv.lower()
    if ft == "STARTS_WITH":
        return [g for g in group_names if g.lower().startswith(low)]
    if ft == "EQUALS":
        return [g for g in group_names if g.lower() == low]
    if ft == "CONTAINS":
        return [g for g in group_names if low in g.lower()]
    return []


# --- helpers ---------------------------------------------------------------
def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None


def _none_if_blank(v):
    return v if v not in ("", None) else None


# --- apps ------------------------------------------------------------------
_CUSTOM_SAML_KEYS = ("ssoAcsUrl", "audience")


def parse_app(raw: dict) -> AppModel:
    # Okta can return signOnMode: null (e.g. some bookmark/internal apps), so fall back on falsy too.
    mode = raw.get("signOnMode") or "UNKNOWN"
    is_saml = mode in SAML_MODES
    settings = raw.get("settings") or {}
    sign_on = settings.get("signOn") or {}
    is_custom = is_saml and all(sign_on.get(k) for k in _CUSTOM_SAML_KEYS)
    creds = raw.get("credentials") or {}

    saml = None
    if is_saml:
        claims: list[ClaimModel] = []
        for i, st in enumerate(sign_on.get("attributeStatements") or []):
            ctype = (st.get("type") or "EXPRESSION").upper()
            if ctype == "GROUP":
                claims.append(ClaimModel(
                    position=i, name=st.get("name", ""), namespace=st.get("namespace"),
                    claim_type="GROUP", group_filter_type=st.get("filterType"),
                    group_filter_value=st.get("filterValue"),
                ))
            else:
                values = [str(v) for v in (st.get("values") or [])]
                claims.append(ClaimModel(
                    position=i, name=st.get("name", ""), namespace=st.get("namespace"),
                    claim_type="EXPRESSION", values=values, analysis=analyse_expression(values),
                ))
        slo = sign_on.get("slo") or {}
        saml = SamlConfigModel(
            config_completeness="FULL" if is_custom else "PARTIAL",
            sso_acs_url=_none_if_blank(sign_on.get("ssoAcsUrl")),
            recipient=_none_if_blank(sign_on.get("recipient")),
            destination=_none_if_blank(sign_on.get("destination")),
            audience=_none_if_blank(sign_on.get("audience")),
            idp_issuer=_none_if_blank(sign_on.get("idpIssuer")),
            sp_issuer=_none_if_blank(sign_on.get("spIssuer")),
            default_relay_state=_none_if_blank(sign_on.get("defaultRelayState")),
            name_id_template=_none_if_blank(sign_on.get("subjectNameIdTemplate")),
            name_id_format=_none_if_blank(sign_on.get("subjectNameIdFormat")),
            response_signed=sign_on.get("responseSigned"),
            assertion_signed=sign_on.get("assertionSigned"),
            signature_algorithm=sign_on.get("signatureAlgorithm"),
            digest_algorithm=sign_on.get("digestAlgorithm"),
            authn_context_class_ref=sign_on.get("authnContextClassRef"),
            honor_force_authn=sign_on.get("honorForceAuthn"),
            request_compressed=sign_on.get("requestCompressed"),
            assertion_lifetime_seconds=sign_on.get("samlAssertionLifetimeSeconds"),
            allow_multiple_acs=bool(sign_on.get("allowMultipleAcsEndpoints")),
            acs_endpoints=[AcsEndpoint(url=e.get("url", ""), index=e.get("index"))
                           for e in (sign_on.get("acsEndpoints") or [])],
            slo_enabled=bool(slo.get("enabled")),
            slo_issuer=slo.get("issuer"),
            slo_logout_url=slo.get("logoutUrl"),
            sp_certificate_present=bool((sign_on.get("spCertificate") or {}).get("x5c")),
            catalog_app_settings={} if is_custom else dict(settings.get("app") or {}),
            claims=claims,
        )

    is_oidc = mode == "OPENID_CONNECT"
    oidc = None
    if is_oidc:
        oc = settings.get("oauthClient") or {}
        cc = creds.get("oauthClient") or {}
        oidc = OidcConfigModel(
            client_id=cc.get("client_id") or raw["id"],
            application_type=oc.get("application_type"),
            grant_types=list(oc.get("grant_types") or []),
            response_types=list(oc.get("response_types") or []),
            redirect_uris=list(oc.get("redirect_uris") or []),
            post_logout_redirect_uris=list(oc.get("post_logout_redirect_uris") or []),
            token_endpoint_auth_method=cc.get("token_endpoint_auth_method"),
            pkce_required=cc.get("pkce_required"),
            initiate_login_uri=oc.get("initiate_login_uri"),
            consent_method=oc.get("consent_method"),
            issuer_mode=oc.get("issuer_mode"),
            wildcard_redirect=oc.get("wildcard_redirect"),
            has_jwks=bool((oc.get("jwks") or {}).get("keys")),
        )

    return AppModel(
        id=raw["id"], label=raw.get("label") or raw.get("name") or raw["id"],
        okta_name=raw.get("name") or "", sign_on_mode=mode, okta_status=raw.get("status") or "UNKNOWN",
        is_saml=is_saml, is_custom_saml=is_custom,
        created=_dt(raw.get("created")), last_updated=_dt(raw.get("lastUpdated")),
        user_name_template=(creds.get("userNameTemplate") or {}).get("template"),
        active_signing_kid=(creds.get("signing") or {}).get("kid"),
        saml=saml, is_oidc=is_oidc, oidc=oidc,
        okta_features=[str(f) for f in (raw.get("features") or [])],
        access_policy_id=_last_segment(((raw.get("_links") or {}).get("accessPolicy") or {}).get("href")),
    )


def _last_segment(href: str | None) -> str | None:
    return href.rstrip("/").rsplit("/", 1)[-1] if href else None


# --- tenant-level objects -----------------------------------------------------
SOCIAL_IDP_TYPES = {"GOOGLE", "FACEBOOK", "MICROSOFT", "APPLE", "LINKEDIN", "AMAZON", "GITHUB", "DISCORD",
                    "GITLAB", "PAYPAL", "SALESFORCE", "SPOTIFY", "XERO", "YAHOO", "YAHOOJP"}


def _rule_requires_mfa(rule: dict) -> bool:
    actions = rule.get("actions") or {}
    so = actions.get("signon") or {}
    if so.get("requireFactor"):
        return True
    vm = ((actions.get("appSignOn") or {}).get("verificationMethod") or {})
    return (vm.get("factorMode") or "").upper() == "2FA"


def parse_tenant_object(kind: str, raw: dict) -> TenantObjectModel:
    """Summarise one tenant object into the attributes the strategy rules need.
    The raw payload is snapshotted separately; only what drives decisions is kept here."""
    emb = raw.get("_embedded") or {}
    name = raw.get("name") or raw.get("label") or (raw.get("key") or "") or raw.get("id", "")
    a: dict = {}
    subtype = None
    client_ids: list[str] = []
    if kind == "policies":
        subtype = raw.get("type")
        rules = emb.get("rules") or []
        conds = [r.get("conditions") or {} for r in rules]
        a = {"system": bool(raw.get("system")), "priority": raw.get("priority"), "rule_count": len(rules),
             "rules": [r.get("name") for r in rules][:20],
             "requires_mfa": any(_rule_requires_mfa(r) for r in rules),
             "uses_network_zones": any((c.get("network") or {}).get("connection") in ("ZONE",) or
                                       (c.get("network") or {}).get("include") for c in conds),
             "uses_device_conditions": any(c.get("device") for c in conds),
             "uses_risk": any(c.get("riskScore") or c.get("risk") for c in conds),
             "group_conditions": any(((c.get("people") or {}).get("groups")) for c in conds)}
    elif kind == "authenticators":
        subtype = raw.get("key") or raw.get("type")
        a = {"type": raw.get("type"), "provider": ((raw.get("provider") or {}).get("type"))}
    elif kind == "group_rules":
        subtype = raw.get("type")
        a = {"expression": (((raw.get("conditions") or {}).get("expression") or {}).get("value")),
             "target_groups": (((raw.get("actions") or {}).get("assignUserToGroups") or {}).get("groupIds") or [])}
    elif kind == "authorization_servers":
        subtype = "default" if raw.get("default") or raw.get("id") == "default" else "custom"
        scopes = emb.get("scopes") or []
        claims = emb.get("claims") or []
        pols = emb.get("policies") or []
        custom_claims = [c for c in claims if not c.get("system")]
        a = {"audiences": raw.get("audiences") or [], "issuer_mode": raw.get("issuerMode"),
             "custom_scopes": [s_.get("name") for s_ in scopes if not s_.get("system")],
             "custom_claims": [c.get("name") for c in custom_claims],
             "expression_claims": [c.get("name") for c in custom_claims if (c.get("valueType") or "") == "EXPRESSION"
                                   and not str(c.get("value") or "").startswith("user.")],
             "policy_count": len(pols)}
        for pol in pols:
            inc = (((pol.get("conditions") or {}).get("clients") or {}).get("include") or [])
            client_ids.extend(x for x in inc if x != "ALL_CLIENTS")
            if "ALL_CLIENTS" in inc:
                a["applies_to_all_clients"] = True
    elif kind == "inline_hooks":
        subtype = raw.get("type")
        cfg = ((raw.get("channel") or {}).get("config") or {})
        a = {"uri_host": _host(cfg.get("uri"))}
    elif kind == "event_hooks":
        subtype = "event_hook"
        cfg = ((raw.get("channel") or {}).get("config") or {})
        a = {"events": ((raw.get("events") or {}).get("items") or [])[:30], "uri_host": _host(cfg.get("uri"))}
    elif kind == "idps":
        subtype = raw.get("type")
        a = {"protocol": ((raw.get("protocol") or {}).get("type")),
             "social": (raw.get("type") or "").upper() in SOCIAL_IDP_TYPES,
             "jit": bool((((raw.get("policy") or {}).get("provisioning") or {}).get("action") or "") == "AUTO")}
    elif kind == "network_zones":
        subtype = raw.get("type")
        a = {"usage": raw.get("usage"), "gateways": len(raw.get("gateways") or []),
             "proxies": len(raw.get("proxies") or []),
             "locations": len(raw.get("locations") or []), "asns": len(raw.get("asns") or [])}
    return TenantObjectModel(kind=kind, okta_id=str(raw.get("id") or raw.get("key") or name), name=str(name),
                             subtype=subtype, status=raw.get("status"), attributes=a, client_ids=client_ids)


def _host(uri: str | None) -> str | None:
    if not uri:
        return None
    from urllib.parse import urlsplit
    return urlsplit(uri).hostname


# --- groups / assignments -------------------------------------------------
def parse_group(raw: dict) -> GroupModel:
    profile = raw.get("profile") or {}
    embedded = raw.get("_embedded") or {}
    stats = embedded.get("stats") or {}
    source_app = (embedded.get("app") or {}).get("name")
    if not source_app and profile.get("windowsDomainQualifiedName"):
        source_app = "active_directory"
    return GroupModel(
        id=raw["id"], name=profile.get("name", raw["id"]), description=profile.get("description"),
        group_type=raw.get("type", "OKTA_GROUP"), source_app=source_app,
        member_count=stats.get("usersCount"),
    )


def parse_app_group(raw: dict) -> AppGroupModel:
    return AppGroupModel(group_id=raw["id"], priority=raw.get("priority"),
                         profile=raw.get("profile") or {})


def parse_app_user(raw: dict) -> AppUserModel:
    user = (raw.get("_embedded") or {}).get("user") or {}
    uprof = user.get("profile") or {}
    return AppUserModel(
        user_id=raw["id"], scope=raw.get("scope"),
        app_username=(raw.get("credentials") or {}).get("userName"),
        login=uprof.get("login"), email=uprof.get("email"),
        status=user.get("status") or raw.get("status"),
        profile=raw.get("profile") or {},
    )


# --- certificates / metadata ----------------------------------------------
def parse_key(raw: dict) -> CertificateModel:
    x5c = (raw.get("x5c") or [None])[0]
    cm = CertificateModel(kid=raw.get("kid", ""), x5c=x5c, not_after=_dt(raw.get("expiresAt")))
    if not x5c:
        return cm
    try:
        der = base64.b64decode(x5c)
        cert = x509.load_der_x509_certificate(der)
        cm.subject = cert.subject.rfc4514_string()
        cm.issuer = cert.issuer.rfc4514_string()
        cm.not_before = cert.not_valid_before_utc.replace(tzinfo=None)
        cm.not_after = cert.not_valid_after_utc.replace(tzinfo=None)
        cm.sha1_thumbprint = hashlib.sha1(der).hexdigest().upper()  # noqa: S324 - thumbprint, not security
        cm.sha256_thumbprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        cm.key_size = getattr(cert.public_key(), "key_size", None)
    except Exception:  # malformed cert: keep what we have, finding rules will flag missing dates
        pass
    return cm


_MD_NS = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}


def parse_metadata(xml_text: str | None) -> MetadataModel:
    if not xml_text:
        return MetadataModel()
    try:
        root = SafeET.fromstring(xml_text.encode("utf-8"))
    except Exception:
        return MetadataModel()
    sso = root.find(".//md:IDPSSODescriptor/md:SingleSignOnService", _MD_NS)
    return MetadataModel(entity_id=root.get("entityID"),
                         sso_url=sso.get("Location") if sso is not None else None)


# --- usage (System Log) -----------------------------------------------------
def summarise_usage(events: list[dict]) -> dict:
    """Successful sign-in / token events -> counts. Actors are users, or the
    client itself for machine-to-machine apps."""
    ok = [e for e in events if ((e.get("outcome") or {}).get("result") or "SUCCESS") == "SUCCESS"]
    users = {(e.get("actor") or {}).get("id") for e in ok if (e.get("actor") or {}).get("type", "User") == "User"}
    users.discard(None)
    last = max((_dt(e.get("published")) for e in ok if e.get("published")), default=None)
    return {"events": len(ok), "unique_users": len(users), "last_seen": last}
