"""Field-by-field Okta vs PingFederate comparison for one SAML app.

Status meanings (used in the UI and the Excel report):
  SAME      - carried over unchanged; nothing to do beyond entering it
  CONFIGURE - standard PingFederate configuration derived from the Okta value
  SP_UPDATE - value changes by design; the SP must be updated at cutover
  ACTION    - preparation needed first (directory, OGNL, groups, decisions)
  UNKNOWN   - Okta's API does not expose it; get it from the vendor
  N/A       - not used by this app
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from app.config import Settings
from app.models.db import Application

SAME, CONFIGURE, SP_UPDATE, ACTION, UNKNOWN, NA = "SAME", "CONFIGURE", "SP_UPDATE", "ACTION", "UNKNOWN", "N/A"
STATUS_ORDER = [ACTION, UNKNOWN, SP_UPDATE, CONFIGURE, SAME, NA]
STATUS_HELP = {
    SAME: "Carried over unchanged",
    CONFIGURE: "Standard PingFederate configuration",
    SP_UPDATE: "Changes by design - update the SP at cutover",
    ACTION: "Preparation required before migration",
    UNKNOWN: "Not exposed by Okta's API - get from vendor",
    NA: "Not used by this app",
}
DEFAULT_AUTHN = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"


@dataclass
class Row:
    section: str
    field: str
    okta_value: str
    pf_setting: str
    pf_value: str
    status: str
    note: str = ""


def _v(x) -> str:
    if x is None or x == "" or x == []:
        return "—"
    if isinstance(x, bool):
        return "Yes" if x else "No"
    return str(x)


def build(app: Application, settings: Settings) -> list[Row]:
    if app.is_oidc and app.oidc is not None:
        return build_oidc(app, settings)
    return build_saml(app, settings)


def build_saml(app: Application, settings: Settings) -> list[Row]:
    s = app.saml
    if s is None:
        return []
    codes = {f.code for f in app.findings}
    base = settings.pf_base_url.rstrip("/")
    partial = s.config_completeness == "PARTIAL"
    rows: list[Row] = []
    add = lambda *a, **k: rows.append(Row(*a, **k))  # noqa: E731
    entity = s.audience

    # --- SP connection ----------------------------------------------------------
    add("SP connection", "Connection name", app.label, "SP Connection > General Info > Connection Name",
        app.label, CONFIGURE)
    if partial and not entity:
        add("SP connection", "SP entity ID", "Not exposed (catalog app)", "Partner's Entity ID (Connection ID)",
            "From vendor SP metadata", UNKNOWN, "Import the SP metadata to fill this in")
    else:
        dup = "DUPLICATE_SP_ENTITY_ID" in codes
        add("SP connection", "SP entity ID", _v(entity), "Partner's Entity ID (Connection ID)", _v(entity),
            ACTION if dup else SAME, "Shared with another Okta app - must be unique in PingFederate" if dup else "")
    add("SP connection", "Okta app status", app.okta_status, "Connection status",
        "Active" if app.okta_status == "ACTIVE" else "Create disabled or skip", SAME if app.okta_status == "ACTIVE" else ACTION)

    acs = s.acs_endpoints or ([{"url": s.sso_acs_url, "index": 0}] if s.sso_acs_url else [])
    if not acs:
        add("SP connection", "ACS URL", "Not exposed (catalog app)" if partial else "—",
            "Protocol Settings > Assertion Consumer Service URL", "From vendor SP metadata", UNKNOWN)
    for e in acs:
        add("SP connection", f"ACS URL (index {e.get('index', 0)})", _v(e.get("url")),
            "Protocol Settings > Assertion Consumer Service URL (HTTP-POST)", _v(e.get("url")), SAME,
            "Set 'Default' on index 0" if len(acs) > 1 and e.get("index", 0) == 0 else "")
    if s.recipient and s.sso_acs_url and s.recipient != s.sso_acs_url:
        add("SP connection", "Recipient", s.recipient, "Recipient (derived from ACS URL)", _v(s.sso_acs_url),
            ACTION, "Differs in Okta - confirm the SP accepts the ACS URL as Recipient")
    add("SP connection", "Default RelayState", _v(s.default_relay_state),
        "IdP-initiated SSO TargetResource", _v(s.default_relay_state), SAME if s.default_relay_state else NA)
    add("SP connection", "Single logout", _v(s.slo_enabled) + (f" ({s.slo_logout_url})" if s.slo_logout_url else ""),
        "Protocol Settings > SLO Service URL", _v(s.slo_logout_url) if s.slo_enabled else "—",
        CONFIGURE if s.slo_enabled else NA)
    add("SP connection", "Signed AuthnRequests", _v(s.sp_certificate_present),
        "Signature Verification > require signed AuthnRequests + SP certificate",
        "Import SP signing certificate" if s.sp_certificate_present else "Not required",
        CONFIGURE if s.sp_certificate_present else NA)

    # --- IdP identity (what the SP trusts) -------------------------------------
    okta_issuer = s.idp_issuer if s.idp_issuer and "${" not in s.idp_issuer else s.metadata_entity_id
    if "CUSTOM_IDP_ISSUER" in codes:
        add("IdP identity", "IdP entity ID (Issuer)", _v(s.idp_issuer), "Virtual Server ID on the connection",
            _v(s.idp_issuer), ACTION, "Add the custom issuer as a virtual server ID so the SP needs no change")
    else:
        add("IdP identity", "IdP entity ID (Issuer)", _v(okta_issuer), "Server Settings > SAML 2.0 Entity ID",
            settings.pf_entity_id, SP_UPDATE, "SP must trust the new issuer")
    add("IdP identity", "SSO URL", _v(s.metadata_sso_url), "Runtime SSO endpoint",
        f"{base}/idp/SSO.saml2", SP_UPDATE)
    if entity:
        add("IdP identity", "IdP-initiated SSO link", "Okta app embed link", "IdP-initiated SSO URL",
            f"{base}/idp/startSSO.ping?PartnerSpId={quote(entity, safe='')}", SP_UPDATE,
            "Update portal bookmarks and links")
        add("IdP identity", "IdP metadata", "Okta app metadata URL", "Metadata export URL",
            f"{base}/pf/federation_metadata.ping?PartnerSpId={quote(entity, safe='')}", SP_UPDATE)
    if s.slo_enabled:
        add("IdP identity", "IdP SLO URL", "Okta SLO endpoint", "Runtime SLO endpoint", f"{base}/idp/SLO.saml2", SP_UPDATE)
    certs = [c for c in app.certificates if c.is_active_signing_key] or app.certificates
    c = certs[0] if certs else None
    add("IdP identity", "Signing certificate",
        f"{c.sha1_thumbprint} (expires {c.not_after:%Y-%m-%d})" if c and c.not_after and c.sha1_thumbprint else "—",
        "Signature Policy > Signing Certificate", "PingFederate signing key (new)", SP_UPDATE,
        "Okta does not export private keys - SP must trust the new certificate")

    # --- Assertion ----------------------------------------------------------------
    add("Assertion", "NameID format", _v(s.name_id_format), "Attribute Contract > SAML_SUBJECT format",
        _v(s.name_id_format), UNKNOWN if partial and not s.name_id_format else SAME)
    ns = {"DATA_STORE": SAME, "TEXT": SAME, "OGNL": ACTION, "UNMAPPED": ACTION}.get(s.pf_nameid_source or "", UNKNOWN)
    if partial and not s.name_id_template:
        ns = UNKNOWN
    add("Assertion", "NameID value", _v(s.name_id_template), "Contract Fulfillment > SAML_SUBJECT",
        _v(s.pf_nameid_detail), ns)
    sig = []
    if s.response_signed:
        sig.append("response")
    if s.assertion_signed:
        sig.append("assertion")
    add("Assertion", "Signing", " + ".join(sig) or "—", "Signature Policy",
        "Sign response + 'Always sign the SAML assertion'" if s.assertion_signed else "Sign response (default)",
        CONFIGURE if s.assertion_signed else SAME)
    alg = (s.signature_algorithm or "")
    add("Assertion", "Signature algorithm", _v(alg or None), "Signature Policy > Signing Algorithm",
        "RSA SHA256" if not alg.upper().endswith("SHA1") else "RSA SHA1 (plan SHA256)",
        ACTION if alg.upper().endswith("SHA1") else SAME)
    add("Assertion", "AuthnContextClassRef", _v(s.authn_context_class_ref),
        "Authentication policy / adapter mapping", _v(s.authn_context_class_ref),
        CONFIGURE if s.authn_context_class_ref and s.authn_context_class_ref != DEFAULT_AUTHN else SAME)
    if s.assertion_lifetime_seconds:
        mins = max(1, round(s.assertion_lifetime_seconds / 60))
        add("Assertion", "Assertion lifetime", f"{s.assertion_lifetime_seconds} s",
            "Protocol Settings > Assertion Lifetime (minutes before / after)", f"{mins} / {mins}", SAME)
    add("Assertion", "App username", _v(app.user_name_template), "Used via SAML_SUBJECT / attributes",
        "Directory attribute" if "CUSTOM_APP_USERNAME" not in codes else "Needs directory attribute or OGNL",
        ACTION if "CUSTOM_APP_USERNAME" in codes else SAME)

    # --- Attribute contract -------------------------------------------------------
    if partial and not app.claims:
        add("Attributes", "Attribute statements", "Not exposed (catalog app)", "Attribute Contract",
            "From vendor documentation", UNKNOWN)
    for cl in app.claims:
        okta = (f"{cl.group_filter_type} {cl.group_filter_value}" if cl.claim_type == "GROUP"
                else ", ".join(cl.values))
        st = {"DATA_STORE": SAME, "TEXT": SAME, "GROUP_LDAP_SEARCH": CONFIGURE,
              "OGNL": ACTION, "GROUP_OGNL": ACTION, "APPUSER": ACTION, "UNMAPPED": ACTION}.get(cl.pf_source or "", UNKNOWN)
        note = ""
        if cl.matched_okta_native_groups:
            st = ACTION
            note = "Okta-only groups: " + ", ".join(cl.matched_okta_native_groups)
        add("Attributes", cl.name,
            okta, f"Attribute Contract '{cl.name}' <- {cl.pf_source}", _v(cl.pf_source_detail), st, note)

    # --- Access control -------------------------------------------------------------
    groups = [a for a in app.assignments if a.principal_type == "GROUP"]
    gnames = [g.principal_name or g.principal_id for g in groups]
    if "ISSUANCE_CRITERIA_REQUIRED" in codes:
        add("Access control", "Assigned groups", ", ".join(gnames) or "—", "Issuance Criteria (memberOf)",
            "memberOf includes one of: " + (", ".join(gnames) or "—"), ACTION,
            "Without this, any authenticated user gets an assertion")
    else:
        add("Access control", "Assigned groups", ", ".join(gnames) or "—", "Issuance Criteria",
            "None needed" if gnames else "—", SAME if gnames else NA)
    if app.direct_user_count:
        add("Access control", "Direct user assignments", f"{app.direct_user_count} user(s)",
            "Issuance Criteria", "Put users in a directory group", ACTION)
    for f in app.findings:
        if f.code == "OKTA_NATIVE_GROUPS_ASSIGNED":
            add("Access control", "Okta-only groups", ", ".join(f.detail.get("groups", [])),
                "Directory groups", "Create and populate in the directory", ACTION)
        if f.code == "ASSIGNMENT_PROFILE_ATTRIBUTES":
            add("Access control", "Assignment attributes", ", ".join(f.detail.get("attributes", [])),
                "Directory attribute or group-derived value", "Store in the directory", ACTION)
    return rows


GRANT_NAMES = {
    "authorization_code": "Authorization Code", "refresh_token": "Refresh Token",
    "client_credentials": "Client Credentials", "implicit": "Implicit",
    "password": "Resource Owner Password Credentials",
    "urn:ietf:params:oauth:grant-type:device_code": "Device Authorization",
    "urn:ietf:params:oauth:grant-type:token-exchange": "Token Exchange",
    "urn:ietf:params:oauth:grant-type:jwt-bearer": "JWT Bearer",
}
AUTH_METHOD = {
    "client_secret_basic": ("Client Secret (HTTP Basic) - new secret", ACTION,
                            "Okta does not return existing secrets; issue a new one and update the app"),
    "client_secret_post": ("Client Secret (POST) - new secret", ACTION,
                           "Okta does not return existing secrets; issue a new one and update the app"),
    "client_secret_jwt": ("Client Secret JWT - new secret", ACTION, "New shared secret required"),
    "private_key_jwt": ("Private Key JWT (import the client's JWKS)", CONFIGURE, "No secret changes"),
    "none": ("None (public client)", SAME, ""),
}


def build_oidc(app: Application, settings: Settings) -> list[Row]:
    o = app.oidc
    codes = {f.code for f in app.findings}
    base = settings.pf_base_url.rstrip("/")
    okta = (settings.okta_org or "https://<okta-org>") + "/oauth2/<auth-server>"
    rows: list[Row] = []
    add = lambda *a, **k: rows.append(Row(*a, **k))  # noqa: E731
    grants = o.grant_types or []

    # --- OAuth client ---------------------------------------------------------
    add("OAuth client", "Client name", app.label, "OAuth Client > Name", app.label, CONFIGURE)
    add("OAuth client", "Client ID", _v(o.client_id), "OAuth Client > Client ID", _v(o.client_id), SAME,
        "PingFederate lets you keep the same client ID, so the app config for it does not change")
    kind = {"web": "Confidential client (web app)", "native": "Public client (native / mobile)",
            "browser": "Public client (single-page app)", "service": "Confidential client (machine-to-machine)"}
    add("OAuth client", "Application type", _v(o.application_type), "Client type (derived)",
        kind.get(o.application_type or "", "—"), CONFIGURE)
    pf_auth, st, note = AUTH_METHOD.get(o.token_endpoint_auth_method or "", ("Confirm with app team", UNKNOWN, ""))
    add("OAuth client", "Client authentication", _v(o.token_endpoint_auth_method), "Client Authentication",
        pf_auth, st, note)
    add("OAuth client", "Okta app status", app.okta_status, "Client status",
        "Enabled" if app.okta_status == "ACTIVE" else "Create disabled or skip", SAME if app.okta_status == "ACTIVE" else ACTION)
    add("OAuth client", "Consent", _v(o.consent_method), "Bypass Authorization Approval",
        "Bypass (trusted)" if (o.consent_method or "").upper() == "TRUSTED" else "Require approval", SAME)

    # --- Redirects ----------------------------------------------------------------
    if not o.redirect_uris:
        add("Redirects", "Redirect URIs", "—", "Redirect URIs", "—", NA)
    wildcard = "OIDC_WILDCARD_REDIRECT" in codes
    for i, u in enumerate(o.redirect_uris, start=1):
        add("Redirects", f"Redirect URI {i}", u, "Redirect URIs", u,
            ACTION if "*" in u else SAME, "Wildcard: confirm PingFederate matching" if "*" in u else "")
    if wildcard and not any("*" in u for u in o.redirect_uris):
        add("Redirects", "Wildcard redirect mode", _v(o.wildcard_redirect), "Redirect URI matching",
            "List URIs explicitly", ACTION)
    for i, u in enumerate(o.post_logout_redirect_uris, start=1):
        add("Redirects", f"Post-logout redirect {i}", u, "Logout URIs", u, SAME)
    if o.initiate_login_uri:
        add("Redirects", "Initiate login URI", o.initiate_login_uri, "Portal / launcher link",
            o.initiate_login_uri, CONFIGURE, "Use in your app launcher; PingFederate does not start OIDC logins itself")

    # --- Grants & tokens ------------------------------------------------------------
    for g in grants:
        st = ACTION if g in ("implicit", "password") else SAME
        note = {"implicit": "Deprecated - move to Authorization Code + PKCE",
                "password": "Bypasses MFA - agree with security"}.get(g, "")
        add("Grants & tokens", f"Grant: {g}", g, "Allowed Grant Types", GRANT_NAMES.get(g, g), st, note)
    add("Grants & tokens", "Response types", ", ".join(o.response_types) or "—", "Restrict Response Types",
        ", ".join(o.response_types) or "—", CONFIGURE if o.response_types else NA)
    public = o.token_endpoint_auth_method == "none" or o.application_type in ("native", "browser")
    if "authorization_code" in grants:
        need = public and not o.pkce_required
        add("Grants & tokens", "PKCE", _v(o.pkce_required), "Require Proof Key for Code Exchange (PKCE)",
            "Yes" if (o.pkce_required or public) else "Optional", ACTION if need else SAME,
            "Public client - require PKCE" if need else "")
    if "refresh_token" in grants:
        add("Grants & tokens", "Existing refresh tokens", "Issued by Okta", "Refresh tokens",
            "Not migrated - users sign in once after cutover", SP_UPDATE)
    add("Grants & tokens", "Access token format / lifetime", "Set on the Okta authorization server",
        "Access Token Manager", "To be defined (next sprint)", UNKNOWN)

    # --- Endpoints (the app must update) -------------------------------------------
    for field, ok, pf in (
        ("Issuer", okta, base),
        ("Discovery document", f"{okta}/.well-known/openid-configuration", f"{base}/.well-known/openid-configuration"),
        ("Authorization endpoint", f"{okta}/v1/authorize", f"{base}/as/authorization.oauth2"),
        ("Token endpoint", f"{okta}/v1/token", f"{base}/as/token.oauth2"),
        ("UserInfo endpoint", f"{okta}/v1/userinfo", f"{base}/idp/userinfo.openid"),
        ("JWKS (signing keys)", f"{okta}/v1/keys", f"{base}/pf/JWKS"),
        ("Logout endpoint", f"{okta}/v1/logout", f"{base}/idp/startSLO.ping"),
    ):
        if field == "Logout endpoint" and not o.post_logout_redirect_uris:
            continue
        if field in ("Authorization endpoint", "UserInfo endpoint") and grants == ["client_credentials"]:
            continue
        add("Endpoints", field, ok, "PingFederate runtime", pf, SP_UPDATE,
            "Apps using the discovery document pick the rest up automatically" if field == "Issuer" else "")

    # --- Scopes & claims -------------------------------------------------------------
    add("Scopes & claims", "Scopes", "Granted by the Okta authorization server policy", "OAuth scopes / scope groups",
        "Analysed next sprint", UNKNOWN)
    if grants != ["client_credentials"]:
        add("Scopes & claims", "ID token claims", "Okta authorization server claims", "OpenID Connect policy",
            "Analysed next sprint", UNKNOWN)
    add("Scopes & claims", "Access token claims", "Okta authorization server claims", "Access token mapping",
        "Analysed next sprint", UNKNOWN)

    # --- Access control -----------------------------------------------------------------
    groups = [a for a in app.assignments if a.principal_type == "GROUP"]
    gnames = [g.principal_name or g.principal_id for g in groups]
    if "OIDC_MACHINE_CLIENT" in codes:
        add("Access control", "Who can use it", "Machine client (no users)", "Client credentials only",
            "Restrict by client and scopes", CONFIGURE)
    elif "OIDC_ACCESS_CONTROL_REQUIRED" in codes:
        add("Access control", "Assigned groups", ", ".join(gnames) or "—",
            "Authentication policy / issuance criteria", "memberOf includes one of: " + (", ".join(gnames) or "—"),
            ACTION, "Without this, any user who can sign in gets tokens")
    else:
        add("Access control", "Assigned groups", ", ".join(gnames) or "—", "Authentication policy",
            "None needed" if gnames else "—", SAME if gnames else NA)
    if app.direct_user_count:
        add("Access control", "Direct user assignments", f"{app.direct_user_count} user(s)",
            "Authentication policy", "Put users in a directory group", ACTION)
    for f in app.findings:
        if f.code == "OKTA_NATIVE_GROUPS_ASSIGNED":
            add("Access control", "Okta-only groups", ", ".join(f.detail.get("groups", [])),
                "Directory groups", "Create and populate in the directory", ACTION)
    return rows


def sections(rows: list[Row]) -> list[str]:
    out: list[str] = []
    for r in rows:
        if r.section not in out:
            out.append(r.section)
    return out


def summarise(rows: list[Row]) -> dict[str, int]:
    out = {k: 0 for k in STATUS_ORDER}
    for r in rows:
        out[r.status] = out.get(r.status, 0) + 1
    return out
