"""Deterministic finding rules for an Okta -> PingFederate SAML migration.

These are facts about the Okta configuration that matter for PingFederate.
They are NOT the risk score (Sprint 2); they are its inputs. Every rule is a
pure function of the discovered data so results are reproducible and
explainable to the customer's change board.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.integrations.pingfederate import mapping as pf
from app.models.domain import (
    AppGroupModel, AppModel, AppUserModel, CertificateModel, GroupModel,
)

INFO, WARNING, CRITICAL = "INFO", "WARNING", "CRITICAL"

DEFAULT_USERNAME_TEMPLATES = {"${source.login}", "${source.email}", None}
DEFAULT_AUTHN_CONTEXT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
DEFAULT_IDP_ISSUER = "http://www.okta.com/${org.externalKey}"


@dataclass
class FindingResult:
    code: str
    severity: str
    message: str
    detail: dict = field(default_factory=dict)


@dataclass
class AppContext:
    app: AppModel
    app_users: list[AppUserModel]
    app_groups: list[AppGroupModel]
    groups_by_id: dict[str, GroupModel]
    certificates: list[CertificateModel]
    group_matches: dict[int, list[str]]            # claim position -> matched group names
    claim_sources: dict[int, pf.PfSource] = field(default_factory=dict)
    okta_native_matches: dict[int, list[str]] = field(default_factory=dict)
    nameid_source: pf.PfSource | None = None
    apps_sharing_entity_id: list[str] = field(default_factory=list)  # other app labels
    changed_since_last_run: bool = False
    usage: dict | None = None      # {"events", "unique_users", "last_seen", "days"} or None if unknown


def _is_directory_group(g: GroupModel) -> bool:
    return g.group_type == "APP_GROUP" or bool(g.source_app)


def evaluate(ctx: AppContext, now: datetime, cert_warning_days: int = 90,
             ognl_allowed: bool = False) -> list[FindingResult]:
    out: list[FindingResult] = []
    app, saml = ctx.app, ctx.app.saml
    add = lambda *a, **k: out.append(FindingResult(*a, **k))  # noqa: E731
    ognl_sev = WARNING if ognl_allowed else CRITICAL
    ognl_note = ("OGNL is allowed, but keep expressions few and reviewed." if ognl_allowed else
                 "OGNL is not allowed here, so the value must be pre-computed into a directory attribute.")

    if ctx.changed_since_last_run:
        add("CHANGED_SINCE_LAST_RUN", INFO,
            "Okta configuration changed since the previous discovery run. Re-review any mapping already done.")
    if app.okta_status != "ACTIVE":
        add("APP_INACTIVE", INFO,
            f"App is {app.okta_status} in Okta. Confirm with the owner whether to migrate or decommission.")

    machine = bool(app.oidc and (app.oidc.application_type == "service"
                                 or set(app.oidc.grant_types) == {"client_credentials"}))
    u = ctx.usage
    if u is not None and app.okta_status == "ACTIVE":
        assigned = len(ctx.app_users)
        if u["events"] == 0 and not machine:
            add("UNUSED_IN_WINDOW", WARNING,
                f"No successful sign-ins in the last {u['days']} days although {assigned} user(s) are assigned. "
                "Strong decommission candidate: confirm with the owner before migrating.",
                {"days": u["days"], "assigned": assigned})
        elif not machine and assigned >= 10 and u["unique_users"] < max(1, assigned // 10):
            add("LOW_USAGE", INFO,
                f"Only {u['unique_users']} of {assigned} assigned users signed in during the last {u['days']} days. "
                "Consider trimming assignments before migrating.",
                {"days": u["days"], "active": u["unique_users"], "assigned": assigned})

    # --- assignments -> PingFederate access control -------------------------
    direct = [u for u in ctx.app_users if (u.scope or "").upper() == "USER"]
    machine_client = bool(app.oidc and (app.oidc.application_type == "service"
                                        or set(app.oidc.grant_types) == {"client_credentials"}))
    if machine_client:
        add("OIDC_MACHINE_CLIENT", INFO,
            "Machine-to-machine client (client_credentials): no users are assigned by design. "
            "Identify the calling system's owner and the APIs (scopes) it needs.")
    elif not ctx.app_users and not ctx.app_groups:
        add("NO_ASSIGNMENTS", WARNING,
            "No users or groups are assigned. Likely a decommission candidate rather than a migration.")
    if direct:
        add("DIRECT_USER_ASSIGNMENTS", WARNING,
            f"{len(direct)} user(s) are assigned directly. PingFederate has no per-user app "
            "assignment; put these users in a directory group and use it in issuance criteria.",
            {"count": len(direct), "users": [u.login or u.app_username for u in direct][:50]})

    assigned = [ctx.groups_by_id.get(ag.group_id) for ag in ctx.app_groups]
    unknown = [ag.group_id for ag, g in zip(ctx.app_groups, assigned) if g is None]
    assigned = [g for g in assigned if g is not None]
    everyone = any(g.group_type == "BUILT_IN" for g in assigned)
    okta_only = [g.name for g in assigned if g.group_type == "OKTA_GROUP"]
    dir_groups = [g.name for g in assigned if _is_directory_group(g)]

    if (assigned or direct) and not everyone and app.is_oidc:
        add("OIDC_ACCESS_CONTROL_REQUIRED", WARNING,
            "Okta only issues tokens to assigned users. In PingFederate, restrict this OAuth client "
            "with an authentication policy or issuance criteria on group membership, otherwise any "
            "user who can sign in gets tokens.",
            {"groups": [g.name for g in assigned], "direct_users": len(direct)})
    elif (assigned or direct) and not everyone:
        add("ISSUANCE_CRITERIA_REQUIRED", WARNING,
            "Okta limits this app to assigned users. PingFederate has no app assignments, so without "
            "issuance criteria (or an authentication policy rule) on the SP connection, any user who "
            "can sign in gets an assertion. Restrict on group membership.",
            {"groups": [g.name for g in assigned], "direct_users": len(direct)})
    if okta_only:
        add("OKTA_NATIVE_GROUPS_ASSIGNED", WARNING,
            f"{len(okta_only)} assigned group(s) exist only in Okta. Create and populate them in the "
            "directory before the issuance criteria can use them.", {"groups": okta_only})
    if dir_groups:
        add("DIRECTORY_SOURCED_GROUPS_ASSIGNED", INFO,
            f"{len(dir_groups)} assigned group(s) come from the directory, so PingFederate can check "
            "them through its LDAP data store.", {"groups": dir_groups})
    if unknown:
        add("UNRESOLVED_GROUP_ASSIGNMENTS", WARNING,
            f"{len(unknown)} assigned group id(s) were not found in the group list.", {"ids": unknown})

    profile_keys = sorted({k for ag in ctx.app_groups for k, v in ag.profile.items() if v not in (None, "", [])}
                          | {k for u in ctx.app_users for k, v in u.profile.items() if v not in (None, "", [])})
    if profile_keys:
        add("ASSIGNMENT_PROFILE_ATTRIBUTES", WARNING,
            "Assignments carry app-specific values (e.g. a role per group). PingFederate has nowhere to "
            "hold these; store them in the directory or derive them from group membership.",
            {"attributes": profile_keys})

    if app.is_oidc and app.oidc is not None:
        out.extend(_oidc_rules(app))
        return out
    if not app.is_saml or saml is None:
        return out

    # --- SAML configuration ------------------------------------------------
    if saml.config_completeness == "PARTIAL":
        add("CATALOG_APP_PARTIAL_CONFIG", WARNING,
            f"OIN catalog app ('{app.okta_name}'). Okta's API does not return the SP's ACS URL, entity "
            "ID or built-in claims. Get the SP metadata from the vendor; PingFederate can import it "
            "when creating the SP connection.", {"catalog_settings": saml.catalog_app_settings})

    if ctx.apps_sharing_entity_id:
        add("DUPLICATE_SP_ENTITY_ID", WARNING,
            f"SP entity ID '{saml.audience}' is also used by: {', '.join(ctx.apps_sharing_entity_id)}. "
            "PingFederate identifies each SP connection by its partner entity ID, so these cannot be "
            "separate connections as-is.", {"entity_id": saml.audience, "apps": ctx.apps_sharing_entity_id})

    if saml.idp_issuer and saml.idp_issuer != DEFAULT_IDP_ISSUER:
        add("CUSTOM_IDP_ISSUER", WARNING,
            f"The SP expects the custom issuer '{saml.idp_issuer}'. Either set a matching virtual "
            "server ID on the PingFederate connection or change the issuer on the SP.",
            {"issuer": saml.idp_issuer})

    ns = ctx.nameid_source
    if ns is not None:
        if ns.unmapped == ["user.id"]:
            add("NAMEID_IS_OKTA_USER_ID", CRITICAL,
                "NameID is the Okta user id. PingFederate can only emit it if the id is copied into a "
                "directory attribute before cutover; otherwise the SP must re-link accounts.",
                {"template": saml.name_id_template})
        elif ns.kind == pf.OGNL:
            add("NAMEID_NEEDS_OGNL", ognl_sev, f"NameID: {ns.detail}. {ognl_note}",
                {"template": saml.name_id_template, "username_template": app.user_name_template})
        elif ns.kind == pf.UNMAPPED and saml.config_completeness == "FULL":
            add("NAMEID_ATTRIBUTE_UNMAPPED", WARNING, f"NameID: {ns.detail}.",
                {"template": saml.name_id_template})

    if app.user_name_template not in DEFAULT_USERNAME_TEMPLATES:
        add("CUSTOM_APP_USERNAME", WARNING,
            f"Custom Okta app username '{app.user_name_template}'. The SP likely keys accounts on it; "
            "PingFederate must produce the identical value (OGNL or a directory attribute).",
            {"template": app.user_name_template})

    if saml.allow_multiple_acs or len(saml.acs_endpoints) > 1:
        add("MULTIPLE_ACS", INFO,
            f"{max(len(saml.acs_endpoints), 1)} ACS endpoints. Add each to the SP connection with the same index.",
            {"endpoints": [{"url": e.url, "index": e.index} for e in saml.acs_endpoints]})
    if saml.sso_acs_url and saml.recipient and saml.recipient != saml.sso_acs_url:
        add("RECIPIENT_DIFFERS_FROM_ACS", INFO,
            "Recipient differs from the ACS URL. PingFederate sets Recipient to the ACS URL; confirm the SP accepts that.")
    if saml.slo_enabled:
        add("SLO_ENABLED", INFO,
            "Single logout is enabled. Enable SLO on the SP connection and add the SP's SLO endpoint.",
            {"logout_url": saml.slo_logout_url})
    if saml.sp_certificate_present:
        add("SIGNED_AUTHN_REQUESTS", INFO,
            "The SP signs AuthnRequests. Import its signing certificate into the SP connection.")
    if saml.response_signed and saml.assertion_signed:
        add("RESPONSE_AND_ASSERTION_SIGNED", INFO,
            "Okta signs both response and assertion. Enable 'Always sign the SAML assertion' on the "
            "SP connection so the SP still gets a signed assertion.")
    if (saml.signature_algorithm or "").upper().endswith("SHA1"):
        add("SHA1_SIGNATURE", INFO, "SHA-1 signing is used. Agree a move to SHA-256 with the vendor at cutover.")
    if saml.default_relay_state:
        add("DEFAULT_RELAY_STATE", INFO,
            "A default RelayState is set. Use it as the TargetResource for IdP-initiated SSO links.",
            {"relay_state": saml.default_relay_state})
    if saml.authn_context_class_ref and saml.authn_context_class_ref != DEFAULT_AUTHN_CONTEXT:
        add("NON_DEFAULT_AUTHN_CONTEXT", INFO,
            f"The SP gets AuthnContextClassRef '{saml.authn_context_class_ref}'. Map it in the PingFederate "
            "authentication policy / adapter mapping.")

    # --- claims ------------------------------------------------------------
    for c in saml.claims:
        src = ctx.claim_sources.get(c.position)
        if src is None:
            continue
        base = {"claim": c.name, "values": c.values, "pf_source": src.kind, "detail": src.detail}
        if src.kind == pf.APPUSER or any(m.lower().startswith("appuser.") for m in src.unmapped):
            add("APPUSER_ATTRIBUTE_CLAIM", WARNING,
                f"Claim '{c.name}' reads an Okta app-user attribute. Store the value in the directory "
                "(or derive it from groups) so PingFederate has a source.", base)
        if src.kind in (pf.OGNL, pf.GROUP_OGNL):
            add("CLAIM_NEEDS_OGNL", ognl_sev, f"Claim '{c.name}': {src.detail}. {ognl_note}", base)
        if src.kind == pf.UNMAPPED or (src.kind == pf.OGNL and
                                       [m for m in src.unmapped if not m.lower().startswith("appuser.")]):
            add("CLAIM_ATTRIBUTE_UNMAPPED", WARNING,
                f"Claim '{c.name}' uses Okta attribute(s) with no known directory equivalent: "
                f"{', '.join(m for m in src.unmapped if not m.lower().startswith('appuser.'))}. "
                "Confirm or add the attribute (or set PF_ATTRIBUTE_MAP_FILE).", base)
        if c.claim_type == "GROUP":
            matched = ctx.group_matches.get(c.position, [])
            add("GROUP_CLAIM", WARNING,
                f"Group claim '{c.name}' ({c.group_filter_type} '{c.group_filter_value}') matches "
                f"{len(matched)} tenant group(s). {src.detail}. Check whether the SP expects nested "
                "group membership.", {**base, "matched_count": len(matched), "sample": matched[:20]})
            native = ctx.okta_native_matches.get(c.position, [])
            if native:
                add("GROUP_CLAIM_OKTA_NATIVE_GROUPS", WARNING,
                    f"Group claim '{c.name}' includes {len(native)} Okta-only group(s) that PingFederate "
                    f"cannot see: {', '.join(native[:10])}. Create them in the directory or accept that "
                    "they drop out of the assertion.", {"claim": c.name, "groups": native})

    # --- certificates ------------------------------------------------------
    if not ctx.certificates:
        add("NO_SIGNING_CERTIFICATE_FOUND", WARNING, "No signing key was returned for this SAML app.")
    for cert in ctx.certificates:
        is_active = cert.kid == app.active_signing_kid or len(ctx.certificates) == 1
        if not is_active or cert.not_after is None:
            continue
        if cert.not_after < now:
            add("CERT_EXPIRED", CRITICAL, f"Active signing certificate expired on {cert.not_after:%Y-%m-%d}.",
                {"kid": cert.kid})
        elif cert.not_after < now + timedelta(days=cert_warning_days):
            days = (cert.not_after - now).days
            add("CERT_EXPIRING", WARNING,
                f"Active signing certificate expires in {days} days ({cert.not_after:%Y-%m-%d}). "
                "Migrating before expiry avoids a rotation on Okta.", {"kid": cert.kid, "days": days})

    return out


CONFIDENTIAL_AUTH = {"client_secret_basic", "client_secret_post", "client_secret_jwt"}


def _oidc_rules(app: AppModel) -> list[FindingResult]:
    o = app.oidc
    out: list[FindingResult] = []
    add = lambda *a, **k: out.append(FindingResult(*a, **k))  # noqa: E731
    grants = set(o.grant_types)

    add("OIDC_ISSUER_CHANGE", INFO,
        "Tokens will be issued by PingFederate, so the issuer, discovery URL and JWKS change. The app "
        "must point at PingFederate's /.well-known/openid-configuration at cutover.")
    if o.token_endpoint_auth_method in CONFIDENTIAL_AUTH:
        add("OIDC_NEW_CLIENT_SECRET", WARNING,
            "Confidential client using a shared secret. Okta does not hand back existing secrets, so plan a "
            "new secret in PingFederate and a coordinated update in the app.",
            {"auth_method": o.token_endpoint_auth_method})
    if o.token_endpoint_auth_method == "private_key_jwt" or o.has_jwks:
        add("OIDC_PRIVATE_KEY_JWT", INFO,
            "The client authenticates with private_key_jwt. Register its public key (JWKS) on the "
            "PingFederate client; no secret needs to change.")
    if "implicit" in grants:
        add("OIDC_IMPLICIT_GRANT", WARNING,
            "Implicit grant is enabled. It is deprecated; use the move to switch the app to "
            "authorization code with PKCE.", {"grant_types": o.grant_types})
    if "refresh_token" in grants:
        add("OIDC_REFRESH_TOKENS", INFO,
            "The app uses refresh tokens. Okta refresh tokens cannot be moved, so users sign in again "
            "once after cutover.")
    if "password" in grants:
        add("OIDC_PASSWORD_GRANT", WARNING,
            "Resource owner password grant is enabled. PingFederate supports it, but it bypasses MFA; "
            "agree with security whether to keep it.")
    public = o.token_endpoint_auth_method == "none" or o.application_type in ("native", "browser")
    if public and not o.pkce_required and "authorization_code" in grants:
        add("OIDC_PKCE_NOT_REQUIRED", WARNING,
            "Public client without PKCE required. Require PKCE on the PingFederate client.")
    if (o.wildcard_redirect or "").upper() not in ("", "DISABLED") or any("*" in u for u in o.redirect_uris):
        add("OIDC_WILDCARD_REDIRECT", WARNING,
            "Wildcard redirect URIs are used. Confirm PingFederate's redirect URI matching will accept "
            "the same values, or list them explicitly.", {"redirect_uris": o.redirect_uris})
    if len(o.redirect_uris) > 3:
        add("OIDC_MANY_REDIRECT_URIS", INFO, f"{len(o.redirect_uris)} redirect URIs. Copy all of them to the client.")
    if o.issuer_mode and o.issuer_mode.upper() != "ORG_URL":
        add("OIDC_CUSTOM_ISSUER_MODE", INFO,
            f"Okta issuer mode '{o.issuer_mode}' (custom domain). Check what issuer value the app validates.")
    add("OIDC_SCOPES_CLAIMS_NOT_ANALYSED", INFO,
        "Scopes, custom claims and access policies live on the Okta authorization server and are not "
        "analysed yet (next sprint). Review them manually for now.")
    return out
