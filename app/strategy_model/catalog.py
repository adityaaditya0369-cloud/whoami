"""Target capability catalog: every Okta feature the strategy model recognises, with the
PingFederate capability it maps to, a compatibility level, a default migration strategy,
the evidence for that call and where it came from.

This is the single place where "is it compatible?" is decided. The LLM never decides it.
Rows are versioned (CATALOG_VERSION); a customer-specific JSON file (CAPABILITY_CATALOG_FILE)
can override or add rows, e.g. after an architect's review or when the customer licenses
PingID / PingOne MFA.

Compatibility
  EQUIVALENT  PingFederate has a direct equivalent
  PARTIAL     possible, but the configuration must be transformed or the design changed
  NONE        no equivalent in PingFederate (another product or a redesign is needed)

Strategy (default for the feature; the decision engine combines them per app)
  RECREATE    rebuild the same configuration in PingFederate
  TRANSFORM   rebuild with mapping rules (expressions, groups, attributes, grants)
  REDESIGN    no direct equivalent: architecture review and a new target design
  RETIRE      stop using it (after business validation)
  RETAIN      keep on Okta for now (coexistence), migrate later

`review` = "DOCS" when the row is backed by the linked vendor documentation, "EXPERT" when
it needs a PingFederate architect's confirmation for this customer (licensing, versions).
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path

CATALOG_VERSION = "2026.09-pf-2"
TARGET = "PingFederate"
LAST_VERIFIED = "2026-09-29"

EQUIVALENT, PARTIAL, NONE = "EQUIVALENT", "PARTIAL", "NONE"
COMPAT_ORDER = [EQUIVALENT, PARTIAL, NONE]
STRATEGIES = ["RECREATE", "TRANSFORM", "REDESIGN", "RETIRE", "RETAIN"]

PF = "https://docs.pingidentity.com/pingfederate/13.0/administrators_reference_guide"
DOC = {
    "sp_conn": f"{PF}/pf_sp_connect_management.html",
    "oauth_clients": f"{PF}/pf_configuring_oauth_clients.html",
    "auth_policies": f"{PF}/pf_authentication_policies.html",
    "cidr": f"{PF}/pf_config_cidr_auth_selector.html",
    "rest_ds": "https://docs.pingidentity.com/pingfederate/12.3/administrators_reference_guide/pf_config_rest_api_datastore.html",
    "multi_ds": f"{PF}/pf_attribut_mapp_w_multiple_dat_sources.html",
    "outbound": f"{PF}/help_spconnectionconfigtasklet_saasprovisioningstate.html",
    "scim": "https://docs.pingidentity.com/integrations/scim/pf_scim_connector.html",
    "wsfed": "https://docs.pingidentity.com/pingfederate/13.0/introduction_to_pingfederate/pf_ws_fed.html",
    "okta_policies": "https://developer.okta.com/docs/concepts/policies/",
}


@dataclass(frozen=True)
class Capability:
    key: str
    area: str                 # Application | Claims & groups | OIDC | Sign-in & MFA | Extensibility | Directory | Federation
    okta_feature: str
    pf_capability: str
    compatibility: str
    strategy: str
    effort_hours: float       # typical engineering hours per occurrence (planning figure)
    evidence: str
    sources: tuple[str, ...] = ()
    review: str = "DOCS"
    prerequisite: bool = False  # tenant-level work that must be ready before apps that use it

    def as_dict(self) -> dict:
        return asdict(self)


_ROWS: list[Capability] = [
    # --- applications --------------------------------------------------------------------
    Capability("app.saml", "Application", "SAML 2.0 app (custom / AIW)", "SP connection (IdP role, SAML 2.0)",
               EQUIVALENT, "RECREATE", 3, "PingFederate is a SAML IdP; each Okta SAML app becomes one SP connection "
               "keyed on the partner entity ID.", (DOC["sp_conn"],)),
    Capability("app.saml.catalog", "Application", "SAML app from the Okta Integration Network (OIN)",
               "SP connection built from the vendor's SP metadata", EQUIVALENT, "RECREATE", 4,
               "Protocol is equivalent, but Okta hides part of an OIN app's configuration: ACS URL, entity ID and "
               "attributes must come from the vendor's metadata or SSO guide.", (DOC["sp_conn"],)),
    Capability("app.wsfed", "Application", "WS-Federation app", "SP connection (WS-Federation)", EQUIVALENT, "RECREATE", 3,
               "PingFederate supports WS-Federation passive requestor SP connections.", (DOC["wsfed"],)),
    Capability("app.oidc", "OIDC", "OIDC app (authorization code, client credentials)",
               "OAuth client + OpenID Connect policy", EQUIVALENT, "RECREATE", 2,
               "Each Okta OIDC app becomes an OAuth client; ID-token claims come from an OIDC policy. The client ID can "
               "be kept; plan for a new client secret unless the existing one can be exported and entered.",
               (DOC["oauth_clients"],)),
    Capability("app.oidc.implicit", "OIDC", "Implicit grant", "Implicit supported; recommend authorization code + PKCE",
               EQUIVALENT,
               "TRANSFORM", 3, "Implicit can be configured, but the migration is the moment to move the client to "
               "authorization code with PKCE; the app code usually changes.", (DOC["oauth_clients"],)),
    Capability("app.oidc.wildcard_redirect", "OIDC", "Wildcard redirect URIs", "Explicit redirect URIs",
               PARTIAL, "TRANSFORM", 1, "List the real redirect URIs explicitly; confirm whether wildcards are "
               "permitted in the customer's PingFederate version and policy.", (DOC["oauth_clients"],), review="EXPERT"),
    Capability("app.oidc.custom_auth_server", "OIDC", "App uses a custom authorization server",
               "Client linked to the access token manager and OIDC policy", PARTIAL, "TRANSFORM", 1,
               "Per-app wiring to the access token manager built for the authorization server (the server itself is "
               "counted once, as a tenant object).", (DOC["oauth_clients"],)),
    Capability("app.swa", "Application", "Password-vaulting app (SWA / auto-login / browser plug-in)",
               "No equivalent (PingFederate is not a password vault)", NONE, "REDESIGN", 6,
               "Federate the app if it supports SAML/OIDC, move it to a password manager / PAM, or retire it.", ()),
    Capability("app.bookmark", "Application", "Bookmark app", "No equivalent (a portal link)", NONE, "RETIRE", 0.5,
               "A bookmark has no federation; publish the link in the intranet or portal instead.", ()),
    Capability("app.access_policy", "Sign-in & MFA", "App sign-in policy (Okta Identity Engine)",
               "Authentication policy tree + selectors", PARTIAL, "REDESIGN", 2,
               "Okta evaluates per-app rules (groups, network, device, factors); PingFederate uses authentication "
               "policies with selectors and adapters. Rules are redesigned, not copied.", (DOC["auth_policies"], DOC["okta_policies"])),
    Capability("app.provisioning", "Directory", "Outbound provisioning to the app (SCIM / API push)",
               "PingFederate outbound provisioning (SaaS connector or SCIM provisioner)", PARTIAL, "TRANSFORM", 6,
               "Supported through SP-connection outbound provisioning; confirm a connector exists for this app and "
               "that the directory holds the attributes Okta pushed.", (DOC["outbound"], DOC["scim"]), review="EXPERT"),
    Capability("app.profile_master", "Directory", "App is a profile source for Okta (profile mastering, e.g. HR)",
               "No equivalent (PingFederate is not a user store)", NONE, "REDESIGN", 12,
               "The joiner/mover/leaver flow from this app must move to the directory or an IGA tool before cutover.", ()),
    Capability("app.provisioning.import", "Directory", "Import users from the app into Okta",
               "No equivalent (PingFederate is not a user store)", NONE, "REDESIGN", 8,
               "Decide the new source of truth for these users (directory, HR system or IGA) before cutover.", ()),
    # --- claims, NameID and groups ---------------------------------------------------------
    Capability("claims.expression", "Claims & groups", "Okta Expression Language claims",
               "OGNL expression or pre-computed LDAP attribute", PARTIAL, "TRANSFORM", 2,
               "Simple user.* claims map to directory attributes; functions and conditionals need OGNL (if the "
               "customer allows it) or a new directory attribute.", (DOC["multi_ds"],)),
    Capability("claims.appuser", "Claims & groups", "App-user profile attributes (appuser.*)",
               "Directory attribute or additional data store", PARTIAL, "TRANSFORM", 3,
               "PingFederate has no per-app user profile; the values must live in the directory or another data store.",
               (DOC["multi_ds"],)),
    Capability("claims.groups", "Claims & groups", "Group attribute statements (filters, regex)",
               "LDAP group lookup with filtering (OGNL or LDAP search)", PARTIAL, "TRANSFORM", 2,
               "Groups come from the directory; Okta's name filters become an LDAP search filter or an OGNL filter.",
               (DOC["multi_ds"],)),
    Capability("groups.okta_only", "Claims & groups", "Okta-only groups used by apps",
               "Groups in the directory (AD / PingDirectory)", PARTIAL, "TRANSFORM", 1,
               "PingFederate reads groups from the directory, so Okta-mastered groups must be created and populated there.", ()),
    Capability("nameid.okta_user_id", "Claims & groups", "NameID = Okta user ID",
               "Persistent NameID from a directory attribute holding the old Okta ID", PARTIAL, "TRANSFORM", 5,
               "The SP keys accounts on the Okta user ID; copy it into a directory attribute or re-link accounts at the SP.", ()),
    Capability("saml.slo", "Application", "SAML single logout", "SAML SLO on the SP connection", EQUIVALENT, "RECREATE", 0.5,
               "Supported on SP connections.", (DOC["sp_conn"],)),
    Capability("saml.multiple_acs", "Application", "Multiple ACS URLs", "Indexed ACS endpoints", EQUIVALENT, "RECREATE", 0.5,
               "Supported on SP connections.", (DOC["sp_conn"],)),
    # --- tenant: sign-in, sessions and MFA ------------------------------------------------------
    Capability("policy.global_session", "Sign-in & MFA", "Global session policy",
               "Authentication sessions + authentication policies", PARTIAL, "REDESIGN", 6,
               "Session lifetime and MFA requirements move into PingFederate session settings and policy trees.",
               (DOC["auth_policies"], DOC["okta_policies"]), prerequisite=True),
    Capability("policy.app_access", "Sign-in & MFA", "Authentication (app sign-in) policy",
               "Authentication policy (selectors + adapters)", PARTIAL, "REDESIGN", 4,
               "Each Okta access policy becomes a branch of the PingFederate policy tree; device and risk conditions "
               "need extra products or adapters.", (DOC["auth_policies"], DOC["okta_policies"]), prerequisite=True),
    Capability("policy.mfa_enroll", "Sign-in & MFA", "MFA enrollment policy",
               "MFA provider enrolment (PingID / PingOne MFA or a third-party MFA adapter)", PARTIAL, "REDESIGN", 8,
               "PingFederate delegates MFA to an adapter; users re-enrol in the new MFA provider. Check licensing.",
               (DOC["auth_policies"],), review="EXPERT", prerequisite=True),
    Capability("policy.password", "Directory", "Password policy", "Directory password policy (not PingFederate)",
               NONE, "REDESIGN", 2, "PingFederate authenticates against the directory; password rules live in "
               "AD / PingDirectory.", (), prerequisite=True),
    Capability("auth.password", "Sign-in & MFA", "Password authenticator", "HTML Form adapter + LDAP password credential validator",
               EQUIVALENT, "RECREATE", 1, "Standard PingFederate username/password sign-in against the directory.",
               (DOC["auth_policies"],), prerequisite=True),
    Capability("auth.okta_verify", "Sign-in & MFA", "Okta Verify (push / TOTP / FastPass)",
               "PingID / PingOne MFA app, or a third-party MFA adapter", PARTIAL, "REDESIGN", 8,
               "Different app and enrolment: every user re-enrols. FastPass-style passwordless needs its own design.",
               (), review="EXPERT", prerequisite=True),
    Capability("auth.webauthn", "Sign-in & MFA", "Security key / biometric (WebAuthn)",
               "FIDO2 via the MFA provider", PARTIAL, "REDESIGN", 4,
               "Passkeys are bound to the relying party; users register them again with the new provider.",
               (), review="EXPERT", prerequisite=True),
    Capability("auth.otp_channel", "Sign-in & MFA", "SMS / voice / email one-time codes",
               "OTP through the MFA provider", PARTIAL, "TRANSFORM", 3,
               "Available through the MFA provider; phone numbers and emails must be available to it.",
               (), review="EXPERT", prerequisite=True),
    Capability("auth.other", "Sign-in & MFA", "Other authenticators (security question, third-party OTP)",
               "Review case by case", PARTIAL, "REDESIGN", 2, "Usually retired or replaced by the new MFA provider.", (),
               review="EXPERT"),
    Capability("zone.ip", "Sign-in & MFA", "IP network zone", "CIDR authentication selector", EQUIVALENT, "RECREATE", 1,
               "IP ranges become CIDR selector ranges in the policy tree. Behind load balancers, configure "
               "PingFederate's forwarded-IP (proxy) settings so the client IP is seen.", (DOC["cidr"],)),
    Capability("zone.dynamic", "Sign-in & MFA", "Dynamic zone (geolocation, ASN, anonymisers)",
               "No native equivalent (risk / fraud product)", NONE, "REDESIGN", 4,
               "The out-of-the-box selectors have no geolocation selector; use a risk product such as PingOne Protect "
               "or a custom selector, or decide the control is no longer needed.",
               ("https://docs.pingidentity.com/pingfederate/13.1/administrators_reference_guide/pf_selectors.html",),
               review="EXPERT"),
    # --- tenant: directory and extensibility -----------------------------------------------------
    Capability("group_rule", "Directory", "Group rule (dynamic membership)",
               "No equivalent in PingFederate (directory / IGA)", NONE, "REDESIGN", 3,
               "Membership must be maintained in the directory, an IGA tool or a script; PingFederate only reads groups.", ()),
    Capability("hook.token", "Extensibility", "Token inline hook (SAML or OAuth token transform)",
               "REST API data store or a custom PingFederate plug-in", PARTIAL, "REDESIGN", 8,
               "The external call can often become a REST API data store lookup during attribute fulfilment; "
               "anything more needs the PingFederate SDK.", (DOC["rest_ds"],)),
    Capability("hook.user", "Extensibility", "Registration / import / password-import inline hook",
               "No equivalent (PingFederate is not a user store)", NONE, "REDESIGN", 6,
               "These hooks belong to user management; move the logic to the directory, IGA or registration service.", ()),
    Capability("hook.telephony", "Sign-in & MFA", "Telephony inline hook (custom SMS / voice provider)",
               "SMS / voice delivery configured in the MFA provider", PARTIAL, "REDESIGN", 3,
               "The OTP channel moves to the new MFA provider; check whether it can use the same telephony vendor.",
               (), review="EXPERT", prerequisite=True),
    Capability("hook.event", "Extensibility", "Event hook (webhook on Okta events)",
               "Audit log forwarding to the SIEM / monitoring", PARTIAL, "REDESIGN", 4,
               "PingFederate writes audit and provisioning logs that can be forwarded; there is no webhook "
               "equivalent for user lifecycle events.", (), review="EXPERT"),
    Capability("idp.enterprise", "Federation", "Inbound enterprise IdP (SAML / OIDC)", "IdP connection",
               EQUIVALENT, "RECREATE", 4, "PingFederate supports IdP connections (SP role) with account linking or JIT.",
               (DOC["sp_conn"],)),
    Capability("idp.social", "Federation", "Social login (Google, Microsoft, Apple…)",
               "OIDC IdP connection or a social integration kit", PARTIAL, "TRANSFORM", 4,
               "Usually rebuilt as an OIDC IdP connection; check the customer's integration kit and account linking.",
               (), review="EXPERT"),
    Capability("policy.profile_enrollment", "Sign-in & MFA", "Profile enrollment (self-registration) policy",
               "Local identity profiles (registration) or a separate registration service", PARTIAL, "REDESIGN", 6,
               "Self-service registration is designed again for PingFederate or moved to another service.", (),
               review="EXPERT", prerequisite=True),
    Capability("policy.idp_discovery", "Federation", "IdP discovery / routing rules",
               "Identifier-first adapter + selectors in the authentication policy", PARTIAL, "TRANSFORM", 4,
               "Routing by domain, app or network becomes selectors in front of IdP connections.",
               (DOC["auth_policies"],), review="EXPERT", prerequisite=True),
    Capability("auth_server.custom", "OIDC", "Custom authorization server",
               "Access token manager + scopes + OIDC policy", PARTIAL, "TRANSFORM", 6,
               "One Okta authorization server usually becomes one access token manager with its scopes, claims "
               "(access token mapping) and an OIDC policy.", (DOC["oauth_clients"],), prerequisite=True),
]
CATALOG: dict[str, Capability] = {c.key: c for c in _ROWS}


def load_catalog(path: Path | None = None) -> dict[str, Capability]:
    """Built-in rows, optionally overridden/extended by a JSON file of partial rows keyed by `key`."""
    cat = dict(CATALOG)
    if path:
        for row in json.loads(Path(path).read_text(encoding="utf-8")):
            key = row["key"]
            if key in cat:
                row = {k: (tuple(v) if k == "sources" else v) for k, v in row.items()}
                cat[key] = replace(cat[key], **{k: v for k, v in row.items() if k != "key"})
            else:
                row["sources"] = tuple(row.get("sources") or ())
                cat[key] = Capability(**row)
        for c in cat.values():
            if c.compatibility not in COMPAT_ORDER or c.strategy not in STRATEGIES:
                raise ValueError(f"Catalog row {c.key}: invalid compatibility or strategy")
            if any(not str(u).startswith("https://") for u in c.sources):
                raise ValueError(f"Catalog row {c.key}: sources must be https:// links")
    return cat


def worst(levels: list[str]) -> str | None:
    return max(levels, key=COMPAT_ORDER.index) if levels else None


COMPAT_LEVEL = {EQUIVALENT: "HIGH", PARTIAL: "MEDIUM", NONE: "LOW"}
