"""PingFederate build package: Admin API JSON per app + directory work pack.

A STARTING POINT for the PingFederate admins, generated deterministically.
* Environment-specific IDs are {{VARIABLES}} listed in variables.json.
* Anything that needs a human (OGNL, unknown catalog settings, SP certificates)
  is listed in TODO.md; the JSON never contains made-up values for it.
* The tool never writes to PingFederate. Review, fill the variables, then import
  with the Admin API (POST /idp/spConnections, POST /oauth/clients) or the console.
Field names follow the PingFederate Admin API; check them against your version's
/pf-admin-api/api-docs before importing.
"""
from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from dataclasses import dataclass, field

from app.config import Settings
from app.models.db import Application
from app.services.readiness import pf_readiness

OKTA_TO_PF_GRANT = {
    "authorization_code": "AUTHORIZATION_CODE", "refresh_token": "REFRESH_TOKEN",
    "client_credentials": "CLIENT_CREDENTIALS", "implicit": "IMPLICIT", "password": "RESOURCE_OWNER_CREDENTIALS",
    "urn:ietf:params:oauth:grant-type:device_code": "DEVICE_CODE",
    "urn:ietf:params:oauth:grant-type:token-exchange": "TOKEN_EXCHANGE",
    "urn:ietf:params:oauth:grant-type:jwt-bearer": "JWT_BEARER",
}
COMMON_VARS = {
    "IDP_ADAPTER_ID": "ID of the IdP adapter (e.g. HTML Form / Kerberos) used for sign-in",
    "LDAP_DATA_STORE_ID": "ID of the LDAP data store pointing at the directory",
    "LDAP_BASE_DN": "Base DN for user searches, e.g. DC=corp,DC=example",
    "LDAP_USER_FILTER": "User search filter, e.g. (sAMAccountName=${username})",
    "SIGNING_KEY_PAIR_ID": "ID of the signing key pair for SAML assertions",
    "OIDC_POLICY_ID": "ID of the OpenID Connect policy",
    "ACCESS_TOKEN_MANAGER_ID": "ID of the access token manager",
}


def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-")[:50] or "app"


def access_group(app: Application) -> str:
    return f"PF-{slug(app.label)}-Users"


@dataclass
class Package:
    app: Application
    kind: str
    filename: str
    payload: dict
    todos: list[str] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)


def sp_connection(app: Application, settings: Settings, ognl_allowed: bool) -> Package:
    s = app.saml
    codes = {f.code for f in app.findings}
    todos, variables = [], dict()
    acs = s.acs_endpoints or ([{"url": s.sso_acs_url, "index": 0}] if s.sso_acs_url else [])
    if not s.audience or not acs:
        todos.append("Entity ID and ACS URL are not visible in Okta (catalog app): take them from the vendor's SP metadata.")
    fulfil, src_attrs = {}, set()
    ns = s.pf_nameid_source
    if ns == "DATA_STORE" and (s.pf_nameid_detail or "").startswith("LDAP: "):
        attr = s.pf_nameid_detail[6:].split(" ")[0]
        fulfil["SAML_SUBJECT"] = {"source": {"type": "LDAP_DATA_STORE", "id": "ldap"}, "value": attr}
        src_attrs.add(attr)
    else:
        fulfil["SAML_SUBJECT"] = {"source": {"type": "TEXT"}, "value": "{{TODO_SAML_SUBJECT}}"}
        variables["TODO_SAML_SUBJECT"] = f"NameID source still to decide: {s.pf_nameid_detail}"
        todos.append(f"SAML_SUBJECT: {s.pf_nameid_detail}.")
    extended = []
    for c in app.claims:
        extended.append({"name": c.name, "nameFormat": c.namespace or "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"})
        if c.pf_source == "DATA_STORE" and c.pf_ldap_attributes:
            fulfil[c.name] = {"source": {"type": "LDAP_DATA_STORE", "id": "ldap"}, "value": c.pf_ldap_attributes[0]}
            src_attrs.add(c.pf_ldap_attributes[0])
        elif c.pf_source == "TEXT":
            fulfil[c.name] = {"source": {"type": "TEXT"}, "value": (c.values or [""])[0].strip('"')}
        elif c.pf_source == "GROUP_LDAP_SEARCH":
            fulfil[c.name] = {"source": {"type": "LDAP_DATA_STORE", "id": "groups"}, "value": "cn"}
            todos.append(f"'{c.name}': add a second LDAP attribute source with id 'groups': {c.pf_source_detail}.")
        elif c.pf_source in ("OGNL", "GROUP_OGNL") and ognl_allowed:
            fulfil[c.name] = {"source": {"type": "EXPRESSION"}, "value": "{{TODO_OGNL_" + slug(c.name).upper() + "}}"}
            variables["TODO_OGNL_" + slug(c.name).upper()] = f"OGNL for '{c.name}' (Okta: {', '.join(c.values) or c.group_filter_value})"
            todos.append(f"'{c.name}': write and review the OGNL expression ({c.pf_source_detail}).")
        else:
            fulfil[c.name] = {"source": {"type": "TEXT"}, "value": "{{TODO_" + slug(c.name).upper() + "}}"}
            variables["TODO_" + slug(c.name).upper()] = f"Source for '{c.name}': {c.pf_source_detail}"
            todos.append(f"'{c.name}': {c.pf_source_detail}. Pre-compute into a directory attribute, then map it.")
    if not app.claims and s.config_completeness == "PARTIAL":
        todos.append("Attribute contract: take the required attributes from the vendor's documentation.")

    mapping = {
        "idpAdapterRef": {"id": "{{IDP_ADAPTER_ID}}"},
        "attributeSources": [{"type": "LDAP", "id": "ldap", "description": "User attributes",
                              "dataStoreRef": {"id": "{{LDAP_DATA_STORE_ID}}"}, "baseDn": "{{LDAP_BASE_DN}}",
                              "searchScope": "SUBTREE", "searchFilter": "{{LDAP_USER_FILTER}}",
                              "searchAttributes": sorted(src_attrs | {"memberOf"})}],
        "attributeContractFulfillment": fulfil,
    }
    if "ISSUANCE_CRITERIA_REQUIRED" in codes:
        g = access_group(app)
        var = "GROUP_DN_" + slug(g).upper()
        variables[var] = f"Distinguished name of directory group {g}"
        mapping["issuanceCriteria"] = {"conditionalCriteria": [{
            "source": {"type": "LDAP_DATA_STORE", "id": "ldap"}, "attributeName": "memberOf",
            "condition": "MULTIVALUE_CONTAINS_DN", "value": "{{" + var + "}}",
            "errorResult": "You are not authorised to use this application."}]}
        todos.append(f"Access control: users must be direct members of {g} (see directory/create-groups.ps1), "
                     "or replace this criterion with your standard nested-group approach.")
    profiles = ["IDP_INITIATED_SSO", "SP_INITIATED_SSO"] + (["IDP_INITIATED_SLO", "SP_INITIATED_SLO"] if s.slo_enabled else [])
    mins = max(1, round((s.assertion_lifetime_seconds or 300) / 60))
    payload = {
        "type": "SP", "name": app.label, "entityId": s.audience or "{{SP_ENTITY_ID}}", "active": False,
        "loggingMode": "STANDARD",
        "spBrowserSso": {
            "protocol": "SAML20", "enabledProfiles": profiles, "incomingBindings": ["POST", "REDIRECT"],
            "ssoServiceEndpoints": [{"binding": "POST", "url": e.get("url") or "{{SP_ACS_URL}}", "index": e.get("index", 0) or 0,
                                     "isDefault": i == 0} for i, e in enumerate(acs or [{}])],
            "signAssertions": bool(s.assertion_signed), "signResponseAsRequired": True,
            "spSamlIdentityMapping": "STANDARD",
            "assertionLifetime": {"minutesBefore": mins, "minutesAfter": mins},
            "attributeContract": {"coreAttributes": [{"name": "SAML_SUBJECT", "nameFormat": s.name_id_format or
                                                      "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"}],
                                  "extendedAttributes": extended},
            "adapterMappings": [mapping],
        },
        "credentials": {"signingSettings": {"signingKeyPairRef": {"id": "{{SIGNING_KEY_PAIR_ID}}"},
                                            "algorithm": "SHA256withRSA"}},
    }
    if not s.audience:
        variables["SP_ENTITY_ID"] = "SP entity ID from the vendor metadata"
    if not acs:
        variables["SP_ACS_URL"] = "ACS URL from the vendor metadata"
    if s.slo_enabled:
        payload["spBrowserSso"]["sloServiceEndpoints"] = [{"binding": "POST", "url": s.slo_logout_url or "{{SP_SLO_URL}}"}]
    if "CUSTOM_IDP_ISSUER" in codes:
        payload["virtualIdentities"] = [s.idp_issuer]
        todos.append(f"Virtual server ID '{s.idp_issuer}' must also be allowed in Server Settings.")
    if s.sp_certificate_present:
        todos.append("Import the SP's signing certificate (signed AuthnRequests) into the connection.")
    if (s.signature_algorithm or "").upper().endswith("SHA1"):
        todos.append("Okta signs with SHA-1; the package uses SHA-256. Confirm the SP accepts it.")
    if "DUPLICATE_SP_ENTITY_ID" in codes:
        todos.append("Entity ID is shared with another Okta app: resolve the decision before importing.")
    return Package(app, "SP_CONNECTION", f"sp-connections/{slug(app.label)}.json", payload, todos, variables)


def oauth_client(app: Application, modernise_implicit: bool) -> Package:
    o = app.oidc
    todos, variables = [], {}
    grants = [OKTA_TO_PF_GRANT.get(g, g.upper()) for g in o.grant_types]
    pkce = bool(o.pkce_required) or o.token_endpoint_auth_method == "none" or o.application_type in ("native", "browser")
    if "IMPLICIT" in grants and modernise_implicit:
        grants = [g for g in grants if g != "IMPLICIT"] + (["AUTHORIZATION_CODE"] if "AUTHORIZATION_CODE" not in grants else [])
        pkce = True
        todos.append("Implicit grant replaced by authorization code + PKCE (decision): the app code must change too.")
    auth = {"client_secret_basic": "SECRET", "client_secret_post": "SECRET", "client_secret_jwt": "SECRET",
            "private_key_jwt": "PRIVATE_KEY_JWT", "none": "NONE"}.get(o.token_endpoint_auth_method or "", "SECRET")
    payload = {
        "clientId": o.client_id, "name": app.label, "enabled": False, "grantTypes": grants,
        "redirectUris": o.redirect_uris, "clientAuth": {"type": auth},
        "requireProofKeyForCodeExchange": pkce,
        "bypassApprovalPage": (o.consent_method or "").upper() == "TRUSTED",
        "defaultAccessTokenManagerRef": {"id": "{{ACCESS_TOKEN_MANAGER_ID}}"},
    }
    if "CLIENT_CREDENTIALS" not in grants or len(grants) > 1:
        payload["oidcPolicy"] = {"policyGroup": {"id": "{{OIDC_POLICY_ID}}"}}
    if auth == "SECRET":
        todos.append("Generate the client secret in PingFederate and hand it over securely (never by email).")
    if auth == "PRIVATE_KEY_JWT":
        var = "CLIENT_JWKS_URL_" + slug(app.label).upper()
        payload["jwksSettings"] = {"jwksUrl": "{{" + var + "}}"}
        variables[var] = f"JWKS URL (or JWKS) of {app.label}'s signing keys"
    if any("*" in u for u in o.redirect_uris):
        todos.append("Wildcard redirect URIs: confirm PingFederate matching, or list the URIs explicitly.")
    if o.post_logout_redirect_uris:
        todos.append("Post-logout redirect URIs to allow: " + ", ".join(o.post_logout_redirect_uris))
    todos.append("Scopes and claims: configure the OIDC policy / access token mapping from the Okta authorization server.")
    if any(f.code == "OIDC_ACCESS_CONTROL_REQUIRED" for f in app.findings):
        todos.append(f"Access control: restrict in the authentication policy to members of {access_group(app)}.")
    return Package(app, "OAUTH_CLIENT", f"oauth-clients/{slug(app.label)}.json", payload, todos, variables)


def build_all(apps: list[Application], settings: Settings, ognl_allowed: bool, modernise_implicit: bool) -> list[Package]:
    out = []
    for a in apps:
        if a.is_saml and a.saml:
            out.append(sp_connection(a, settings, ognl_allowed))
        elif a.is_oidc and a.oidc:
            out.append(oauth_client(a, modernise_implicit))
    return out


def directory_pack(apps: list[Application], directory) -> dict[str, str]:
    groups: dict[str, set] = {}
    attrs: dict[str, set] = {}
    access: list[tuple[str, list[str]]] = []
    for a in apps:
        r = pf_readiness(a)
        for g in r["okta_only_groups"]:
            groups.setdefault(g, set()).add(a.label)
        for m in r["missing_inputs"]:
            attrs.setdefault(m, set()).add(a.label)
        codes = {f.code for f in a.findings}
        if "ISSUANCE_CRITERIA_REQUIRED" in codes or "OIDC_ACCESS_CONTROL_REQUIRED" in codes:
            access.append((access_group(a), a.label,
                           [x.principal_name or x.principal_id for x in a.assignments if x.principal_type == "GROUP"],
                           [x.principal_name for x in a.assignments
                            if x.principal_type == "USER" and (x.scope or "").upper() == "USER" and x.principal_name]))
    f1 = io.StringIO()
    w = csv.writer(f1)
    w.writerow(["group", "purpose", "used_by_apps", "okta_source_groups"])
    for g, used in sorted(groups.items()):
        w.writerow([g, "Recreate Okta-only group", "; ".join(sorted(used)), ""])
    for g, label, sources, _direct in access:
        w.writerow([g, "Per-app access group (issuance criteria / access policy)", label, "; ".join(sources)])
    f2 = io.StringIO()
    w = csv.writer(f2)
    w.writerow(["okta_value", "used_by_apps", "suggested_directory_attribute"])
    for m, used in sorted(attrs.items()):
        w.writerow([m, "; ".join(sorted(used)), "extensionAttributeN (AD)" if directory.value == "AD" else "custom attribute"])
    q = lambda v: "'" + str(v).replace("'", "''") + "'"  # noqa: E731 - PowerShell single-quote escaping
    ps = ["# Review-only script generated by the Migration Factory. It runs with -WhatIf unless -Apply is given.",
          "# Run only after review and change approval.",
          "param([string]$OU = 'OU=PingFederate,OU=Groups,DC=corp,DC=example', [switch]$Apply)",
          "Import-Module ActiveDirectory",
          "$w = -not $Apply", "",
          "# 1. Recreate Okta-only groups. They start EMPTY: populate them from the Okta group membership",
          "#    (Okta Admin > Directory > Groups > export, or the Groups API) before step 2.", ""]
    for g in sorted(groups):
        ps.append(f"New-ADGroup -Name {q(g)} -GroupScope Global -GroupCategory Security -Path $OU -WhatIf:$w")
    ps += ["", "# 2. One access group per app, used by the issuance criteria / access policy.",
           "#    Copies current members of the Okta-assigned groups (flattened) and directly assigned users.", ""]
    for g, _label, sources, direct in access:
        ps.append(f"New-ADGroup -Name {q(g)} -GroupScope Global -GroupCategory Security -Path $OU -WhatIf:$w")
        for src in sources:
            ps.append(f"Get-ADGroupMember -Identity {q(src)} -Recursive | ForEach-Object "
                      f"{{ Add-ADGroupMember -Identity {q(g)} -Members $_ -WhatIf:$w }}")
        for upn in direct:
            ps.append(f"Get-ADUser -Filter \"UserPrincipalName -eq '{upn.replace(chr(39), chr(39) * 2)}'\" | ForEach-Object "
                      f"{{ Add-ADGroupMember -Identity {q(g)} -Members $_ -WhatIf:$w }}  # directly assigned in Okta")
        ps.append("")
    return {"directory/groups.csv": f1.getvalue(), "directory/attributes.csv": f2.getvalue(),
            "directory/create-groups.ps1": "\r\n".join(ps) + "\r\n"}


def to_zip(pkgs: list[Package], apps: list[Application], settings: Settings, title: str) -> bytes:
    buf = io.BytesIO()
    variables = dict(COMMON_VARS)
    todo = [f"# {title}", "", "Review every item before importing. The tool never writes to PingFederate.", ""]
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in pkgs:
            z.writestr(p.filename, json.dumps(p.payload, indent=2))
            variables.update(p.variables)
            todo.append(f"## {p.app.label} ({'SP connection' if p.kind == 'SP_CONNECTION' else 'OAuth client'})")
            todo.append(f"File: `{p.filename}`")
            todo += [f"- [ ] {t}" for t in p.todos] or ["- [ ] Review only"]
            todo.append("")
        for name, content in directory_pack(apps, settings.pf_directory_type).items():
            z.writestr(name, content)
        z.writestr("variables.json", json.dumps({k: {"description": v, "value": ""} for k, v in sorted(variables.items())}, indent=2))
        z.writestr("TODO.md", "\n".join(todo))
        z.writestr("README.md", (__doc__ or "").strip() + "\n\nImport order: directory work -> fill variables.json -> "
                   "replace {{VARIABLES}} -> import JSON (connections are created disabled) -> test -> enable.\n")
    return buf.getvalue()
