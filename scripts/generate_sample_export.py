"""Generate a realistic *fictional* Okta export (Northwind) for local runs and tests.

Covers the three MVP app types plus the awkward cases a real tenant has:
  1. Expense Portal         - simple custom SAML
  2. HR Analytics (Tableau) - custom SAML + expression claims, direct users, cert expiring soon
  3. Engineering Wiki       - custom SAML + group claim (REGEX) + conditional claim, 2 ACS, SLO
  4. ServiceNow             - OIN catalog app (partial config via API)
  5. Salesforce             - OIN catalog app + custom username template
  6. Expense Portal (UAT)   - reuses the production SP entity ID
  7. Legacy Travel Booking  - inactive, unassigned, NameID = Okta user id, SHA-1, expired cert
  8. Employee Portal (OIDC)   - web app, auth code + refresh, client secret
  9. Mobile Expenses (OIDC)   - native app, PKCE, refresh tokens
  10. Reporting API (OIDC)    - service, client_credentials, private_key_jwt
  11. Legacy Intranet SPA     - browser app, implicit grant, wildcard redirect, no PKCE
  12-13. Bookmark / SWA apps that stay out of scope

Usage:  python scripts/generate_sample_export.py [out_dir]
"""
from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ORG = "https://northwind.okta.com"
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "data" / "exports" / "sample-tenant"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def cert_b64(cn: str, not_before: datetime, not_after: datetime) -> str:
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Okta"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SSOProvider"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(KEY.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(not_before).not_valid_after(not_after).sign(KEY, hashes.SHA256()))
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def dt(y, m, d):
    return datetime(y, m, d, tzinfo=timezone.utc)


def iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%S.000Z")


# --- users & groups --------------------------------------------------------
FIRST = ["Asha", "Ben", "Chen", "Divya", "Elena", "Farid", "Grace", "Hiro", "Isla", "Jon",
         "Kavya", "Liam", "Maya", "Nikhil", "Olga", "Pablo", "Quinn", "Ravi", "Sara", "Tom",
         "Uma", "Victor", "Wen", "Xavier", "Yara"]
LAST = ["Rao", "Adams", "Li", "Iyer", "Petrova", "Khan", "Ng", "Sato", "Moore", "Berg",
        "Menon", "Walsh", "Cohen", "Shah", "Ivanova", "Diaz", "Reid", "Kumar", "Lund", "Hart",
        "Nair", "Costa", "Zhou", "Roux", "Haddad"]
DEPTS = ["Finance", "HR", "Engineering", "Engineering", "Sales"]
USERS = []
for i, (f, l) in enumerate(zip(FIRST, LAST)):
    login = f"{f.lower()}.{l.lower()}@northwind.example"
    USERS.append({"id": f"00u{i:02d}nwusr{i:02d}abcdefgh"[:20], "status": "ACTIVE",
                  "profile": {"login": login, "email": login, "firstName": f, "lastName": l,
                              "department": DEPTS[i % 5], "employeeNumber": f"E{1000 + i}"}})


def group(gid, name, gtype, count, desc=None, ad=False):
    g = {"id": gid, "type": gtype, "profile": {"name": name, "description": desc},
         "_embedded": {"stats": {"usersCount": count}}}
    if ad:
        g["profile"]["windowsDomainQualifiedName"] = f"NORTHWIND\\{name}"
        g["_embedded"]["app"] = {"name": "active_directory"}
    return g


GROUPS = [
    group("00g0everyone0000000a", "Everyone", "BUILT_IN", 25, "All users in your organization"),
    group("00g0allemployees000b", "All Employees", "APP_GROUP", 25, ad=True),
    group("00g0finance00000000c", "Finance", "OKTA_GROUP", 5),
    group("00g0hranalysts00000d", "HR-Analysts", "OKTA_GROUP", 5),
    group("00g0engplatform0000e", "ENG-Platform", "APP_GROUP", 4, ad=True),
    group("00g0engdata0000000f", "ENG-Data", "APP_GROUP", 3, ad=True),
    group("00g0engmobile00000g", "ENG-Mobile", "APP_GROUP", 3, ad=True),
    group("00g0engcontractors0h", "ENG-Contractors", "OKTA_GROUP", 2, "External contractors"),
    group("00g0snitil00000000i", "SN-ITIL", "OKTA_GROUP", 8),
    group("00g0snapprovers000j", "SN-Approvers", "OKTA_GROUP", 4),
    group("00g0sales000000000k", "Sales", "OKTA_GROUP", 5),
]


def app_user(u, scope="GROUP", username=None, profile=None):
    return {"id": u["id"], "scope": scope, "status": "PROVISIONED",
            "credentials": {"userName": username or u["profile"]["login"]},
            "profile": profile or {}, "_embedded": {"user": u}}


def saml_signon(**kw):
    base = {
        "defaultRelayState": "", "ssoAcsUrl": "", "idpIssuer": "http://www.okta.com/${org.externalKey}",
        "audience": "", "recipient": "", "destination": "",
        "subjectNameIdTemplate": "${user.userName}",
        "subjectNameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "responseSigned": True, "assertionSigned": True, "signatureAlgorithm": "RSA_SHA256",
        "digestAlgorithm": "SHA256", "honorForceAuthn": True,
        "authnContextClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        "spIssuer": None, "requestCompressed": False, "attributeStatements": [],
        "allowMultipleAcsEndpoints": False, "acsEndpoints": [],
        "slo": {"enabled": False}, "samlAssertionLifetimeSeconds": 300,
    }
    base.update(kw)
    return base


def app(aid, label, name, mode, status, sign_on=None, app_settings=None, kid=None,
        username_tpl="${source.login}", created=dt(2021, 3, 4), updated=dt(2025, 11, 20)):
    a = {"id": aid, "name": name, "label": label, "status": status, "signOnMode": mode,
         "created": iso(created), "lastUpdated": iso(updated),
         "credentials": {"userNameTemplate": {"template": username_tpl, "type": "BUILT_IN"}},
         "settings": {"app": app_settings or {}},
         "_links": {"metadata": {"href": f"{ORG}/api/v1/apps/{aid}/sso/saml/metadata"}}}
    if kid:
        a["credentials"]["signing"] = {"kid": kid}
    if sign_on is not None:
        a["settings"]["signOn"] = sign_on
    return a


def expr(name, *values, ns="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"):
    return {"type": "EXPRESSION", "name": name, "namespace": ns, "values": list(values)}


APPS, DETAILS = [], {}


def add_saml(a, groups, users, cert_window, idp_key="exk"):
    APPS.append(a)
    kid = a["credentials"]["signing"]["kid"]
    nb, na = cert_window
    x5c = cert_b64(a["name"], nb, na)
    DETAILS[a["id"]] = {
        "groups": groups, "users": users,
        "keys": [{"kid": kid, "kty": "RSA", "use": "sig", "x5c": [x5c],
                  "created": iso(nb), "lastUpdated": iso(nb), "expiresAt": iso(na)}],
        "metadata": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://www.okta.com/{idp_key}{a["id"][3:]}">'
            '<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>'
            f'<ds:X509Certificate>{x5c}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
            '<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>'
            f'<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{ORG}/app/{a["name"]}/{idp_key}{a["id"][3:]}/sso/saml"/>'
            '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
            f'Location="{ORG}/app/{a["name"]}/{idp_key}{a["id"][3:]}/sso/saml"/>'
            '</md:IDPSSODescriptor></md:EntityDescriptor>'),
    }


U = USERS
# 1. Simple SAML
add_saml(app("0oa1expenseportal01", "Expense Portal", "northwind_expenseportal_1", "SAML_2_0", "ACTIVE",
             saml_signon(ssoAcsUrl="https://expenses.northwind.example/saml/acs",
                         audience="https://expenses.northwind.example",
                         recipient="https://expenses.northwind.example/saml/acs",
                         destination="https://expenses.northwind.example/saml/acs",
                         subjectNameIdTemplate="${user.email}",
                         subjectNameIdFormat="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                         attributeStatements=[expr("email", "user.email")]),
             kid="kidExpense01", username_tpl="${source.email}"),
         [{"id": "00g0allemployees000b", "priority": 0, "profile": {}}],
         [app_user(u) for u in U], (dt(2024, 6, 1), dt(2029, 6, 1)))

# 1b. UAT copy that reuses the production entity ID (common, and a PingFederate problem)
add_saml(app("0oa1expenseuat00011", "Expense Portal (UAT)", "northwind_expenseportaluat_1", "SAML_2_0", "ACTIVE",
             saml_signon(ssoAcsUrl="https://expenses-uat.northwind.example/saml/acs",
                         audience="https://expenses.northwind.example",
                         recipient="https://expenses-uat.northwind.example/saml/acs",
                         destination="https://expenses-uat.northwind.example/saml/acs",
                         subjectNameIdTemplate="${user.email}",
                         subjectNameIdFormat="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                         attributeStatements=[expr("email", "user.email")]),
             kid="kidExpenseUat11", username_tpl="${source.email}"),
         [{"id": "00g0finance00000000c", "priority": 0, "profile": {}}],
         [app_user(u) for u in U[0:5]], (dt(2024, 6, 1), dt(2029, 6, 1)))

# 2. SAML + custom claims
add_saml(app("0oa2hranalytics0002", "HR Analytics (Tableau)", "northwind_hranalytics_1", "SAML_2_0", "ACTIVE",
             saml_signon(ssoAcsUrl="https://tableau.northwind.example/wg/saml/SSO/index.html",
                         audience="https://tableau.northwind.example",
                         recipient="https://tableau.northwind.example/wg/saml/SSO/index.html",
                         destination="https://tableau.northwind.example/wg/saml/SSO/index.html",
                         attributeStatements=[
                             expr("firstName", "user.firstName"),
                             expr("lastName", "user.lastName"),
                             expr("email", "user.email"),
                             expr("employeeNumber", "user.employeeNumber"),
                             expr("displayName", 'user.firstName + " " + user.lastName'),
                             expr("username", 'String.substringBefore(user.login, "@")'),
                             expr("costCenter", "appuser.costCenter"),
                         ]),
             kid="kidHrAnalytics02"),
         [{"id": "00g0hranalysts00000d", "priority": 0, "profile": {}}],
         [app_user(u, profile={"costCenter": "CC-200"}) for u in U[1:4]]
         + [app_user(U[10], scope="USER", profile={"costCenter": "CC-210"}),
            app_user(U[11], scope="USER", profile={"costCenter": "CC-210"})],
         (dt(2023, 11, 11), dt(2026, 11, 11)))

# 3. SAML + groups + custom claims
add_saml(app("0oa3engwiki00000003", "Engineering Wiki (Confluence DC)", "northwind_engwiki_1", "SAML_2_0", "ACTIVE",
             saml_signon(ssoAcsUrl="https://wiki.northwind.example/plugins/servlet/samlconsumer",
                         audience="https://wiki.northwind.example",
                         recipient="https://wiki.northwind.example/plugins/servlet/samlconsumer",
                         destination="https://wiki.northwind.example/plugins/servlet/samlconsumer",
                         subjectNameIdTemplate="${user.login}",
                         idpIssuer="https://sso.northwind.example/wiki",
                         defaultRelayState="https://wiki.northwind.example/dashboard.action",
                         allowMultipleAcsEndpoints=True,
                         acsEndpoints=[{"url": "https://wiki.northwind.example/plugins/servlet/samlconsumer", "index": 0},
                                       {"url": "https://wiki-dr.northwind.example/plugins/servlet/samlconsumer", "index": 1}],
                         slo={"enabled": True, "issuer": "https://wiki.northwind.example",
                              "logoutUrl": "https://wiki.northwind.example/plugins/servlet/samlslo"},
                         spCertificate={"x5c": ["MIIC...truncated-sp-cert..."]},
                         attributeStatements=[
                             expr("email", "user.email"),
                             expr("fullName", 'user.firstName + " " + user.lastName'),
                             expr("wikiRole", 'user.department == "Engineering" ? "wiki-admin" : "wiki-user"'),
                             {"type": "GROUP", "name": "groups",
                              "namespace": "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
                              "filterType": "REGEX", "filterValue": "ENG-.*"},
                         ]),
             kid="kidEngWiki03"),
         [{"id": "00g0engplatform0000e", "priority": 0, "profile": {"wikiSpace": "PLAT"}},
          {"id": "00g0engdata0000000f", "priority": 1, "profile": {}},
          {"id": "00g0engmobile00000g", "priority": 2, "profile": {}}],
         [app_user(u) for u in U[2:12]], (dt(2024, 1, 15), dt(2028, 1, 15)))

# 4. ServiceNow - OIN catalog app
add_saml(app("0oa4servicenow00004", "ServiceNow", "servicenow_ud", "SAML_2_0", "ACTIVE",
             {"defaultRelayState": None, "ssoAcsUrlOverride": None, "audienceOverride": None,
              "recipientOverride": None, "destinationOverride": None, "attributeStatements": []},
             app_settings={"instanceName": "northwind", "loginURL": "https://northwind.service-now.com"},
             kid="kidServiceNow04", username_tpl="${source.email}"),
         [{"id": "00g0snitil00000000i", "priority": 0, "profile": {}},
          {"id": "00g0snapprovers000j", "priority": 1, "profile": {}}],
         [app_user(u) for u in U[5:17]], (dt(2024, 3, 1), dt(2028, 3, 1)))

# 5. Salesforce - OIN catalog app + custom username
add_saml(app("0oa5salesforce00005", "Salesforce", "salesforce", "SAML_2_0", "ACTIVE",
             {"defaultRelayState": None, "attributeStatements": []},
             app_settings={"instanceType": "PRODUCTION", "loginUrl": "https://northwind.my.salesforce.com",
                           "integrationType": "STANDARD"},
             kid="kidSalesforce05", username_tpl="${source.employeeNumber}@northwind.sfdc"),
         [{"id": "00g0sales000000000k", "priority": 0, "profile": {}}],
         [app_user(u, username=f"{u['profile']['employeeNumber']}@northwind.sfdc") for u in U[17:25]],
         (dt(2024, 8, 1), dt(2028, 8, 1)))

# 6. Legacy, inactive, risky
add_saml(app("0oa6legacytravel006", "Legacy Travel Booking", "northwind_legacytravel_1", "SAML_2_0", "INACTIVE",
             saml_signon(ssoAcsUrl="https://travel-old.northwind.example/sso/acs",
                         audience="urn:northwind:travel",
                         recipient="https://travel-old.northwind.example/sso/acs",
                         destination="https://travel-old.northwind.example/sso/acs",
                         subjectNameIdTemplate="${user.id}",
                         subjectNameIdFormat="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                         signatureAlgorithm="RSA_SHA1", digestAlgorithm="SHA1",
                         attributeStatements=[expr("mail", "user.email")]),
             kid="kidLegacy06", created=dt(2018, 5, 2), updated=dt(2022, 1, 9)),
         [], [], (dt(2021, 3, 1), dt(2026, 3, 1)))

# 7-9. Non-SAML apps (must be inventoried but skipped)
def oidc_app(aid, label, client_id, app_type, grants, responses, redirects, auth_method, pkce,
             groups, users, logout=None, wildcard="DISABLED", jwks=False, login_uri=None):
    a = app(aid, label, "oidc_client", "OPENID_CONNECT", "ACTIVE")
    a["credentials"]["oauthClient"] = {"client_id": client_id, "token_endpoint_auth_method": auth_method,
                                       "pkce_required": pkce, "autoKeyRotation": True}
    a["settings"]["oauthClient"] = {
        "application_type": app_type, "grant_types": grants, "response_types": responses,
        "redirect_uris": redirects, "post_logout_redirect_uris": logout or [],
        "consent_method": "TRUSTED", "issuer_mode": "ORG_URL", "wildcard_redirect": wildcard,
        "initiate_login_uri": login_uri}
    if jwks:
        a["settings"]["oauthClient"]["jwks"] = {"keys": [{"kty": "RSA", "kid": "rpt-1", "e": "AQAB", "n": "sXch..."}]}
    del a["_links"]
    APPS.append(a)
    DETAILS[aid] = {"groups": groups, "users": users}


oidc_app("0oa7employeeportal7", "Employee Portal", "0oa7EmpPortalClient01", "web",
         ["authorization_code", "refresh_token"], ["code"],
         ["https://portal.northwind.example/callback", "https://portal.northwind.example/silent-renew"],
         "client_secret_basic", False,
         [{"id": "00g0allemployees000b", "priority": 0, "profile": {}}], [app_user(u) for u in U],
         logout=["https://portal.northwind.example/"], login_uri="https://portal.northwind.example/login")
oidc_app("0oa8mobileexpense08", "Mobile Expenses", "0oa8MobileExpClient08", "native",
         ["authorization_code", "refresh_token"], ["code"], ["com.northwind.expenses:/callback"],
         "none", True, [{"id": "00g0finance00000000c", "priority": 0, "profile": {}}],
         [app_user(u) for u in U[0:5]])
oidc_app("0oa9reportingapi009", "Reporting API", "0oa9ReportingSvc0009", "service",
         ["client_credentials"], ["token"], [], "private_key_jwt", False, [], [], jwks=True)
oidc_app("0oa10legacyspa00010", "Legacy Intranet SPA", "0oa10LegacySpaClnt10", "browser",
         ["implicit"], ["id_token", "token"],
         ["https://intranet.northwind.example/*", "https://intranet-old.northwind.example/auth"],
         "none", False, [{"id": "00g0sales000000000k", "priority": 0, "profile": {}}],
         [app_user(u) for u in U[17:25]] + [app_user(U[1], scope="USER")], wildcard="SUBDOMAIN")
APPS.append(app("0oa8handbook0000008", "Company Handbook", "bookmark", "BOOKMARK", "ACTIVE"))
APPS.append(app("0oa9vendorportal009", "Vendor Portal", "template_swa", "AUTO_LOGIN", "ACTIVE"))


# --- app-level extras: provisioning features and OIE app sign-in policies -----------------
def _app(aid):
    return next(a for a in APPS if a["id"] == aid)


_app("0oa5salesforce00005")["features"] = ["PUSH_NEW_USERS", "PUSH_PROFILE_UPDATES", "PUSH_USER_DEACTIVATION"]
_app("0oa4servicenow00004")["features"] = ["PUSH_NEW_USERS", "IMPORT_NEW_USERS"]
for aid, pol in (("0oa2hranalytics0002", "rst0highassur00001"), ("0oa5salesforce00005", "rst0highassur00001"),
                 ("0oa1expenseportal01", "rst0finance0000002"), ("0oa4servicenow00004", "rst0default0000000"),
                 ("0oa7employeeportal7", "rst0default0000000")):
    _app(aid).setdefault("_links", {})["accessPolicy"] = {"href": f"{ORG}/api/v1/policies/{pol}"}


# --- tenant-level objects (tenant/<kind>.json) --------------------------------------
def _rule(name, **kw):
    return {"id": "0pr" + name.replace(" ", "")[:14], "name": name, "status": "ACTIVE", **kw}


TENANT = {
    "policies": [
        {"id": "00p0globaldefault01", "name": "Default Policy", "type": "OKTA_SIGN_ON", "system": True, "priority": 2,
         "status": "ACTIVE", "_embedded": {"rules": [_rule("Default Rule", actions={"signon": {"access": "ALLOW", "requireFactor": False}})]}},
        {"id": "00p0contractors0002", "name": "Contractors session", "type": "OKTA_SIGN_ON", "priority": 1, "status": "ACTIVE",
         "_embedded": {"rules": [_rule("Contractors MFA", actions={"signon": {"access": "ALLOW", "requireFactor": True}},
                                       conditions={"people": {"groups": {"include": ["00g0engcontractors0h"]}},
                                                   "network": {"connection": "ZONE", "include": ["nzo0legacyip000001"]}})]}},
        {"id": "rst0default0000000", "name": "Default Policy", "type": "ACCESS_POLICY", "system": True, "status": "ACTIVE",
         "_embedded": {"rules": [_rule("Catch-all Rule", actions={"appSignOn": {"access": "ALLOW", "verificationMethod": {"factorMode": "1FA", "type": "ASSURANCE"}}})]}},
        {"id": "rst0highassur00001", "name": "High assurance apps", "type": "ACCESS_POLICY", "status": "ACTIVE",
         "_embedded": {"rules": [
             _rule("Managed devices", actions={"appSignOn": {"access": "ALLOW", "verificationMethod": {"factorMode": "2FA", "type": "ASSURANCE"}}},
                   conditions={"device": {"registered": True, "managed": True}}),
             _rule("Off network: deny", actions={"appSignOn": {"access": "DENY"}},
                   conditions={"network": {"connection": "ZONE", "exclude": ["nzo0legacyip000001"]}})]}},
        {"id": "rst0finance0000002", "name": "Finance apps", "type": "ACCESS_POLICY", "status": "ACTIVE",
         "_embedded": {"rules": [_rule("Finance MFA", actions={"appSignOn": {"access": "ALLOW", "verificationMethod": {"factorMode": "2FA", "type": "ASSURANCE"}}},
                                       conditions={"people": {"groups": {"include": ["00g0finance00000000c"]}}})]}},
        {"id": "00p0mfaenroll000001", "name": "Default Policy", "type": "MFA_ENROLL", "system": True, "status": "ACTIVE",
         "settings": {"authenticators": [{"key": "okta_verify", "enroll": {"self": "REQUIRED"}}]}, "_embedded": {"rules": []}},
        {"id": "00p0password0000001", "name": "Default Policy", "type": "PASSWORD", "system": True, "status": "ACTIVE",
         "_embedded": {"rules": []}},
    ],
    "authenticators": [
        {"id": "aut0password00001", "key": "okta_password", "type": "password", "name": "Password", "status": "ACTIVE"},
        {"id": "aut0oktaverify0001", "key": "okta_verify", "type": "app", "name": "Okta Verify", "status": "ACTIVE"},
        {"id": "aut0webauthn00001", "key": "webauthn", "type": "security_key", "name": "Security Key or Biometric", "status": "ACTIVE"},
        {"id": "aut0phone0000001", "key": "phone_number", "type": "phone", "name": "Phone", "status": "ACTIVE"},
        {"id": "aut0email0000001", "key": "okta_email", "type": "email", "name": "Email", "status": "ACTIVE"},
        {"id": "aut0secq00000001", "key": "security_question", "type": "security_question", "name": "Security Question", "status": "INACTIVE"},
    ],
    "group_rules": [
        {"id": "0pr0financedept01", "name": "Finance department", "type": "group_rule", "status": "ACTIVE",
         "conditions": {"expression": {"value": 'user.department=="Finance"', "type": "urn:okta:expression:1.0"}},
         "actions": {"assignUserToGroups": {"groupIds": ["00g0finance00000000c"]}}},
        {"id": "0pr0salesdept0002", "name": "Sales department", "type": "group_rule", "status": "ACTIVE",
         "conditions": {"expression": {"value": 'user.department=="Sales"', "type": "urn:okta:expression:1.0"}},
         "actions": {"assignUserToGroups": {"groupIds": ["00g0sales000000000k"]}}},
    ],
    "authorization_servers": [
        {"id": "default", "name": "default", "default": True, "audiences": ["api://default"], "issuerMode": "ORG_URL",
         "status": "ACTIVE", "_embedded": {"scopes": [], "claims": [], "policies": []}},
        {"id": "aus0nwapi000000001", "name": "Northwind API", "audiences": ["api://northwind"], "issuerMode": "CUSTOM_URL",
         "status": "ACTIVE", "_embedded": {
             "scopes": [{"name": "reports.read", "system": False}, {"name": "openid", "system": True}],
             "claims": [{"name": "department", "valueType": "EXPRESSION", "value": "user.department", "system": False},
                        {"name": "roles", "valueType": "EXPRESSION", "system": False,
                         "value": 'isMemberOfGroupName("Finance") ? "finance" : "staff"'}],
             "policies": [{"name": "API clients", "conditions": {"clients": {"include": [
                 "0oa9ReportingSvc0009", "0oa7EmpPortalClient01"]}}}]}},
    ],
    "inline_hooks": [
        {"id": "cal0tokenhook0001", "name": "Add entitlements to tokens", "type": "com.okta.oauth2.tokens.transform",
         "status": "ACTIVE", "channel": {"config": {"uri": "https://hooks.northwind.example/tokens"}}},
        {"id": "cal0prereg000002", "name": "Pre-registration check", "type": "com.okta.user.pre-registration",
         "status": "ACTIVE", "channel": {"config": {"uri": "https://hooks.northwind.example/register"}}},
    ],
    "event_hooks": [
        {"id": "who0siem00000001", "name": "SIEM user events", "status": "ACTIVE",
         "events": {"type": "EVENT_TYPE", "items": ["user.lifecycle.create", "user.session.start"]},
         "channel": {"config": {"uri": "https://siem.northwind.example/okta"}}},
    ],
    "idps": [
        {"id": "0oa0contosoidp001", "name": "Partner: Contoso (SAML)", "type": "SAML2", "status": "ACTIVE",
         "protocol": {"type": "SAML2"}, "policy": {"provisioning": {"action": "AUTO"}}},
        {"id": "0oa0googleidp0002", "name": "Google", "type": "GOOGLE", "status": "ACTIVE",
         "protocol": {"type": "OIDC"}, "policy": {"provisioning": {"action": "DISABLED"}}},
    ],
    "network_zones": [
        {"id": "nzo0legacyip000001", "name": "Corporate network", "type": "IP", "usage": "POLICY", "status": "ACTIVE",
         "gateways": [{"type": "CIDR", "value": "10.0.0.0/8"}, {"type": "CIDR", "value": "203.0.113.0/24"}]},
        {"id": "nzo0blocked000002", "name": "Blocked IPs", "type": "IP", "usage": "BLOCKLIST", "status": "ACTIVE",
         "gateways": [{"type": "RANGE", "value": "198.51.100.1-198.51.100.20"}]},
        {"id": "nzo0highrisk00003", "name": "High-risk countries", "type": "DYNAMIC", "usage": "POLICY", "status": "ACTIVE",
         "locations": [{"country": "XX"}, {"country": "YY"}, {"country": "ZZ"}]},
    ],
}


# --- System Log sample: (app id -> number of distinct active users, sign-ins each) ------
import random  # noqa: E402

USAGE = {
    "0oa1expenseportal01": (22, 6), "0oa1expenseuat00011": (0, 0), "0oa2hranalytics0002": (4, 5),
    "0oa3engwiki00000003": (9, 12), "0oa4servicenow00004": (12, 20), "0oa5salesforce00005": (7, 15),
    "0oa7employeeportal7": (24, 10), "0oa8mobileexpense08": (4, 8), "0oa10legacyspa00010": (0, 0),
}


def usage_events(aid):
    rnd = random.Random(aid)
    n_users, per_user = USAGE.get(aid, (0, 0))
    users = [u for u in USERS][:max(n_users, 0)]
    events = []
    for u in users:
        for _ in range(per_user):
            day = rnd.randint(1, 88)
            ts = datetime(2026, 9, 25, tzinfo=timezone.utc) - timedelta(days=day, minutes=rnd.randint(0, 1400))
            events.append({"uuid": f"{aid}-{len(events)}", "published": iso(ts),
                           "eventType": "user.authentication.sso",
                           "actor": {"id": u["id"], "type": "User", "alternateId": u["profile"]["login"]},
                           "target": [{"id": aid, "type": "AppInstance"}], "outcome": {"result": "SUCCESS"}})
    if aid == "0oa9reportingapi009":   # machine client: token grants by the client itself
        for i in range(60):
            ts = datetime(2026, 9, 25, tzinfo=timezone.utc) - timedelta(hours=i * 30)
            events.append({"uuid": f"{aid}-{i}", "published": iso(ts), "eventType": "app.oauth2.as.token.grant.access_token",
                           "actor": {"id": "0oa9ReportingSvc0009", "type": "PublicClientApp"},
                           "target": [{"id": aid, "type": "AppInstance"}], "outcome": {"result": "SUCCESS"}})
    return sorted(events, key=lambda e: e["published"])


def write(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    write(OUT / "apps.json", APPS)
    write(OUT / "groups.json", GROUPS)
    for aid, d in DETAILS.items():
        write(OUT / "apps" / aid / "groups.json", d["groups"])
        write(OUT / "apps" / aid / "users.json", d["users"])
        write(OUT / "apps" / aid / "logs.json", usage_events(aid))
        if "keys" in d:
            write(OUT / "apps" / aid / "keys.json", d["keys"])
            (OUT / "apps" / aid / "metadata.xml").write_text(d["metadata"], encoding="utf-8")
    for kind, items in TENANT.items():
        write(OUT / "tenant" / f"{kind}.json", items)
    (OUT / "README.txt").write_text(
        "FICTIONAL sample Okta export (Northwind). Generated by scripts/generate_sample_export.py.\n"
        "Same layout as `flask okta-export` produces from a real tenant.\n", encoding="utf-8")
    print(f"Wrote {len(APPS)} apps ({len(DETAILS)} with SAML/OIDC details) to {OUT}")
