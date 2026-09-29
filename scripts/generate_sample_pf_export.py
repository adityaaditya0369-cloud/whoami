"""Generate a FICTIONAL PingFederate export (Admin API shapes) for the Northwind sample.

Shows every reconciliation outcome:
  Expense Portal     - built and matching
  Engineering Wiki   - built, but missing ACS index 1, 'wikiRole', virtual server ID, issuance criteria, SLO
  ServiceNow         - built (matched by name; Okta hides the catalog app's entity ID)
  Employee Portal    - OAuth client built, one redirect URI missing
  Reporting API      - OAuth client built and matching
  Payroll, pingaccess-agent - exist only on PingFederate
Usage: python scripts/generate_sample_pf_export.py [out_dir]
"""
import json
import sys
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "data" / "pf-exports" / "sample-pf"
UNSPEC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"


def sp(cid, name, entity, acs, attrs, sign=True, criteria=False, vids=None, slo=None):
    mapping = {"idpAdapterRef": {"id": "HTMLFormAD"}, "attributeContractFulfillment": {
        a: {"source": {"type": "LDAP_DATA_STORE"}, "value": a} for a in ["SAML_SUBJECT"] + attrs}}
    if criteria:
        mapping["issuanceCriteria"] = {"conditionalCriteria": [{
            "source": {"type": "LDAP_DATA_STORE"}, "attributeName": "memberOf", "condition": "MULTIVALUE_CONTAINS_DN",
            "value": "CN=App Users,OU=Groups,DC=northwind,DC=example"}]}
    return {"id": cid, "type": "SP", "name": name, "entityId": entity, "active": True,
            "virtualIdentities": vids or [],
            "credentials": {"signingSettings": {"signingKeyPairRef": {"id": "pfsigning2026"}, "algorithm": "SHA256withRSA"}},
            "spBrowserSso": {"protocol": "SAML20", "enabledProfiles": ["IDP_INITIATED_SSO", "SP_INITIATED_SSO"],
                             "signAssertions": sign,
                             "ssoServiceEndpoints": [{"binding": "POST", "url": u, "index": i, "isDefault": i == 0}
                                                     for i, u in enumerate(acs)],
                             "sloServiceEndpoints": [{"binding": "POST", "url": slo}] if slo else [],
                             "attributeContract": {"coreAttributes": [{"name": "SAML_SUBJECT", "nameFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"}],
                                                   "extendedAttributes": [{"name": a, "nameFormat": UNSPEC} for a in attrs]},
                             "adapterMappings": [mapping]}}


def client(cid, name, grants, redirects, auth, pkce=False):
    return {"clientId": cid, "name": name, "enabled": True, "grantTypes": grants, "redirectUris": redirects,
            "clientAuth": {"type": auth}, "requireProofKeyForCodeExchange": pkce,
            "bypassApprovalPage": True, "oidcPolicy": {"policyGroup": {"id": "default-oidc"}}}


SP = [
    sp("expense", "Expense Portal", "https://expenses.northwind.example",
       ["https://expenses.northwind.example/saml/acs"], ["email"], criteria=True),
    sp("engwiki", "Engineering Wiki (Confluence DC)", "https://wiki.northwind.example",
       ["https://wiki.northwind.example/plugins/servlet/samlconsumer"], ["email", "fullName", "groups"]),
    sp("servicenow", "ServiceNow", "https://northwind.service-now.com",
       ["https://northwind.service-now.com/navpage.do"], [], criteria=True),
    sp("payroll", "Payroll (already on PingFederate)", "https://payroll.northwind.example",
       ["https://payroll.northwind.example/sso"], ["email"], criteria=True),
]
OC = [
    client("0oa7EmpPortalClient01", "Employee Portal", ["AUTHORIZATION_CODE", "REFRESH_TOKEN"],
           ["https://portal.northwind.example/callback"], "SECRET"),
    client("0oa9ReportingSvc0009", "Reporting API", ["CLIENT_CREDENTIALS"], [], "PRIVATE_KEY_JWT"),
    client("pingaccess-agent", "PingAccess agent", ["CLIENT_CREDENTIALS"], [], "SECRET"),
]

if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sp_connections.json").write_text(json.dumps({"items": SP}, indent=2), encoding="utf-8")
    (OUT / "oauth_clients.json").write_text(json.dumps({"items": OC}, indent=2), encoding="utf-8")
    (OUT / "README.txt").write_text("FICTIONAL PingFederate export for the Northwind sample. Same shapes as "
                                    "GET /pf-admin-api/v1/idp/spConnections and /oauth/clients.\n", encoding="utf-8")
    print(f"Wrote {len(SP)} SP connections and {len(OC)} OAuth clients to {OUT}")
