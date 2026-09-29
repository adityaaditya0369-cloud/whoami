"""Per-app PingFederate readiness checklist, derived from claims and findings."""
from __future__ import annotations

from app.models.db import Application


def pf_readiness(a: Application) -> dict:
    """Per-app PingFederate checklist, derived from claims + findings."""
    codes = {f.code for f in a.findings}
    okta_only = set()
    for f in a.findings:
        if f.code == "OKTA_NATIVE_GROUPS_ASSIGNED":
            okta_only |= set(f.detail.get("groups", []))
        if f.code == "GROUP_CLAIM_OKTA_NATIVE_GROUPS":
            okta_only |= set(f.detail.get("groups", []))
    ldap = sorted({x for c in a.claims for x in (c.pf_ldap_attributes or [])})
    nameid_ldap = (a.saml.pf_nameid_detail or "") if a.saml and a.saml.pf_nameid_source == "DATA_STORE" else ""
    if nameid_ldap.startswith("LDAP: "):
        ldap = sorted(set(ldap) | {nameid_ldap[6:].split(" ")[0]})
    return {
        "nameid_source": a.saml.pf_nameid_source if a.saml else "",
        "ognl_claims": [c.name for c in a.claims if c.pf_source in ("OGNL", "GROUP_OGNL")]
                       + (["NameID"] if a.saml and a.saml.pf_nameid_source == "OGNL" else []),
        "ldap_attributes": ldap,
        "missing_inputs": sorted({x for c in a.claims for x in (c.pf_missing_inputs or [])}
                                 | ({"user.id"} if "NAMEID_IS_OKTA_USER_ID" in codes else set())),
        "issuance_criteria": "ISSUANCE_CRITERIA_REQUIRED" in codes,
        "okta_only_groups": sorted(okta_only),
        "virtual_server_id": "CUSTOM_IDP_ISSUER" in codes,
        "duplicate_entity_id": "DUPLICATE_SP_ENTITY_ID" in codes,
    }
