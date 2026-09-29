"""PingFederate Admin API JSON -> normalised PfObjectModel (pure functions)."""
from __future__ import annotations

from pydantic import BaseModel, Field

# PingFederate grant type enum -> OAuth/Okta grant name
PF_GRANTS = {
    "AUTHORIZATION_CODE": "authorization_code", "REFRESH_TOKEN": "refresh_token",
    "CLIENT_CREDENTIALS": "client_credentials", "IMPLICIT": "implicit",
    "RESOURCE_OWNER_CREDENTIALS": "password", "DEVICE_CODE": "urn:ietf:params:oauth:grant-type:device_code",
    "TOKEN_EXCHANGE": "urn:ietf:params:oauth:grant-type:token-exchange",
    "JWT_BEARER": "urn:ietf:params:oauth:grant-type:jwt-bearer",
}
PF_CLIENT_AUTH = {"SECRET": "client_secret", "PRIVATE_KEY_JWT": "private_key_jwt", "NONE": "none",
                  "CLIENT_CERT": "tls_client_auth"}


class PfObjectModel(BaseModel):
    kind: str                       # SP_CONNECTION | OAUTH_CLIENT
    pf_id: str
    key: str                        # SP entity ID or client ID (matching key)
    name: str
    active: bool = True
    acs_urls: list[dict] = Field(default_factory=list)      # [{url, index, default}]
    attributes: list[str] = Field(default_factory=list)
    sign_assertions: bool | None = None
    virtual_identities: list[str] = Field(default_factory=list)
    has_issuance_criteria: bool = False
    slo_urls: list[str] = Field(default_factory=list)
    grant_types: list[str] = Field(default_factory=list)
    redirect_uris: list[str] = Field(default_factory=list)
    client_auth: str | None = None
    pkce_required: bool | None = None


def parse_sp_connection(raw: dict) -> PfObjectModel:
    sso = raw.get("spBrowserSso") or {}
    contract = sso.get("attributeContract") or {}
    attrs = [a.get("name") for a in (contract.get("coreAttributes") or []) + (contract.get("extendedAttributes") or [])
             if a.get("name")]
    criteria = False
    for m in sso.get("adapterMappings") or []:
        ic = m.get("issuanceCriteria") or {}
        if ic.get("conditionalCriteria") or ic.get("expressionCriteria"):
            criteria = True
    return PfObjectModel(
        kind="SP_CONNECTION", pf_id=str(raw.get("id") or raw.get("entityId")), key=raw.get("entityId") or "",
        name=raw.get("name") or raw.get("entityId") or "", active=bool(raw.get("active", True)),
        acs_urls=[{"url": e.get("url"), "index": e.get("index", 0), "default": bool(e.get("isDefault"))}
                  for e in sso.get("ssoServiceEndpoints") or []],
        attributes=attrs, sign_assertions=sso.get("signAssertions"),
        virtual_identities=list(raw.get("virtualIdentities") or []),
        has_issuance_criteria=criteria,
        slo_urls=[e.get("url") for e in sso.get("sloServiceEndpoints") or [] if e.get("url")],
    )


def parse_oauth_client(raw: dict) -> PfObjectModel:
    auth = (raw.get("clientAuth") or {}).get("type")
    return PfObjectModel(
        kind="OAUTH_CLIENT", pf_id=raw.get("clientId") or "", key=raw.get("clientId") or "",
        name=raw.get("name") or raw.get("clientId") or "", active=bool(raw.get("enabled", True)),
        grant_types=[PF_GRANTS.get(g, g.lower()) for g in raw.get("grantTypes") or []],
        redirect_uris=list(raw.get("redirectUris") or []),
        client_auth=PF_CLIENT_AUTH.get(auth, (auth or "").lower() or None),
        pkce_required=raw.get("requireProofKeyForCodeExchange"),
    )
