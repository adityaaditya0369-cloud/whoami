"""Pydantic domain models: the normalised, validated shape of what we discovered.

The Okta parser produces these; the discovery service persists them. Later
sprints (AI assessment, mapping) consume these rather than raw Okta JSON.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ExpressionAnalysis(BaseModel):
    kind: Literal["DIRECT", "LITERAL", "COMPLEX"]
    source_attributes: list[str] = Field(default_factory=list)
    functions_used: list[str] = Field(default_factory=list)


class ClaimModel(BaseModel):
    position: int
    name: str
    namespace: str | None = None
    claim_type: Literal["EXPRESSION", "GROUP"]
    values: list[str] = Field(default_factory=list)
    analysis: ExpressionAnalysis | None = None
    group_filter_type: str | None = None
    group_filter_value: str | None = None


class AcsEndpoint(BaseModel):
    url: str
    index: int | None = None


class SamlConfigModel(BaseModel):
    config_completeness: Literal["FULL", "PARTIAL"]
    sso_acs_url: str | None = None
    recipient: str | None = None
    destination: str | None = None
    audience: str | None = None
    idp_issuer: str | None = None
    sp_issuer: str | None = None
    default_relay_state: str | None = None
    name_id_template: str | None = None
    name_id_format: str | None = None
    response_signed: bool | None = None
    assertion_signed: bool | None = None
    signature_algorithm: str | None = None
    digest_algorithm: str | None = None
    authn_context_class_ref: str | None = None
    honor_force_authn: bool | None = None
    request_compressed: bool | None = None
    assertion_lifetime_seconds: int | None = None
    allow_multiple_acs: bool = False
    acs_endpoints: list[AcsEndpoint] = Field(default_factory=list)
    slo_enabled: bool = False
    slo_issuer: str | None = None
    slo_logout_url: str | None = None
    sp_certificate_present: bool = False
    catalog_app_settings: dict = Field(default_factory=dict)
    claims: list[ClaimModel] = Field(default_factory=list)


class OidcConfigModel(BaseModel):
    client_id: str | None = None
    application_type: str | None = None          # web | native | browser | service
    grant_types: list[str] = Field(default_factory=list)
    response_types: list[str] = Field(default_factory=list)
    redirect_uris: list[str] = Field(default_factory=list)
    post_logout_redirect_uris: list[str] = Field(default_factory=list)
    token_endpoint_auth_method: str | None = None
    pkce_required: bool | None = None
    initiate_login_uri: str | None = None
    consent_method: str | None = None
    issuer_mode: str | None = None
    wildcard_redirect: str | None = None
    has_jwks: bool = False


class AppModel(BaseModel):
    id: str
    label: str
    okta_name: str
    sign_on_mode: str
    okta_status: str
    is_saml: bool
    is_custom_saml: bool
    created: datetime | None = None
    last_updated: datetime | None = None
    user_name_template: str | None = None
    active_signing_kid: str | None = None
    saml: SamlConfigModel | None = None
    is_oidc: bool = False
    oidc: OidcConfigModel | None = None
    okta_features: list[str] = []           # e.g. PUSH_NEW_USERS, IMPORT_NEW_USERS (provisioning)
    access_policy_id: str | None = None     # Okta Identity Engine app sign-in policy


class GroupModel(BaseModel):
    id: str
    name: str
    description: str | None = None
    group_type: str
    source_app: str | None = None
    member_count: int | None = None


class AppUserModel(BaseModel):
    user_id: str
    scope: str | None = None       # USER = direct, GROUP = via group
    app_username: str | None = None
    login: str | None = None
    email: str | None = None
    status: str | None = None
    profile: dict = Field(default_factory=dict)


class AppGroupModel(BaseModel):
    group_id: str
    priority: int | None = None
    profile: dict = Field(default_factory=dict)


class CertificateModel(BaseModel):
    kid: str
    subject: str | None = None
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    sha1_thumbprint: str | None = None
    sha256_thumbprint: str | None = None
    key_size: int | None = None
    x5c: str | None = None


class MetadataModel(BaseModel):
    entity_id: str | None = None
    sso_url: str | None = None


class TenantObjectModel(BaseModel):
    kind: str
    okta_id: str
    name: str
    subtype: str | None = None
    status: str | None = None
    attributes: dict = {}
    client_ids: list[str] = []      # OAuth client ids this object applies to (authorization server policies)
