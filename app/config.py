"""Application configuration.

All secrets come from the environment (or a local .env file that is never
committed). Nothing here should ever be logged in full.
"""
from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class OktaSourceMode(str, Enum):
    LIVE = "live"   # call the Okta Management API
    FILE = "file"   # read an offline export directory (same JSON shapes as the API)


class OktaAuthMode(str, Enum):
    OAUTH = "oauth"  # OAuth 2.0 service app, private_key_jwt (recommended)
    SSWS = "ssws"    # API token (read-only admin) - acceptable for a pilot


class DirectoryType(str, Enum):
    AD = "AD"                        # Active Directory
    PINGDIRECTORY = "PINGDIRECTORY"  # PingDirectory / generic inetOrgPerson LDAP


class PfSourceMode(str, Enum):
    NONE = "none"    # plan only, no PingFederate data
    FILE = "file"    # read an export folder (sp_connections.json, oauth_clients.json)
    LIVE = "live"    # read-only PingFederate Admin API


class AiProvider(str, Enum):
    OFFLINE = "offline"      # deterministic templates, no data leaves the machine
    ANTHROPIC = "anthropic"  # Claude via the Anthropic API


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env", env_file_encoding="utf-8", extra="ignore",
        populate_by_name=True,
    )

    # --- Flask -----------------------------------------------------------
    secret_key: SecretStr = Field(default=SecretStr("dev-only-change-me"), alias="FLASK_SECRET_KEY")
    database_url: str = Field(
        default=f"sqlite:///{BASE_DIR / 'data' / 'factory.db'}", alias="DATABASE_URL"
    )
    customer_name: str = Field(default="Customer", alias="CUSTOMER_NAME")

    # --- Okta source -----------------------------------------------------
    okta_source: OktaSourceMode = Field(default=OktaSourceMode.FILE, alias="OKTA_SOURCE")
    okta_export_dir: Path = Field(
        default=BASE_DIR / "data" / "exports" / "sample-tenant", alias="OKTA_EXPORT_DIR"
    )

    okta_org_url: str | None = Field(default=None, alias="OKTA_ORG_URL")
    okta_auth_mode: OktaAuthMode = Field(default=OktaAuthMode.OAUTH, alias="OKTA_AUTH_MODE")
    okta_api_token: SecretStr | None = Field(default=None, alias="OKTA_API_TOKEN")
    okta_client_id: str | None = Field(default=None, alias="OKTA_CLIENT_ID")
    okta_private_key_path: Path | None = Field(default=None, alias="OKTA_PRIVATE_KEY_PATH")
    okta_private_key_kid: str | None = Field(default=None, alias="OKTA_PRIVATE_KEY_KID")
    okta_scopes: str = Field(
        default="okta.apps.read okta.groups.read okta.users.read okta.logs.read", alias="OKTA_SCOPES"
    )
    okta_timeout_seconds: float = Field(default=30.0, alias="OKTA_TIMEOUT_SECONDS")
    okta_max_retries: int = Field(default=5, alias="OKTA_MAX_RETRIES")

    # --- Usage analysis (Okta System Log, needs okta.logs.read) ------------
    okta_usage_enabled: bool = Field(default=True, alias="OKTA_USAGE_ENABLED")
    # Tenant-level objects (policies, authenticators, group rules, authorization servers, hooks, IdPs,
    # network zones). Each kind needs its own read scope; a kind that cannot be read is recorded, not fatal.
    okta_tenant_enabled: bool = Field(default=True, alias="OKTA_TENANT_ENABLED")
    # Optional JSON file overriding/adding rows of the PingFederate capability catalog
    capability_catalog_file: Path | None = Field(default=None, alias="CAPABILITY_CATALOG_FILE")
    okta_usage_days: int = Field(default=90, alias="OKTA_USAGE_DAYS")
    okta_usage_max_events: int = Field(default=20000, alias="OKTA_USAGE_MAX_EVENTS")  # per app, safety cap

    # --- Data handling ---------------------------------------------------
    # When false, per-user rows are not stored (only counts). Assignment rows
    # for users are still needed later for pilot selection, so default true.
    store_user_details: bool = Field(default=True, alias="STORE_USER_DETAILS")

    # --- Findings thresholds ---------------------------------------------
    cert_expiry_warning_days: int = Field(default=90, alias="CERT_EXPIRY_WARNING_DAYS")

    # --- PingFederate target ---------------------------------------------
    # Directory PingFederate will read users/groups from (LDAP data store).
    pf_directory_type: DirectoryType = Field(default=DirectoryType.AD, alias="PF_DIRECTORY_TYPE")
    # OGNL expressions are disabled by default in PingFederate and many security
    # teams forbid them. When false, claims that need OGNL are CRITICAL.
    pf_ognl_allowed: bool = Field(default=False, alias="PF_OGNL_ALLOWED")
    # Optional JSON file {"oktaAttr": "ldapAttr"} overriding/extending the default map.
    pf_attribute_map_file: Path | None = Field(default=None, alias="PF_ATTRIBUTE_MAP_FILE")
    # Used to show the PingFederate-side values in the comparison report.
    pf_base_url: str = Field(default="https://sso.example.com", alias="PF_BASE_URL")
    pf_entity_id: str = Field(default="https://sso.example.com", alias="PF_ENTITY_ID")

    # --- PingFederate read-only source (what is actually built) ------------
    pf_source: PfSourceMode = Field(default=PfSourceMode.FILE, alias="PF_SOURCE")
    pf_export_dir: Path = Field(default=BASE_DIR / "data" / "pf-exports" / "sample-pf", alias="PF_EXPORT_DIR")
    pf_admin_url: str | None = Field(default=None, alias="PF_ADMIN_URL")   # https://pf-admin:9999/pf-admin-api/v1
    pf_admin_user: str | None = Field(default=None, alias="PF_ADMIN_USER")
    pf_admin_password: SecretStr | None = Field(default=None, alias="PF_ADMIN_PASSWORD")
    pf_ca_bundle: Path | None = Field(default=None, alias="PF_CA_BUNDLE")  # for a private CA / self-signed admin cert
    pf_timeout_seconds: float = Field(default=30.0, alias="PF_TIMEOUT_SECONDS")

    # --- Risk engine (Sprint 2) --------------------------------------------
    # Optional JSON overriding weights in app/services/risk.py (see README).
    risk_weights_file: Path | None = Field(default=None, alias="RISK_WEIGHTS_FILE")

    # --- AI assessment (Sprint 2) ------------------------------------------
    ai_provider: AiProvider = Field(default=AiProvider.OFFLINE, alias="AI_PROVIDER")
    anthropic_api_key: SecretStr | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    claude_model: str = Field(default="claude-sonnet-5", alias="CLAUDE_MODEL")
    ai_max_tokens: int = Field(default=4000, alias="AI_MAX_TOKENS")
    # Replace hostnames, URLs and group names with tokens before sending to Claude.
    ai_mask_data: bool = Field(default=False, alias="AI_MASK_DATA")

    # --- Knowledge base (RAG) -------------------------------------------------
    knowledge_max_upload_mb: int = Field(default=10, alias="KNOWLEDGE_MAX_UPLOAD_MB")

    # --- Approval ------------------------------------------------------------
    # Four-eyes: the person approving a plan cannot be the one who submitted it.
    approval_four_eyes: bool = Field(default=True, alias="APPROVAL_FOUR_EYES")

    # --- PingFederate write (gated) ----------------------------------------------
    # Off by default. When on, an APPROVED plan can be created on PingFederate
    # (disabled, create-only, never update/delete) after a dry run.
    pf_write_enabled: bool = Field(default=False, alias="PF_WRITE_ENABLED")
    # Separate admin account for writes (the read account stays Auditor / GET only).
    pf_write_user: str | None = Field(default=None, alias="PF_WRITE_USER")
    pf_write_password: SecretStr | None = Field(default=None, alias="PF_WRITE_PASSWORD")
    # JSON {"VARIABLE": "value"} (or the variables.json shape from the build package).
    pf_variables_file: Path | None = Field(default=None, alias="PF_VARIABLES_FILE")
    pf_dry_run_valid_minutes: int = Field(default=30, alias="PF_DRY_RUN_VALID_MINUTES")

    # --- SAML validation ---------------------------------------------------
    # PEM of PingFederate's SAML signing certificate (to verify signatures).
    pf_signing_cert_file: Path | None = Field(default=None, alias="PF_SIGNING_CERT_FILE")
    validation_max_age_days: int = Field(default=14, alias="VALIDATION_MAX_AGE_DAYS")
    validation_clock_skew_seconds: int = Field(default=180, alias="VALIDATION_CLOCK_SKEW_SECONDS")

    # --- Automated test SSO (Playwright, optional) ------------------------------
    test_sso_enabled: bool = Field(default=False, alias="TEST_SSO_ENABLED")
    test_sso_username: str | None = Field(default=None, alias="TEST_SSO_USERNAME")
    test_sso_password: SecretStr | None = Field(default=None, alias="TEST_SSO_PASSWORD")
    # {pf_base_url} and {entity_id} are substituted (URL-encoded entity ID).
    test_sso_start_url: str = Field(default="{pf_base_url}/idp/startSSO.ping?PartnerSpId={entity_id}",
                                    alias="TEST_SSO_START_URL")
    test_sso_username_selector: str = Field(default='input[name="pf.username"], #username', alias="TEST_SSO_USERNAME_SELECTOR")
    test_sso_password_selector: str = Field(default='input[name="pf.pass"], #password', alias="TEST_SSO_PASSWORD_SELECTOR")
    test_sso_submit_selector: str = Field(default='#signOnButton, button[type="submit"], input[type="submit"]',
                                          alias="TEST_SSO_SUBMIT_SELECTOR")
    test_sso_timeout_seconds: int = Field(default=45, alias="TEST_SSO_TIMEOUT_SECONDS")
    test_sso_ignore_https_errors: bool = Field(default=False, alias="TEST_SSO_IGNORE_HTTPS_ERRORS")

    @model_validator(mode="after")
    def _check_live_settings(self) -> "Settings":
        if self.okta_source == OktaSourceMode.LIVE:
            if not self.okta_org_url:
                raise ValueError("OKTA_ORG_URL is required when OKTA_SOURCE=live")
            if not self.okta_org_url.startswith("https://"):
                raise ValueError("OKTA_ORG_URL must start with https://")
            if self.okta_auth_mode == OktaAuthMode.SSWS and not self.okta_api_token:
                raise ValueError("OKTA_API_TOKEN is required when OKTA_AUTH_MODE=ssws")
            if self.okta_auth_mode == OktaAuthMode.OAUTH and not (
                self.okta_client_id and self.okta_private_key_path
            ):
                raise ValueError(
                    "OKTA_CLIENT_ID and OKTA_PRIVATE_KEY_PATH are required when OKTA_AUTH_MODE=oauth"
                )
        if self.pf_source == PfSourceMode.LIVE:
            if not (self.pf_admin_url and self.pf_admin_url.startswith("https://")):
                raise ValueError("PF_ADMIN_URL (https://...) is required when PF_SOURCE=live")
            if not (self.pf_admin_user and self.pf_admin_password):
                raise ValueError("PF_ADMIN_USER and PF_ADMIN_PASSWORD are required when PF_SOURCE=live")
        if self.pf_write_enabled and self.pf_source != PfSourceMode.LIVE:
            raise ValueError("PF_WRITE_ENABLED=true needs PF_SOURCE=live (the write goes to the Admin API)")
        if self.pf_write_enabled and not (self.pf_write_user and self.pf_write_password):
            raise ValueError("PF_WRITE_USER and PF_WRITE_PASSWORD (a separate write account) are required when PF_WRITE_ENABLED=true")
        if self.test_sso_enabled and not (self.test_sso_username and self.test_sso_password):
            raise ValueError("TEST_SSO_USERNAME and TEST_SSO_PASSWORD are required when TEST_SSO_ENABLED=true")
        if self.ai_provider == AiProvider.ANTHROPIC and not self.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is required when AI_PROVIDER=anthropic")
        return self

    @property
    def okta_org(self) -> str | None:
        return self.okta_org_url.rstrip("/") if self.okta_org_url else None


def get_settings(**overrides) -> Settings:
    return Settings(**overrides)
