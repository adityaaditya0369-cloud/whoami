"""Database models (SQLAlchemy 2.x). SQLite now, PostgreSQL later - no
SQLite-specific types are used, so switching is a DATABASE_URL change.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship, scoped_session, sessionmaker,
)

from app.models.state import MigrationState


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class DiscoveryRun(Base):
    __tablename__ = "discovery_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    source: Mapped[str] = mapped_column(String(20))          # live | file
    source_ref: Mapped[str] = mapped_column(String(500))     # org URL or export path
    actor: Mapped[str] = mapped_column(String(200), default="system")
    status: Mapped[str] = mapped_column(String(20), default="RUNNING")  # RUNNING|SUCCESS|FAILED
    error: Mapped[str | None] = mapped_column(Text)
    apps_total: Mapped[int] = mapped_column(Integer, default=0)
    saml_apps: Mapped[int] = mapped_column(Integer, default=0)
    oidc_apps: Mapped[int | None] = mapped_column(Integer, default=0)
    changed_apps: Mapped[int] = mapped_column(Integer, default=0)
    new_apps: Mapped[int] = mapped_column(Integer, default=0)
    removed_apps: Mapped[int] = mapped_column(Integer, default=0)


class Application(Base):
    """Every Okta app is recorded; only SAML apps enter the migration flow."""
    __tablename__ = "applications"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # Okta app id
    label: Mapped[str] = mapped_column(String(500))
    okta_name: Mapped[str] = mapped_column(String(200))   # catalog key, e.g. servicenow_ud
    sign_on_mode: Mapped[str] = mapped_column(String(50))
    okta_status: Mapped[str] = mapped_column(String(20))
    is_saml: Mapped[bool] = mapped_column(Boolean, default=False)
    is_custom_saml: Mapped[bool] = mapped_column(Boolean, default=False)  # AIW app vs OIN catalog
    is_oidc: Mapped[bool] = mapped_column(Boolean, default=False)
    okta_created: Mapped[datetime | None] = mapped_column(DateTime)
    okta_last_updated: Mapped[datetime | None] = mapped_column(DateTime)
    user_name_template: Mapped[str | None] = mapped_column(String(500))

    user_count: Mapped[int] = mapped_column(Integer, default=0)
    direct_user_count: Mapped[int] = mapped_column(Integer, default=0)
    group_count: Mapped[int] = mapped_column(Integer, default=0)

    state: Mapped[str] = mapped_column(String(40), default=MigrationState.DISCOVERED.value)
    wave: Mapped[str | None] = mapped_column(String(50))
    business_owner: Mapped[str | None] = mapped_column(String(200))
    business_criticality: Mapped[str | None] = mapped_column(String(20))  # LOW|MEDIUM|HIGH
    has_test_environment: Mapped[bool | None] = mapped_column(Boolean)
    notes: Mapped[str | None] = mapped_column(Text)

    # Usage from the Okta System Log (None = unknown)
    usage_known: Mapped[bool] = mapped_column(Boolean, default=False)
    usage_window_days: Mapped[int | None] = mapped_column(Integer)
    usage_events: Mapped[int | None] = mapped_column(Integer)
    usage_unique_users: Mapped[int | None] = mapped_column(Integer)
    usage_last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    usage_capped: Mapped[bool] = mapped_column(Boolean, default=False)

    # Current risk (denormalised from the latest RiskScore row for fast listing)
    complexity_score: Mapped[int | None] = mapped_column(Integer)
    complexity_level: Mapped[str | None] = mapped_column(String(10))
    impact_score: Mapped[int | None] = mapped_column(Integer)
    impact_level: Mapped[str | None] = mapped_column(String(10))
    overall_level: Mapped[str | None] = mapped_column(String(10))
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    suggested_wave: Mapped[str | None] = mapped_column(String(40))

    raw_sha256: Mapped[str | None] = mapped_column(String(64))
    first_seen_run_id: Mapped[int | None] = mapped_column(ForeignKey("discovery_runs.id"))
    last_seen_run_id: Mapped[int | None] = mapped_column(ForeignKey("discovery_runs.id"))
    removed_from_okta: Mapped[bool] = mapped_column(Boolean, default=False)
    changed_in_last_run: Mapped[bool] = mapped_column(Boolean, default=False)

    # Strategy model (app/strategy_model): detected features, compatibility and the chosen strategy
    okta_features: Mapped[list | None] = mapped_column(JSON)          # raw Okta app "features" (provisioning)
    access_policy_id: Mapped[str | None] = mapped_column(String(64))  # OIE app sign-in policy
    auth_server_id: Mapped[str | None] = mapped_column(String(64))    # custom authorization server (OIDC)
    compat_level: Mapped[str | None] = mapped_column(String(10))      # HIGH | MEDIUM | LOW
    strategy: Mapped[str | None] = mapped_column(String(20))          # RECREATE | TRANSFORM | REDESIGN | RETIRE | RETAIN
    strategy_reasons: Mapped[list | None] = mapped_column(JSON)

    saml: Mapped["SamlConfiguration | None"] = relationship(
        back_populates="application", uselist=False, cascade="all, delete-orphan")
    oidc: Mapped["OidcConfiguration | None"] = relationship(
        back_populates="application", uselist=False, cascade="all, delete-orphan")

    @property
    def protocol(self) -> str:
        return "SAML" if self.is_saml else ("OIDC" if self.is_oidc else "OTHER")

    @property
    def in_scope_protocol(self) -> bool:
        return bool(self.is_saml or self.is_oidc)
    claims: Mapped[list["Claim"]] = relationship(
        back_populates="application", cascade="all, delete-orphan", order_by="Claim.position")
    assignments: Mapped[list["Assignment"]] = relationship(
        back_populates="application", cascade="all, delete-orphan")
    certificates: Mapped[list["Certificate"]] = relationship(
        back_populates="application", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="application", cascade="all, delete-orphan")
    events: Mapped[list["MigrationEvent"]] = relationship(
        back_populates="application", order_by="MigrationEvent.id.desc()")


class SamlConfiguration(Base):
    __tablename__ = "saml_configurations"
    app_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), primary_key=True)
    config_completeness: Mapped[str] = mapped_column(String(20))  # FULL | PARTIAL
    sso_acs_url: Mapped[str | None] = mapped_column(String(2000))
    recipient: Mapped[str | None] = mapped_column(String(2000))
    destination: Mapped[str | None] = mapped_column(String(2000))
    audience: Mapped[str | None] = mapped_column(String(2000))     # SP entity ID
    idp_issuer: Mapped[str | None] = mapped_column(String(2000))
    sp_issuer: Mapped[str | None] = mapped_column(String(2000))
    default_relay_state: Mapped[str | None] = mapped_column(String(2000))
    name_id_template: Mapped[str | None] = mapped_column(String(1000))
    name_id_format: Mapped[str | None] = mapped_column(String(200))
    response_signed: Mapped[bool | None] = mapped_column(Boolean)
    assertion_signed: Mapped[bool | None] = mapped_column(Boolean)
    signature_algorithm: Mapped[str | None] = mapped_column(String(50))
    digest_algorithm: Mapped[str | None] = mapped_column(String(50))
    authn_context_class_ref: Mapped[str | None] = mapped_column(String(300))
    honor_force_authn: Mapped[bool | None] = mapped_column(Boolean)
    request_compressed: Mapped[bool | None] = mapped_column(Boolean)
    assertion_lifetime_seconds: Mapped[int | None] = mapped_column(Integer)
    allow_multiple_acs: Mapped[bool] = mapped_column(Boolean, default=False)
    acs_endpoints: Mapped[list] = mapped_column(JSON, default=list)
    slo_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    slo_issuer: Mapped[str | None] = mapped_column(String(2000))
    slo_logout_url: Mapped[str | None] = mapped_column(String(2000))
    sp_certificate_present: Mapped[bool] = mapped_column(Boolean, default=False)
    catalog_app_settings: Mapped[dict] = mapped_column(JSON, default=dict)
    metadata_xml: Mapped[str | None] = mapped_column(Text)
    metadata_entity_id: Mapped[str | None] = mapped_column(String(2000))
    metadata_sso_url: Mapped[str | None] = mapped_column(String(2000))
    pf_nameid_source: Mapped[str | None] = mapped_column(String(30))
    pf_nameid_detail: Mapped[str | None] = mapped_column(Text)

    application: Mapped[Application] = relationship(back_populates="saml")


class OidcConfiguration(Base):
    __tablename__ = "oidc_configurations"
    app_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), primary_key=True)
    client_id: Mapped[str | None] = mapped_column(String(200))
    application_type: Mapped[str | None] = mapped_column(String(30))
    grant_types: Mapped[list] = mapped_column(JSON, default=list)
    response_types: Mapped[list] = mapped_column(JSON, default=list)
    redirect_uris: Mapped[list] = mapped_column(JSON, default=list)
    post_logout_redirect_uris: Mapped[list] = mapped_column(JSON, default=list)
    token_endpoint_auth_method: Mapped[str | None] = mapped_column(String(50))
    pkce_required: Mapped[bool | None] = mapped_column(Boolean)
    initiate_login_uri: Mapped[str | None] = mapped_column(String(2000))
    consent_method: Mapped[str | None] = mapped_column(String(30))
    issuer_mode: Mapped[str | None] = mapped_column(String(30))
    wildcard_redirect: Mapped[str | None] = mapped_column(String(30))
    has_jwks: Mapped[bool] = mapped_column(Boolean, default=False)

    application: Mapped[Application] = relationship(back_populates="oidc")


class Claim(Base):
    """One SAML attribute statement (EXPRESSION or GROUP)."""
    __tablename__ = "claims"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(500))
    namespace: Mapped[str | None] = mapped_column(String(300))
    claim_type: Mapped[str] = mapped_column(String(20))      # EXPRESSION | GROUP
    values: Mapped[list] = mapped_column(JSON, default=list)
    expression_kind: Mapped[str | None] = mapped_column(String(20))  # DIRECT | LITERAL | COMPLEX
    source_attributes: Mapped[list] = mapped_column(JSON, default=list)
    functions_used: Mapped[list] = mapped_column(JSON, default=list)
    group_filter_type: Mapped[str | None] = mapped_column(String(30))
    group_filter_value: Mapped[str | None] = mapped_column(String(1000))
    matched_group_count: Mapped[int | None] = mapped_column(Integer)
    matched_group_sample: Mapped[list] = mapped_column(JSON, default=list)
    matched_okta_native_groups: Mapped[list] = mapped_column(JSON, default=list)
    # PingFederate readiness (see app/integrations/pingfederate/mapping.py)
    pf_source: Mapped[str | None] = mapped_column(String(30))
    pf_source_detail: Mapped[str | None] = mapped_column(Text)
    pf_ldap_attributes: Mapped[list] = mapped_column(JSON, default=list)
    pf_missing_inputs: Mapped[list] = mapped_column(JSON, default=list)

    application: Mapped[Application] = relationship(back_populates="claims")


class Group(Base):
    __tablename__ = "groups"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(500), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    group_type: Mapped[str] = mapped_column(String(30))   # OKTA_GROUP | APP_GROUP | BUILT_IN
    source_app: Mapped[str | None] = mapped_column(String(200))  # e.g. active_directory
    member_count: Mapped[int | None] = mapped_column(Integer)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    login: Mapped[str | None] = mapped_column(String(500), index=True)
    email: Mapped[str | None] = mapped_column(String(500))
    status: Mapped[str | None] = mapped_column(String(30))


class Assignment(Base):
    __tablename__ = "assignments"
    __table_args__ = (UniqueConstraint("app_id", "principal_type", "principal_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    principal_type: Mapped[str] = mapped_column(String(10))   # GROUP | USER
    principal_id: Mapped[str] = mapped_column(String(64))
    principal_name: Mapped[str | None] = mapped_column(String(500))
    scope: Mapped[str | None] = mapped_column(String(10))     # for users: USER (direct) | GROUP
    priority: Mapped[int | None] = mapped_column(Integer)
    app_username: Mapped[str | None] = mapped_column(String(500))
    app_profile: Mapped[dict] = mapped_column(JSON, default=dict)

    application: Mapped[Application] = relationship(back_populates="assignments")


class Certificate(Base):
    __tablename__ = "certificates"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    kid: Mapped[str] = mapped_column(String(200))
    is_active_signing_key: Mapped[bool] = mapped_column(Boolean, default=False)
    subject: Mapped[str | None] = mapped_column(String(1000))
    issuer: Mapped[str | None] = mapped_column(String(1000))
    not_before: Mapped[datetime | None] = mapped_column(DateTime)
    not_after: Mapped[datetime | None] = mapped_column(DateTime)
    sha1_thumbprint: Mapped[str | None] = mapped_column(String(64))
    sha256_thumbprint: Mapped[str | None] = mapped_column(String(100))
    key_size: Mapped[int | None] = mapped_column(Integer)
    x5c: Mapped[str | None] = mapped_column(Text)

    application: Mapped[Application] = relationship(back_populates="certificates")


class Finding(Base):
    """Deterministic, rule-based observation. Inputs for the Sprint 2 risk engine."""
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("discovery_runs.id"))
    code: Mapped[str] = mapped_column(String(60), index=True)
    severity: Mapped[str] = mapped_column(String(10))   # INFO | WARNING | CRITICAL
    message: Mapped[str] = mapped_column(Text)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)

    application: Mapped[Application] = relationship(back_populates="findings")


class RawSnapshot(Base):
    """Immutable copy of what Okta returned - the baseline for validation and rollback."""
    __tablename__ = "raw_snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("discovery_runs.id"), index=True)
    app_id: Mapped[str | None] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(30))   # app | app_groups | app_users | keys | metadata
    sha256: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str] = mapped_column(Text)
    captured_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class MigrationEvent(Base):
    """Append-only audit log."""
    __tablename__ = "migration_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_id: Mapped[str | None] = mapped_column(ForeignKey("applications.id"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(200))
    event_type: Mapped[str] = mapped_column(String(50))
    from_state: Mapped[str | None] = mapped_column(String(40))
    to_state: Mapped[str | None] = mapped_column(String(40))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)

    application: Mapped[Application | None] = relationship(back_populates="events")


class PfSyncRun(Base):
    __tablename__ = "pf_sync_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    source: Mapped[str] = mapped_column(String(20))
    source_ref: Mapped[str] = mapped_column(String(500))
    actor: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="RUNNING")
    error: Mapped[str | None] = mapped_column(Text)
    sp_connections: Mapped[int] = mapped_column(Integer, default=0)
    oauth_clients: Mapped[int] = mapped_column(Integer, default=0)


class PfObject(Base):
    """An SP connection or OAuth client found on PingFederate (read-only copy)."""
    __tablename__ = "pf_objects"
    __table_args__ = (UniqueConstraint("kind", "pf_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(20))          # SP_CONNECTION | OAUTH_CLIENT
    pf_id: Mapped[str] = mapped_column(String(500))
    key: Mapped[str] = mapped_column(String(2000), index=True)
    name: Mapped[str] = mapped_column(String(500))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    last_sync_id: Mapped[int | None] = mapped_column(ForeignKey("pf_sync_runs.id"))
    removed: Mapped[bool] = mapped_column(Boolean, default=False)


class MigrationTask(Base):
    """One step of an app's migration checklist. Updates are audited."""
    __tablename__ = "migration_tasks"
    __table_args__ = (UniqueConstraint("app_id", "step_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    step_key: Mapped[str] = mapped_column(String(30))
    position: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), default="NOT_STARTED")  # NOT_STARTED|IN_PROGRESS|DONE|BLOCKED|N/A
    owner: Mapped[str | None] = mapped_column(String(200))
    due_date: Mapped[datetime | None] = mapped_column(DateTime)
    notes: Mapped[str | None] = mapped_column(Text)
    updated_by: Mapped[str | None] = mapped_column(String(200))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime)


class Decision(Base):
    """A migration-wide decision (e.g. OGNL policy). Deciding one unblocks the apps it affects."""
    __tablename__ = "decisions"
    key: Mapped[str] = mapped_column(String(40), primary_key=True)
    status: Mapped[str] = mapped_column(String(20), default="OPEN")   # OPEN | DECIDED
    choice: Mapped[str | None] = mapped_column(String(300))
    owner: Mapped[str | None] = mapped_column(String(200))
    due_date: Mapped[datetime | None] = mapped_column(DateTime)
    notes: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[str | None] = mapped_column(String(200))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)


class PlanSettings(Base):
    """Single row of timeline assumptions (editable in the UI)."""
    __tablename__ = "plan_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    start_date: Mapped[datetime | None] = mapped_column(DateTime)
    engineers: Mapped[float] = mapped_column(default=2)
    hours_per_week: Mapped[float] = mapped_column(default=30)
    vendor_lead_days: Mapped[int] = mapped_column(Integer, default=14)
    pilot_days: Mapped[int] = mapped_column(Integer, default=5)
    hypercare_days: Mapped[int] = mapped_column(Integer, default=7)
    decision_lead_days: Mapped[int] = mapped_column(Integer, default=21)
    buffer_pct: Mapped[int] = mapped_column(Integer, default=20)
    updated_by: Mapped[str | None] = mapped_column(String(200))


class StrategyDraft(Base):
    """Optional AI-written narrative for the strategy report (validated, review before use)."""
    __tablename__ = "strategy_drafts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    requested_by: Mapped[str] = mapped_column(String(200))
    provider: Mapped[str] = mapped_column(String(20))
    model: Mapped[str | None] = mapped_column(String(100))
    input_sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(30))
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    errors: Mapped[list] = mapped_column(JSON, default=list)


class RiskScore(Base):
    """Append-only history of deterministic risk calculations."""
    __tablename__ = "risk_scores"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    computed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    rules_version: Mapped[str] = mapped_column(String(40))
    input_sha256: Mapped[str] = mapped_column(String(64))
    complexity_score: Mapped[int] = mapped_column(Integer)
    complexity_level: Mapped[str] = mapped_column(String(10))
    impact_score: Mapped[int] = mapped_column(Integer)
    impact_level: Mapped[str] = mapped_column(String(10))
    overall_level: Mapped[str] = mapped_column(String(10))
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    blockers: Mapped[list] = mapped_column(JSON, default=list)
    suggested_wave: Mapped[str] = mapped_column(String(40))
    breakdown: Mapped[list] = mapped_column(JSON, default=list)  # [{dimension, rule, points, reason}]


class AiAssessment(Base):
    """One AI (or offline) assessment. Output is validated JSON; never executable."""
    __tablename__ = "ai_assessments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    risk_score_id: Mapped[int | None] = mapped_column(ForeignKey("risk_scores.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    requested_by: Mapped[str] = mapped_column(String(200))
    provider: Mapped[str] = mapped_column(String(20))
    model: Mapped[str | None] = mapped_column(String(100))
    input_sha256: Mapped[str] = mapped_column(String(64))
    masked: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(30))  # VALID | REJECTED_SCHEMA | REJECTED_POLICY | ERROR
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    review_status: Mapped[str] = mapped_column(String(20), default="PENDING")  # PENDING|ACCEPTED|REJECTED
    reviewed_by: Mapped[str | None] = mapped_column(String(200))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime)
    review_comment: Mapped[str | None] = mapped_column(Text)


class MigrationPlan(Base):
    """Versioned, approvable migration plan for one app. `plan` is what gets
    approved - and exactly what may later be written to PingFederate."""
    __tablename__ = "migration_plans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    plan: Mapped[dict] = mapped_column(JSON, default=dict)
    # DRAFT | SUBMITTED | APPROVED | REJECTED | SUPERSEDED
    status: Mapped[str] = mapped_column(String(30), default="DRAFT")
    sha256: Mapped[str | None] = mapped_column(String(64))
    payload_sha256: Mapped[str | None] = mapped_column(String(64))
    generated_by: Mapped[str | None] = mapped_column(String(200))
    submitted_by: Mapped[str | None] = mapped_column(String(200))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime)
    decided_by: Mapped[str | None] = mapped_column(String(200))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)
    decision_comment: Mapped[str | None] = mapped_column(Text)


class ValidationResult(Base):
    """One SAML response check. The raw response is not stored (only its hash
    and the parsed summary), because it can contain personal data."""
    __tablename__ = "validation_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    result: Mapped[dict] = mapped_column(JSON, default=dict)      # {checks: [...], summary: {...}}
    verdict: Mapped[str] = mapped_column(String(20))             # PASS | PASS_WITH_WARNINGS | FAIL | ERROR
    stage: Mapped[str | None] = mapped_column(String(20))        # BASELINE_OKTA | PRE_CUTOVER | POST_CUTOVER
    source: Mapped[str | None] = mapped_column(String(20))       # CAPTURED | AUTOMATED
    actor: Mapped[str | None] = mapped_column(String(200))
    response_sha256: Mapped[str | None] = mapped_column(String(64))
    plan_id: Mapped[int | None] = mapped_column(ForeignKey("migration_plans.id"))


class KnowledgeDoc(Base):
    """A document uploaded to the knowledge base (runbook, vendor SSO guide, notes)."""
    __tablename__ = "knowledge_docs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(500))
    filename: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    app_id: Mapped[str | None] = mapped_column(ForeignKey("applications.id"), index=True)  # None = all apps
    tags: Mapped[list] = mapped_column(JSON, default=list)
    uploaded_by: Mapped[str] = mapped_column(String(200))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    chars: Mapped[int] = mapped_column(Integer, default=0)
    chunks: Mapped[list["KnowledgeChunk"]] = relationship(
        back_populates="doc", cascade="all, delete-orphan", order_by="KnowledgeChunk.position")


class KnowledgeChunk(Base):
    __tablename__ = "knowledge_chunks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    doc_id: Mapped[int] = mapped_column(ForeignKey("knowledge_docs.id"), index=True)
    position: Mapped[int] = mapped_column(Integer)
    heading: Mapped[str | None] = mapped_column(String(500))
    text: Mapped[str] = mapped_column(Text)
    doc: Mapped[KnowledgeDoc] = relationship(back_populates="chunks")

    @property
    def ref(self) -> str:
        return f"KB-{self.id}"


class AgentRun(Base):
    """One run of the four review agents for an app, reviewed as a whole by a person."""
    __tablename__ = "agent_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    requested_by: Mapped[str] = mapped_column(String(200))
    provider: Mapped[str] = mapped_column(String(20))
    model: Mapped[str | None] = mapped_column(String(100))
    masked: Mapped[bool] = mapped_column(Boolean, default=False)
    input_sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20))          # VALID | REJECTED | ERROR
    review_status: Mapped[str] = mapped_column(String(20), default="PENDING")  # PENDING|ACCEPTED|REJECTED
    reviewed_by: Mapped[str | None] = mapped_column(String(200))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime)
    review_comment: Mapped[str | None] = mapped_column(Text)
    resolutions: Mapped[dict] = mapped_column(JSON, default=dict)   # "AGENT:item" -> note
    reviews: Mapped[list["AgentReview"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="AgentReview.position")


class AgentReview(Base):
    __tablename__ = "agent_reviews"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("agent_runs.id"), index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    agent: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30))   # VALID | REJECTED_SCHEMA | REJECTED_POLICY | ERROR
    items: Mapped[list] = mapped_column(JSON, default=list)        # what the agent was asked to review
    knowledge_refs: Mapped[list] = mapped_column(JSON, default=list)  # KB refs offered to it
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    run: Mapped[AgentRun] = relationship(back_populates="reviews")


class TenantScan(Base):
    """Which tenant-level object kinds could be read in a discovery run."""
    __tablename__ = "tenant_scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("discovery_runs.id"), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20))          # OK | UNAVAILABLE | NOT_EXPORTED
    count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)


class TenantObject(Base):
    """Okta objects that are not apps: policies, authenticators, group rules, authorization
    servers, hooks, identity providers, network zones. Replaced on every discovery run."""
    __tablename__ = "tenant_objects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    okta_id: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(500))
    subtype: Mapped[str | None] = mapped_column(String(60))
    status: Mapped[str | None] = mapped_column(String(20))
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    app_ids: Mapped[list] = mapped_column(JSON, default=list)      # apps that use this object
    run_id: Mapped[int | None] = mapped_column(ForeignKey("discovery_runs.id"))
    compat_level: Mapped[str | None] = mapped_column(String(10))
    strategy: Mapped[str | None] = mapped_column(String(20))
    strategy_reasons: Mapped[list | None] = mapped_column(JSON)
    __table_args__ = (UniqueConstraint("kind", "okta_id"),)


class Dependency(Base):
    """An edge in the dependency graph: `source` depends on `target`.
    Nodes are "app:<okta id>", "obj:<kind>:<okta id>" or "ext:<free text>"."""
    __tablename__ = "dependencies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(300), index=True)
    target: Mapped[str] = mapped_column(String(300), index=True)
    kind: Mapped[str] = mapped_column(String(40), default="DEPENDS_ON")
    origin: Mapped[str] = mapped_column(String(20))       # DISCOVERED | IMPORTED | MANUAL | SUGGESTED
    status: Mapped[str] = mapped_column(String(20))       # CONFIRMED | SUGGESTED | REJECTED
    evidence: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(200), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    decided_by: Mapped[str | None] = mapped_column(String(200))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)
    __table_args__ = (UniqueConstraint("source", "target", "kind"),)


class StrategyOverride(Base):
    """An architect's decision to use a different strategy than the rules chose (audited)."""
    __tablename__ = "strategy_overrides"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    app_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    strategy: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


# ---------------------------------------------------------------------------
engine = None
SessionLocal = scoped_session(sessionmaker(expire_on_commit=False))


def init_engine(database_url: str):
    global engine
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, connect_args=connect_args, future=True)
    SessionLocal.remove()
    SessionLocal.configure(bind=engine)
    Base.metadata.create_all(engine)
    _add_missing_columns(engine)
    return engine


def _add_missing_columns(eng) -> None:
    """Lightweight upgrade for databases created by an earlier sprint: add any new
    columns as nullable. (Use Alembic once this moves to PostgreSQL.)"""
    from sqlalchemy import inspect, text
    insp = inspect(eng)
    with eng.begin() as conn:
        for table in Base.metadata.sorted_tables:
            existing = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name not in existing:
                    ddl = col.type.compile(dialect=eng.dialect)
                    conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN "{col.name}" {ddl}'))
