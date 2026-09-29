"""Discovery: Okta -> normalised inventory in the database.

Read-only against Okta. Every run:
  * snapshots raw payloads (immutable baseline for validation/rollback),
  * detects new / changed / removed apps (drift),
  * re-evaluates deterministic findings,
  * writes audit events.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.integrations.okta import parser
from app.integrations.okta.client import TENANT_KINDS, OktaSource, TenantUnavailable, UsageUnavailable
from app.integrations.pingfederate import mapping as pfmap
from app.models.db import (
    Application, Assignment, Certificate, Claim, DiscoveryRun, Finding, Group, OidcConfiguration, RawSnapshot,
    SamlConfiguration, TenantObject, TenantScan, User, utcnow,
)
from app.models.domain import AppModel
from app.services import findings as rules
from app.services import risk
from app.services.state_service import record_event

log = logging.getLogger(__name__)


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _snapshot(session: Session, run: DiscoveryRun, kind: str, payload, app_id: str | None = None) -> str:
    text = payload if isinstance(payload, str) else _canonical(payload)
    digest = _sha(text)
    session.add(RawSnapshot(run_id=run.id, app_id=app_id, kind=kind, sha256=digest, payload=text))
    return digest


def run_discovery(session: Session, source: OktaSource, settings: Settings,
                  actor: str = "system", source_mode: str = "file",
                  now: datetime | None = None) -> DiscoveryRun:
    now = now or utcnow()
    run = DiscoveryRun(source=source_mode, source_ref=source.describe(), actor=actor)
    session.add(run)
    session.flush()
    record_event(session, "DISCOVERY_STARTED", actor, detail={"run_id": run.id, "source": run.source_ref})
    session.commit()

    try:
        _discover(session, run, source, settings, now)
        if settings.okta_tenant_enabled:
            _discover_tenant(session, run, source)
        session.flush()
        risk.score_all(session, risk.load_weights(settings.risk_weights_file))
        from app.strategy_model import service as strategy_model
        strategy_model.analyse(session, settings)
        run.status = "SUCCESS"
        run.finished_at = utcnow()
        record_event(session, "DISCOVERY_COMPLETED", actor, detail={
            "run_id": run.id, "apps_total": run.apps_total, "saml_apps": run.saml_apps, "oidc_apps": run.oidc_apps,
            "new": run.new_apps, "changed": run.changed_apps, "removed": run.removed_apps})
        session.commit()
    except Exception as exc:
        session.rollback()
        run = session.get(DiscoveryRun, run.id)
        run.status = "FAILED"
        run.error = f"{type(exc).__name__}: {exc}"[:2000]
        run.finished_at = utcnow()
        record_event(session, "DISCOVERY_FAILED", actor, detail={"run_id": run.id, "error": run.error})
        session.commit()
        log.exception("Discovery run %s failed", run.id)
        raise
    return run


def _discover(session: Session, run: DiscoveryRun, source: OktaSource, settings: Settings,
              now: datetime) -> None:
    raw_apps = source.list_apps()
    raw_groups = source.list_groups()
    _snapshot(session, run, "groups", raw_groups)

    # --- groups (full replace; groups are tenant-wide reference data) -------
    groups = [parser.parse_group(g) for g in raw_groups]
    groups_by_id = {g.id: g for g in groups}
    group_names = [g.name for g in groups]
    existing_groups = {g.id: g for g in session.scalars(select(Group))}
    for g in groups:
        row = existing_groups.pop(g.id, None) or Group(id=g.id)
        row.name, row.description, row.group_type = g.name, g.description, g.group_type
        row.source_app, row.member_count = g.source_app, g.member_count
        session.add(row)
    for stale in existing_groups.values():
        session.delete(stale)

    seen_ids: set[str] = set()
    known = {a.id: a for a in session.scalars(select(Application))}
    parsed = [(raw, parser.parse_app(raw)) for raw in raw_apps]

    # PingFederate keys SP connections on the partner entity ID: find collisions.
    by_entity: dict[str, list[str]] = {}
    for _, m in parsed:
        if m.is_saml and m.saml and m.saml.audience:
            by_entity.setdefault(m.saml.audience, []).append(m.label)
    amap = pfmap.attribute_map(settings.pf_directory_type, settings.pf_attribute_map_file)
    pf_ctx = {"by_entity": by_entity, "amap": amap, "groups_by_name": {g.name: g for g in groups}}

    for raw, model in parsed:
        seen_ids.add(model.id)
        run.apps_total += 1
        digest = _snapshot(session, run, "app", raw, model.id)

        row = known.get(model.id)
        is_new = row is None
        if is_new:
            row = Application(id=model.id, first_seen_run_id=run.id)
            session.add(row)
            run.new_apps += 1
        changed = (not is_new) and row.raw_sha256 is not None and row.raw_sha256 != digest
        if changed:
            run.changed_apps += 1
        _apply_app_fields(row, model)
        row.raw_sha256 = digest
        row.last_seen_run_id = run.id
        row.removed_from_okta = False
        row.changed_in_last_run = changed
        session.flush()

        if is_new:
            record_event(session, "APP_DISCOVERED", run.actor, model.id,
                         {"run_id": run.id, "label": model.label, "sign_on_mode": model.sign_on_mode})
        elif changed:
            record_event(session, "APP_CONFIG_CHANGED", run.actor, model.id, {"run_id": run.id})

        if model.is_saml:
            run.saml_apps += 1
            _discover_saml_details(session, run, source, settings, row, model, raw,
                                   groups_by_id, group_names, changed, now, pf_ctx)
        elif model.is_oidc:
            run.oidc_apps = (run.oidc_apps or 0) + 1
            _discover_oidc_details(session, run, source, settings, row, model, groups_by_id, changed, now)
        else:
            _clear_children(session, row.id)

    for app_id, row in known.items():
        if app_id not in seen_ids and not row.removed_from_okta:
            row.removed_from_okta = True
            run.removed_apps += 1
            record_event(session, "APP_REMOVED_FROM_OKTA", run.actor, app_id, {"run_id": run.id})


def _apply_app_fields(row: Application, m: AppModel) -> None:
    row.label, row.okta_name, row.sign_on_mode = m.label, m.okta_name, m.sign_on_mode
    row.okta_status, row.is_saml, row.is_custom_saml = m.okta_status, m.is_saml, m.is_custom_saml
    row.is_oidc = m.is_oidc
    row.okta_created, row.okta_last_updated = m.created, m.last_updated
    row.user_name_template = m.user_name_template
    row.okta_features = list(m.okta_features)
    row.access_policy_id = m.access_policy_id


def _clear_children(session: Session, app_id: str) -> None:
    for model in (Claim, Assignment, Certificate, Finding):
        session.execute(delete(model).where(model.app_id == app_id))
    session.execute(delete(SamlConfiguration).where(SamlConfiguration.app_id == app_id))
    session.execute(delete(OidcConfiguration).where(OidcConfiguration.app_id == app_id))


def _discover_oidc_details(session, run, source, settings, row, model, groups_by_id, changed, now) -> None:
    """OIDC apps: client settings + assignments. Authorization-server scopes and
    claims are analysed in the next sprint."""
    raw_app_groups = source.list_app_groups(model.id)
    raw_app_users = source.list_app_users(model.id)
    _snapshot(session, run, "app_groups", raw_app_groups, model.id)
    _snapshot(session, run, "app_users", raw_app_users, model.id)
    app_groups = [parser.parse_app_group(g) for g in raw_app_groups]
    app_users = [parser.parse_app_user(u) for u in raw_app_users]

    _clear_children(session, model.id)
    session.flush()
    o = model.oidc
    session.add(OidcConfiguration(app_id=model.id, **o.model_dump()))
    _store_assignments(session, settings, row, model, app_groups, app_users, groups_by_id)

    usage = _collect_usage(session, run, source, settings, row, model)
    ctx = rules.AppContext(app=model, app_users=app_users, app_groups=app_groups,
                           groups_by_id=groups_by_id, certificates=[], group_matches={},
                           changed_since_last_run=changed, usage=usage)
    for f in rules.evaluate(ctx, now, settings.cert_expiry_warning_days, settings.pf_ognl_allowed):
        session.add(Finding(app_id=model.id, run_id=run.id, code=f.code, severity=f.severity,
                            message=f.message, detail=f.detail))


def _collect_usage(session, run, source, settings, row, model) -> dict | None:
    if not settings.okta_usage_enabled:
        return None
    try:
        events = source.list_app_usage_events(model.id, settings.okta_usage_days, settings.okta_usage_max_events)
    except UsageUnavailable:
        row.usage_known = False
        return None
    u = parser.summarise_usage(events)
    row.usage_known, row.usage_window_days = True, settings.okta_usage_days
    row.usage_events, row.usage_unique_users, row.usage_last_seen = u["events"], u["unique_users"], u["last_seen"]
    row.usage_capped = len(events) >= settings.okta_usage_max_events
    return {**u, "days": settings.okta_usage_days}


def _store_assignments(session, settings, row, model, app_groups, app_users, groups_by_id) -> None:
    for ag in app_groups:
        g = groups_by_id.get(ag.group_id)
        session.add(Assignment(app_id=model.id, principal_type="GROUP", principal_id=ag.group_id,
                               principal_name=g.name if g else None, priority=ag.priority,
                               app_profile=ag.profile))
    for u in app_users:
        if settings.store_user_details:
            user = session.get(User, u.user_id) or User(id=u.user_id)
            user.login, user.email, user.status = u.login, u.email, u.status
            session.add(user)
            session.add(Assignment(app_id=model.id, principal_type="USER", principal_id=u.user_id,
                                   principal_name=u.login or u.app_username, scope=u.scope,
                                   app_username=u.app_username, app_profile=u.profile))
    row.user_count = len(app_users)
    row.direct_user_count = sum(1 for u in app_users if (u.scope or "").upper() == "USER")
    row.group_count = len(app_groups)


def _discover_saml_details(session, run, source, settings, row, model, raw_app,
                           groups_by_id, group_names, changed, now, pf_ctx) -> None:
    raw_app_groups = source.list_app_groups(model.id)
    raw_app_users = source.list_app_users(model.id)
    raw_keys = source.list_app_keys(model.id)
    metadata_xml = source.get_app_metadata(raw_app)
    _snapshot(session, run, "app_groups", raw_app_groups, model.id)
    _snapshot(session, run, "app_users", raw_app_users, model.id)
    _snapshot(session, run, "keys", raw_keys, model.id)
    if metadata_xml:
        _snapshot(session, run, "metadata", metadata_xml, model.id)

    app_groups = [parser.parse_app_group(g) for g in raw_app_groups]
    app_users = [parser.parse_app_user(u) for u in raw_app_users]
    certs = [parser.parse_key(k) for k in raw_keys]
    md = parser.parse_metadata(metadata_xml)

    _clear_children(session, model.id)
    session.flush()

    s = model.saml
    amap, directory = pf_ctx["amap"], settings.pf_directory_type
    nameid_src = pfmap.classify_nameid(s.name_id_template, model.user_name_template, amap)
    session.add(SamlConfiguration(
        app_id=model.id, config_completeness=s.config_completeness,
        sso_acs_url=s.sso_acs_url, recipient=s.recipient, destination=s.destination,
        audience=s.audience, idp_issuer=s.idp_issuer, sp_issuer=s.sp_issuer,
        default_relay_state=s.default_relay_state, name_id_template=s.name_id_template,
        name_id_format=s.name_id_format, response_signed=s.response_signed,
        assertion_signed=s.assertion_signed, signature_algorithm=s.signature_algorithm,
        digest_algorithm=s.digest_algorithm, authn_context_class_ref=s.authn_context_class_ref,
        honor_force_authn=s.honor_force_authn, request_compressed=s.request_compressed,
        assertion_lifetime_seconds=s.assertion_lifetime_seconds,
        allow_multiple_acs=s.allow_multiple_acs,
        acs_endpoints=[e.model_dump() for e in s.acs_endpoints],
        slo_enabled=s.slo_enabled, slo_issuer=s.slo_issuer, slo_logout_url=s.slo_logout_url,
        sp_certificate_present=s.sp_certificate_present,
        catalog_app_settings=s.catalog_app_settings,
        metadata_xml=metadata_xml, metadata_entity_id=md.entity_id, metadata_sso_url=md.sso_url,
        pf_nameid_source=nameid_src.kind, pf_nameid_detail=nameid_src.detail,
    ))

    group_matches: dict[int, list[str]] = {}
    okta_native: dict[int, list[str]] = {}
    claim_sources: dict[int, pfmap.PfSource] = {}
    for c in s.claims:
        matched = None
        native: list[str] = []
        if c.claim_type == "GROUP":
            matched = parser.match_group_filter(c.group_filter_type, c.group_filter_value, group_names)
            group_matches[c.position] = matched
            native = [n for n in matched if pf_ctx["groups_by_name"][n].group_type == "OKTA_GROUP"]
            okta_native[c.position] = native
        src = pfmap.classify_claim(c, amap, directory)
        claim_sources[c.position] = src
        session.add(Claim(
            app_id=model.id, position=c.position, name=c.name, namespace=c.namespace,
            claim_type=c.claim_type, values=c.values,
            expression_kind=c.analysis.kind if c.analysis else None,
            source_attributes=c.analysis.source_attributes if c.analysis else [],
            functions_used=c.analysis.functions_used if c.analysis else [],
            group_filter_type=c.group_filter_type, group_filter_value=c.group_filter_value,
            matched_group_count=len(matched) if matched is not None else None,
            matched_group_sample=(matched or [])[:50],
            matched_okta_native_groups=native,
            pf_source=src.kind, pf_source_detail=src.detail,
            pf_ldap_attributes=src.ldap_attributes, pf_missing_inputs=src.unmapped,
        ))

    for ag in app_groups:
        g = groups_by_id.get(ag.group_id)
        session.add(Assignment(app_id=model.id, principal_type="GROUP", principal_id=ag.group_id,
                               principal_name=g.name if g else None, priority=ag.priority,
                               app_profile=ag.profile))
    for u in app_users:
        if settings.store_user_details:
            user = session.get(User, u.user_id) or User(id=u.user_id)
            user.login, user.email, user.status = u.login, u.email, u.status
            session.add(user)
            session.add(Assignment(app_id=model.id, principal_type="USER", principal_id=u.user_id,
                                   principal_name=u.login or u.app_username, scope=u.scope,
                                   app_username=u.app_username, app_profile=u.profile))
    for cm in certs:
        session.add(Certificate(
            app_id=model.id, kid=cm.kid, is_active_signing_key=(cm.kid == model.active_signing_kid),
            subject=cm.subject, issuer=cm.issuer, not_before=cm.not_before, not_after=cm.not_after,
            sha1_thumbprint=cm.sha1_thumbprint, sha256_thumbprint=cm.sha256_thumbprint,
            key_size=cm.key_size, x5c=cm.x5c))

    row.user_count = len(app_users)
    row.direct_user_count = sum(1 for u in app_users if (u.scope or "").upper() == "USER")
    row.group_count = len(app_groups)

    usage = _collect_usage(session, run, source, settings, row, model)
    ctx = rules.AppContext(app=model, app_users=app_users, app_groups=app_groups,
                           groups_by_id=groups_by_id, certificates=certs, usage=usage,
                           group_matches=group_matches, changed_since_last_run=changed,
                           claim_sources=claim_sources, okta_native_matches=okta_native,
                           nameid_source=nameid_src,
                           apps_sharing_entity_id=[l for l in pf_ctx["by_entity"].get(s.audience or "", [])
                                                   if l != model.label] if s.audience else [])
    for f in rules.evaluate(ctx, now, settings.cert_expiry_warning_days, settings.pf_ognl_allowed):
        session.add(Finding(app_id=model.id, run_id=run.id, code=f.code, severity=f.severity,
                            message=f.message, detail=f.detail))


def _discover_tenant(session: Session, run: DiscoveryRun, source: OktaSource) -> None:
    """Tenant-level objects. A kind that cannot be read (missing scope, not exported, not in this Okta
    edition) is recorded as such and its previous rows are KEPT: "could not read" never means "none"."""
    apps = list(session.scalars(select(Application).where(Application.removed_from_okta.is_(False))))
    by_client = {a.oidc.client_id: a.id for a in apps if a.is_oidc and a.oidc and a.oidc.client_id}
    by_policy: dict[str, list[str]] = {}
    for a in apps:
        if a.access_policy_id:
            by_policy.setdefault(a.access_policy_id, []).append(a.id)
    list_tenant = getattr(source, "list_tenant", None)
    for kind in TENANT_KINDS:
        if list_tenant is None:
            session.add(TenantScan(run_id=run.id, kind=kind, status="NOT_EXPORTED", error="Source has no tenant data"))
            continue
        try:
            raw_items = list_tenant(kind)
        except TenantUnavailable as exc:
            session.add(TenantScan(run_id=run.id, kind=kind, status=exc.status, error=str(exc)[:500]))
            continue
        session.execute(delete(TenantObject).where(TenantObject.kind == kind))
        session.flush()
        _snapshot(session, run, f"tenant:{kind}", raw_items)
        if kind == "authorization_servers":
            for a in apps:
                a.auth_server_id = None
        for raw in raw_items:
            m = parser.parse_tenant_object(kind, raw)
            app_ids: list[str] = []
            attrs = dict(m.attributes)
            if kind == "policies" and m.subtype == "ACCESS_POLICY":
                app_ids = by_policy.get(m.okta_id, [])
            if kind == "authorization_servers":
                app_ids = [by_client[c] for c in m.client_ids if c in by_client]
                if attrs.get("applies_to_all_clients"):
                    # Any OIDC client may use it; which ones actually do is not visible in Okta's configuration.
                    attrs["possible_app_ids"] = [aid for aid in by_client.values() if aid not in app_ids]
                for aid in app_ids:
                    app = session.get(Application, aid)
                    app.auth_server_id = app.auth_server_id or m.okta_id
            session.add(TenantObject(kind=kind, okta_id=m.okta_id, name=m.name, subtype=m.subtype, status=m.status,
                                     attributes=attrs, app_ids=app_ids, run_id=run.id))
        session.add(TenantScan(run_id=run.id, kind=kind, status="OK", count=len(raw_items)))
    record_event(session, "TENANT_DISCOVERED", run.actor, detail={"run_id": run.id})
