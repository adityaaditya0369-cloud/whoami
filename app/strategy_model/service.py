"""Strategy model orchestration: run the engine over the inventory, and assemble the
Migration Strategy Pack (executive, architect and engineer views) from stored results."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.db import Application, Dependency, StrategyOverride, TenantObject, TenantScan, utcnow
from app.services import risk
from app.services.state_service import record_event
from app.strategy_model import dependencies as dg
from app.strategy_model import engine, waves
from app.strategy_model.catalog import CATALOG_VERSION, STRATEGIES, TARGET, load_catalog

STRATEGY_HELP = {
    "RECREATE": "Rebuild the same configuration in PingFederate",
    "TRANSFORM": "Rebuild with mapping rules (expressions, groups, attributes, grants)",
    "REDESIGN": "No direct equivalent: architecture review and a new design",
    "RETIRE": "Stop using it after business validation",
    "RETAIN": "Keep on Okta for now (coexistence), migrate later",
}


def _apps(session: Session) -> list[Application]:
    return list(session.scalars(select(Application).where(Application.removed_from_okta.is_(False))
                                .order_by(Application.label)))


def active_override(session: Session, app_id: str) -> StrategyOverride | None:
    return session.scalars(select(StrategyOverride).where(StrategyOverride.app_id == app_id,
                                                          StrategyOverride.active.is_(True))
                           .order_by(StrategyOverride.id.desc()).limit(1)).first()


def policies_by_id(session: Session) -> dict[str, TenantObject]:
    return {o.okta_id: o for o in session.scalars(select(TenantObject).where(TenantObject.kind == "policies"))}


def analyse(session: Session, settings: Settings, actor: str = "system") -> dict:
    """Recompute features, compatibility and strategy for every app and tenant object."""
    catalog = load_catalog(settings.capability_catalog_file)
    pols = policies_by_id(session)
    counts: Counter = Counter()
    for o in session.scalars(select(TenantObject)):
        d = engine.decide_tenant(o, catalog)
        o.strategy, o.compat_level, o.strategy_reasons = d.strategy, d.compat_level, d.reasons
    for a in _apps(session):
        d = engine.decide_app(a, catalog, pols, active_override(session, a.id))
        a.strategy, a.compat_level, a.strategy_reasons = d.strategy, d.compat_level, d.reasons
        counts[d.strategy] += 1
    dg.refresh_discovered(session)
    session.flush()
    record_event(session, "STRATEGY_ANALYSED", actor, detail={"catalog": CATALOG_VERSION, "rules": risk.RULES_VERSION,
                                                              **{k: v for k, v in counts.items() if k}})
    return dict(counts)


def ensure_analysed(session: Session, settings: Settings) -> bool:
    """Databases from an earlier version (or apps added since) have no strategy yet: analyse once."""
    if any(a.strategy is None for a in _apps(session)):
        analyse(session, settings)
        return True
    return False


def set_override(session: Session, settings: Settings, app: Application, strategy: str, reason: str, actor: str) -> None:
    actor = (actor or "").strip()
    if not actor or actor.lower() in {"system", "ai", "claude"}:
        raise ValueError("A named architect is required")
    if not reason.strip():
        raise ValueError("A reason is required for an architecture exception")
    for o in session.scalars(select(StrategyOverride).where(StrategyOverride.app_id == app.id,
                                                            StrategyOverride.active.is_(True))):
        o.active = False
    if strategy != "RULES":
        if strategy not in STRATEGIES:
            raise ValueError("Unknown strategy")
        session.add(StrategyOverride(app_id=app.id, strategy=strategy, reason=reason.strip(), actor=actor))
    session.flush()
    record_event(session, "STRATEGY_OVERRIDE", actor, app.id, {"strategy": strategy, "reason": reason.strip()})
    analyse(session, settings, actor)


# --- the pack ---------------------------------------------------------------------------
@dataclass
class AppRow:
    app: Application
    strategy: str | None
    compat: str | None
    reasons: list[dict]
    hits: list
    prerequisites: list
    wave: str
    base_wave: str
    wave_reasons: list[str]
    flags: list[str]
    depends_on: list[tuple[str, str]]      # (label, kind)
    depended_by: list[tuple[str, str]]
    factors: dict[str, int]
    complexity: str
    risk: str
    effort_hours: float
    overridden: bool
    validation: list[str] = field(default_factory=list)


@dataclass
class StrategyPack:
    generated: object
    target: str
    catalog_version: str
    rules_version: str
    apps: list[AppRow]
    tenant: list[dict]
    scans: list[TenantScan]
    matrix: list[dict]
    deps: list[dict]
    suggested: list[dict]
    summary: dict
    waves: dict[str, list[AppRow]]
    foundation: list[dict]
    timeline: object
    catalog: dict


def validation_checklist(a: Application, row_deps: list[str]) -> list[str]:
    """Deterministic test cases per app; AI may add to these in review, never remove them."""
    t: list[str] = []
    if a.is_saml and a.saml:
        s = a.saml
        t.append("SP-initiated sign-in succeeds")
        t.append("IdP-initiated sign-in succeeds" + (" and lands on the default relay state" if s.default_relay_state else ""))
        t.append("NameID value matches the Okta baseline for the same test user")
        t += [f"Attribute '{c.name}' present and correct" for c in a.claims if c.claim_type != "GROUP"][:8]
        if any(c.claim_type == "GROUP" for c in a.claims):
            t.append("Group attribute contains the expected groups; authorization in the app is unchanged")
        if s.slo_enabled:
            t.append("Single logout ends the session at the SP and at PingFederate")
        if len(s.acs_endpoints or []) > 1:
            t.append("Every ACS URL is accepted (one test per endpoint)")
        t.append("SP accepts the PingFederate signing certificate")
    elif a.is_oidc and a.oidc:
        o = a.oidc
        grants = o.grant_types or []
        if "client_credentials" in grants and len(grants) == 1:
            t.append("Client credentials token is issued with the expected scopes and audience")
        else:
            t.append("Authorization-code sign-in succeeds" + (" with PKCE enforced" if o.pkce_required else ""))
            t.append("ID token claims (sub, email, groups) match the Okta baseline")
        if "refresh_token" in grants:
            t.append("Refresh token flow works and respects the new lifetime")
        if o.post_logout_redirect_uris:
            t.append("Logout redirects to the registered post-logout URI")
        if a.auth_server_id:
            t.append("API accepts access tokens from the new access token manager (audience, scopes, claims)")
    if a.access_policy_id:
        t.append("Sign-in policy behaves as designed (MFA prompts, network and device conditions)")
    if any(f.startswith("PUSH_") for f in (a.okta_features or [])):
        t.append("Provisioning: create, update and deactivate a test user")
    t += [f"Validate dependency: {d}" for d in row_deps]
    return t


def _latest_scans(session: Session) -> list[TenantScan]:
    from sqlalchemy import func
    last = session.scalar(select(func.max(TenantScan.run_id)))
    return list(session.scalars(select(TenantScan).where(TenantScan.run_id == last).order_by(TenantScan.kind))) if last else []


def build_pack(session: Session, settings: Settings) -> StrategyPack:
    from app.services import estimate
    catalog = load_catalog(settings.capability_catalog_file)
    pols = policies_by_id(session)
    apps = _apps(session)
    deps_all = list(session.scalars(select(Dependency)))
    conf = [d for d in deps_all if d.status == "CONFIRMED"]
    labels = dg.label_map(session)
    placements = waves.plan([a for a in apps if a.in_scope_protocol], conf)

    rows: list[AppRow] = []
    for a in apps:
        d = engine.decide_app(a, catalog, pols, active_override(session, a.id))
        node = dg.app_node(a.id)
        on, by = dg.edges_for(conf, node)
        rs = risk.latest_score(session, a.id)
        p = placements.get(a.id)
        base = a.wave or a.suggested_wave or "—"
        if p is None:   # not SAML/OIDC: its own track (WS-Fed, password vaulting, bookmarks...)
            wave = {"RETIRE": "Decommission review", "REDESIGN": "Redesign track", "RETAIN": "Blocked",
                    "RECREATE": "Other protocols track", "TRANSFORM": "Other protocols track"}.get(a.strategy or "",
                                                                                         "Not yet assessed")
            p = waves.Placement(wave, base)
        est = estimate.app_effort(a) if a.in_scope_protocol else None
        rows.append(AppRow(
            app=a, strategy=a.strategy, compat=a.compat_level, reasons=a.strategy_reasons or [], hits=d.hits,
            prerequisites=d.prerequisites, wave=p.wave, base_wave=p.base, wave_reasons=p.reasons, flags=p.flags,
            depends_on=[(dg.label(x.target, labels), x.kind) for x in on],
            depended_by=[(dg.label(x.source, labels), x.kind) for x in by],
            factors=engine.complexity_breakdown(rs.breakdown if rs else [], len(on) + len(by)),
            complexity=engine.LEVEL_LABEL.get(a.complexity_level or "", "—"),
            risk=engine.LEVEL_LABEL.get(a.overall_level or "", "—"),
            effort_hours=est.total if est else sum(catalog[h.key].effort_hours for h in d.hits if h.key in catalog),
            overridden=any(r.get("rule") == "OVERRIDE" for r in (a.strategy_reasons or [])),
            validation=validation_checklist(a, [dg.label(x.target, labels) for x in on if x.target.startswith(("app:", "ext:"))]
                                            + [dg.label(x.source, labels) for x in by if x.source.startswith(("app:", "ext:"))])))

    tenant = []
    for o in session.scalars(select(TenantObject).order_by(TenantObject.kind, TenantObject.name)):
        hits = engine.tenant_hits(o)
        cap = catalog.get(hits[0].key) if hits else None
        tenant.append({"obj": o, "hits": hits, "cap": cap, "hours": sum(catalog[h.key].effort_hours for h in hits if h.key in catalog),
                       "apps": [labels.get(dg.app_node(x), x) for x in (o.app_ids or [])]})

    # compatibility matrix: one row per catalog feature that occurs
    use: dict[str, dict] = {}
    for r in rows:
        for h in r.hits + r.prerequisites:
            u = use.setdefault(h.key, {"apps": [], "objects": [], "evidence": h.evidence})
            u["apps"].append(r.app.label)
    for t in tenant:
        for h in t["hits"]:
            u = use.setdefault(h.key, {"apps": [], "objects": [], "evidence": h.evidence})
            u["objects"].append(t["obj"].name)
    matrix = []
    for key, cap in catalog.items():
        if key in use:
            matrix.append({"cap": cap, "apps": sorted(set(use[key]["apps"])), "objects": sorted(set(use[key]["objects"])),
                           "example": use[key]["evidence"]})
    order = {"NONE": 0, "PARTIAL": 1, "EQUIVALENT": 2}
    matrix.sort(key=lambda m: (order[m["cap"].compatibility], m["cap"].area, m["cap"].key))

    dep_rows = [{"dep": x, "source": dg.label(x.source, labels), "target": dg.label(x.target, labels)}
                for x in deps_all if x.status != "SUGGESTED"]
    suggested = [{"dep": x, "source": dg.label(x.source, labels), "target": dg.label(x.target, labels)}
                 for x in deps_all if x.status == "SUGGESTED"]

    in_scope = [r for r in rows if r.app.in_scope_protocol]
    by_wave: dict[str, list[AppRow]] = {}
    for r in rows:
        by_wave.setdefault(r.wave, []).append(r)
    wave_names = [w for w in estimate.WAVE_ORDER if w in by_wave] + \
                 [w for w in ("Other protocols track", "Redesign track", "Decommission review", "Not yet assessed")
                  if w in by_wave]
    by_wave = {w: by_wave[w] for w in wave_names}

    foundation = [t for t in tenant if t["cap"] is not None and t["obj"].strategy in ("REDESIGN", "TRANSFORM", "RECREATE")
                  and t["cap"].prerequisite]
    foundation_hours = round(sum(t["hours"] for t in foundation), 1)
    timeline = estimate.build_timeline(session, [r.app for r in in_scope],
                                       waves_override={r.app.id: r.wave for r in in_scope},
                                       foundation_hours=foundation_hours)
    strat = Counter(r.strategy for r in rows)
    summary = {
        "total": len(rows), "federated": len(in_scope),
        "migratable": strat["RECREATE"] + strat["TRANSFORM"],
        "recreate": strat["RECREATE"], "transform": strat["TRANSFORM"], "redesign": strat["REDESIGN"],
        "retire": strat["RETIRE"], "retain": strat["RETAIN"],
        "high_risk": sum(1 for r in in_scope if (r.app.overall_level or "") in ("HIGH", "CRITICAL")),
        "waves": sum(1 for w in by_wave if w.startswith("Wave")),
        "tenant_objects": len(tenant), "tenant_redesign": sum(1 for t in tenant if t["obj"].strategy == "REDESIGN"),
        "foundation_hours": foundation_hours,
        "app_hours": round(timeline.total_hours - timeline.prep_hours, 1), "end": timeline.end,
        "unassessed": strat[None],
        "unscanned": [sc.kind for sc in _latest_scans(session) if sc.status != "OK"],
        "deps_confirmed": len(conf), "deps_suggested": len(suggested),
        "compat": Counter(r.compat for r in rows if r.compat),
        "moved_by_deps": sum(1 for r in rows if any("depends on" in x for x in r.wave_reasons)),
        "expert_rows": sum(1 for m in matrix if m["cap"].review == "EXPERT"),
    }
    return StrategyPack(generated=utcnow(), target=TARGET, catalog_version=CATALOG_VERSION,
                        rules_version=risk.RULES_VERSION, apps=rows, tenant=tenant,
                        scans=_latest_scans(session),
                        matrix=matrix, deps=dep_rows, suggested=suggested, summary=summary, waves=by_wave,
                        foundation=foundation, timeline=timeline, catalog=catalog)
