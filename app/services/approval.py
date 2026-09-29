"""Per-app migration plan: generate -> submit -> approve / reject.

The plan freezes, for one app, everything later steps rely on: the PingFederate
SP connection payload (exactly what may be written), directory prep, the
validation expectations, the cutover/rollback values and the agent review.
It is hashed. Approval needs a named person and, by default, a second person
(four-eyes). If Okta changed since the plan was generated, approval is refused.
"""
from __future__ import annotations

import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.db import Application, MigrationPlan, utcnow
from app.models.state import MigrationState
from app.services import build_package as bpk
from app.services import risk
from app.services.readiness import pf_readiness
from app.services.state_service import record_event, transition

S = MigrationState
PLANNABLE = {S.MAPPING_READY.value, S.PLAN_GENERATED.value, S.REJECTED.value, S.OKTA_ACTIVE.value}
_BAD_ACTORS = {"system", "ai", "claude"}


def _hash(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def _named(actor: str) -> str:
    actor = (actor or "").strip()
    if not actor or actor.lower() in _BAD_ACTORS:
        raise ValueError("A named person is required")
    return actor


def _choice(session: Session, key: str) -> str:
    from app.models.db import Decision
    d = session.get(Decision, key)
    return (d.choice or "") if d and d.status == "DECIDED" else ""


def ognl_allowed(session: Session, settings: Settings) -> bool:
    return settings.pf_ognl_allowed or _choice(session, "OGNL_POLICY").startswith("Allow")


def current_package(session: Session, app: Application, settings: Settings) -> bpk.Package:
    return bpk.sp_connection(app, settings, ognl_allowed(session, settings))


def latest_plan(session: Session, app_id: str) -> MigrationPlan | None:
    return session.scalars(select(MigrationPlan).where(MigrationPlan.app_id == app_id)
                           .order_by(MigrationPlan.id.desc()).limit(1)).first()


def approved_plan(session: Session, app_id: str) -> MigrationPlan | None:
    return session.scalars(select(MigrationPlan).where(MigrationPlan.app_id == app_id, MigrationPlan.status == "APPROVED")
                           .order_by(MigrationPlan.id.desc()).limit(1)).first()


def _cutover_date(session: Session, app: Application):
    from app.services import estimate
    from app.services.plan import plan_apps
    try:
        tl = estimate.build_timeline(session, plan_apps(session))
        wave = estimate.effective_wave(app)
        d = tl.cutover.get(wave)
        return d.strftime("%Y-%m-%d") if d else None
    except Exception:  # timeline is advisory
        return None


def generate(session: Session, app: Application, settings: Settings, actor: str) -> MigrationPlan:
    actor = _named(actor)
    if not app.is_saml or app.saml is None:
        raise ValueError("Plans are generated for SAML apps")
    if app.state not in PLANNABLE:
        raise ValueError(f"App is in {app.state}; accept the agent review first (MAPPING_READY)")
    score = risk.score_app(session, app, risk.load_weights(settings.risk_weights_file))
    if score and score.blocked:
        raise ValueError("App is blocked by: " + ", ".join(score.blockers) + ". Resolve the decisions first.")
    from app.services.agents.service import latest_run
    from app.services.cutover import expected_values, rollback_values
    run = latest_run(session, app.id)
    pkg = current_package(session, app, settings)
    r = pf_readiness(app)
    plan = {
        "app": {"id": app.id, "label": app.label, "wave": app.wave or app.suggested_wave,
                "business_owner": app.business_owner, "assigned_users": app.user_count},
        "risk": None if score is None else {"rules_version": score.rules_version, "overall": score.overall_level,
                                            "complexity": score.complexity_level, "impact": score.impact_level},
        "agent_review": None if run is None else {"run_id": run.id, "status": run.review_status,
                                                  "reviewed_by": run.reviewed_by, "resolutions": run.resolutions},
        "pingfederate": {"kind": pkg.kind, "payload": pkg.payload, "todos": pkg.todos, "variables": pkg.variables},
        "directory_prep": {"okta_only_groups": r["okta_only_groups"], "missing_inputs": r["missing_inputs"],
                           "access_group": bpk.access_group(app) if r["issuance_criteria"] else None},
        "validation": expected_values(app, settings),
        "rollback": rollback_values(app, settings),
        "cutover_date": _cutover_date(session, app),
    }
    prev = latest_plan(session, app.id)
    for p in session.scalars(select(MigrationPlan).where(MigrationPlan.app_id == app.id,
                                                          MigrationPlan.status.in_(["DRAFT", "SUBMITTED"]))):
        p.status = "SUPERSEDED"
    row = MigrationPlan(app_id=app.id, version=(prev.version + 1) if prev else 1, plan=plan, status="DRAFT",
                        sha256=_hash(plan), payload_sha256=_hash(pkg.payload), generated_by=actor)
    session.add(row)
    session.flush()
    if app.state != S.PLAN_GENERATED.value:
        transition(session, app, S.PLAN_GENERATED, actor, reason=f"Plan v{row.version} generated",
                   detail={"plan_id": row.id, "sha256": row.sha256})
    else:
        record_event(session, "PLAN_REGENERATED", actor, app.id, {"plan_id": row.id, "version": row.version})
    return row


def submit(session: Session, plan: MigrationPlan, actor: str) -> None:
    actor = _named(actor)
    if plan.status != "DRAFT":
        raise ValueError(f"Plan is {plan.status.lower()}; only a draft can be submitted")
    app = session.get(Application, plan.app_id)
    if app.state != S.PLAN_GENERATED.value:
        raise ValueError(f"App is in {app.state}")
    plan.status, plan.submitted_by, plan.submitted_at = "SUBMITTED", actor, utcnow()
    transition(session, app, S.AWAITING_APPROVAL, actor, reason=f"Plan v{plan.version} submitted for approval",
               detail={"plan_id": plan.id})


def drift(session: Session, plan: MigrationPlan, settings: Settings) -> bool:
    """True if Okta (or a decision) changed since the plan was generated."""
    app = session.get(Application, plan.app_id)
    return _hash(current_package(session, app, settings).payload) != plan.payload_sha256


def decide(session: Session, plan: MigrationPlan, settings: Settings, actor: str, decision: str, comment: str = "") -> None:
    actor = _named(actor)
    if decision not in ("APPROVED", "REJECTED"):
        raise ValueError("Decision must be APPROVED or REJECTED")
    if plan.status != "SUBMITTED":
        raise ValueError(f"Plan is {plan.status.lower()}; only a submitted plan can be decided")
    if settings.approval_four_eyes and actor.lower() in {(plan.submitted_by or "").lower(), (plan.generated_by or "").lower()}:
        raise ValueError("Four-eyes rule: the approver must be a different person from who generated or submitted the plan")
    if decision == "REJECTED" and not comment.strip():
        raise ValueError("A comment is required when rejecting")
    if decision == "APPROVED" and drift(session, plan, settings):
        raise ValueError("Okta configuration or a decision changed since this plan was generated. Regenerate it.")
    app = session.get(Application, plan.app_id)
    plan.status, plan.decided_by, plan.decided_at, plan.decision_comment = decision, actor, utcnow(), comment or None
    transition(session, app, S(decision), actor, reason=comment or f"Plan v{plan.version} {decision.lower()}",
               detail={"plan_id": plan.id, "sha256": plan.sha256})
