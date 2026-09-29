"""Migration plan: a fixed 7-step checklist per in-scope app, grouped by wave.

The checklist is for tracking people's work. It does not change the app's
migration state (that stays behind the approval workflow). Every update is
written to the audit log.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db import Application, MigrationTask, utcnow
from app.services.state_service import record_event

STEP_STATUSES = ["NOT_STARTED", "IN_PROGRESS", "DONE", "BLOCKED", "N/A"]
WAVE_ORDER = ["Wave 0 (pilot)", "Wave 1", "Wave 2", "Wave 3 (high impact)", "Blocked", "Decommission review"]


@dataclass(frozen=True)
class Step:
    key: str
    title: str
    owner: str        # default owning team
    help_saml: str
    help_oidc: str


STEPS: list[Step] = [
    Step("PREPARE", "Prepare directory & decisions", "Directory team",
         "Create Okta-only groups, add missing attributes, settle OGNL / duplicate entity ID decisions.",
         "Create Okta-only groups; agree scopes and claims; decide on implicit / password grants."),
    Step("BUILD", "Build in PingFederate", "IAM team",
         "Create the SP connection: ACS URLs, attribute contract, signing, issuance criteria.",
         "Create the OAuth client: client ID, redirect URIs, grants, client authentication, OIDC policy."),
    Step("PILOT", "Test with pilot users", "IAM team",
         "Pilot users sign in through PingFederate; compare the assertion with Okta's.",
         "Pilot users sign in; compare ID / access token claims with Okta's."),
    Step("SP_UPDATE", "Update the SP / app", "App owner",
         "Give the SP PingFederate's metadata (entity ID, SSO URL, signing certificate).",
         "Point the app at PingFederate's issuer / discovery URL; deploy the new client secret if any."),
    Step("CUTOVER", "Cutover", "IAM team + App owner",
         "Switch production sign-in to PingFederate in the agreed change window.",
         "Switch production to PingFederate; users sign in again once (refresh tokens don't move)."),
    Step("VERIFY", "Verify", "App owner",
         "Confirm sign-in, roles and group access for real users; watch for errors for a few days.",
         "Confirm sign-in, API calls and token refresh for real users."),
    Step("DECOMMISSION", "Remove from Okta", "IAM team",
         "Deactivate, then delete the Okta app after the rollback window closes.",
         "Deactivate, then delete the Okta app after the rollback window closes."),
]
STEP_BY_KEY = {s.key: s for s in STEPS}


def plan_apps(session: Session) -> list[Application]:
    apps = session.scalars(select(Application).where(Application.removed_from_okta.is_(False))
                           .order_by(Application.label)).all()
    return [a for a in apps if a.in_scope_protocol and a.state != "OUT_OF_SCOPE"]


def effective_wave(app: Application) -> str:
    return app.wave or app.suggested_wave or "Unassigned"


def ensure_tasks(session: Session, app: Application) -> dict[str, MigrationTask]:
    existing = {t.step_key: t for t in session.scalars(select(MigrationTask).where(MigrationTask.app_id == app.id))}
    for i, step in enumerate(STEPS, start=1):
        if step.key not in existing:
            t = MigrationTask(app_id=app.id, step_key=step.key, position=i, status="NOT_STARTED")
            session.add(t)
            existing[step.key] = t
    session.flush()
    return existing


def tasks_for(session: Session, apps: list[Application]) -> dict[str, dict[str, MigrationTask]]:
    return {a.id: ensure_tasks(session, a) for a in apps}


def progress(tasks: dict[str, MigrationTask]) -> tuple[int, int]:
    applicable = [t for t in tasks.values() if t.status != "N/A"]
    return sum(1 for t in applicable if t.status == "DONE"), len(applicable)


def next_step(tasks: dict[str, MigrationTask]) -> Step | None:
    for s in STEPS:
        t = tasks.get(s.key)
        if t and t.status not in ("DONE", "N/A"):
            return s
    return None


def update_task(session: Session, task: MigrationTask, actor: str, status: str, owner: str | None,
                due: str | None, notes: str | None) -> bool:
    """Returns True if anything changed. Raises ValueError on bad input."""
    actor = (actor or "").strip()
    if not actor:
        raise ValueError("Your name is required to update the plan")
    if status not in STEP_STATUSES:
        raise ValueError(f"Unknown status {status}")
    due_dt = None
    if due:
        try:
            due_dt = datetime.strptime(due, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError("Due date must be YYYY-MM-DD") from exc
    new = {"status": status, "owner": (owner or "").strip() or None, "due_date": due_dt,
           "notes": (notes or "").strip() or None}
    old = {k: getattr(task, k) for k in new}
    if new == old:
        return False
    for k, v in new.items():
        setattr(task, k, v)
    task.updated_by, task.updated_at = actor, utcnow()
    record_event(session, "PLAN_TASK_UPDATED", actor, task.app_id, {
        "step": task.step_key,
        "changes": {k: [str(old[k]) if old[k] is not None else None, str(new[k]) if new[k] is not None else None]
                    for k in new if old[k] != new[k]}})
    return True


def overdue(tasks_by_app: dict[str, dict[str, MigrationTask]], now: datetime | None = None) -> list[MigrationTask]:
    now = now or utcnow()
    return sorted([t for ts in tasks_by_app.values() for t in ts.values()
                   if t.due_date and t.due_date < now and t.status not in ("DONE", "N/A")],
                  key=lambda t: t.due_date)
