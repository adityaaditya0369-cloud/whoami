"""Gated creation of an approved SP connection on PingFederate.

  1. The app is APPROVED and its approved plan still matches Okta (no drift).
  2. Dry run: variables filled, no {{PLACEHOLDER}} left, entity ID not already on
     PingFederate, referenced adapter / data store / signing key exist. Recorded.
  3. Apply (named person, within PF_DRY_RUN_VALID_MINUTES of a dry run of the
     same payload): checks run again, then ONE create call, connection disabled.
  4. The created object is stored and the app moves to PF_CONFIGURED.
Alternative: admins import the build package themselves; after a PingFederate
sync finds the connection, "confirm manual import" moves the app on.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import PfSourceMode, Settings
from app.integrations.pingfederate import parser as pfp
from app.integrations.pingfederate.client import PfError
from app.integrations.pingfederate.writer import PfWriter, ref_paths
from app.models.db import Application, MigrationEvent, PfObject, utcnow
from app.models.state import MigrationState
from app.services import approval
from app.services.state_service import record_event, transition

_VAR = re.compile(r"\{\{\s*([^{}\s]+)\s*\}\}")


@dataclass
class DryRun:
    checks: list[tuple[str, bool, str]] = field(default_factory=list)
    payload: dict | None = None
    payload_sha256: str | None = None
    unresolved: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(ok for _, ok, _ in self.checks)


def load_variables(path: Path | None) -> dict[str, str]:
    if not path:
        return {}
    if not Path(path).exists():
        raise ValueError(f"PF_VARIABLES_FILE not found: {path}")
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    out = {}
    for k, v in raw.items():
        val = v.get("value") if isinstance(v, dict) else v
        if val not in (None, ""):
            out[k] = str(val)
    return out


def substitute(obj, variables: dict[str, str]):
    if isinstance(obj, dict):
        return {k: substitute(v, variables) for k, v in obj.items()}
    if isinstance(obj, list):
        return [substitute(v, variables) for v in obj]
    if isinstance(obj, str):
        return _VAR.sub(lambda m: variables.get(m.group(1), m.group(0)), obj)
    return obj


def _strings(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)
    elif isinstance(obj, str):
        yield obj


def unresolved(obj) -> list[str]:
    names = set()
    for text in _strings(obj):
        found = _VAR.findall(text)
        names.update(found)
        if not found and ("{{" in text or "}}" in text):
            names.add(f"(malformed placeholder in '{text[:40]}')")   # never let a stray {{ through
    return sorted(names)


def _sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def dry_run(session: Session, app: Application, settings: Settings, actor: str, writer: PfWriter | None = None,
            record: bool = True) -> DryRun:
    d = DryRun()
    add = lambda label, ok, detail="": d.checks.append((label, bool(ok), detail))  # noqa: E731
    add("App is approved", app.state == MigrationState.APPROVED.value, app.state)
    plan = approval.approved_plan(session, app.id)
    add("Approved plan on file", plan is not None, f"v{plan.version} by {plan.decided_by}" if plan else "none")
    if plan is None:
        return d
    add("Okta unchanged since approval", not approval.drift(session, plan, settings),
        "Regenerate and re-approve the plan" if approval.drift(session, plan, settings) else "no drift")
    add("Writes enabled (PF_WRITE_ENABLED)", settings.pf_write_enabled, "" if settings.pf_write_enabled else
        "Off - use the build package and confirm the manual import instead")
    add("PingFederate source is live", settings.pf_source == PfSourceMode.LIVE, settings.pf_source.value)
    try:
        variables = load_variables(settings.pf_variables_file)
        add("Variables file loaded", True, f"{len(variables)} value(s)")
    except ValueError as exc:
        variables = {}
        add("Variables file loaded", False, str(exc))
    payload = substitute(plan.plan["pingfederate"]["payload"], variables)
    d.payload, d.payload_sha256 = payload, _sha(payload)
    d.unresolved = unresolved(payload)
    add("All {{VARIABLES}} filled", not d.unresolved, ", ".join(d.unresolved) or "all filled")
    add("Created disabled", payload.get("active") is False, "active=false")
    if settings.pf_write_enabled and settings.pf_source == PfSourceMode.LIVE:
        try:
            writer = writer or PfWriter(settings)
            existing = writer.find_sp_connection(payload.get("entityId") or "")
            add("Entity ID not yet on PingFederate", existing is None,
                f"already exists as '{existing.get('name')}' - the tool never overwrites; use manual import"
                if existing else payload.get("entityId", ""))
            if not d.unresolved:
                for label, path in ref_paths(payload).items():
                    add(f"{label} exists", writer.ref_exists(path), path)
        except PfError as exc:
            add("PingFederate reachable", False, str(exc)[:300])
    if record:
        record_event(session, "PF_DRY_RUN", actor or "system", app.id,
                     {"plan_id": plan.id, "ok": d.ok, "payload_sha256": d.payload_sha256,
                      "failed": [label for label, ok, _ in d.checks if not ok],
                      "checks": [[label, ok, detail] for label, ok, detail in d.checks]})
    return d


def _recent_ok_dry_run(session: Session, app: Application, sha: str, minutes: int) -> bool:
    since = utcnow() - timedelta(minutes=minutes)
    for ev in session.scalars(select(MigrationEvent).where(MigrationEvent.app_id == app.id,
                                                           MigrationEvent.event_type == "PF_DRY_RUN",
                                                           MigrationEvent.ts >= since)):
        if ev.detail.get("ok") and ev.detail.get("payload_sha256") == sha:
            return True
    return False


def apply(session: Session, app: Application, settings: Settings, actor: str, writer: PfWriter | None = None) -> PfObject:
    actor = (actor or "").strip()
    if not actor or actor.lower() in {"system", "ai", "claude"}:
        raise ValueError("A named person is required to write to PingFederate")
    writer = writer or PfWriter(settings)
    d = dry_run(session, app, settings, actor, writer=writer, record=False)
    if not d.ok:
        raise ValueError("Checks failed: " + "; ".join(f"{label} ({detail})" for label, ok, detail in d.checks if not ok))
    if not _recent_ok_dry_run(session, app, d.payload_sha256, settings.pf_dry_run_valid_minutes):
        raise ValueError(f"Run a dry run first (valid {settings.pf_dry_run_valid_minutes} minutes for the same payload)")
    plan = approval.approved_plan(session, app.id)
    # The attempt is committed BEFORE the POST, and any failure is committed before re-raising, so the
    # audit trail survives the caller's rollback - even when the POST may have landed (timeout).
    record_event(session, "PF_WRITE_ATTEMPT", actor, app.id,
                 {"plan_id": plan.id, "entity_id": d.payload.get("entityId"), "payload_sha256": d.payload_sha256,
                  "target": writer.describe()})
    session.commit()
    try:
        created = writer.create_sp_connection(d.payload)
        m = pfp.parse_sp_connection(created)
    except Exception as exc:  # noqa: BLE001 - PfError, requests errors, bad response body
        import requests
        uncertain = isinstance(exc, (requests.Timeout, requests.ConnectionError)) or not isinstance(exc, (PfError,))
        record_event(session, "PF_WRITE_FAILED", actor, app.id,
                     {"plan_id": plan.id, "error": f"{type(exc).__name__}: {str(exc)[:1500]}",
                      "may_have_been_created": uncertain})
        session.commit()
        if uncertain:
            raise PfError(f"The write may or may not have reached PingFederate ({type(exc).__name__}). "
                          "Run a PingFederate sync before trying again.") from exc
        raise
    obj = session.scalars(select(PfObject).where(PfObject.kind == m.kind, PfObject.pf_id == m.pf_id)).first() \
        or PfObject(kind=m.kind, pf_id=m.pf_id)
    obj.key, obj.name, obj.active, obj.removed = m.key, m.name, m.active, False
    obj.details = m.model_dump(exclude={"kind", "pf_id", "key", "name", "active"})
    obj.raw = created
    session.add(obj)
    record_event(session, "PF_WRITE_CREATED", actor, app.id,
                 {"plan_id": plan.id, "pf_id": m.pf_id, "entity_id": m.key, "payload_sha256": d.payload_sha256,
                  "target": writer.describe()})
    transition(session, app, MigrationState.PF_CONFIGURED, actor,
               reason=f"SP connection created on PingFederate (disabled) from plan v{plan.version}",
               detail={"pf_id": m.pf_id})
    return obj


def confirm_manual(session: Session, app: Application, actor: str) -> PfObject:
    """Admins imported the connection themselves; a PingFederate sync must have found it."""
    actor = (actor or "").strip()
    if not actor:
        raise ValueError("Your name is required")
    if app.state != MigrationState.APPROVED.value:
        raise ValueError(f"App is in {app.state}; the plan must be approved first")
    from app.services.reconcile import reconcile
    rec = next((r for r in reconcile(session)[0] if r.app.id == app.id), None)
    if not rec or not rec.pf:
        raise ValueError("No matching connection found on PingFederate. Import it, then run a PingFederate sync.")
    transition(session, app, MigrationState.PF_CONFIGURED, actor,
               reason=f"Manual import confirmed: '{rec.pf.name}' found on PingFederate",
               detail={"pf_id": rec.pf.pf_id, "differences": [c.check for c in rec.problems]})
    return rec.pf
