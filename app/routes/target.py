"""PingFederate apps (planned / found / reconciliation) and the Migration plan."""
from __future__ import annotations

from collections import Counter, defaultdict

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from sqlalchemy import select

from app.integrations.pingfederate.client import PfError, build_pf_source
from app.models.db import Application, PfSyncRun, SessionLocal, utcnow
from app.services import plan as planmod
from app.services.pf_sync import run_pf_sync
from app.services.readiness import pf_readiness
from app.services.reconcile import BUILD_LABEL, BUILD_STATUSES, build_status, reconcile

bp = Blueprint("target", __name__)


def _settings():
    return current_app.config["SETTINGS"]


def _actor() -> str:
    name = (request.form.get("actor") or "").strip()
    if name:
        session["actor"] = name[:200]
    return name


@bp.app_context_processor
def _globals():
    return {"BUILD_LABEL": BUILD_LABEL, "PLAN_STEPS": planmod.STEPS, "STEP_STATUSES": planmod.STEP_STATUSES}


# --- PingFederate apps ---------------------------------------------------------
@bp.get("/pingfederate")
def pingfederate():
    db = SessionLocal()
    recs, pf_only = reconcile(db)
    apps = [r.app for r in recs]
    tasks = planmod.tasks_for(db, [a for a in apps if a.state != "OUT_OF_SCOPE"])
    rows = []
    for r in recs:
        a = r.app
        rows.append({"r": r, "a": a, "status": build_status(a, r, tasks.get(a.id)),
                     "pf": pf_readiness(a) if a.is_saml else None,
                     "key": (a.saml.audience if a.is_saml and a.saml else (a.oidc.client_id if a.oidc else None))})
    db.commit()
    counts = Counter(x["status"] for x in rows)
    found = sorted([r for r in recs if r.pf] , key=lambda r: r.pf.name.lower())
    last = db.scalars(select(PfSyncRun).order_by(PfSyncRun.id.desc()).limit(1)).first()
    return render_template("pingfederate.html", rows=rows, counts=counts, statuses=BUILD_STATUSES,
                           found=found, pf_only=pf_only, recs=recs, last=last)


@bp.post("/pingfederate/sync")
def pingfederate_sync():
    s = _settings()
    actor = _actor() or "ui-operator"
    try:
        source = build_pf_source(s)
        if source is None:
            flash("PF_SOURCE=none: set PF_SOURCE=file or live in .env to read PingFederate.", "error")
        else:
            run = run_pf_sync(SessionLocal(), source, s, actor)
            flash(f"PingFederate read: {run.sp_connections} SP connections, {run.oauth_clients} OAuth clients.", "ok")
    except (PfError, OSError, Exception) as exc:  # noqa: BLE001 - surface any read error to the operator
        flash(f"PingFederate read failed: {exc}", "error")
    return redirect(url_for("target.pingfederate"))


# --- Migration plan -------------------------------------------------------------
@bp.get("/plan")
def plan():
    db = SessionLocal()
    apps = planmod.plan_apps(db)
    tasks = planmod.tasks_for(db, apps)
    recs = {r.app.id: r for r in reconcile(db)[0]}
    db.commit()
    cards = []
    for a in apps:
        done, total = planmod.progress(tasks[a.id])
        cards.append({"a": a, "wave": planmod.effective_wave(a), "done": done, "total": total,
                      "next": planmod.next_step(tasks[a.id]), "tasks": tasks[a.id],
                      "build": build_status(a, recs.get(a.id), tasks[a.id])})
    by_wave = defaultdict(list)
    for c in cards:
        by_wave[c["wave"]].append(c)
    waves = [w for w in planmod.WAVE_ORDER if w in by_wave] + sorted(w for w in by_wave if w not in planmod.WAVE_ORDER)
    wave_progress = {w: (sum(c["done"] for c in by_wave[w]), sum(c["total"] for c in by_wave[w])) for w in waves}
    step_counts = {s.key: Counter(tasks[a.id][s.key].status for a in apps) for s in planmod.STEPS}
    total_done = sum(c["done"] for c in cards)
    total_all = sum(c["total"] for c in cards)
    return render_template("plan.html", cards=cards, by_wave=by_wave, waves=waves, wave_progress=wave_progress,
                           step_counts=step_counts, total_done=total_done, total_all=total_all,
                           overdue=planmod.overdue(tasks), apps_by_id={a.id: a for a in apps}, now=utcnow())


@bp.post("/applications/<app_id>/plan")
def save_plan(app_id: str):
    db = SessionLocal()
    a = db.get(Application, app_id) or abort(404)
    actor = _actor()
    tasks = planmod.ensure_tasks(db, a)
    try:
        changed = 0
        for step in planmod.STEPS:
            t = tasks[step.key]
            changed += planmod.update_task(
                db, t, actor, request.form.get(f"{step.key}_status", t.status),
                request.form.get(f"{step.key}_owner"), request.form.get(f"{step.key}_due"),
                request.form.get(f"{step.key}_notes"))
        db.commit()
        flash(f"Plan saved ({changed} step(s) changed)" if changed else "No changes", "ok")
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "error")
    return redirect(url_for("web.application", app_id=app_id, _anchor="tab-plan"))
