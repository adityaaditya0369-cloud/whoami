"""End-to-end pipeline: agents -> plan & approval -> PingFederate -> validation -> cutover / rollback,
plus the knowledge base."""
from __future__ import annotations

import json
from collections import Counter

from flask import (
    Blueprint, Response, abort, current_app, flash, redirect, render_template, request, session, url_for,
)
from sqlalchemy import select

from app.integrations.pingfederate.client import PfError
from app.models.db import (
    AgentRun, Application, KnowledgeDoc, MigrationEvent, MigrationPlan, SessionLocal, ValidationResult,
)
from app.models.state import InvalidTransition, MigrationState
from app.services import approval, cutover, knowledge, pf_write, test_sso
from app.services import pipeline as pl
from app.services.agents import service as agents
from app.services.agents.schema import AGENT_TITLE
from app.services.saml_validation import SamlInputError

bp = Blueprint("pipeline", __name__)
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _settings():
    return current_app.config["SETTINGS"]


def _actor() -> str:
    name = (request.form.get("actor") or "").strip()
    if name:
        session["actor"] = name[:200]
    return name


def _saml_app(db, app_id) -> Application:
    a = db.get(Application, app_id) or abort(404)
    if not a.is_saml or a.saml is None:
        abort(404)
    return a


def _back(app_id, tab):
    return redirect(url_for("pipeline.app_pipeline", app_id=app_id, _anchor=f"tab-{tab}"))


def _do(db, fn, ok_msg, app_id, tab):
    try:
        fn()
        db.commit()
        flash(ok_msg, "ok")
    except (ValueError, InvalidTransition, SamlInputError, PfError) as exc:
        db.rollback()
        flash(str(exc), "error")
    return _back(app_id, tab)


@bp.app_context_processor
def _globals():
    return {"STAGES": pl.STAGES, "AGENT_TITLE": AGENT_TITLE, "VSTAGES": cutover.STAGES}


# --- board -------------------------------------------------------------------------
@bp.get("/pipeline")
def board():
    db = SessionLocal()
    apps = [a for a in db.scalars(select(Application).where(Application.removed_from_okta.is_(False))
                                  .order_by(Application.label)) if a.is_saml and a.state != "OUT_OF_SCOPE"]
    cols = {k: [] for k in pl.STAGE_KEYS}
    for a in apps:
        cols[pl.stage_of(a.state)].append(a)
    last_v = {}
    for v in db.scalars(select(ValidationResult).order_by(ValidationResult.id)):
        last_v[v.app_id] = v
    runs = {r.app_id: r for r in db.scalars(select(AgentRun).order_by(AgentRun.id))}
    oidc = sum(1 for a in db.scalars(select(Application).where(Application.removed_from_okta.is_(False)))
               if a.is_oidc and a.state != "OUT_OF_SCOPE")
    return render_template("pipeline.html", cols=cols, apps=apps, last_v=last_v, runs=runs,
                           next_action=pl.NEXT_ACTION, S=MigrationState, oidc=oidc, kb=knowledge.stats(db))


# --- per app -------------------------------------------------------------------------
@bp.get("/applications/<app_id>/pipeline")
def app_pipeline(app_id: str):
    db = SessionLocal()
    s = _settings()
    a = _saml_app(db, app_id)
    run = agents.latest_run(db, a.id)
    plans = db.scalars(select(MigrationPlan).where(MigrationPlan.app_id == a.id).order_by(MigrationPlan.id.desc())).all()
    plan = plans[0] if plans else None
    approved = approval.approved_plan(db, a.id)
    drift = approval.drift(db, plan, s) if plan and plan.status in ("DRAFT", "SUBMITTED", "APPROVED") else False
    dry = db.scalars(select(MigrationEvent).where(MigrationEvent.app_id == a.id, MigrationEvent.event_type == "PF_DRY_RUN")
                     .order_by(MigrationEvent.id.desc()).limit(1)).first()
    preview, unresolved = None, []
    if approved:
        try:
            preview = pf_write.substitute(approved.plan["pingfederate"]["payload"], pf_write.load_variables(s.pf_variables_file))
        except ValueError:
            preview = approved.plan["pingfederate"]["payload"]
        unresolved = pf_write.unresolved(preview)
    from app.services.reconcile import reconcile
    rec = next((r for r in reconcile(db)[0] if r.app.id == a.id), None)
    validations = cutover.results(db, a.id)
    gate = cutover.gate(db, a, s)
    kb_titles = {f"KB-{c.id}": f"{c.doc.title}{' > ' + c.heading if c.heading else ''}"
                 for d in db.scalars(select(KnowledgeDoc)) for c in d.chunks}
    return render_template(
        "app_pipeline.html", a=a, run=run, counts=agents.counts(run) if run else None,
        disagreements=agents.disagreements(run) if run else [], plans=plans, plan=plan, approved=approved,
        drift=drift, dry=dry, preview=preview, unresolved=unresolved, rec=rec, validations=validations,
        gate=gate, gate_ok=cutover.gate_ok(gate), stage=pl.stage_of(a.state), tab=pl.tab_for(a.state),
        next_action=pl.NEXT_ACTION.get(MigrationState(a.state), ""), S=MigrationState,
        default_stage=cutover.default_stage(a), cutover_values=cutover.cutover_values(a, s),
        rollback_values=cutover.rollback_values(a, s), kb_titles=kb_titles,
        cert_configured=bool(s.pf_signing_cert_file and s.pf_signing_cert_file.exists()),
        test_sso_url=test_sso.start_url(s, a.saml.audience or ""), test_sso_enabled=s.test_sso_enabled,
        four_eyes=s.approval_four_eyes)


@bp.post("/applications/<app_id>/agents/run")
def run_agents(app_id: str):
    db = SessionLocal()
    a = _saml_app(db, app_id)
    actor = _actor() or "ui-operator"
    provider = request.form.get("provider") or None
    try:
        r = agents.run_panel(db, a, _settings(), actor, provider_name=provider, force=bool(request.form.get("force")))
        db.commit()
        flash(f"Agents finished: {r.status.lower()}", "ok" if r.status == "VALID" else "error")
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "error")
    return _back(app_id, "agents")


@bp.post("/agent-runs/<int:run_id>/review")
def review_agents(run_id: int):
    db = SessionLocal()
    run = db.get(AgentRun, run_id) or abort(404)
    res = {k[len("resolve::"):]: v for k, v in request.form.items() if k.startswith("resolve::")}
    decision = request.form.get("decision", "")
    return _do(db, lambda: agents.review(db, run, _actor(), decision, request.form.get("comment", ""), res),
               f"Agent review {decision.lower()}", run.app_id, "agents")


@bp.post("/applications/<app_id>/plan/generate")
def generate_plan(app_id: str):
    db = SessionLocal()
    a = _saml_app(db, app_id)
    return _do(db, lambda: approval.generate(db, a, _settings(), _actor()), "Plan generated", app_id, "plan")


@bp.post("/plans/<int:plan_id>/submit")
def submit_plan(plan_id: int):
    db = SessionLocal()
    p = db.get(MigrationPlan, plan_id) or abort(404)
    return _do(db, lambda: approval.submit(db, p, _actor()), "Plan submitted for approval", p.app_id, "plan")


@bp.post("/plans/<int:plan_id>/decide")
def decide_plan(plan_id: int):
    db = SessionLocal()
    p = db.get(MigrationPlan, plan_id) or abort(404)
    decision = request.form.get("decision", "")
    return _do(db, lambda: approval.decide(db, p, _settings(), _actor(), decision, request.form.get("comment", "")),
               f"Plan {decision.lower()}", p.app_id, "plan")


@bp.get("/plans/<int:plan_id>.json")
def plan_json(plan_id: int):
    db = SessionLocal()
    p = db.get(MigrationPlan, plan_id) or abort(404)
    body = json.dumps({"id": p.id, "app_id": p.app_id, "version": p.version, "status": p.status, "sha256": p.sha256,
                       "approved_by": p.decided_by if p.status == "APPROVED" else None, "plan": p.plan}, indent=2, default=str)
    return Response(body, mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=plan-{p.app_id}-v{p.version}.json"})


@bp.post("/applications/<app_id>/pf/dry-run")
def pf_dry_run(app_id: str):
    db = SessionLocal()
    a = _saml_app(db, app_id)
    try:
        d = pf_write.dry_run(db, a, _settings(), _actor() or "ui-operator")
        db.commit()
        flash("Dry run passed - you can create the connection" if d.ok else "Dry run found problems (see below)",
              "ok" if d.ok else "error")
    except (ValueError, PfError) as exc:
        db.rollback()
        flash(str(exc), "error")
    return _back(app_id, "build")


@bp.post("/applications/<app_id>/pf/apply")
def pf_apply(app_id: str):
    db = SessionLocal()
    a = _saml_app(db, app_id)
    return _do(db, lambda: pf_write.apply(db, a, _settings(), _actor()),
               "SP connection created on PingFederate (disabled)", app_id, "build")


@bp.post("/applications/<app_id>/pf/confirm-manual")
def pf_confirm_manual(app_id: str):
    db = SessionLocal()
    a = _saml_app(db, app_id)
    return _do(db, lambda: pf_write.confirm_manual(db, a, _actor()), "Manual import confirmed", app_id, "build")


@bp.post("/applications/<app_id>/validate")
def validate(app_id: str):
    db = SessionLocal()
    a = _saml_app(db, app_id)
    f = request.form
    resp = f.get("response", "")[:3_000_000]
    up = request.files.get("response_file")
    if up and up.filename:
        resp = up.read(2_000_000).decode("utf-8", errors="replace")
    holder = {}

    def go():
        holder["v"] = cutover.record_validation(db, a, _settings(), resp, _actor(), f.get("stage", ""), "CAPTURED",
                                                cert_pem=(f.get("cert_pem") or "").strip() or None)
    r = _do(db, go, "Validation recorded", app_id, "validation")
    if "v" in holder:
        flash(f"Result: {holder['v'].verdict.replace('_', ' ').lower()}", "ok" if holder["v"].verdict != "FAIL" else "error")
    return r


@bp.post("/applications/<app_id>/validate/auto")
def validate_auto(app_id: str):
    from pathlib import Path
    db = SessionLocal()
    a = _saml_app(db, app_id)
    s = _settings()
    actor = _actor()
    try:
        if not actor:
            raise ValueError("Your name is required")
        cap = test_sso.capture(s, a.saml.audience or "", screenshot_dir=Path(current_app.instance_path) / "test-sso")
        v = cutover.record_validation(db, a, s, cap.form_body, actor, request.form.get("stage", "PRE_CUTOVER"), "AUTOMATED")
        db.commit()
        flash(f"Automated test SSO captured a response: {v.verdict.replace('_', ' ').lower()}",
              "ok" if v.verdict != "FAIL" else "error")
    except (ValueError, InvalidTransition, SamlInputError, test_sso.TestSsoError) as exc:
        db.rollback()
        flash(str(exc), "error")
    return _back(app_id, "validation")


@bp.get("/validations/<int:vid>")
def validation_detail(vid: int):
    db = SessionLocal()
    v = db.get(ValidationResult, vid) or abort(404)
    return render_template("validation.html", v=v, a=db.get(Application, v.app_id))


CUTOVER_ACTIONS = {
    "signoff": (lambda db, a, s, actor, c: cutover.business_signoff(db, a, s, actor, c), "Business sign-off recorded"),
    "go": (lambda db, a, s, actor, c: cutover.go_decision(db, a, s, actor, c), "Go decision recorded: ready for cutover"),
    "done": (lambda db, a, s, actor, c: cutover.cutover_done(db, a, actor, c, s), "Cutover recorded - run the post-cutover validation"),
    "fail": (lambda db, a, s, actor, c: cutover.declare_failed(db, a, actor, c), "Failure recorded"),
    "retry": (lambda db, a, s, actor, c: cutover.retry_testing(db, a, actor, c), "Back to testing"),
    "rollback": (lambda db, a, s, actor, c: cutover.start_rollback(db, a, s, actor, c), "Rollback started - restore the Okta values on the SP"),
    "rollback-confirm": (lambda db, a, s, actor, c: cutover.confirm_rollback(db, a, actor, c), "Rollback confirmed: app is on Okta"),
}


@bp.post("/applications/<app_id>/cutover/<action>")
def cutover_action(app_id: str, action: str):
    if action not in CUTOVER_ACTIONS:
        abort(404)
    db = SessionLocal()
    a = _saml_app(db, app_id)
    fn, msg = CUTOVER_ACTIONS[action]
    tab = "validation" if action in ("signoff", "retry") else "cutover"
    return _do(db, lambda: fn(db, a, _settings(), _actor(), request.form.get("comment", "")), msg, app_id, tab)


@bp.get("/applications/<app_id>/runbook.docx")
def runbook_docx(app_id: str):
    db = SessionLocal()
    a = _saml_app(db, app_id)
    rb = cutover.runbook(db, a, _settings())
    data = cutover.runbook_docx(rb, _settings().customer_name)
    return Response(data, mimetype=DOCX, headers={
        "Content-Disposition": f"attachment; filename=runbook-{a.label.replace(' ', '-')[:40]}.docx"})


# --- knowledge base ------------------------------------------------------------------------
@bp.get("/knowledge")
def knowledge_page():
    db = SessionLocal()
    q = (request.args.get("q") or "").strip()
    app_id = request.args.get("app") or None
    docs = db.scalars(select(KnowledgeDoc).order_by(KnowledgeDoc.uploaded_at.desc())).all()
    hits = knowledge.search(db, q, k=8, app_id=app_id, min_score=0.1) if q else []
    apps = [a for a in db.scalars(select(Application).order_by(Application.label)) if a.in_scope_protocol]
    by_app = Counter(d.app_id for d in docs)
    return render_template("knowledge.html", docs=docs, q=q, hits=hits, apps=apps, app_id=app_id, by_app=by_app,
                           stats=knowledge.stats(db), allowed=sorted(knowledge.ALLOWED_EXT))


@bp.post("/knowledge/upload")
def knowledge_upload():
    db = SessionLocal()
    f = request.files.get("file")
    try:
        if not f or not f.filename:
            raise knowledge.KnowledgeError("Choose a file")
        data = f.read(_settings().knowledge_max_upload_mb * 1024 * 1024 + 1)
        doc = knowledge.add_document(db, f.filename, data, _actor(), title=request.form.get("title") or None,
                                     app_id=request.form.get("app_id") or None,
                                     tags=(request.form.get("tags") or "").split(","),
                                     max_mb=_settings().knowledge_max_upload_mb)
        db.commit()
        flash(f"Added '{doc.title}' ({len(doc.chunks)} passages)", "ok")
    except knowledge.KnowledgeError as exc:
        db.rollback()
        flash(str(exc), "error")
    return redirect(url_for("pipeline.knowledge_page"))


@bp.post("/knowledge/<int:doc_id>/delete")
def knowledge_delete(doc_id: int):
    db = SessionLocal()
    d = db.get(KnowledgeDoc, doc_id) or abort(404)
    try:
        title = d.title
        knowledge.delete_document(db, d, _actor())
        db.commit()
        flash(f"Removed '{title}'", "ok")
    except knowledge.KnowledgeError as exc:
        db.rollback()
        flash(str(exc), "error")
    return redirect(url_for("pipeline.knowledge_page"))
