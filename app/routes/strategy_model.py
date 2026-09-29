"""Strategy pack: executive / architect / engineer views, compatibility matrix, dependency graph,
tenant objects and the capability catalog, plus Excel and Word exports."""
from __future__ import annotations

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, session, url_for

from app.models.db import Application, SessionLocal
from app.strategy_model import dependencies as dg
from app.strategy_model import export as pack_export
from app.strategy_model import service
from app.strategy_model.catalog import STRATEGIES
from app.strategy_model.engine import FACTORS

bp = Blueprint("strategy_model", __name__)
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _settings():
    return current_app.config["SETTINGS"]


def _actor() -> str:
    name = (request.form.get("actor") or "").strip()
    if name:
        session["actor"] = name[:200]
    return name


def _back(tab: str):
    return redirect(url_for("strategy_model.pack", _anchor=f"tab-{tab}"))


@bp.get("/strategy-pack")
def pack():
    db = SessionLocal()
    if service.ensure_analysed(db, _settings()):
        db.commit()
    p = service.build_pack(db, _settings())
    return render_template("strategy_pack.html", p=p, STRATEGIES=STRATEGIES, HELP=service.STRATEGY_HELP,
                           KINDS=dg.KINDS)


@bp.get("/strategy-pack/apps/<app_id>")
def app_detail(app_id: str):
    db = SessionLocal()
    a = db.get(Application, app_id) or abort(404)
    if service.ensure_analysed(db, _settings()):
        db.commit()
    p = service.build_pack(db, _settings())
    row = next((r for r in p.apps if r.app.id == app_id), None) or abort(404)
    return render_template("strategy_app.html", p=p, r=row, a=a, STRATEGIES=STRATEGIES, HELP=service.STRATEGY_HELP,
                           FACTORS=FACTORS, override=service.active_override(db, app_id))


@bp.post("/strategy-pack/analyse")
def analyse():
    db = SessionLocal()
    counts = service.analyse(db, _settings(), _actor() or "system")
    db.commit()
    flash("Strategy recalculated: " + ", ".join(f"{v} {k.lower()}" for k, v in sorted(counts.items()) if k), "ok")
    return _back("executive")


@bp.post("/strategy-pack/apps/<app_id>/override")
def override(app_id: str):
    db = SessionLocal()
    a = db.get(Application, app_id) or abort(404)
    try:
        service.set_override(db, _settings(), a, request.form.get("strategy", ""), request.form.get("reason", ""), _actor())
        db.commit()
        flash("Architecture decision recorded", "ok")
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "error")
    return redirect(url_for("strategy_model.app_detail", app_id=app_id))


@bp.post("/dependencies/import")
def dep_import():
    db = SessionLocal()
    up = request.files.get("file")
    try:
        if not up or not up.filename:
            raise ValueError("Choose a CSV file")
        text = up.read(2_000_000).decode("utf-8", errors="replace")
        res = dg.import_csv(db, text, _actor())
        db.commit()
        flash(f"Imported: {res['added']} new, {res['updated']} updated" +
              (f"; treated as external systems (not Okta apps): {', '.join(res['external'][:6])}" if res["external"] else "") +
              (f"; {len(res['errors'])} line(s) skipped: " + "; ".join(res["errors"][:3]) if res["errors"] else ""),
              "ok" if not res["errors"] else "error")
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "error")
    return _back("dependencies")


@bp.post("/dependencies/add")
def dep_add():
    db = SessionLocal()
    f = request.form
    try:
        dg.add_manual(db, f.get("source", ""), f.get("target", ""), f.get("kind", "DEPENDS_ON"), f.get("note", ""), _actor())
        db.commit()
        flash("Dependency added", "ok")
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "error")
    return _back("dependencies")


@bp.post("/dependencies/suggest")
def dep_suggest():
    db = SessionLocal()
    try:
        res = dg.suggest(db, _settings(), _actor())
        db.commit()
        flash(f"{res['method']}: {res['found']} link(s) found in the knowledge base, {res['new']} new suggestion(s). "
              "Confirm or reject each one; suggestions do not affect the plan.", "ok")
    except Exception as exc:  # noqa: BLE001 - provider errors are shown, not raised
        db.rollback()
        flash(f"Suggestion failed: {type(exc).__name__}: {str(exc)[:200]}", "error")
    return _back("dependencies")


@bp.post("/dependencies/<int:dep_id>/decide")
def dep_decide(dep_id: int):
    db = SessionLocal()
    try:
        dg.decide(db, dep_id, _actor(), request.form.get("decision", ""), request.form.get("note", ""))
        db.commit()
        flash("Recorded", "ok")
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "error")
    return _back("dependencies")


@bp.get("/strategy-pack.xlsx")
def pack_xlsx():
    db = SessionLocal()
    s = _settings()
    if service.ensure_analysed(db, s):
        db.commit()
    data = pack_export.to_xlsx(service.build_pack(db, s), s.customer_name)
    return Response(data, mimetype=XLSX,
                    headers={"Content-Disposition": "attachment; filename=migration-strategy-pack.xlsx"})


@bp.get("/strategy-pack.docx")
def pack_docx():
    db = SessionLocal()
    s = _settings()
    if service.ensure_analysed(db, s):
        db.commit()
    data = pack_export.to_docx(service.build_pack(db, s), s.customer_name)
    return Response(data, mimetype=DOCX,
                    headers={"Content-Disposition": "attachment; filename=migration-strategy-pack.docx"})
