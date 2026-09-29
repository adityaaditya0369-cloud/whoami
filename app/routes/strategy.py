"""Strategy (report, decisions, what-if, timeline) and Delivery (comms pack, build package)."""
from __future__ import annotations

import json
import re

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, session, url_for

from app.models.db import Application, SessionLocal, utcnow
from app.services import build_package as bpk
from app.services import comms as commsmod
from app.services import decisions as dm
from app.services import estimate as em
from app.services import risk
from app.services import strategy as stm
from app.services.ai.service import latest_assessment

bp = Blueprint("strategy", __name__)
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _settings():
    return current_app.config["SETTINGS"]


def _actor() -> str:
    name = (request.form.get("actor") or "").strip()
    if name:
        session["actor"] = name[:200]
    return name


def _choice(db, key: str) -> str | None:
    for v in dm.register(db):
        if v.d.key == key and v.row.status == "DECIDED":
            return v.row.choice
    return None


# --- Strategy ---------------------------------------------------------------------
@bp.get("/strategy")
def strategy():
    db = SessionLocal()
    st = stm.build(db, _settings())
    assumed = [k for k in request.args.getlist("assume") if k in dm.BY_KEY]
    sim = dm.simulate(db, assumed, risk.load_weights(_settings().risk_weights_file)) if assumed else None
    sim_tl = em.build_timeline(db, dm.scope_apps(db), sim.after) if sim else None
    gantt, ticks = em.gantt_rows(st.timeline)
    db.commit()
    return render_template("strategy.html", st=st, reg=dm.register(db), catalogue=dm.CATALOGUE, assumed=assumed,
                           sim=sim, sim_tl=sim_tl, gantt=gantt, ticks=ticks, now=utcnow(),
                           efforts=sorted(st.timeline.efforts.values(), key=lambda e: -e.total),
                           approach=stm.APPROACH)


@bp.post("/strategy/assumptions")
def assumptions():
    db = SessionLocal()
    try:
        em.update_settings(db, _actor(), request.form)
        db.commit()
        flash("Assumptions saved; timeline recalculated", "ok")
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "error")
    return redirect(url_for("strategy.strategy", _anchor="tab-timeline"))


@bp.post("/decisions/<key>")
def decide(key: str):
    db = SessionLocal()
    try:
        dm.decide(db, key, _actor(), request.form.get("choice") or None, request.form.get("owner"),
                  request.form.get("due") or None, request.form.get("notes"), reopen=bool(request.form.get("reopen")))
        db.flush()
        risk.score_all(db, risk.load_weights(_settings().risk_weights_file))
        db.commit()
        flash("Decision saved; scores and waves recalculated", "ok")
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "error")
    return redirect(url_for("strategy.strategy", _anchor="tab-decisions"))


@bp.post("/strategy/narrative")
def narrative():
    db = SessionLocal()
    try:
        st = stm.build(db, _settings())
        row = stm.generate_draft(db, st, _settings(), _actor() or "ui-operator")
        db.commit()
        flash(f"AI draft {row.status.lower()}" + (f": {row.errors[0]}" if row.errors else ""),
              "ok" if row.status == "VALID" else "error")
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "error")
    return redirect(url_for("strategy.strategy"))


@bp.get("/strategy.docx")
def strategy_docx():
    db = SessionLocal()
    st = stm.build(db, _settings())
    data = stm.to_docx(st, _settings(), use_draft=bool(request.args.get("draft")))
    db.commit()
    return Response(data, mimetype=DOCX, headers={
        "Content-Disposition": f"attachment; filename=okta_pingfederate_strategy_{utcnow():%Y%m%d}.docx"})


# --- Delivery ------------------------------------------------------------------------
def _messages(db):
    tl = em.build_timeline(db, dm.scope_apps(db))
    channel = _choice(db, "CLIENT_SECRET_ROTATION")
    out = []
    for w, apps in tl.waves.items():
        for a in apps:
            a_ = latest_assessment(db, a.id) if a.is_saml else None
            qs = (a_.output.get("questions_for_app_owner") or []) if a_ and a_.status == "VALID" else []
            out.append(commsmod.build_message(a, _settings(), tl, qs, channel))
    return out, tl


def _packages(db, apps):
    s = _settings()
    ognl = s.pf_ognl_allowed or (_choice(db, "OGNL_POLICY") or "").startswith("Allow")
    modern = (_choice(db, "IMPLICIT_GRANT") or "").startswith("Yes")
    return bpk.build_all(apps, s, ognl, modern)


@bp.get("/delivery")
def delivery():
    db = SessionLocal()
    msgs, tl = _messages(db)
    apps = [a for v in tl.waves.values() for a in v]
    pkgs = _packages(db, apps)
    db.commit()
    return render_template("delivery.html", msgs=msgs, pkgs=pkgs, waves=list(tl.waves.keys()),
                           wave_of={a.id: w for w, v in tl.waves.items() for a in v},
                           dirpack=bpk.directory_pack(apps, _settings().pf_directory_type),
                           json=json)


@bp.get("/delivery/comms.xlsx")
def comms_xlsx():
    db = SessionLocal()
    msgs, _ = _messages(db)
    return Response(commsmod.to_xlsx(msgs),
                    mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f"attachment; filename=app_owner_comms_{utcnow():%Y%m%d}.xlsx"})


@bp.get("/delivery/build-package.zip")
def build_zip():
    db = SessionLocal()
    tl = em.build_timeline(db, dm.scope_apps(db))
    wave = request.args.get("wave")
    app_id = request.args.get("app")
    if app_id:
        a = db.get(Application, app_id) or abort(404)
        apps, title = [a], a.label
    elif wave:
        apps, title = list(tl.waves.get(wave, [])), wave
    else:
        apps, title = [a for v in tl.waves.values() for a in v], "All waves"
    data = bpk.to_zip(_packages(db, apps), apps, _settings(), f"PingFederate build package - {title}")
    name = re.sub(r"[^A-Za-z0-9]+", "_", title).strip("_").lower()
    return Response(data, mimetype="application/zip",
                    headers={"Content-Disposition": f"attachment; filename=pf_build_package_{name}.zip"})
