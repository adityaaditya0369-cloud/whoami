"""UI + read-only JSON/CSV/Excel endpoints."""
from __future__ import annotations

import csv
import io
import re
from collections import Counter

from flask import (
    Blueprint, Response, abort, current_app, flash, jsonify, redirect, render_template, request,
    session, url_for,
)
from sqlalchemy import func, select

from app.integrations.okta.client import OktaError, build_source
from app.models.db import (
    AiAssessment, Application, DiscoveryRun, Finding, MigrationEvent, RawSnapshot, SessionLocal, utcnow,
)
from app.models.state import ALLOWED_TRANSITIONS, InvalidTransition, MigrationState
from app.services import comparison, risk
from app.services.ai import service as ai
from app.services.discovery import run_discovery
from app.services.excel_report import build_workbook
from app.services.readiness import pf_readiness
from app.services.state_service import record_event, transition

bp = Blueprint("web", __name__)
SEV_ORDER = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
LEVELS = risk.LEVELS
WAVES = ["Wave 0 (pilot)", "Wave 1", "Wave 2", "Wave 3 (high impact)", "Blocked", "Decommission review"]
# Manual transitions exposed so far; the rest arrive with their sprints.
MANUAL_TARGETS = {MigrationState.OUT_OF_SCOPE, MigrationState.DISCOVERED}
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def _settings():
    return current_app.config["SETTINGS"]


def _actor() -> str:
    """Name from the form; remembered in the session to pre-fill later forms."""
    name = (request.form.get("actor") or "").strip()
    if name:
        session["actor"] = name[:200]
    return name


def _worst(findings) -> str | None:
    sevs = {f.severity for f in findings}
    return next((s for s in ("CRITICAL", "WARNING", "INFO") if s in sevs), None)


PROTOCOLS = ("SAML", "OIDC", "OTHER")


def _protocol_apps(db, protocol: str = "ALL"):
    """In-scope protocol apps (SAML + OIDC) by default; 'OTHER' = bookmark/SWA/etc."""
    apps = db.scalars(select(Application).where(Application.removed_from_okta.is_(False))
                      .order_by(Application.label)).all()
    if protocol == "ALL":
        return [a for a in apps if a.in_scope_protocol]
    return [a for a in apps if a.protocol == protocol]


def _protocol_counts(db) -> dict:
    apps = db.scalars(select(Application).where(Application.removed_from_okta.is_(False))).all()
    c = Counter(a.protocol for a in apps)
    return {p: c.get(p, 0) for p in PROTOCOLS}


_TOKEN_RE = re.compile(r"[A-Za-z0-9]+|[^A-Za-z0-9]")


@bp.app_template_filter("diffmark")
def _diffmark(value, other, side="new"):
    """Highlight the words/URL segments of `value` that differ from `other`."""
    from difflib import SequenceMatcher

    from markupsafe import Markup, escape
    a, b = str(value or ""), str(other or "")
    if not a or not b or a == b or len(a) > 600 or len(b) > 600 or "—" in (a, b):
        return escape(a)
    ta, tb = _TOKEN_RE.findall(a), _TOKEN_RE.findall(b)
    sm = SequenceMatcher(None, tb, ta, autojunk=False)
    if sm.ratio() < 0.3:          # mostly different: highlight the whole value
        return Markup(f'<mark class="{side}">{escape(a)}</mark>')
    out, pending = [], []

    def flush():
        if pending:
            out.append(Markup(f'<mark class="{side}">{escape("".join(pending))}</mark>'))
            pending.clear()
    for op, _i1, _i2, j1, j2 in sm.get_opcodes():
        chunk = ta[j1:j2]
        if not chunk:
            continue
        if op == "equal" and not (len(chunk) == 1 and not chunk[0].isalnum()):
            flush()
            out.append(escape("".join(chunk)))
        elif op == "equal":       # a lone separator between two changes stays inside the mark
            pending.extend(chunk)
        else:
            pending.extend(chunk)
    flush()
    return Markup("").join(out)


def _saml_apps(db):
    return db.scalars(select(Application).where(Application.is_saml.is_(True),
                                                Application.removed_from_okta.is_(False))
                      .order_by(Application.label)).all()


@bp.app_template_filter("dt")
def _fmt_dt(value, fmt="%Y-%m-%d %H:%M"):
    return value.strftime(fmt) + (" UTC" if "%H" in fmt else "") if value else "—"


@bp.app_template_filter("yesno")
def _yesno(value):
    return "—" if value is None else ("Yes" if value else "No")


@bp.app_template_filter("humanize")
def _humanize(value):
    out = (value or "").replace("_", " ").title().replace("Iam ", "IAM ").replace("Sp ", "SP ")
    return out.replace("Pf Configured", "PingFederate Configured")


@bp.app_context_processor
def _globals():
    return {"current_actor": session.get("actor", ""), "LEVELS": LEVELS,
            "STATUS_HELP": comparison.STATUS_HELP, "STATUS_ORDER": comparison.STATUS_ORDER}


# ---------------------------------------------------------------------------
@bp.get("/")
def dashboard():
    db = SessionLocal()
    protocol = (request.args.get("protocol") or "ALL").upper()
    if protocol not in ("ALL", "SAML", "OIDC"):
        protocol = "ALL"
    apps = db.scalars(select(Application).where(Application.removed_from_okta.is_(False))).all()
    saml = [a for a in apps if a.is_saml]
    oidc = [a for a in apps if a.is_oidc]
    selected = {"ALL": saml + oidc, "SAML": saml, "OIDC": oidc}[protocol]
    by_mode = Counter(a.sign_on_mode for a in apps)
    by_state = Counter(a.state for a in saml)
    code_counts = db.execute(
        select(Finding.code, Finding.severity, func.count(func.distinct(Finding.app_id)))
        .join(Application).where(Application.removed_from_okta.is_(False))
        .group_by(Finding.code, Finding.severity)).all()
    code_counts = sorted(code_counts, key=lambda r: (SEV_ORDER[r[1]], -r[2], r[0]))
    last_run = db.scalars(select(DiscoveryRun).order_by(DiscoveryRun.id.desc()).limit(1)).first()
    now = utcnow()
    expiring = sorted(
        [(a, c) for a in saml for c in a.certificates
         if c.not_after and (c.is_active_signing_key or len(a.certificates) == 1)
         and (c.not_after - now).days < _settings().cert_expiry_warning_days],
        key=lambda t: t[1].not_after)
    in_scope = [a for a in selected if a.state != "OUT_OF_SCOPE"]
    readiness = [pf_readiness(a) for a in saml if a.saml and a.state != "OUT_OF_SCOPE"]
    pf_summary = {
        "ognl_apps": sum(1 for r in readiness if r["ognl_claims"]),
        "ognl_claims": sum(len(r["ognl_claims"]) for r in readiness),
        "issuance": sum(1 for r in readiness if r["issuance_criteria"]),
        "okta_only_groups": sorted({g for r in readiness for g in r["okta_only_groups"]}),
        "ldap_attributes": sorted({x for r in readiness for x in r["ldap_attributes"]}),
        "missing_inputs": sorted({x for r in readiness for x in r["missing_inputs"]}),
        "vsid": sum(1 for r in readiness if r["virtual_server_id"]),
        "dup": sum(1 for r in readiness if r["duplicate_entity_id"]),
    }
    # Complexity (rows, high->low) x Impact (cols, low->high)
    matrix = {(c, i): [] for c in LEVELS for i in LEVELS}
    for a in in_scope:
        if a.complexity_level and a.impact_level:
            matrix[(a.complexity_level, a.impact_level)].append(a)
    max_cell = max([len(v) for v in matrix.values()] + [1])
    waves = Counter(a.suggested_wave for a in in_scope if a.suggested_wave)
    assessed = {a.id: ai.latest_assessment(db, a.id) for a in in_scope if a.is_saml}
    stats = {
        "total": len(apps), "saml": len(saml), "oidc": len(oidc), "selected": len(selected),
        "other": len(apps) - len(saml) - len(oidc),
        "custom": sum(1 for a in saml if a.is_custom_saml),
        "catalog": sum(1 for a in saml if not a.is_custom_saml),
        "users": sum(a.user_count for a in in_scope),
        "blocked": sum(1 for a in in_scope if a.suggested_wave == "Blocked"),
        "accepted": sum(1 for x in assessed.values() if x and x.review_status == "ACCEPTED"),
        "pending": sum(1 for x in assessed.values() if x and x.status == "VALID" and x.review_status == "PENDING"),
        "not_assessed": sum(1 for x in assessed.values() if not x),
        "overall": Counter(a.overall_level for a in in_scope if a.overall_level),
    }
    return render_template("dashboard.html", stats=stats, by_mode=by_mode, by_state=by_state,
                           code_counts=code_counts, last_run=last_run, expiring=expiring, now=now,
                           states=list(MigrationState), pf=pf_summary, matrix=matrix, max_cell=max_cell,
                           waves=waves, wave_names=WAVES, protocol=protocol)


@bp.get("/applications")
def applications():
    db = SessionLocal()
    protocol = (request.args.get("protocol") or ("ALL" if request.args.get("scope") == "all" else "SAML")).upper()
    if protocol not in PROTOCOLS + ("ALL",):
        protocol = "SAML"
    q = (request.args.get("q") or "").strip().lower()
    f = {k: request.args.get(k) or "" for k in ("code", "severity", "state", "overall", "wave",
                                                  "complexity", "impact")}
    stmt = select(Application).where(Application.removed_from_okta.is_(False)).order_by(Application.label)
    apps = db.scalars(stmt).all()
    if protocol != "ALL":
        apps = [a for a in apps if a.protocol == protocol]
    if q:
        apps = [a for a in apps if q in a.label.lower() or q in a.okta_name.lower() or q in a.id.lower()]
    if f["code"]:
        apps = [a for a in apps if any(x.code == f["code"] for x in a.findings)]
    if f["severity"]:
        apps = [a for a in apps if _worst(a.findings) == f["severity"]]
    for key, attr in (("state", "state"), ("overall", "overall_level"), ("wave", "suggested_wave"),
                      ("complexity", "complexity_level"), ("impact", "impact_level")):
        if f[key]:
            apps = [a for a in apps if getattr(a, attr) == f[key]]
    rows = [{"app": a, "worst": _worst(a.findings), "claims": len(a.claims),
             "fcount": Counter(x.severity for x in a.findings),
             "assessment": ai.latest_assessment(db, a.id) if a.is_saml else None} for a in apps]
    return render_template("applications.html", rows=rows, protocol=protocol, q=q, f=f,
                           states=list(MigrationState), waves=WAVES, counts=_protocol_counts(db))


@bp.get("/applications/<app_id>")
def application(app_id: str):
    db = SessionLocal()
    a = db.get(Application, app_id) or abort(404)
    findings = sorted(a.findings, key=lambda x: (SEV_ORDER[x.severity], x.code))
    groups = [x for x in a.assignments if x.principal_type == "GROUP"]
    users = [x for x in a.assignments if x.principal_type == "USER"]
    raw = db.scalars(select(RawSnapshot).where(RawSnapshot.app_id == app_id, RawSnapshot.kind == "app")
                     .order_by(RawSnapshot.id.desc()).limit(1)).first()
    targets = [t for t in ALLOWED_TRANSITIONS[MigrationState(a.state)] if t in MANUAL_TARGETS]
    cmp_rows = comparison.build(a, _settings()) if a.in_scope_protocol else []
    assessments = db.scalars(select(AiAssessment).where(AiAssessment.app_id == app_id)
                             .order_by(AiAssessment.id.desc())).all()
    recon, tasks, bstatus = None, {}, None
    if a.in_scope_protocol:
        from app.services import plan as planmod
        from app.services.reconcile import build_status, reconcile
        recon = next((r for r in reconcile(db)[0] if r.app.id == a.id), None)
        tasks = planmod.ensure_tasks(db, a)
        bstatus = build_status(a, recon, tasks)
        db.commit()
    return render_template(
        "application.html", a=a, findings=findings, groups=groups, users=users, raw=raw,
        targets=targets, now=utcnow(), pf=pf_readiness(a) if a.is_saml and a.saml else None,
        score=risk.latest_score(db, a.id), cmp_rows=cmp_rows, cmp_summary=comparison.summarise(cmp_rows),
        cmp_sections=comparison.sections(cmp_rows), assessments=assessments, latest=assessments[0] if assessments else None,
        anthropic_ready=bool(_settings().anthropic_api_key), recon=recon, tasks=tasks, bstatus=bstatus)


@bp.get("/applications/<app_id>/report")
def app_report(app_id: str):
    db = SessionLocal()
    a = db.get(Application, app_id) or abort(404)
    if not a.in_scope_protocol:
        abort(404)
    cmp_rows = comparison.build(a, _settings())
    return render_template("report.html", a=a, score=risk.latest_score(db, a.id),
                           latest=ai.latest_assessment(db, a.id), pf=pf_readiness(a),
                           cmp_rows=cmp_rows, cmp_summary=comparison.summarise(cmp_rows),
                           findings=sorted(a.findings, key=lambda x: (SEV_ORDER[x.severity], x.code)),
                           now=utcnow())


# --- actions -------------------------------------------------------------------
@bp.post("/applications/<app_id>/state")
def change_state(app_id: str):
    db = SessionLocal()
    a = db.get(Application, app_id) or abort(404)
    actor, reason = _actor(), (request.form.get("reason") or "").strip()
    try:
        target = MigrationState(request.form.get("target", ""))
        if target not in MANUAL_TARGETS:
            raise InvalidTransition("That transition is not available yet")
        if not reason:
            raise InvalidTransition("A reason is required")
        transition(db, a, target, actor=actor, reason=reason)
        db.commit()
        flash(f"{a.label}: moved to {target.value}", "ok")
    except (ValueError, InvalidTransition) as exc:
        db.rollback()
        flash(str(exc), "error")
    return redirect(url_for("web.application", app_id=app_id, _anchor="tab-business"))


@bp.post("/applications/<app_id>/details")
def update_details(app_id: str):
    """Business context the API cannot provide; feeds the Impact score."""
    db = SessionLocal()
    a = db.get(Application, app_id) or abort(404)
    actor = _actor()
    if not actor:
        flash("Your name is required to record changes", "error")
        return redirect(url_for("web.application", app_id=app_id, _anchor="tab-business"))
    fields = ("business_owner", "business_criticality", "has_test_environment", "wave", "notes")
    before = {k: getattr(a, k) for k in fields}
    a.business_owner = request.form.get("business_owner") or None
    crit = request.form.get("business_criticality") or None
    a.business_criticality = crit if crit in {"LOW", "MEDIUM", "HIGH"} else None
    a.has_test_environment = {"yes": True, "no": False}.get(request.form.get("has_test_environment"))
    a.wave = request.form.get("wave") or None
    a.notes = request.form.get("notes") or None
    after = {k: getattr(a, k) for k in fields}
    db.add(MigrationEvent(app_id=a.id, actor=actor, event_type="DETAILS_UPDATED",
                          detail={"before": before, "after": after}))
    db.flush()
    old = (a.overall_level, a.impact_level)
    risk.score_app(db, a, risk.load_weights(_settings().risk_weights_file))
    db.commit()
    msg = "Details saved"
    if (a.overall_level, a.impact_level) != old:
        msg += f". Impact is now {a.impact_level}, overall {a.overall_level}"
    flash(msg, "ok")
    return redirect(url_for("web.application", app_id=app_id, _anchor="tab-business"))


@bp.post("/applications/<app_id>/assess")
def assess(app_id: str):
    db = SessionLocal()
    a = db.get(Application, app_id) or abort(404)
    actor = _actor() or "ui-operator"
    provider = request.form.get("provider") or None
    try:
        row = ai.run_assessment(db, a, _settings(), actor, provider_name=provider,
                                force=bool(request.form.get("force")))
        db.commit()
        cat = "ok" if row.status == "VALID" else "error"
        flash(f"Assessment #{row.id} ({row.provider}): {row.status}", cat)
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "error")
    return redirect(url_for("web.application", app_id=app_id, _anchor="tab-assessment"))


@bp.post("/assess-all")
def assess_all():
    db = SessionLocal()
    actor = _actor() or "ui-operator"
    provider = request.form.get("provider") or None
    counts = Counter()
    try:
        for a in _saml_apps(db):
            if a.state == "OUT_OF_SCOPE":
                continue
            counts[ai.run_assessment(db, a, _settings(), actor, provider_name=provider).status] += 1
        db.commit()
        flash("Assessments: " + ", ".join(f"{v} {k.lower()}" for k, v in counts.items()), "ok")
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "error")
    return redirect(url_for("web.dashboard"))


@bp.post("/assessments/<int:aid>/review")
def review_assessment(aid: int):
    db = SessionLocal()
    row = db.get(AiAssessment, aid) or abort(404)
    try:
        ai.review(db, row, _actor(), request.form.get("decision", ""), request.form.get("comment", ""))
        db.commit()
        flash(f"Assessment #{aid} {row.review_status.lower()}", "ok")
    except (ValueError, InvalidTransition) as exc:
        db.rollback()
        flash(str(exc), "error")
    return redirect(url_for("web.application", app_id=row.app_id, _anchor="tab-assessment"))


@bp.post("/discovery/run")
def discovery_run():
    s = _settings()
    actor = _actor() or "ui-operator"
    try:
        run = run_discovery(SessionLocal(), build_source(s), s, actor=actor, source_mode=s.okta_source.value)
        flash(f"Discovery run {run.id} complete: {run.apps_total} apps, {run.saml_apps} SAML, "
              f"{run.new_apps} new, {run.changed_apps} changed, {run.removed_apps} removed.", "ok")
    except (OktaError, OSError) as exc:
        flash(f"Discovery failed: {exc}", "error")
    return redirect(url_for("web.dashboard"))


@bp.get("/discovery/runs")
def discovery_runs():
    runs = SessionLocal().scalars(select(DiscoveryRun).order_by(DiscoveryRun.id.desc()).limit(50)).all()
    return render_template("runs.html", runs=runs)


@bp.get("/audit")
def audit():
    events = SessionLocal().scalars(select(MigrationEvent).order_by(MigrationEvent.id.desc()).limit(300)).all()
    return render_template("audit.html", events=events)


@bp.get("/reports")
def reports():
    db = SessionLocal()
    return render_template("reports.html", apps=_protocol_apps(db))


# --- exports -----------------------------------------------------------------
def _xlsx_response(data: bytes, name: str) -> Response:
    return Response(data, mimetype=XLSX, headers={"Content-Disposition": f"attachment; filename={name}"})


@bp.get("/export/report.xlsx")
def export_xlsx():
    db = SessionLocal()
    proto = (request.args.get("protocol") or "ALL").upper()
    apps = [a for a in _protocol_apps(db, proto if proto in ("SAML", "OIDC") else "ALL")
            if a.state != "OUT_OF_SCOPE" or request.args.get("all")]
    data = build_workbook(db, apps, _settings(), "Okta to PingFederate SAML Migration Report")
    record_event(db, "REPORT_EXPORTED", session.get("actor") or "ui-operator", None, {"apps": len(apps)})
    db.commit()
    return _xlsx_response(data, f"okta_pingfederate_report_{utcnow():%Y%m%d}.xlsx")


@bp.get("/applications/<app_id>/export.xlsx")
def export_app_xlsx(app_id: str):
    db = SessionLocal()
    a = db.get(Application, app_id) or abort(404)
    data = build_workbook(db, [a], _settings(), f"{a.label}: Okta to PingFederate")
    slug = re.sub(r"[^A-Za-z0-9]+", "_", a.label).strip("_")[:40] or a.id
    return _xlsx_response(data, f"{slug}_okta_pingfederate.xlsx")


CSV_COLUMNS = ["okta_app_id", "label", "okta_name", "sign_on_mode", "okta_status", "type",
               "state", "config_completeness", "entity_id", "acs_url", "name_id_template",
               "name_id_format", "claims", "complex_claims", "group_claims", "users",
               "direct_users", "groups", "cert_expires", "critical", "warning", "info",
               "finding_codes",
               "complexity_score", "complexity_level", "impact_score", "impact_level", "overall_level",
               "blocked", "suggested_wave",
               "pf_nameid_source", "pf_ognl_claims", "pf_ldap_attributes", "pf_missing_directory_inputs",
               "pf_needs_issuance_criteria", "pf_okta_only_groups_to_create", "pf_needs_virtual_server_id",
               "pf_duplicate_entity_id",
               "business_owner", "criticality", "test_env", "wave"]


def _inventory_rows():
    for a in _saml_apps(SessionLocal()):
        s = a.saml
        active = [c for c in a.certificates if c.is_active_signing_key] or a.certificates
        sev = Counter(x.severity for x in a.findings)
        pf = pf_readiness(a)
        yield {
            "okta_app_id": a.id, "label": a.label, "okta_name": a.okta_name,
            "sign_on_mode": a.sign_on_mode, "okta_status": a.okta_status,
            "type": "custom" if a.is_custom_saml else "catalog", "state": a.state,
            "config_completeness": s.config_completeness if s else "",
            "entity_id": s.audience if s else "", "acs_url": s.sso_acs_url if s else "",
            "name_id_template": s.name_id_template if s else "",
            "name_id_format": s.name_id_format if s else "",
            "claims": len(a.claims),
            "complex_claims": sum(1 for c in a.claims if c.expression_kind == "COMPLEX"),
            "group_claims": sum(1 for c in a.claims if c.claim_type == "GROUP"),
            "users": a.user_count, "direct_users": a.direct_user_count, "groups": a.group_count,
            "cert_expires": active[0].not_after.date().isoformat() if active and active[0].not_after else "",
            "critical": sev["CRITICAL"], "warning": sev["WARNING"], "info": sev["INFO"],
            "finding_codes": ";".join(sorted({x.code for x in a.findings})),
            "complexity_score": a.complexity_score, "complexity_level": a.complexity_level,
            "impact_score": a.impact_score, "impact_level": a.impact_level,
            "overall_level": a.overall_level, "blocked": str(bool(a.blocked)).lower(),
            "suggested_wave": a.suggested_wave or "",
            "pf_nameid_source": pf["nameid_source"] or "",
            "pf_ognl_claims": ";".join(pf["ognl_claims"]),
            "pf_ldap_attributes": ";".join(pf["ldap_attributes"]),
            "pf_missing_directory_inputs": ";".join(pf["missing_inputs"]),
            "pf_needs_issuance_criteria": str(pf["issuance_criteria"]).lower(),
            "pf_okta_only_groups_to_create": ";".join(pf["okta_only_groups"]),
            "pf_needs_virtual_server_id": str(pf["virtual_server_id"]).lower(),
            "pf_duplicate_entity_id": str(pf["duplicate_entity_id"]).lower(),
            "business_owner": a.business_owner or "", "criticality": a.business_criticality or "",
            "test_env": "" if a.has_test_environment is None else str(a.has_test_environment).lower(),
            "wave": a.wave or "",
        }


@bp.get("/export/inventory.csv")
def export_csv():
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS)
    w.writeheader()
    for row in _inventory_rows():
        w.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@" else v) for k, v in row.items()})
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=saml_inventory.csv"})


@bp.get("/api/applications")
def api_applications():
    return jsonify(list(_inventory_rows()))
