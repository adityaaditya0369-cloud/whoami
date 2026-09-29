"""Flask application factory."""
from __future__ import annotations

import logging
import secrets
from pathlib import Path

import click
from flask import Flask, abort, request, session

from app.config import BASE_DIR, OktaSourceMode, Settings, get_settings
from app.models.db import SessionLocal, init_engine


def create_app(settings: Settings | None = None) -> Flask:
    settings = settings or get_settings()
    app = Flask(__name__, template_folder=str(BASE_DIR / "templates"),
                static_folder=str(BASE_DIR / "static"))
    app.config["SETTINGS"] = settings
    # Largest request: a knowledge document plus form fields (SAML responses are capped at 2 MB separately).
    app.config["MAX_CONTENT_LENGTH"] = (settings.knowledge_max_upload_mb + 2) * 1024 * 1024
    app.secret_key = settings.secret_key.get_secret_value()
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if settings.database_url.startswith("sqlite:///"):
        Path(settings.database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    init_engine(settings.database_url)

    @app.teardown_appcontext
    def _remove_session(exc=None):
        SessionLocal.remove()

    # --- minimal CSRF protection for form POSTs --------------------------
    def csrf_token() -> str:
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_urlsafe(32)
        return session["_csrf"]

    @app.before_request
    def _check_csrf():
        if request.method == "POST" and not app.config.get("TESTING_DISABLE_CSRF"):
            sent = request.form.get("_csrf", "")
            if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
                abort(400, "Invalid or missing CSRF token")

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["settings"] = settings

    from app.routes.pipeline import bp as pipeline_bp
    from app.routes.strategy import bp as strategy_bp
    from app.routes.target import bp as target_bp
    from app.routes.web import bp
    app.register_blueprint(bp)
    app.register_blueprint(target_bp)
    app.register_blueprint(strategy_bp)
    app.register_blueprint(pipeline_bp)
    from app.routes.strategy_model import bp as strategy_model_bp
    app.register_blueprint(strategy_model_bp)
    _register_cli(app)
    return app


def _register_cli(app: Flask) -> None:
    from app.integrations.okta.client import LiveOktaClient, build_source
    from app.services.discovery import run_discovery

    @app.cli.command("discover")
    @click.option("--actor", default="cli", help="Name recorded in the audit log.")
    def discover_cmd(actor):
        """Run Okta discovery using OKTA_SOURCE settings."""
        s: Settings = app.config["SETTINGS"]
        run = run_discovery(SessionLocal(), build_source(s), s, actor=actor,
                            source_mode=s.okta_source.value)
        click.echo(f"Run {run.id}: {run.status} - {run.apps_total} apps, {run.saml_apps} SAML, "
                   f"{run.new_apps} new, {run.changed_apps} changed, {run.removed_apps} removed")

    @app.cli.command("assess")
    @click.option("--actor", default="cli")
    @click.option("--provider", type=click.Choice(["offline", "anthropic"]), default=None,
                  help="Defaults to AI_PROVIDER.")
    @click.option("--force", is_flag=True, help="Re-run even if inputs are unchanged.")
    def assess_cmd(actor, provider, force):
        """Score and assess every in-scope SAML app."""
        from collections import Counter

        from app.models.db import Application
        from app.services.ai.service import run_assessment
        s: Settings = app.config["SETTINGS"]
        db = SessionLocal()
        counts = Counter()
        for a in db.query(Application).filter(Application.is_saml.is_(True),
                                              Application.removed_from_okta.is_(False)).order_by(Application.label):
            if a.state == "OUT_OF_SCOPE":
                continue
            row = run_assessment(db, a, s, actor, provider_name=provider, force=force)
            counts[row.status] += 1
            click.echo(f"{a.label:40} {row.status:16} {row.output.get('migration_approach', '')}")
        db.commit()
        click.echo(dict(counts))

    @app.cli.command("report")
    @click.option("--out", "out_path", default="migration_report.xlsx", type=click.Path(path_type=Path))
    def report_cmd(out_path: Path):
        """Write the Excel migration report."""
        from app.models.db import Application
        from app.services.excel_report import build_workbook
        s: Settings = app.config["SETTINGS"]
        db = SessionLocal()
        apps = db.query(Application).filter(Application.is_saml.is_(True) | Application.is_oidc.is_(True),
                                            Application.removed_from_okta.is_(False),
                                            Application.state != "OUT_OF_SCOPE").order_by(Application.label).all()
        out_path.write_bytes(build_workbook(db, apps, s, "Okta to PingFederate SAML Migration Report"))
        click.echo(f"Wrote {out_path} ({len(apps)} apps)")

    @app.cli.command("pf-sync")
    @click.option("--actor", default="cli")
    def pf_sync_cmd(actor):
        """Read PingFederate (PF_SOURCE=file|live) and store SP connections / OAuth clients."""
        from app.integrations.pingfederate.client import build_pf_source
        from app.services.pf_sync import run_pf_sync
        s: Settings = app.config["SETTINGS"]
        source = build_pf_source(s)
        if source is None:
            raise click.UsageError("PF_SOURCE=none")
        run = run_pf_sync(SessionLocal(), source, s, actor)
        click.echo(f"PingFederate sync {run.status}: {run.sp_connections} SP connections, {run.oauth_clients} OAuth clients")

    @app.cli.command("pf-export")
    @click.option("--out", "out_dir", required=True, type=click.Path(path_type=Path))
    def pf_export_cmd(out_dir: Path):
        """Export SP connections and OAuth clients from the PingFederate Admin API (read-only)."""
        from app.config import PfSourceMode
        from app.integrations.pingfederate.client import LivePfClient
        s: Settings = app.config["SETTINGS"]
        if s.pf_source != PfSourceMode.LIVE:
            raise click.UsageError("Set PF_SOURCE=live and PF_ADMIN_* settings to export.")
        click.echo(LivePfClient(s).export_to(out_dir))

    @app.cli.command("okta-export")
    @click.option("--out", "out_dir", required=True, type=click.Path(path_type=Path))
    def export_cmd(out_dir: Path):
        """Export a live Okta tenant to an offline folder (read-only API calls)."""
        s: Settings = app.config["SETTINGS"]
        if s.okta_source != OktaSourceMode.LIVE:
            raise click.UsageError("Set OKTA_SOURCE=live and Okta credentials to export.")
        counts = LiveOktaClient(s).export_to(out_dir)
        click.echo(f"Exported {counts['apps']} apps ({counts['detailed_apps']} SAML/OIDC with details) to {out_dir}")

    @app.cli.command("strategy-pack")
    @click.option("--out", "out_dir", default=".", help="Folder for migration-strategy-pack.xlsx / .docx")
    def strategy_pack_cmd(out_dir):
        """Recalculate the strategy model and write the Excel and Word strategy pack."""
        from pathlib import Path as _P
        from app.strategy_model import export as pack_export
        from app.strategy_model import service as sm
        s: Settings = app.config["SETTINGS"]
        db = SessionLocal()
        sm.analyse(db, s, "cli")
        db.commit()
        pack = sm.build_pack(db, s)
        if pack.summary["unscanned"]:
            click.echo("Warning: not read from Okta: " + ", ".join(pack.summary["unscanned"]))
        out = _P(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "migration-strategy-pack.xlsx").write_bytes(pack_export.to_xlsx(pack, s.customer_name))
        (out / "migration-strategy-pack.docx").write_bytes(pack_export.to_docx(pack, s.customer_name))
        sm_ = pack.summary
        click.echo(f"{sm_['total']} apps: {sm_['recreate']} recreate, {sm_['transform']} transform, {sm_['redesign']} redesign, "
                   f"{sm_['retire']} retire, {sm_['retain']} retain; {sm_['waves']} wave(s). Written to {out.resolve()}")

    @app.cli.command("kb-add")
    @click.argument("files", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option("--actor", required=True, help="Your name (recorded in the audit log).")
    @click.option("--app-id", default=None, help="Limit the document to one Okta app id.")
    def kb_add_cmd(files, actor, app_id):
        """Add documents (txt, md, docx, pdf, html) to the knowledge base."""
        from app.services import knowledge
        db = SessionLocal()
        for f in files:
            try:
                d = knowledge.add_document(db, f.name, f.read_bytes(), actor, app_id=app_id)
                db.commit()
                click.echo(f"Added {f.name}: {len(d.chunks)} passages")
            except knowledge.KnowledgeError as exc:
                db.rollback()
                click.echo(f"Skipped {f.name}: {exc}")

    @app.cli.command("agents")
    @click.option("--actor", default="cli")
    @click.option("--app-id", default=None, help="One app; default all SAML apps in DISCOVERED/ASSESSED/MAPPING_READY.")
    @click.option("--provider", type=click.Choice(["offline", "anthropic"]), default=None)
    @click.option("--force", is_flag=True)
    def agents_cmd(actor, app_id, provider, force):
        """Run the four review agents (results still need a person to accept them in the UI)."""
        from sqlalchemy import select as _select

        from app.models.db import Application
        from app.services.agents import service as ag
        s: Settings = app.config["SETTINGS"]
        db = SessionLocal()
        apps = [db.get(Application, app_id)] if app_id else [
            a for a in db.scalars(_select(Application).where(Application.removed_from_okta.is_(False)))
            if a.is_saml and a.state in ("DISCOVERED", "ASSESSED", "MAPPING_READY")]
        for a in apps:
            if a is None:
                raise click.UsageError("Unknown app id")
            r = ag.run_panel(db, a, s, actor, provider_name=provider, force=force)
            db.commit()
            c = ag.counts(r)
            click.echo(f"{a.label}: {r.status} - {c['AGREE']} agree, {c['CONCERN']} concern, {c['DISAGREE']} disagree")

    @app.cli.command("validate-saml")
    @click.argument("app_id")
    @click.argument("response_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option("--actor", required=True)
    @click.option("--stage", type=click.Choice(["BASELINE_OKTA", "PRE_CUTOVER", "POST_CUTOVER"]), required=True)
    @click.option("--cert", "cert_file", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None,
                  help="IdP signing certificate (PEM); defaults to PF_SIGNING_CERT_FILE / the Okta cert for a baseline.")
    def validate_saml_cmd(app_id, response_file, actor, stage, cert_file):
        """Validate a captured SAML response (XML, base64 or form body) and record the result."""
        from app.models.db import Application
        from app.services import cutover
        s: Settings = app.config["SETTINGS"]
        db = SessionLocal()
        a = db.get(Application, app_id)
        if a is None:
            raise click.UsageError("Unknown app id")
        v = cutover.record_validation(db, a, s, response_file.read_text(encoding="utf-8"), actor, stage, "CAPTURED",
                                      cert_pem=cert_file.read_text() if cert_file else None)
        db.commit()
        for c in v.result["checks"]:
            click.echo(f"  {c['status']:<5} {c['label']}: {c['actual']}" + (f"  ({c['note']})" if c['note'] else ""))
        click.echo(f"{a.label}: {v.verdict} (validation #{v.id}); app state {a.state}")

    @app.cli.command("test-sso")
    @click.argument("app_id")
    @click.option("--actor", required=True)
    @click.option("--stage", type=click.Choice(["PRE_CUTOVER", "POST_CUTOVER"]), default="PRE_CUTOVER")
    def test_sso_cmd(app_id, actor, stage):
        """Sign the test user in through PingFederate (headless), capture and validate the SAML response."""
        from app.models.db import Application
        from app.services import cutover, test_sso
        s: Settings = app.config["SETTINGS"]
        db = SessionLocal()
        a = db.get(Application, app_id)
        if a is None or not a.is_saml:
            raise click.UsageError("Unknown SAML app id")
        cap = test_sso.capture(s, a.saml.audience or "", screenshot_dir=Path(app.instance_path) / "test-sso")
        v = cutover.record_validation(db, a, s, cap.form_body, actor, stage, "AUTOMATED")
        db.commit()
        click.echo(f"{a.label}: {v.verdict} (validation #{v.id}); app state {a.state}")
