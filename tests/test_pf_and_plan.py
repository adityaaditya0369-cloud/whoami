"""PingFederate read-only source, reconciliation and the migration plan."""
import io
import shutil
from pathlib import Path

import openpyxl
import pytest
from sqlalchemy import select

from app.config import Settings
from app.integrations.okta.client import FileOktaSource
from app.integrations.pingfederate import parser as pfp
from app.integrations.pingfederate.client import FilePfSource, LivePfClient
from app.models.db import Application, MigrationEvent, MigrationTask, PfObject
from app.services import plan as planmod
from app.services.discovery import run_discovery
from app.services.excel_report import build_workbook
from app.services.pf_sync import run_pf_sync
from app.services.reconcile import build_status, reconcile
from tests.conftest import csrf

PF_SAMPLE = Path(__file__).resolve().parent.parent / "data" / "pf-exports" / "sample-pf"


@pytest.fixture
def pf_dir(tmp_path):
    d = tmp_path / "pf"
    shutil.copytree(PF_SAMPLE, d)
    return d


@pytest.fixture
def synced(db, settings, export_dir, pf_dir):
    run_discovery(db, FileOktaSource(export_dir), settings, actor="t")
    run_pf_sync(db, FilePfSource(pf_dir), settings, "t")
    return db


def recon_map(db):
    recs, only = reconcile(db)
    return {r.app.label: r for r in recs}, only


# --- parser / client -------------------------------------------------------------
def test_parse_sp_connection():
    import json
    raw = json.loads((PF_SAMPLE / "sp_connections.json").read_text())["items"][0]
    m = pfp.parse_sp_connection(raw)
    assert m.kind == "SP_CONNECTION" and m.key == "https://expenses.northwind.example"
    assert m.attributes == ["SAML_SUBJECT", "email"] and m.has_issuance_criteria and m.sign_assertions


def test_parse_oauth_client_maps_enums():
    m = pfp.parse_oauth_client({"clientId": "c1", "grantTypes": ["AUTHORIZATION_CODE", "RESOURCE_OWNER_CREDENTIALS"],
                                "clientAuth": {"type": "SECRET"}, "requireProofKeyForCodeExchange": True})
    assert m.grant_types == ["authorization_code", "password"] and m.client_auth == "client_secret" and m.pkce_required


class FakeResp:
    def __init__(self, body, status=200):
        self._b, self.status_code, self.text = body, status, ""

    def json(self):
        return self._b


class FakeSession:
    def __init__(self, pages):
        self.pages, self.calls, self.headers, self.auth = list(pages), [], {}, None

    def get(self, url, params=None, timeout=None, verify=None):
        self.calls.append((url, params))
        return self.pages.pop(0)


def test_live_pf_client_pages_and_headers():
    s = Settings(PF_SOURCE="live", PF_ADMIN_URL="https://pf.example:9999/pf-admin-api/v1",
                 PF_ADMIN_USER="auditor", PF_ADMIN_PASSWORD="pw", _env_file=None)
    items = [{"entityId": f"e{i}", "id": str(i)} for i in range(100)]
    fs = FakeSession([FakeResp({"items": items, "totalCount": 101}),
                      FakeResp({"items": [{"entityId": "e100", "id": "100"}], "totalCount": 101})])
    c = LivePfClient(s, fs)
    assert len(c.list_sp_connections()) == 101
    assert fs.headers["X-XSRF-Header"] == "PingFederate" and fs.auth == ("auditor", "pw")
    assert fs.calls[1][1]["page"] == 2


def test_live_pf_settings_validation():
    with pytest.raises(ValueError):
        Settings(PF_SOURCE="live", PF_ADMIN_URL="http://insecure", PF_ADMIN_USER="a", PF_ADMIN_PASSWORD="b", _env_file=None)
    with pytest.raises(ValueError):
        Settings(PF_SOURCE="live", PF_ADMIN_URL="https://pf", _env_file=None)


# --- sync & reconciliation -----------------------------------------------------------
def test_sync_counts_and_removal(synced, settings, pf_dir):
    assert len(synced.scalars(select(PfObject)).all()) == 7
    (pf_dir / "oauth_clients.json").write_text('{"items": []}')
    run_pf_sync(synced, FilePfSource(pf_dir), settings, "t")
    assert len(synced.scalars(select(PfObject).where(PfObject.removed.is_(False))).all()) == 4


def test_reconciliation_outcomes(synced):
    rm, only = recon_map(synced)
    assert rm["Expense Portal"].status == "MATCHES"
    assert rm["ServiceNow"].status == "MATCHES" and rm["ServiceNow"].matched_by == "name"
    assert rm["Reporting API"].status == "MATCHES"
    wiki = {c.check for c in rm["Engineering Wiki (Confluence DC)"].problems}
    assert wiki == {"ACS URLs", "Attribute contract", "Virtual server ID", "Issuance criteria (access control)",
                    "Single logout"}
    assert {c.check for c in rm["Employee Portal"].problems} == {"Redirect URIs"}
    assert rm["Expense Portal (UAT)"].problems[0].check == "Own SP connection"
    assert rm["Salesforce"].status == "NOT_BUILT"
    assert {o.name for o in only} == {"Payroll (already on PingFederate)", "PingAccess agent"}


def test_build_status(synced):
    rm, _ = recon_map(synced)
    assert build_status(rm["Expense Portal"].app, rm["Expense Portal"]) == "BUILT"
    assert build_status(rm["HR Analytics (Tableau)"].app, rm["HR Analytics (Tableau)"]) == "BLOCKED"
    assert build_status(rm["Salesforce"].app, rm["Salesforce"]) == "READY_TO_BUILD"
    assert build_status(rm["Employee Portal"].app, rm["Employee Portal"]) == "BUILT_WITH_DIFFERENCES"


# --- plan --------------------------------------------------------------------------
def test_tasks_created_and_updated(synced):
    a = synced.get(Application, "0oa1expenseportal01")
    tasks = planmod.ensure_tasks(synced, a)
    assert [t.step_key for t in sorted(tasks.values(), key=lambda t: t.position)] == [s.key for s in planmod.STEPS]
    assert planmod.progress(tasks) == (0, 7)
    assert planmod.update_task(synced, tasks["PREPARE"], "alice", "DONE", "Dir team", "2026-10-01", "CHG123")
    tasks["DECOMMISSION"].status = "N/A"
    assert planmod.progress(tasks) == (1, 6) and planmod.next_step(tasks).key == "BUILD"
    assert not planmod.update_task(synced, tasks["PREPARE"], "alice", "DONE", "Dir team", "2026-10-01", "CHG123")
    ev = synced.scalars(select(MigrationEvent).where(MigrationEvent.event_type == "PLAN_TASK_UPDATED")).all()
    assert len(ev) == 1 and ev[0].detail["step"] == "PREPARE"
    with pytest.raises(ValueError):
        planmod.update_task(synced, tasks["BUILD"], "", "DONE", None, None, None)
    with pytest.raises(ValueError):
        planmod.update_task(synced, tasks["BUILD"], "alice", "DONE", None, "01/10/2026", None)


def test_verified_status(synced):
    rm, _ = recon_map(synced)
    a = rm["Expense Portal"].app
    tasks = planmod.ensure_tasks(synced, a)
    tasks["VERIFY"].status = "DONE"
    assert build_status(a, rm["Expense Portal"], tasks) == "VERIFIED"


def test_overdue(synced):
    a = synced.get(Application, "0oa1expenseportal01")
    tasks = planmod.ensure_tasks(synced, a)
    planmod.update_task(synced, tasks["BUILD"], "alice", "IN_PROGRESS", None, "2020-01-01", None)
    assert [t.step_key for t in planmod.overdue({a.id: tasks})] == ["BUILD"]


def test_excel_has_plan_and_reconciliation(synced, settings):
    apps = synced.scalars(select(Application).where(Application.is_saml | Application.is_oidc)).all()
    wb = openpyxl.load_workbook(io.BytesIO(build_workbook(synced, apps, settings, "R")))
    assert wb["Migration plan"].max_row == 1 + 7 * 11
    results = {c.value for c in wb["PingFederate reconciliation"]["H"][1:]}
    assert results == {"OK", "DIFFERS", "NOT BUILT"}


# --- routes --------------------------------------------------------------------------
def test_pingfederate_and_plan_pages(client):
    client.post("/discovery/run", data={"_csrf": csrf(client), "actor": "alice"})
    r = client.post("/pingfederate/sync", data={"_csrf": csrf(client), "actor": "alice"}, follow_redirects=True)
    assert b"4 SP connections, 3 OAuth clients" in r.data
    for text in (b"Planned", b"Found in PingFederate", b"Reconciliation", b"Only on PingFederate",
                 b"Built - differs", b"Issuance criteria (access control)"):
        assert text in r.data, text
    r = client.get("/plan")
    assert r.status_code == 200 and b"Waves board" in r.data and b"Wave 1" in r.data and b"Checklist" in r.data
    r = client.post("/applications/0oa4servicenow00004/plan",
                    data={"_csrf": csrf(client), "actor": "alice", "PREPARE_status": "DONE",
                          "PREPARE_owner": "Dir team", "BUILD_due": "2026-10-15"}, follow_redirects=True)
    assert b"Plan saved (2 step(s) changed)" in r.data and b"Checklist" in r.data
    from app.models.db import SessionLocal
    t = SessionLocal().scalars(select(MigrationTask).where(MigrationTask.app_id == "0oa4servicenow00004",
                                                           MigrationTask.step_key == "PREPARE")).one()
    assert t.status == "DONE" and t.updated_by == "alice"
    r = client.post("/applications/0oa4servicenow00004/plan",
                    data={"_csrf": csrf(client), "actor": "alice", "BUILD_due": "15-10-2026"}, follow_redirects=True)
    assert b"YYYY-MM-DD" in r.data
    r = client.get("/applications/0oa3engwiki00000003")
    assert b"Built - differs" in r.data and b'data-tab="plan"' in r.data
