"""Strategy model: tenant discovery, capability catalog, decisions, dependencies, waves, pack and UI."""
from __future__ import annotations

import io
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from openpyxl import load_workbook

from app.integrations.okta.client import build_source
from app.models.db import (
    Application, Dependency, KnowledgeChunk, KnowledgeDoc, MigrationEvent, TenantObject, TenantScan,
)
from app.services import decisions, risk
from app.services.discovery import run_discovery
from app.strategy_model import catalog as cat
from app.strategy_model import dependencies as dg
from app.strategy_model import export, service, waves
from tests.conftest import csrf

KB = Path(__file__).resolve().parent.parent / "data" / "knowledge" / "northwind-architecture-notes.md"
CSV = Path(__file__).resolve().parent.parent / "data" / "samples" / "dependencies.csv"
IDS = {"handbook": "0oa8handbook0000008", "vendor": "0oa9vendorportal009", "travel": "0oa6legacytravel006",
       "snow": "0oa4servicenow00004", "sfdc": "0oa5salesforce00005", "portal": "0oa7employeeportal7",
       "expense": "0oa1expenseportal01", "uat": "0oa1expenseuat00011", "mobile": "0oa8mobileexpense08",
       "report": "0oa9reportingapi009", "wiki": "0oa3engwiki00000003"}


@pytest.fixture
def disc(db, settings):
    run_discovery(db, build_source(settings), settings, actor="t")
    db.commit()
    return db


def _strategy(db, key):
    return db.get(Application, IDS[key]).strategy


# --- discovery -----------------------------------------------------------------------
def test_tenant_objects_discovered_and_linked(disc):
    scans = {s.kind: s for s in disc.query(TenantScan).all()}
    from app.integrations.okta.client import TENANT_KINDS
    assert set(scans) == set(TENANT_KINDS) and all(s.status == "OK" for s in scans.values())
    assert scans["policies"].count == 7
    hi = disc.query(TenantObject).filter_by(kind="policies", okta_id="rst0highassur00001").one()
    assert set(hi.app_ids) == {IDS["sfdc"], "0oa2hranalytics0002"}
    assert disc.get(Application, IDS["report"]).auth_server_id == "aus0nwapi000000001"
    assert disc.get(Application, IDS["sfdc"]).okta_features[0].startswith("PUSH_")


def test_missing_tenant_export_is_recorded_not_fatal(db, settings, export_dir):
    shutil.rmtree(export_dir / "tenant")
    run = run_discovery(db, build_source(settings), settings, actor="t")
    assert run.status == "SUCCESS"
    assert {s.status for s in db.query(TenantScan).all()} == {"NOT_EXPORTED"}
    assert db.get(Application, IDS["expense"]).strategy is not None


# --- catalog -----------------------------------------------------------------------------
def test_catalog_rows_valid_and_override_file(tmp_path):
    for c in cat.CATALOG.values():
        assert c.compatibility in cat.COMPAT_ORDER and c.strategy in cat.STRATEGIES and c.evidence
    f = tmp_path / "cat.json"
    f.write_text(json.dumps([{"key": "auth.okta_verify", "compatibility": "EQUIVALENT", "strategy": "TRANSFORM",
                              "review": "DOCS"}]))
    c2 = cat.load_catalog(f)
    assert c2["auth.okta_verify"].compatibility == "EQUIVALENT" and cat.CATALOG["auth.okta_verify"].compatibility == "PARTIAL"
    f.write_text(json.dumps([{"key": "zone.ip", "strategy": "MAYBE"}]))
    with pytest.raises(ValueError):
        cat.load_catalog(f)


# --- decisions ----------------------------------------------------------------------------
def test_app_strategies_on_sample_tenant(disc, settings):
    assert _strategy(disc, "handbook") == "RETIRE"          # bookmark
    assert _strategy(disc, "vendor") == "REDESIGN"          # password vaulting
    assert _strategy(disc, "travel") == "RETIRE"            # inactive
    assert _strategy(disc, "uat") == "RETIRE"               # unused
    assert _strategy(disc, "snow") == "REDESIGN"            # Okta imports users from the app
    assert _strategy(disc, "sfdc") == "TRANSFORM"           # provisioning via connector
    assert _strategy(disc, "portal") == "TRANSFORM"         # custom authorization server
    assert _strategy(disc, "expense") == "RETAIN"           # blocked by the duplicate entity ID
    decisions.decide(disc, "DUPLICATE_ENTITY_ID", "Lead", "Decommission the duplicate (e.g. unused UAT)", None, None, None)
    risk.score_all(disc, risk.load_weights(None))
    service.analyse(disc, settings)
    assert _strategy(disc, "expense") == "RECREATE"
    reasons = disc.get(Application, IDS["vendor"]).strategy_reasons
    assert reasons[0]["rule"] == "app.swa" and "evidence" in reasons[0]


def test_tenant_object_strategies(disc):
    by = {(o.kind, o.name): o for o in disc.query(TenantObject).all()}
    assert by[("group_rules", "Finance department")].strategy == "REDESIGN"
    assert by[("network_zones", "Corporate network")].strategy == "RECREATE"
    assert by[("network_zones", "High-risk countries")].strategy == "REDESIGN"
    assert by[("authenticators", "Security Question")].strategy == "RETIRE"          # inactive
    assert by[("authorization_servers", "default")].strategy is None                 # nothing custom
    assert by[("inline_hooks", "Add entitlements to tokens")].compat_level == "MEDIUM"


def test_override_needs_name_and_reason_and_can_revert(disc, settings):
    app = disc.get(Application, IDS["sfdc"])
    with pytest.raises(ValueError, match="named"):
        service.set_override(disc, settings, app, "REDESIGN", "x", "system")
    with pytest.raises(ValueError, match="reason"):
        service.set_override(disc, settings, app, "REDESIGN", " ", "Lead")
    service.set_override(disc, settings, app, "REDESIGN", "Moving to a new SCIM design", "Lead")
    assert app.strategy == "REDESIGN" and app.strategy_reasons[0]["rules_chose"] == "TRANSFORM"
    service.set_override(disc, settings, app, "RULES", "Back to the rules", "Lead")
    assert app.strategy == "TRANSFORM"
    assert disc.query(MigrationEvent).filter_by(event_type="STRATEGY_OVERRIDE").count() == 2


# --- dependencies ---------------------------------------------------------------------------
def _kb(db):
    doc = KnowledgeDoc(title="notes", filename="n.md", sha256="x", uploaded_by="t")
    db.add(doc)
    db.flush()
    for i, para in enumerate(KB.read_text().split("\n\n")):
        db.add(KnowledgeChunk(doc_id=doc.id, position=i, text=para))
    db.flush()


def test_discovered_import_manual_and_rejection_kept(disc, settings):
    kinds = {(d.source, d.kind) for d in disc.query(Dependency).filter_by(origin="DISCOVERED")}
    assert (dg.app_node(IDS["report"]), "USES_AUTH_SERVER") in kinds and (dg.app_node(IDS["sfdc"]), "USES_POLICY") in kinds
    res = dg.import_csv(disc, CSV.read_text(), "Asha")
    assert res == {"added": 3, "updated": 0, "errors": [], "external": ["Jira DC", "Workday"]}
    d = disc.query(Dependency).filter_by(source=dg.app_node(IDS["wiki"])).one()
    assert d.target == "ext:Jira DC" and d.status == "CONFIRMED"
    with pytest.raises(ValueError, match="source"):
        dg.import_csv(disc, "a,b\n1,2", "Asha")
    with pytest.raises(ValueError, match="itself"):
        dg.add_manual(disc, "Salesforce", "Salesforce", "DEPENDS_ON", "", "Asha")
    with pytest.raises(ValueError, match="named"):
        dg.add_manual(disc, "Salesforce", "ServiceNow", "DEPENDS_ON", "", "")
    pol = disc.query(Dependency).filter_by(source=dg.app_node(IDS["sfdc"]), kind="USES_POLICY").one()
    with pytest.raises(ValueError, match="why"):
        dg.decide(disc, pol.id, "Lead", "REJECTED")
    dg.decide(disc, pol.id, "Lead", "REJECTED", "Policy is being retired")
    service.analyse(disc, settings)                                          # a re-run keeps the rejection
    assert disc.get(Dependency, pol.id).status == "REJECTED"


def test_suggestions_from_documents_need_confirmation(disc, settings):
    _kb(disc)
    res = dg.suggest(disc, settings, "Asha")
    assert res["method"] == "offline text analysis"
    pairs = {(d.source, d.target) for d in disc.query(Dependency).filter_by(status="SUGGESTED")}
    assert (dg.app_node(IDS["portal"]), dg.app_node(IDS["report"])) in pairs
    assert (dg.app_node(IDS["mobile"]), dg.app_node(IDS["expense"])) in pairs          # not the UAT copy
    assert (dg.app_node(IDS["snow"]), dg.app_node(IDS["sfdc"])) in pairs
    before = {r.app.id: r.wave for r in service.build_pack(disc, settings).apps}
    sug = disc.query(Dependency).filter_by(source=dg.app_node(IDS["snow"]), status="SUGGESTED").one()
    dg.decide(disc, sug.id, "Asha", "CONFIRMED")
    after = {r.app.id: r for r in service.build_pack(disc, settings).apps}
    assert before[IDS["snow"]] == "Wave 1" and after[IDS["snow"]].wave == after[IDS["sfdc"]].wave == "Wave 2"
    assert any("depends on Salesforce" in x for x in after[IDS["snow"]].wave_reasons)


def test_claude_suggestions_are_filtered(disc, settings):
    _kb(disc)
    ref = next(c.ref for c in disc.query(KnowledgeChunk).all() if "Employee Portal calls" in c.text)

    class Fake:
        class messages:
            @staticmethod
            def create(**kw):
                assert kw["tool_choice"]["name"] == "submit_dependencies"
                return SimpleNamespace(content=[SimpleNamespace(type="tool_use", input={"dependencies": [
                    {"source": "Employee Portal", "target": "Reporting API", "kind": "CALLS", "citation": ref},
                    {"source": "Employee Portal", "target": "Made Up App", "kind": "CALLS", "citation": ref},
                    {"source": "Salesforce", "target": "ServiceNow", "kind": "CALLS", "citation": "KB-999"}]})])

    res = dg.suggest(disc, settings, "Asha", client=Fake())
    assert res["found"] == 1 and res["method"] == "Claude"


def test_wave_planner_rules():
    A = lambda i, w, s="RECREATE": SimpleNamespace(id=i, label=i, wave=None, suggested_wave=w, strategy=s)  # noqa: E731
    E = lambda s, t: SimpleNamespace(source=f"app:{s}", target=f"app:{t}")  # noqa: E731
    apps = [A("a", "Wave 0 (pilot)"), A("b", "Wave 2"), A("c", "Wave 1"), A("d", "Wave 1"), A("e", "Wave 1"),
            A("f", "Wave 1", "RETIRE"), A("g", "Wave 1"), A("h", "Wave 1", "RETAIN")]
    p = waves.plan(apps, [E("a", "b"), E("c", "d"), E("d", "c"), E("e", "f"), E("g", "h")])
    assert p["a"].wave == "Wave 2" and "depends on b" in p["a"].reasons[0]
    assert p["c"].wave == p["d"].wave == "Wave 1" and any("Mutual dependency" in f for f in p["c"].flags)
    assert p["e"].wave == "Wave 1" and any("Decommission review" in f for f in p["e"].flags)
    assert p["f"].wave == "Decommission review" and p["h"].wave == "Blocked" and p["g"].wave == "Blocked"


# --- pack, exports and UI -----------------------------------------------------------------
def test_pack_summary_and_exports(disc, settings):
    p = service.build_pack(disc, settings)
    s = p.summary
    assert s["total"] == 13 and s["migratable"] + s["redesign"] + s["retire"] + s["retain"] == 13
    assert p.foundation and all(f["cap"].prerequisite for f in p.foundation)
    assert any(m["cap"].key == "group_rule" for m in p.matrix)
    portal = next(r for r in p.apps if r.app.id == IDS["portal"])
    assert any("API accepts access tokens" in t for t in portal.validation)
    wb = load_workbook(io.BytesIO(export.to_xlsx(p, "Northwind")))
    assert {"Executive summary", "Portfolio (architect)", "Compatibility matrix", "Tenant objects", "Dependencies",
            "Wave plan", "Engineer detail", "Capability catalog"} <= set(wb.sheetnames)
    assert export.to_docx(p, "Northwind")[:2] == b"PK"


def test_strategy_pages_and_forms(client, app, settings):
    from app.models.db import SessionLocal
    with app.app_context():
        run_discovery(SessionLocal(), build_source(settings), settings, actor="t")
        SessionLocal().commit()
    assert client.get("/strategy-pack").status_code == 200
    for key in ("wiki", "portal", "vendor"):
        r = client.get(f"/strategy-pack/apps/{IDS[key]}")
        assert r.status_code == 200 and b"Validation checklist" in r.data
    tok = csrf(client)
    r = client.post("/dependencies/import", data={"_csrf": tok, "actor": "Asha",
                                                  "file": (io.BytesIO(CSV.read_bytes()), "deps.csv")},
                    content_type="multipart/form-data", follow_redirects=True)
    assert b"Imported: 3 new" in r.data
    r = client.post("/dependencies/add", data={"_csrf": tok, "actor": "Asha", "source": "Salesforce",
                                               "target": "ServiceNow", "kind": "CALLS"}, follow_redirects=True)
    assert b"Dependency added" in r.data
    r = client.post(f"/strategy-pack/apps/{IDS['sfdc']}/override",
                    data={"_csrf": tok, "actor": "Asha", "strategy": "REDESIGN", "reason": "SCIM redesign"},
                    follow_redirects=True)
    assert b"Architecture decision recorded" in r.data and b"Override by Asha" in r.data
    assert client.post("/dependencies/add", data={"actor": "Asha"}).status_code in (400, 403)   # CSRF enforced
    for path in ("/strategy-pack.xlsx", "/strategy-pack.docx"):
        assert client.get(path).data[:2] == b"PK"


def test_review_regressions(disc, settings):
    """Fixes from the independent review."""
    import time
    # dense graph: strongly connected components, not every cycle
    A = lambda i: SimpleNamespace(id=i, label=i, wave=None, suggested_wave="Wave 1", strategy="RECREATE")  # noqa: E731
    apps = [A(str(i)) for i in range(14)]
    edges = [SimpleNamespace(source=f"app:{a.id}", target=f"app:{b.id}") for a in apps for b in apps if a is not b]
    t0 = time.time()
    p = waves.plan(apps, edges)
    assert time.time() - t0 < 2 and len(p["0"].flags) == 1
    # a person's edge survives an Okta refresh; a re-import does not revive a rejection
    row = dg.add_manual(disc, "Salesforce", dg.obj_node("policies", "rst0highassur00001"), "USES_POLICY", "", "Alice")
    service.analyse(disc, settings)
    assert disc.get(Dependency, row.id).origin == "MANUAL"
    dg.import_csv(disc, "source,target\nMobile Expenses,Salesforce\n", "Asha")
    d = disc.query(Dependency).filter_by(source=dg.app_node(IDS["mobile"]), target=dg.app_node(IDS["sfdc"])).one()
    dg.decide(disc, d.id, "Lead", "REJECTED", "wrong")
    dg.import_csv(disc, "source,target\nMobile Expenses,Salesforce\n", "Asha")
    assert disc.get(Dependency, d.id).status == "REJECTED"
    # a row with extra fields is reported, not a crash
    res = dg.import_csv(disc, "source,target\nMobile Expenses,Expense Portal,x,y,z\n", "Asha")
    assert res["errors"] == [] and res["added"] == 1
    # "X feeds Y": Y depends on X
    doc = KnowledgeDoc(title="n", filename="n.md", sha256="y", uploaded_by="t")
    disc.add(doc)
    disc.flush()
    disc.add(KnowledgeChunk(doc_id=doc.id, position=0, text="Salesforce feeds ServiceNow with case data every hour."))
    disc.flush()
    dg.suggest(disc, settings, "Asha")
    assert disc.query(Dependency).filter_by(source=dg.app_node(IDS["snow"]), target=dg.app_node(IDS["sfdc"]),
                                            status="SUGGESTED").count() == 1


def test_unreadable_kind_keeps_previous_rows_and_old_db_is_analysed(db, settings, export_dir):
    run_discovery(db, build_source(settings), settings, actor="t")
    db.commit()
    assert db.get(Application, IDS["report"]).auth_server_id
    (export_dir / "tenant" / "authorization_servers.json").unlink()
    run_discovery(db, build_source(settings), settings, actor="t")
    db.commit()
    assert db.query(TenantObject).filter_by(kind="authorization_servers").count() == 2
    assert db.get(Application, IDS["report"]).auth_server_id == "aus0nwapi000000001"
    p = service.build_pack(db, settings)
    assert "authorization_servers" in p.summary["unscanned"]
    for a in db.query(Application).all():
        a.strategy = None
    db.flush()
    assert service.ensure_analysed(db, settings) and db.get(Application, IDS["sfdc"]).strategy == "TRANSFORM"
    s = service.build_pack(db, settings).summary
    assert s["migratable"] + s["redesign"] + s["retire"] + s["retain"] + s["unassessed"] == s["total"]
    tl = service.build_pack(db, settings).timeline
    assert tl.phases[0].name.startswith("Foundation") or any(ph.name.startswith("Foundation") for ph in tl.phases)
