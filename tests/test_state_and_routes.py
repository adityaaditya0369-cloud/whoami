import pytest

from app.models.db import Application, SessionLocal
from app.models.state import ALLOWED_TRANSITIONS, InvalidTransition, MigrationState as S, check_transition
from tests.conftest import csrf


def test_every_state_has_transition_entry():
    assert set(ALLOWED_TRANSITIONS) == set(S)


def test_cannot_skip_approval():
    with pytest.raises(InvalidTransition):
        check_transition(S.PLAN_GENERATED, S.APPROVED, "alice")
    with pytest.raises(InvalidTransition):
        check_transition(S.DISCOVERED, S.PF_CONFIGURED, "alice")


def test_approval_requires_human():
    for bot in ("", "system", "AI", "claude"):
        with pytest.raises(InvalidTransition):
            check_transition(S.AWAITING_APPROVAL, S.APPROVED, bot)
    check_transition(S.AWAITING_APPROVAL, S.APPROVED, "alice@customer")


def test_rollback_path():
    check_transition(S.TESTING, S.FAILED, "system")
    check_transition(S.FAILED, S.ROLLBACK, "alice")
    check_transition(S.ROLLBACK, S.OKTA_ACTIVE, "system")


# --- routes ------------------------------------------------------------------
def run(client):
    return client.post("/discovery/run", data={"_csrf": csrf(client), "actor": "tester"},
                       follow_redirects=True)


def test_empty_dashboard(client):
    r = client.get("/")
    assert r.status_code == 200 and b"No applications yet" in r.data


def test_post_without_csrf_rejected(client):
    assert client.post("/discovery/run", data={"actor": "x"}).status_code == 400


def test_discovery_and_pages(client):
    r = run(client)
    assert b"Discovery run 1 complete" in r.data and b"PingFederate readiness" in r.data
    r = client.get("/applications")
    assert b"Engineering Wiki" in r.data and b"Employee Portal" not in r.data
    assert b"Employee Portal" in client.get("/applications?scope=all").data
    assert b"Legacy Travel" in client.get("/applications?severity=CRITICAL").data
    r = client.get("/applications/0oa3engwiki00000003")
    assert r.status_code == 200 and b"ENG-.*" in r.data and b"GROUP_CLAIM" in r.data
    assert b"PingFederate readiness checklist" in r.data and b"GROUP_LDAP_SEARCH" in r.data
    assert client.get("/applications/nope").status_code == 404
    assert client.get("/discovery/runs").status_code == 200
    assert b"DISCOVERY_COMPLETED" in client.get("/audit").data


def test_csv_and_json_export(client):
    run(client)
    r = client.get("/export/inventory.csv")
    lines = r.data.decode().strip().splitlines()
    assert lines[0].startswith("okta_app_id,label") and len(lines) == 8
    assert "pf_needs_issuance_criteria" in lines[0]
    data = client.get("/api/applications").get_json()
    wiki = next(x for x in data if x["okta_app_id"] == "0oa3engwiki00000003")
    assert wiki["group_claims"] == 1 and wiki["complex_claims"] == 2
    assert wiki["pf_ognl_claims"] == "fullName;wikiRole"
    assert wiki["pf_needs_virtual_server_id"] == "true"
    assert "ENG-Contractors" in wiki["pf_okta_only_groups_to_create"]


def test_out_of_scope_needs_reason_and_name(client):
    run(client)
    url = "/applications/0oa6legacytravel006/state"
    r = client.post(url, data={"_csrf": csrf(client), "target": "OUT_OF_SCOPE", "actor": "alice", "reason": ""},
                    follow_redirects=True)
    assert b"A reason is required" in r.data
    r = client.post(url, data={"_csrf": csrf(client), "target": "OUT_OF_SCOPE", "actor": "", "reason": "retired"},
                    follow_redirects=True)
    assert b"requires a named human actor" in r.data
    r = client.post(url, data={"_csrf": csrf(client), "target": "OUT_OF_SCOPE", "actor": "alice",
                               "reason": "Retired in 2022"}, follow_redirects=True)
    assert b"moved to OUT_OF_SCOPE" in r.data
    assert SessionLocal().get(Application, "0oa6legacytravel006").state == "OUT_OF_SCOPE"


def test_later_sprint_transitions_not_exposed(client):
    run(client)
    r = client.post("/applications/0oa1expenseportal01/state",
                    data={"_csrf": csrf(client), "target": "APPROVED", "actor": "alice", "reason": "x"},
                    follow_redirects=True)
    assert b"not available yet" in r.data


def test_business_details_are_audited(client):
    run(client)
    r = client.post("/applications/0oa1expenseportal01/details",
                    data={"_csrf": csrf(client), "actor": "alice", "business_owner": "Finance Ops",
                          "business_criticality": "HIGH", "has_test_environment": "yes", "wave": "Wave 0"},
                    follow_redirects=True)
    assert b"Details saved" in r.data
    a = SessionLocal().get(Application, "0oa1expenseportal01")
    assert (a.business_criticality, a.has_test_environment, a.wave) == ("HIGH", True, "Wave 0")
    assert b"DETAILS_UPDATED" in client.get("/audit").data


def test_csv_formula_injection_neutralised(client):
    run(client)
    db = SessionLocal()
    a = db.get(Application, "0oa1expenseportal01")
    a.business_owner = "=HYPERLINK(\"http://evil\")"
    db.commit()
    assert "'=HYPERLINK" in client.get("/export/inventory.csv").data.decode()
