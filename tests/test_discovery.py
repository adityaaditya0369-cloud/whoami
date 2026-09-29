import json
from datetime import datetime

import pytest
from sqlalchemy import func, select

from app.integrations.okta.client import FileOktaSource
from app.models.db import Application, Assignment, Finding, MigrationEvent, RawSnapshot
from app.services.discovery import run_discovery

NOW = datetime(2026, 9, 27)


def codes(db, app_id):
    return {f.code for f in db.scalars(select(Finding).where(Finding.app_id == app_id))}


def discover(db, settings, export_dir):
    return run_discovery(db, FileOktaSource(export_dir), settings, actor="tester", now=NOW)


def test_first_run_inventory(db, settings, export_dir):
    run = discover(db, settings, export_dir)
    assert run.status == "SUCCESS"
    assert (run.apps_total, run.saml_apps, run.oidc_apps, run.new_apps) == (13, 7, 4, 13)
    saml = db.scalars(select(Application).where(Application.is_saml.is_(True))).all()
    assert len(saml) == 7 and all(a.state == "DISCOVERED" for a in saml)
    hr = db.get(Application, "0oa2hranalytics0002")
    assert (hr.user_count, hr.direct_user_count, hr.group_count) == (5, 2, 1)
    assert len(hr.claims) == 7 and len(hr.certificates) == 1
    assert db.get(Application, "0oa7employeeportal7").saml is None


@pytest.mark.parametrize("app_id,expected,absent", [
    ("0oa1expenseportal01", {"DIRECTORY_SOURCED_GROUPS_ASSIGNED", "ISSUANCE_CRITERIA_REQUIRED",
                             "DUPLICATE_SP_ENTITY_ID"},
     {"CLAIM_NEEDS_OGNL", "CERT_EXPIRING", "NO_ASSIGNMENTS", "CUSTOM_IDP_ISSUER"}),
    ("0oa1expenseuat00011", {"DUPLICATE_SP_ENTITY_ID", "OKTA_NATIVE_GROUPS_ASSIGNED"}, set()),
    ("0oa2hranalytics0002", {"CLAIM_NEEDS_OGNL", "APPUSER_ATTRIBUTE_CLAIM", "CERT_EXPIRING",
                             "DIRECT_USER_ASSIGNMENTS", "OKTA_NATIVE_GROUPS_ASSIGNED",
                             "ISSUANCE_CRITERIA_REQUIRED"}, {"CLAIM_ATTRIBUTE_UNMAPPED"}),
    ("0oa3engwiki00000003", {"GROUP_CLAIM", "GROUP_CLAIM_OKTA_NATIVE_GROUPS", "CUSTOM_IDP_ISSUER",
                             "MULTIPLE_ACS", "SLO_ENABLED", "SIGNED_AUTHN_REQUESTS", "CLAIM_NEEDS_OGNL",
                             "ASSIGNMENT_PROFILE_ATTRIBUTES", "DEFAULT_RELAY_STATE"}, {"DUPLICATE_SP_ENTITY_ID"}),
    ("0oa4servicenow00004", {"CATALOG_APP_PARTIAL_CONFIG", "ISSUANCE_CRITERIA_REQUIRED"}, set()),
    ("0oa5salesforce00005", {"CATALOG_APP_PARTIAL_CONFIG", "CUSTOM_APP_USERNAME"}, set()),
    ("0oa6legacytravel006", {"APP_INACTIVE", "NO_ASSIGNMENTS", "NAMEID_IS_OKTA_USER_ID",
                             "SHA1_SIGNATURE", "CERT_EXPIRED"}, {"ISSUANCE_CRITERIA_REQUIRED"}),
])
def test_findings_per_app(db, settings, export_dir, app_id, expected, absent):
    discover(db, settings, export_dir)
    found = codes(db, app_id)
    assert expected <= found, expected - found
    assert not (absent & found)


def test_group_claim_counts_all_matching_tenant_groups(db, settings, export_dir):
    discover(db, settings, export_dir)
    wiki = db.get(Application, "0oa3engwiki00000003")
    gc = next(c for c in wiki.claims if c.claim_type == "GROUP")
    # ENG-Contractors matches the regex even though it is not assigned to the app,
    # and it is Okta-only, so PingFederate (reading AD) will not see it.
    assert gc.matched_group_count == 4 and "ENG-Contractors" in gc.matched_group_sample
    assert gc.matched_okta_native_groups == ["ENG-Contractors"]
    assert gc.pf_source == "GROUP_LDAP_SEARCH" and "cn=ENG-*" in gc.pf_source_detail


def test_ognl_severity_follows_policy(db, settings, export_dir):
    discover(db, settings, export_dir)
    sev = {f.severity for f in db.scalars(select(Finding).where(Finding.code == "CLAIM_NEEDS_OGNL"))}
    assert sev == {"CRITICAL"}


def test_ognl_allowed_downgrades_to_warning(db, settings, export_dir):
    discover(db, settings.model_copy(update={"pf_ognl_allowed": True}), export_dir)
    sev = {f.severity for f in db.scalars(select(Finding).where(Finding.code == "CLAIM_NEEDS_OGNL"))}
    assert sev == {"WARNING"}


def test_claim_pf_sources(db, settings, export_dir):
    discover(db, settings, export_dir)
    hr = db.get(Application, "0oa2hranalytics0002")
    src = {c.name: c.pf_source for c in hr.claims}
    assert src == {"firstName": "DATA_STORE", "lastName": "DATA_STORE", "email": "DATA_STORE",
                   "employeeNumber": "DATA_STORE", "displayName": "OGNL", "username": "OGNL",
                   "costCenter": "APPUSER"}
    assert hr.saml.pf_nameid_source == "DATA_STORE"


def test_pingdirectory_mapping(db, settings, export_dir):
    discover(db, settings.model_copy(update={"pf_directory_type": "PINGDIRECTORY"}), export_dir)
    hr = db.get(Application, "0oa2hranalytics0002")
    assert {c.name: c.pf_ldap_attributes for c in hr.claims}["employeeNumber"] == ["employeeNumber"]
    assert "uid" in hr.saml.pf_nameid_detail


def test_attribute_map_override(db, settings, export_dir, tmp_path):
    f = tmp_path / "map.json"
    f.write_text('{"employeeNumber": "extensionAttribute1"}')
    discover(db, settings.model_copy(update={"pf_attribute_map_file": f}), export_dir)
    hr = db.get(Application, "0oa2hranalytics0002")
    assert {c.name: c.pf_ldap_attributes for c in hr.claims}["employeeNumber"] == ["extensionAttribute1"]


def test_rerun_is_idempotent(db, settings, export_dir):
    discover(db, settings, export_dir)
    n_assign = db.scalar(select(func.count(Assignment.id)))
    n_find = db.scalar(select(func.count(Finding.id)))
    run2 = discover(db, settings, export_dir)
    assert (run2.new_apps, run2.changed_apps, run2.removed_apps) == (0, 0, 0)
    assert db.scalar(select(func.count(Assignment.id))) == n_assign
    assert db.scalar(select(func.count(Finding.id))) == n_find


def test_drift_detection_changed_and_removed(db, settings, export_dir):
    discover(db, settings, export_dir)
    apps = json.loads((export_dir / "apps.json").read_text())
    for a in apps:
        if a["id"] == "0oa1expenseportal01":
            a["settings"]["signOn"]["attributeStatements"].append(
                {"type": "EXPRESSION", "name": "dept", "values": ["user.department"]})
    apps = [a for a in apps if a["id"] != "0oa9vendorportal009"]
    (export_dir / "apps.json").write_text(json.dumps(apps))

    run2 = discover(db, settings, export_dir)
    assert (run2.changed_apps, run2.removed_apps) == (1, 1)
    exp = db.get(Application, "0oa1expenseportal01")
    assert exp.changed_in_last_run and "CHANGED_SINCE_LAST_RUN" in codes(db, exp.id)
    assert len(exp.claims) == 2
    assert db.get(Application, "0oa9vendorportal009").removed_from_okta
    types = {e.event_type for e in db.scalars(select(MigrationEvent))}
    assert {"APP_CONFIG_CHANGED", "APP_REMOVED_FROM_OKTA", "DISCOVERY_COMPLETED"} <= types


def test_raw_snapshots_are_kept_per_run(db, settings, export_dir):
    discover(db, settings, export_dir)
    discover(db, settings, export_dir)
    snaps = db.scalars(select(RawSnapshot).where(RawSnapshot.app_id == "0oa2hranalytics0002",
                                                 RawSnapshot.kind == "app")).all()
    assert len(snaps) == 2 and snaps[0].sha256 == snaps[1].sha256


def test_user_details_can_be_disabled(db, settings, export_dir):
    s = settings.model_copy(update={"store_user_details": False})
    discover(db, s, export_dir)
    hr = db.get(Application, "0oa2hranalytics0002")
    assert hr.user_count == 5
    assert not [x for x in hr.assignments if x.principal_type == "USER"]


def test_failed_run_is_recorded(db, settings, export_dir):
    (export_dir / "groups.json").write_text("{not json")
    with pytest.raises(Exception):
        discover(db, settings, export_dir)
    ev = db.scalars(select(MigrationEvent).where(MigrationEvent.event_type == "DISCOVERY_FAILED")).all()
    assert len(ev) == 1
