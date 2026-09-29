import json

import pytest

from app.integrations.okta import parser
from tests.conftest import SAMPLE


@pytest.mark.parametrize("values,kind", [
    (["user.email"], "DIRECT"),
    (["appuser.costCenter"], "DIRECT"),
    (['"constant-value"'], "LITERAL"),
    (['user.firstName + " " + user.lastName'], "COMPLEX"),
    (['String.substringBefore(user.login, "@")'], "COMPLEX"),
    (['user.department == "Engineering" ? "admin" : "user"'], "COMPLEX"),
    (['isMemberOfGroupName("Admins") ? "a" : "b"'], "COMPLEX"),
    (["user.email", "user.secondEmail"], "COMPLEX"),   # multi-valued needs OGNL or a multi-valued source
])
def test_expression_classification(values, kind):
    assert parser.analyse_expression(values).kind == kind


def test_expression_extracts_attributes_and_functions():
    a = parser.analyse_expression(['String.substringBefore(user.login, "@") + user.department'])
    assert a.source_attributes == ["user.department", "user.login"]
    assert "String.substringBefore" in a.functions_used
    assert "<concatenation>" in a.functions_used


def test_conditional_detected():
    a = parser.analyse_expression(['user.department == "Eng" ? "x" : "y"'])
    assert "<conditional>" in a.functions_used


@pytest.mark.parametrize("ftype,fval,expected", [
    ("REGEX", "ENG-.*", ["ENG-Platform", "ENG-Data"]),
    ("REGEX", "ENG", []),                               # regex must match the whole name
    ("STARTS_WITH", "eng-", ["ENG-Platform", "ENG-Data"]),
    ("EQUALS", "sales", ["Sales"]),
    ("CONTAINS", "plat", ["ENG-Platform"]),
    ("REGEX", "([", []),                                # invalid regex does not crash
    (None, None, []),
])
def test_group_filter(ftype, fval, expected):
    names = ["ENG-Platform", "ENG-Data", "Sales", "Finance"]
    assert parser.match_group_filter(ftype, fval, names) == expected


def _apps():
    return {a["id"]: a for a in json.loads((SAMPLE / "apps.json").read_text())}


def test_parse_custom_saml_app():
    m = parser.parse_app(_apps()["0oa3engwiki00000003"])
    assert m.is_saml and m.is_custom_saml
    assert m.saml.config_completeness == "FULL"
    assert m.saml.audience == "https://wiki.northwind.example"
    assert len(m.saml.acs_endpoints) == 2 and m.saml.slo_enabled and m.saml.sp_certificate_present
    kinds = {c.name: (c.claim_type, c.analysis.kind if c.analysis else None) for c in m.saml.claims}
    assert kinds["email"] == ("EXPRESSION", "DIRECT")
    assert kinds["wikiRole"] == ("EXPRESSION", "COMPLEX")
    assert kinds["groups"] == ("GROUP", None)


def test_parse_catalog_app_is_partial():
    m = parser.parse_app(_apps()["0oa4servicenow00004"])
    assert m.is_saml and not m.is_custom_saml
    assert m.saml.config_completeness == "PARTIAL"
    assert m.saml.catalog_app_settings["instanceName"] == "northwind"


def test_parse_non_saml_app():
    m = parser.parse_app(_apps()["0oa7employeeportal7"])
    assert not m.is_saml and m.saml is None


def test_parse_app_with_null_sign_on_mode():
    # Live Okta returns explicit nulls for some apps; they must not break discovery.
    m = parser.parse_app({"id": "0oanull", "name": None, "label": "Odd app",
                          "signOnMode": None, "status": None})
    assert m.sign_on_mode == "UNKNOWN" and m.okta_status == "UNKNOWN" and m.okta_name == ""
    assert not m.is_saml and not m.is_oidc


def test_parse_key_extracts_thumbprints_and_dates():
    key = json.loads((SAMPLE / "apps" / "0oa2hranalytics0002" / "keys.json").read_text())[0]
    c = parser.parse_key(key)
    assert c.not_after.year == 2026 and c.not_after.month == 11
    assert len(c.sha1_thumbprint) == 40 and c.key_size == 2048
    assert "CN=northwind_hranalytics_1" in c.subject


def test_parse_key_tolerates_garbage():
    c = parser.parse_key({"kid": "x", "x5c": ["not-base64!!"], "expiresAt": "2030-01-01T00:00:00.000Z"})
    assert c.kid == "x" and c.not_after.year == 2030 and c.sha1_thumbprint is None


def test_parse_metadata():
    xml = (SAMPLE / "apps" / "0oa1expenseportal01" / "metadata.xml").read_text()
    md = parser.parse_metadata(xml)
    assert md.entity_id.startswith("http://www.okta.com/")
    assert md.sso_url.endswith("/sso/saml")


def test_parse_metadata_rejects_entity_expansion():
    evil = ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>'
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&b;"/>')
    assert parser.parse_metadata(evil).entity_id is None
