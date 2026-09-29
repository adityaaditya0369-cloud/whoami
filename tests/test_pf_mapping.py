import pytest

from app.config import DirectoryType
from app.integrations.okta.parser import analyse_expression
from app.integrations.pingfederate import mapping as pf
from app.models.domain import ClaimModel

AMAP = pf.attribute_map(DirectoryType.AD)


def expr(*values):
    return ClaimModel(position=0, name="c", claim_type="EXPRESSION", values=list(values),
                      analysis=analyse_expression(list(values)))


def group(ftype, fval):
    return ClaimModel(position=0, name="groups", claim_type="GROUP",
                      group_filter_type=ftype, group_filter_value=fval)


@pytest.mark.parametrize("claim,kind", [
    (expr("user.email"), pf.DATA_STORE),
    (expr('"static"'), pf.TEXT),
    (expr("user.costCenter"), pf.UNMAPPED),
    (expr("appuser.role"), pf.APPUSER),
    (expr('user.firstName + " " + user.lastName'), pf.OGNL),
    (group("STARTS_WITH", "SN-"), pf.GROUP_LDAP_SEARCH),
    (group("EQUALS", "Sales"), pf.GROUP_LDAP_SEARCH),
    (group("REGEX", "^ENG-.*$"), pf.GROUP_LDAP_SEARCH),
    (group("REGEX", "(ENG|OPS)-.*"), pf.GROUP_OGNL),
    (group("STARTS_WITH", "a*b"), pf.GROUP_OGNL),        # LDAP-special chars are not passed through
])
def test_classify_claim(claim, kind):
    assert pf.classify_claim(claim, AMAP, DirectoryType.AD).kind == kind


def test_data_store_uses_ad_attribute_names():
    src = pf.classify_claim(expr("user.lastName"), AMAP, DirectoryType.AD)
    assert src.ldap_attributes == ["sn"] and src.detail == "LDAP: sn"


def test_ognl_reports_missing_inputs():
    src = pf.classify_claim(expr('user.costCenter + "-" + user.department'), AMAP, DirectoryType.AD)
    assert src.kind == pf.OGNL and src.ldap_attributes == ["department"]
    assert src.unmapped == ["user.costCenter"]


def test_pingdirectory_group_filter():
    src = pf.classify_claim(group("STARTS_WITH", "ENG-"), pf.attribute_map(DirectoryType.PINGDIRECTORY),
                            DirectoryType.PINGDIRECTORY)
    assert "uniqueMember" in src.detail and "groupOfUniqueNames" in src.detail


@pytest.mark.parametrize("nameid,username_tpl,kind,ldap", [
    ("${user.email}", None, pf.DATA_STORE, ["mail"]),
    ("${user.userName}", "${source.login}", pf.DATA_STORE, ["userPrincipalName"]),
    ("${user.userName}", "${source.email}", pf.DATA_STORE, ["mail"]),
    ("${user.userName}", "${source.employeeNumber}@x.sfdc", pf.OGNL, []),
    ("${user.id}", None, pf.UNMAPPED, []),
    ('${fn:substringBefore(user.email, "@")}', None, pf.OGNL, []),
    (None, None, pf.UNMAPPED, []),
])
def test_classify_nameid(nameid, username_tpl, kind, ldap):
    src = pf.classify_nameid(nameid, username_tpl, AMAP)
    assert src.kind == kind and src.ldap_attributes == ldap
