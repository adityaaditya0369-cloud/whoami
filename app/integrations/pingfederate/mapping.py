"""Where will each Okta claim come from in PingFederate?

PingFederate is not a directory. Every value in an assertion comes from:
  * a data store attribute (LDAP: AD or PingDirectory)   -> DATA_STORE
  * a constant                                           -> TEXT
  * an OGNL expression (disabled by default in PF)       -> OGNL
Okta-only concepts (app-user profile attributes, Okta-native groups, the Okta
user id) have no source until someone puts them in the directory.

Pure functions - deterministic and unit-tested. This is the input for the
Sprint 3 mapping engine; Claude will explain these results, never decide them.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from app.config import DirectoryType
from app.models.domain import ClaimModel

# Okta Universal Directory profile attribute -> LDAP attribute
AD_MAP: dict[str, str] = {
    "login": "userPrincipalName", "email": "mail", "firstName": "givenName", "lastName": "sn",
    "displayName": "displayName", "title": "title", "department": "department",
    "division": "division", "organization": "company", "employeeNumber": "employeeID",
    "mobilePhone": "mobile", "primaryPhone": "telephoneNumber", "streetAddress": "streetAddress",
    "city": "l", "state": "st", "zipCode": "postalCode", "countryCode": "c",
    "manager": "manager", "samAccountName": "sAMAccountName", "secondEmail": "otherMailbox",
}
PINGDIRECTORY_MAP: dict[str, str] = {
    "login": "uid", "email": "mail", "firstName": "givenName", "lastName": "sn",
    "displayName": "displayName", "title": "title", "department": "departmentNumber",
    "organization": "o", "employeeNumber": "employeeNumber", "mobilePhone": "mobile",
    "primaryPhone": "telephoneNumber", "streetAddress": "street", "city": "l", "state": "st",
    "zipCode": "postalCode", "countryCode": "c", "manager": "manager",
}
# Where the "user is a member of group X" data lives, and the group name attribute.
GROUP_LDAP = {
    DirectoryType.AD: {"member_attr": "member", "object_class": "group", "name_attr": "cn"},
    DirectoryType.PINGDIRECTORY: {"member_attr": "uniqueMember", "object_class": "groupOfUniqueNames",
                                  "name_attr": "cn"},
}


def attribute_map(directory: DirectoryType, override_file: Path | None = None) -> dict[str, str]:
    base = dict(AD_MAP if directory == DirectoryType.AD else PINGDIRECTORY_MAP)
    if override_file:
        base.update(json.loads(Path(override_file).read_text(encoding="utf-8")))
    return base


# --- result type ------------------------------------------------------------
DATA_STORE, TEXT, OGNL, APPUSER, UNMAPPED = "DATA_STORE", "TEXT", "OGNL", "APPUSER", "UNMAPPED"
GROUP_LDAP_SEARCH, GROUP_OGNL = "GROUP_LDAP_SEARCH", "GROUP_OGNL"


@dataclass
class PfSource:
    kind: str
    detail: str
    ldap_attributes: list[str]
    unmapped: list[str]


def _okta_attr(ref: str) -> tuple[str, str]:
    scope, _, name = ref.partition(".")
    return scope.lower(), name


def _resolve(refs: list[str], amap: dict[str, str]) -> tuple[list[str], list[str], list[str]]:
    """-> (ldap attrs, unmapped okta attrs, appuser attrs)"""
    ldap, unmapped, appuser = [], [], []
    for ref in refs:
        scope, name = _okta_attr(ref)
        if scope == "appuser":
            appuser.append(ref)
        elif scope == "user" and name in amap:
            ldap.append(amap[name])
        else:
            unmapped.append(ref)
    return sorted(set(ldap)), sorted(set(unmapped)), sorted(set(appuser))


_PREFIX_REGEX = re.compile(r"^\^?([A-Za-z0-9 _\-]+)\.\*\$?$")


def group_filter_to_ldap(filter_type: str | None, value: str | None) -> str | None:
    """LDAP wildcard for the group name, or None if only OGNL can express it."""
    if not filter_type or value is None:
        return None
    ft = filter_type.upper()
    if any(ch in value for ch in "()*\\\0") and ft != "REGEX":
        return None
    if ft == "EQUALS":
        return value
    if ft == "STARTS_WITH":
        return f"{value}*"
    if ft == "CONTAINS":
        return f"*{value}*"
    if ft == "REGEX":
        m = _PREFIX_REGEX.match(value)
        return f"{m.group(1)}*" if m else None
    return None


def classify_claim(claim: ClaimModel, amap: dict[str, str], directory: DirectoryType) -> PfSource:
    if claim.claim_type == "GROUP":
        g = GROUP_LDAP[directory]
        wildcard = group_filter_to_ldap(claim.group_filter_type, claim.group_filter_value)
        if wildcard is not None:
            return PfSource(GROUP_LDAP_SEARCH,
                            f"Chained LDAP attribute source returning {g['name_attr']}, e.g. "
                            f"(&(objectClass={g['object_class']})({g['member_attr']}=<user DN>)"
                            f"({g['name_attr']}={wildcard}))",
                            [g["name_attr"]], [])
        return PfSource(GROUP_OGNL,
                        f"{claim.group_filter_type} '{claim.group_filter_value}' cannot be written as an "
                        "LDAP filter; needs OGNL over memberOf (DN to name, then filter)",
                        ["memberOf"], [])

    a = claim.analysis
    if a is None:
        return PfSource(UNMAPPED, "No value", [], [])
    ldap, unmapped, appuser = _resolve(a.source_attributes, amap)
    if a.kind == "LITERAL":
        return PfSource(TEXT, f"Text: {', '.join(claim.values)}", [], [])
    if a.kind == "DIRECT":
        if appuser:
            return PfSource(APPUSER, f"{appuser[0]} is an Okta app-user attribute; it must be "
                            "stored in the directory (or derived from groups) first", [], appuser)
        if ldap:
            return PfSource(DATA_STORE, f"LDAP: {ldap[0]}", ldap, [])
        return PfSource(UNMAPPED, f"No default LDAP attribute for {', '.join(unmapped)}; "
                        "confirm or add one in the directory", [], unmapped)
    # COMPLEX
    parts = []
    if ldap:
        parts.append(f"LDAP inputs: {', '.join(ldap)}")
    if unmapped or appuser:
        parts.append(f"missing inputs: {', '.join(unmapped + appuser)}")
    fn = ", ".join(a.functions_used) or "multi-valued"
    return PfSource(OGNL, f"OGNL needed ({fn}); " + "; ".join(parts) if parts else f"OGNL needed ({fn})",
                    ldap, unmapped + appuser)


def classify_nameid(name_id_template: str | None, user_name_template: str | None,
                    amap: dict[str, str]) -> PfSource:
    """NameID source. ${user.userName} is the Okta *app username*, itself built
    from the app's username template (${source.login}, ${source.email}, custom)."""
    tpl = (name_id_template or "").replace(" ", "")
    if not tpl:
        return PfSource(UNMAPPED, "No NameID template visible (catalog app)", [], [])
    if "user.id" in tpl and "user.userName" not in tpl:
        return PfSource(UNMAPPED, "Okta user id: not present in any directory", [], ["user.id"])
    if tpl == "${user.userName}":
        ut = (user_name_template or "${source.login}").replace(" ", "")
        m = re.fullmatch(r"\$\{source\.([A-Za-z_][A-Za-z0-9_]*)\}", ut)
        if m and m.group(1) in amap:
            return PfSource(DATA_STORE, f"LDAP: {amap[m.group(1)]} (via app username {ut})",
                            [amap[m.group(1)]], [])
        return PfSource(OGNL, f"App username template {ut} needs OGNL or a pre-computed attribute", [], [])
    m = re.fullmatch(r"\$\{user\.([A-Za-z_][A-Za-z0-9_]*)\}", tpl)
    if m:
        if m.group(1) in amap:
            return PfSource(DATA_STORE, f"LDAP: {amap[m.group(1)]}", [amap[m.group(1)]], [])
        return PfSource(UNMAPPED, f"No default LDAP attribute for user.{m.group(1)}", [], [f"user.{m.group(1)}"])
    return PfSource(OGNL, f"Expression {name_id_template} needs OGNL or a pre-computed attribute", [], [])
