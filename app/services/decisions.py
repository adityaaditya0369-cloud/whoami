"""Decisions register + what-if simulation.

A handful of migration-wide decisions unblock or reshape many apps. Each
decision lists the finding codes it settles; deciding it (with any option)
removes those codes from the blockers. The what-if simulator recomputes waves
and the timeline as if selected open decisions were already taken, without
saving anything.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db import Application, Decision, utcnow
from app.services.state_service import record_event


@dataclass(frozen=True)
class DecisionDef:
    key: str
    title: str
    why: str
    codes: frozenset[str]            # findings that make this decision relevant
    unblocks: frozenset[str]         # blocker codes it settles once decided
    options: tuple[str, ...]
    owner: str
    removes_from_scope: bool = False  # decommission-type decision


CATALOGUE: list[DecisionDef] = [
    DecisionDef("OGNL_POLICY", "Allow OGNL expressions in PingFederate?",
                "Claims built from expressions (concatenation, conditions, string functions) need OGNL or a value "
                "pre-computed in the directory.",
                frozenset({"CLAIM_NEEDS_OGNL", "NAMEID_NEEDS_OGNL"}), frozenset({"CLAIM_NEEDS_OGNL", "NAMEID_NEEDS_OGNL"}),
                ("Allow OGNL (reviewed, documented expressions)", "No OGNL: pre-compute values in the directory"),
                "Security + IAM lead"),
    DecisionDef("DUPLICATE_ENTITY_ID", "How to handle apps that share one SP entity ID?",
                "PingFederate needs a unique partner entity ID per SP connection.",
                frozenset({"DUPLICATE_SP_ENTITY_ID"}), frozenset({"DUPLICATE_SP_ENTITY_ID"}),
                ("Change the non-production SP's entity ID", "Decommission the duplicate (e.g. unused UAT)",
                 "Use one connection for both"), "App owners"),
    DecisionDef("OKTA_USER_ID_NAMEID", "Apps keyed on the Okta user ID: copy IDs or re-link?",
                "PingFederate cannot emit Okta user IDs unless they are stored in the directory.",
                frozenset({"NAMEID_IS_OKTA_USER_ID"}), frozenset({"NAMEID_IS_OKTA_USER_ID"}),
                ("Copy Okta user IDs into a directory attribute", "Vendor re-links accounts", "Decommission the app"),
                "IAM lead + App owner"),
    DecisionDef("DECOMMISSION_UNUSED", "Decommission unused / unassigned apps instead of migrating?",
                "Apps with no sign-ins in the usage window, no assignments, or inactive in Okta.",
                frozenset({"UNUSED_IN_WINDOW", "NO_ASSIGNMENTS", "APP_INACTIVE"}), frozenset(),
                ("Decommission after owner confirmation", "Migrate anyway"), "Service owner", removes_from_scope=True),
    DecisionDef("OKTA_ONLY_GROUPS", "Okta-only groups: recreate in the directory or replace?",
                "PingFederate reads groups from the directory; Okta-native groups do not exist there.",
                frozenset({"OKTA_NATIVE_GROUPS_ASSIGNED", "GROUP_CLAIM_OKTA_NATIVE_GROUPS"}), frozenset(),
                ("Create in the directory and sync membership", "Replace with existing directory groups"),
                "Directory team"),
    DecisionDef("APP_SPECIFIC_ATTRIBUTES", "Where do app-specific attributes live after Okta?",
                "Okta app-user profile values and per-assignment values have no home in PingFederate.",
                frozenset({"APPUSER_ATTRIBUTE_CLAIM", "ASSIGNMENT_PROFILE_ATTRIBUTES"}), frozenset(),
                ("Directory attributes (e.g. extensionAttributeN)", "Derive from group membership"), "Directory team"),
    DecisionDef("IMPLICIT_GRANT", "Move implicit-grant OIDC apps to code + PKCE during migration?",
                "Implicit grant is deprecated; changing it needs app code changes.",
                frozenset({"OIDC_IMPLICIT_GRANT"}), frozenset(),
                ("Yes, modernise during migration", "No, keep implicit for now"), "App owners"),
    DecisionDef("CLIENT_SECRET_ROTATION", "How are new OIDC client secrets delivered to app teams?",
                "Okta does not return existing secrets, so confidential clients get new ones.",
                frozenset({"OIDC_NEW_CLIENT_SECRET"}), frozenset(),
                ("Secrets vault hand-off", "Direct secure hand-off at cutover"), "Security"),
]
BY_KEY = {d.key: d for d in CATALOGUE}


@dataclass
class DecisionView:
    d: DecisionDef
    row: Decision
    apps: list[Application] = field(default_factory=list)
    blocked_apps: list[Application] = field(default_factory=list)   # would be unblocked
    users: int = 0


def _rows(session: Session) -> dict[str, Decision]:
    rows = {r.key: r for r in session.scalars(select(Decision))}
    for d in CATALOGUE:
        if d.key not in rows:
            rows[d.key] = Decision(key=d.key, status="OPEN", owner=d.owner)
            session.add(rows[d.key])
    session.flush()
    return rows


def resolved_codes(session: Session) -> set[str]:
    codes: set[str] = set()
    for r in session.scalars(select(Decision).where(Decision.status == "DECIDED")):
        d = BY_KEY.get(r.key)
        if d:
            codes |= d.unblocks
    return codes


def scope_apps(session: Session) -> list[Application]:
    apps = session.scalars(select(Application).where(Application.removed_from_okta.is_(False))
                           .order_by(Application.label)).all()
    return [a for a in apps if a.in_scope_protocol and a.state != "OUT_OF_SCOPE"]


def register(session: Session) -> list[DecisionView]:
    rows = _rows(session)
    apps = scope_apps(session)
    out = []
    for d in CATALOGUE:
        affected = [a for a in apps if {f.code for f in a.findings} & d.codes]
        if not affected and rows[d.key].status == "OPEN":
            continue
        blocked = [a for a in affected if a.blocked and d.unblocks]
        users = sum((a.usage_unique_users if a.usage_known and a.usage_unique_users is not None else a.user_count)
                    for a in affected)
        out.append(DecisionView(d, rows[d.key], affected, blocked, users))
    return out


def decide(session: Session, key: str, actor: str, choice: str | None, owner: str | None, due: str | None,
           notes: str | None, reopen: bool = False) -> Decision:
    actor = (actor or "").strip()
    if not actor or actor.lower() in {"system", "ai", "claude"}:
        raise ValueError("A named person is required to record a decision")
    d = BY_KEY.get(key)
    if d is None:
        raise ValueError("Unknown decision")
    row = _rows(session)[key]
    due_dt = None
    if due:
        try:
            due_dt = datetime.strptime(due, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError("Due date must be YYYY-MM-DD") from exc
    row.owner, row.due_date, row.notes = (owner or row.owner), due_dt or row.due_date, notes or row.notes
    if reopen:
        row.status, row.choice, row.decided_by, row.decided_at = "OPEN", None, None, None
        event = "DECISION_REOPENED"
    elif choice:
        if choice not in d.options:
            raise ValueError("Pick one of the listed options")
        row.status, row.choice, row.decided_by, row.decided_at = "DECIDED", choice, actor, utcnow()
        event = "DECISION_RECORDED"
    else:
        event = "DECISION_UPDATED"
    record_event(session, event, actor, None, {"decision": key, "choice": row.choice, "owner": row.owner})
    return row


# --- what-if --------------------------------------------------------------------
@dataclass
class Simulation:
    assumed: list[str]
    before: dict[str, str]           # app id -> wave
    after: dict[str, str]
    removed: list[str]               # app ids removed from scope by a decommission assumption
    apps: dict[str, Application]

    @property
    def moved(self) -> list[tuple[Application, str, str]]:
        return [(self.apps[i], self.before[i], self.after.get(i, "Out of scope"))
                for i in self.before if self.before[i] != self.after.get(i, "Out of scope")]


def simulate(session: Session, assumed_keys: list[str], weights=None) -> Simulation:
    from app.services import risk
    apps = scope_apps(session)
    base_resolved = resolved_codes(session)
    extra = set()
    decommission = False
    for k in assumed_keys:
        d = BY_KEY.get(k)
        if d:
            extra |= d.unblocks
            decommission = decommission or d.removes_from_scope
    before, after, removed = {}, {}, []
    for a in apps:
        before[a.id] = a.suggested_wave or risk.compute(a, weights, base_resolved).suggested_wave
        r = risk.compute(a, weights, base_resolved | extra)
        if decommission and r.suggested_wave == "Decommission review":
            removed.append(a.id)
            continue
        after[a.id] = r.suggested_wave
    return Simulation(list(assumed_keys), before, after, removed, {a.id: a for a in apps})
