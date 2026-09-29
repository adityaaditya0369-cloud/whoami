"""Effort and timeline estimator (deterministic, editable assumptions).

Effort per app = base hours for its type + hours per finding + fixed test /
cutover hours. Shared directory work (groups, attributes) is estimated once.
The schedule runs waves in order with one build team; the SP side needs a
vendor lead time; the Blocked wave starts after the decision lead time.
Calendar days, not business days. These are planning numbers, not promises.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models.db import Application, PlanSettings, utcnow
from app.services.readiness import pf_readiness

BASE_HOURS = {"SAML_CUSTOM": 3.0, "SAML_CATALOG": 4.0, "OIDC": 2.0}
FINDING_HOURS = {
    "CLAIM_NEEDS_OGNL": 2, "NAMEID_NEEDS_OGNL": 2, "APPUSER_ATTRIBUTE_CLAIM": 2, "CLAIM_ATTRIBUTE_UNMAPPED": 1,
    "GROUP_CLAIM": 2, "GROUP_CLAIM_OKTA_NATIVE_GROUPS": 1, "MULTIPLE_ACS": 0.5, "SLO_ENABLED": 0.5,
    "SIGNED_AUTHN_REQUESTS": 0.5, "CUSTOM_IDP_ISSUER": 1, "CATALOG_APP_PARTIAL_CONFIG": 2,
    "ISSUANCE_CRITERIA_REQUIRED": 0.5, "OIDC_ACCESS_CONTROL_REQUIRED": 0.5, "DIRECT_USER_ASSIGNMENTS": 0.5,
    "CUSTOM_APP_USERNAME": 1, "ASSIGNMENT_PROFILE_ATTRIBUTES": 1, "NAMEID_IS_OKTA_USER_ID": 4,
    "DUPLICATE_SP_ENTITY_ID": 1, "OIDC_NEW_CLIENT_SECRET": 1, "OIDC_IMPLICIT_GRANT": 2,
    "OIDC_PKCE_NOT_REQUIRED": 0.5, "OIDC_WILDCARD_REDIRECT": 1, "OIDC_PRIVATE_KEY_JWT": 0.5,
}
TEST_HOURS = {"pilot": 2.0, "cutover": 1.0, "verify": 1.0, "decommission": 0.5}
GROUP_HOURS = 1.0        # create + populate one directory group
ATTRIBUTE_HOURS = 3.0    # add + populate one directory attribute
WAVE_ORDER = ["Wave 0 (pilot)", "Wave 1", "Wave 2", "Wave 3 (high impact)", "Blocked"]


@dataclass
class AppEffort:
    app: Application
    build: float
    test: float
    items: list[tuple[str, float]]

    @property
    def total(self) -> float:
        return self.build + self.test

    @property
    def drivers(self) -> list[str]:
        items = [(n, h) for n, h in self.items if not n.startswith(("Base", "Test"))]
        return [n for n, _ in sorted(items, key=lambda x: -x[1])[:3]]


@dataclass
class Phase:
    wave: str
    name: str
    start: datetime
    end: datetime
    kind: str         # prep | build | vendor | pilot | cutover | hypercare


@dataclass
class Timeline:
    settings: PlanSettings
    efforts: dict[str, AppEffort]
    waves: dict[str, list[Application]]
    wave_hours: dict[str, float]
    prep_hours: float
    phases: list[Phase] = field(default_factory=list)
    cutover: dict[str, datetime] = field(default_factory=dict)   # wave -> cutover date
    start: datetime | None = None
    end: datetime | None = None

    @property
    def total_hours(self) -> float:
        return round(sum(self.wave_hours.values()) + self.prep_hours, 1)

    def app_cutover(self, app: Application, wave: str) -> datetime | None:
        return self.cutover.get(wave)


def get_settings(session: Session) -> PlanSettings:
    row = session.get(PlanSettings, 1)
    if row is None:
        today = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        row = PlanSettings(id=1, start_date=today + timedelta(days=(7 - today.weekday()) % 7 or 7))  # next Monday
        session.add(row)
        session.flush()
    return row


def app_effort(app: Application) -> AppEffort:
    kind = "OIDC" if app.is_oidc else ("SAML_CUSTOM" if app.is_custom_saml else "SAML_CATALOG")
    items = [(f"Base ({kind.replace('_', ' ').lower()})", BASE_HOURS[kind])]
    counts: dict[str, int] = {}
    for f in app.findings:
        counts[f.code] = counts.get(f.code, 0) + 1
    for code, n in sorted(counts.items()):
        if code in FINDING_HOURS:
            items.append((code if n == 1 else f"{code} x{n}", FINDING_HOURS[code] * n))
    build = sum(h for _, h in items)
    test = sum(TEST_HOURS.values())
    items += [(f"Test/cutover: {k}", v) for k, v in TEST_HOURS.items()]
    return AppEffort(app, round(build, 1), test, items)


def effective_wave(app: Application, waves_override: dict[str, str] | None = None) -> str:
    if waves_override is not None:
        return waves_override.get(app.id, "Out of scope")
    return app.wave or app.suggested_wave or "Wave 2"


def build_timeline(session: Session, apps: list[Application],
                   waves_override: dict[str, str] | None = None, foundation_hours: float = 0.0) -> Timeline:
    """foundation_hours: tenant-level work (sign-in policies, MFA, token services) that must be done by the
    same team before Wave 0 can start. 0 keeps the previous behaviour."""
    ps = get_settings(session)
    capacity = max(ps.engineers * ps.hours_per_week, 1.0)   # hours per week
    buffer = 1 + (ps.buffer_pct or 0) / 100
    efforts = {a.id: app_effort(a) for a in apps}
    waves: dict[str, list[Application]] = {w: [] for w in WAVE_ORDER}
    for a in apps:
        w = effective_wave(a, waves_override)
        if w in ("Decommission review", "Out of scope"):
            continue
        waves.setdefault(w, []).append(a)
    waves = {w: v for w, v in waves.items() if v}
    wave_hours = {w: round(sum(efforts[a.id].total for a in v) * buffer, 1) for w, v in waves.items()}

    groups, attrs = set(), set()
    for v in waves.values():
        for a in v:
            r = pf_readiness(a)
            groups |= set(r["okta_only_groups"])
            attrs |= {m for m in r["missing_inputs"] if m != "user.id"}
    prep_hours = round((len(groups) * GROUP_HOURS + len(attrs) * ATTRIBUTE_HOURS) * buffer, 1)

    t = Timeline(ps, efforts, waves, wave_hours, prep_hours)
    start = ps.start_date or utcnow()
    t.start = start
    weeks = lambda h: max(1, math.ceil(h / capacity))  # noqa: E731
    if prep_hours:
        t.phases.append(Phase("All waves", "Directory prep", start, start + timedelta(weeks=weeks(prep_hours)), "prep"))
    team_free = start
    if foundation_hours:
        f_end = start + timedelta(weeks=weeks(foundation_hours * buffer))
        t.phases.append(Phase("All waves", "Foundation: sign-in, MFA, token services", start, f_end, "prep"))
        t.prep_hours = round(t.prep_hours + foundation_hours * buffer, 1)
        team_free = f_end
    for w in [x for x in WAVE_ORDER if x in waves] + [x for x in waves if x not in WAVE_ORDER]:
        build_h = sum(efforts[a.id].build for a in waves[w]) * buffer
        b_start = team_free
        if w == "Blocked":
            b_start = max(b_start, start + timedelta(days=ps.decision_lead_days))
            t.phases.append(Phase(w, "Decisions", start, b_start, "prep"))
        b_end = b_start + timedelta(weeks=weeks(build_h))
        vendor_ready = b_start + timedelta(days=ps.vendor_lead_days)
        t.phases.append(Phase(w, "Build in PingFederate", b_start, b_end, "build"))
        t.phases.append(Phase(w, "SP / app changes (vendor lead time)", b_start, vendor_ready, "vendor"))
        p_start = max(b_end, vendor_ready)
        p_end = p_start + timedelta(days=ps.pilot_days)
        cut = p_end + timedelta(days=1)
        t.phases.append(Phase(w, "Pilot", p_start, p_end, "pilot"))
        t.phases.append(Phase(w, "Cutover", p_end, cut, "cutover"))
        t.phases.append(Phase(w, "Hypercare, then remove from Okta", cut, cut + timedelta(days=ps.hypercare_days), "hypercare"))
        t.cutover[w] = cut
        team_free = b_end
    t.end = max((p.end for p in t.phases), default=start)
    return t


def gantt_rows(t: Timeline) -> tuple[list[dict], list[datetime]]:
    """Rows with left/width percentages for a CSS Gantt, plus week tick dates."""
    if not t.phases:
        return [], []
    span = max((t.end - t.start).days, 1)
    rows = [{"p": p, "left": 100 * (p.start - t.start).days / span,
             "width": max(100 * (p.end - p.start).days / span, 1.2)} for p in t.phases]
    ticks, d = [], t.start
    while d <= t.end:
        ticks.append(d)
        d += timedelta(weeks=1 if span <= 84 else 2)
    return rows, ticks


def update_settings(session: Session, actor: str, form: dict) -> PlanSettings:
    actor = (actor or "").strip()
    if not actor:
        raise ValueError("Your name is required to change assumptions")
    ps = get_settings(session)
    try:
        if form.get("start_date"):
            ps.start_date = datetime.strptime(form["start_date"], "%Y-%m-%d")
        ps.engineers = max(0.5, float(form.get("engineers", ps.engineers)))
        ps.hours_per_week = max(1.0, float(form.get("hours_per_week", ps.hours_per_week)))
        for k in ("vendor_lead_days", "pilot_days", "hypercare_days", "decision_lead_days", "buffer_pct"):
            if form.get(k) not in (None, ""):
                setattr(ps, k, max(0, int(form[k])))
    except ValueError as exc:
        raise ValueError("Check the assumption values (numbers, dates as YYYY-MM-DD)") from exc
    ps.updated_by = actor
    from app.services.state_service import record_event
    record_event(session, "PLAN_ASSUMPTIONS_UPDATED", actor, None, {
        "start": ps.start_date.strftime("%Y-%m-%d") if ps.start_date else None, "engineers": ps.engineers,
        "hours_per_week": ps.hours_per_week, "vendor_lead_days": ps.vendor_lead_days, "buffer_pct": ps.buffer_pct})
    return ps
