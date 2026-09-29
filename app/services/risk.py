"""Deterministic risk engine.

Two dimensions, because one score hides the trade-off that drives wave planning:
  * Complexity - technical effort to reproduce the app in PingFederate (from findings)
  * Impact     - damage if the cutover goes wrong (users, criticality, test environment)
Overall = the higher of the two, raised one level when both are HIGH or worse.

Claude never computes or changes these numbers; it only explains them.
Every result stores its breakdown and RULES_VERSION so any score can be defended.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db import Application, RiskScore

RULES_VERSION = "2026.09-pf-2"
LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Complexity points per finding code, and how many occurrences count (per-claim codes repeat).
COMPLEXITY_WEIGHTS: dict[str, tuple[int, int]] = {
    # code: (points, max occurrences counted)
    "CLAIM_NEEDS_OGNL": (3, 3),
    "NAMEID_NEEDS_OGNL": (3, 1),
    "APPUSER_ATTRIBUTE_CLAIM": (3, 3),
    "CLAIM_ATTRIBUTE_UNMAPPED": (2, 3),
    "NAMEID_ATTRIBUTE_UNMAPPED": (2, 1),
    "NAMEID_IS_OKTA_USER_ID": (5, 1),
    "GROUP_CLAIM": (3, 2),
    "GROUP_CLAIM_OKTA_NATIVE_GROUPS": (2, 2),
    "OKTA_NATIVE_GROUPS_ASSIGNED": (2, 1),
    "DIRECT_USER_ASSIGNMENTS": (1, 1),
    "ASSIGNMENT_PROFILE_ATTRIBUTES": (2, 1),
    "ISSUANCE_CRITERIA_REQUIRED": (1, 1),
    "CATALOG_APP_PARTIAL_CONFIG": (5, 1),      # "unknown configuration" in the original plan
    "CUSTOM_IDP_ISSUER": (2, 1),
    "DUPLICATE_SP_ENTITY_ID": (3, 1),
    "CUSTOM_APP_USERNAME": (2, 1),
    "MULTIPLE_ACS": (2, 1),
    "SLO_ENABLED": (1, 1),
    "SIGNED_AUTHN_REQUESTS": (1, 1),
    "NON_DEFAULT_AUTHN_CONTEXT": (1, 1),
    "UNRESOLVED_GROUP_ASSIGNMENTS": (2, 1),
    "NO_SIGNING_CERTIFICATE_FOUND": (2, 1),
    # OIDC
    "OIDC_ACCESS_CONTROL_REQUIRED": (1, 1),
    "OIDC_NEW_CLIENT_SECRET": (2, 1),
    "OIDC_IMPLICIT_GRANT": (3, 1),
    "OIDC_PASSWORD_GRANT": (2, 1),
    "OIDC_PKCE_NOT_REQUIRED": (1, 1),
    "OIDC_WILDCARD_REDIRECT": (2, 1),
    "OIDC_REFRESH_TOKENS": (1, 1),
    "OIDC_SCOPES_CLAIMS_NOT_ANALYSED": (2, 1),   # unknown configuration until next sprint
}
COMPLEXITY_BANDS = [(0, "LOW"), (5, "MEDIUM"), (10, "HIGH"), (16, "CRITICAL")]

# Impact inputs
USER_BANDS = [(0, 0), (1, 1), (50, 2), (500, 4), (5000, 6)]     # (min users, points)
CRITICALITY_POINTS = {"HIGH": 5, "MEDIUM": 2, "LOW": 0, None: 2}  # None = not yet captured
TEST_ENV_POINTS = {False: 5, None: 2, True: 0}
IMPACT_BANDS = [(0, "LOW"), (4, "MEDIUM"), (8, "HIGH"), (12, "CRITICAL")]

# Findings that stop a migration until resolved (independent of score).
BLOCKER_CODES = {"NAMEID_IS_OKTA_USER_ID", "DUPLICATE_SP_ENTITY_ID"}


@dataclass
class Contribution:
    dimension: str      # COMPLEXITY | IMPACT
    rule: str
    points: int
    reason: str


@dataclass
class RiskResult:
    complexity_score: int
    complexity_level: str
    impact_score: int
    impact_level: str
    overall_level: str
    blocked: bool
    blockers: list[str]
    suggested_wave: str
    breakdown: list[Contribution] = field(default_factory=list)


def _band(score: int, bands) -> str:
    level = bands[0][1]
    for threshold, name in bands:
        if score >= threshold:
            level = name
    return level


def load_weights(path: Path | None) -> dict[str, tuple[int, int]]:
    weights = dict(COMPLEXITY_WEIGHTS)
    if path:
        for code, v in json.loads(Path(path).read_text(encoding="utf-8")).items():
            weights[code] = (int(v[0]), int(v[1])) if isinstance(v, list) else (int(v), weights.get(code, (0, 1))[1])
    return weights


def compute(app: Application, weights: dict[str, tuple[int, int]] | None = None,
            resolved: set[str] | None = None) -> RiskResult:
    """`resolved` = blocker codes settled by recorded decisions (see services/decisions.py)."""
    resolved = resolved or set()
    weights = weights or COMPLEXITY_WEIGHTS
    breakdown: list[Contribution] = []

    # --- complexity -------------------------------------------------------
    counts: dict[str, int] = {}
    severities: dict[str, str] = {}
    for f in app.findings:
        counts[f.code] = counts.get(f.code, 0) + 1
        severities[f.code] = f.severity
    complexity = 0
    for code in sorted(counts):
        if code not in weights:
            continue
        pts, cap = weights[code]
        n = min(counts[code], cap)
        if pts and n:
            complexity += pts * n
            breakdown.append(Contribution("COMPLEXITY", code, pts * n,
                                          f"{counts[code]} occurrence(s) x {pts}" + (f" (capped at {cap})" if counts[code] > cap else "")))

    # --- impact -------------------------------------------------------------
    impact = 0
    inactive = app.okta_status != "ACTIVE"
    if inactive:
        breakdown.append(Contribution("IMPACT", "APP_INACTIVE", 0, "Inactive in Okta: no live users affected"))
    else:
        use_active = bool(getattr(app, "usage_known", False)) and getattr(app, "usage_unique_users", None) is not None
        n_users = app.usage_unique_users if use_active else app.user_count
        upts = 0
        for threshold, pts in USER_BANDS:
            if n_users >= threshold:
                upts = pts
        impact += upts
        if use_active:
            breakdown.append(Contribution("IMPACT", "ACTIVE_USERS", upts,
                                          f"{n_users} active users in {app.usage_window_days} days "
                                          f"({app.user_count} assigned)"))
        else:
            breakdown.append(Contribution("IMPACT", "ASSIGNED_USERS", upts, f"{app.user_count} assigned users"))
        cpts = CRITICALITY_POINTS.get(app.business_criticality, 2)
        impact += cpts
        breakdown.append(Contribution("IMPACT", "BUSINESS_CRITICALITY", cpts,
                                      f"Criticality {app.business_criticality or 'not captured (assumed MEDIUM)'}"))
        tpts = TEST_ENV_POINTS.get(app.has_test_environment, 2)
        impact += tpts
        breakdown.append(Contribution("IMPACT", "TEST_ENVIRONMENT", tpts, {
            True: "SP has a test environment", False: "No SP test environment: first test is production",
            None: "Test environment not captured"}[app.has_test_environment]))

    c_level = _band(complexity, COMPLEXITY_BANDS)
    i_level = "LOW" if inactive else _band(impact, IMPACT_BANDS)
    overall_idx = max(LEVELS.index(c_level), LEVELS.index(i_level))
    if LEVELS.index(c_level) >= 2 and LEVELS.index(i_level) >= 2:
        overall_idx = min(overall_idx + 1, 3)
    overall = LEVELS[overall_idx]

    blockers = sorted(c for c in counts if (c in BLOCKER_CODES
                      or (severities.get(c) == "CRITICAL" and c not in {"CERT_EXPIRED"})) and c not in resolved)
    blocked = bool(blockers)

    if "NO_ASSIGNMENTS" in counts or "UNUSED_IN_WINDOW" in counts or inactive:
        wave = "Decommission review"
    elif blocked:
        wave = "Blocked"
    elif c_level == "LOW" and i_level == "LOW":
        wave = "Wave 0 (pilot)"
    elif LEVELS.index(c_level) <= 1 and LEVELS.index(i_level) <= 1:
        wave = "Wave 1"
    elif LEVELS.index(i_level) <= 1:
        wave = "Wave 2"
    else:
        wave = "Wave 3 (high impact)"

    return RiskResult(complexity, c_level, impact, i_level, overall, blocked, blockers, wave, breakdown)


def _input_hash(app: Application, resolved: set[str] | None = None) -> str:
    payload = {
        "resolved": sorted(resolved or []),
        "rules": RULES_VERSION,
        "findings": sorted((f.code, f.severity) for f in app.findings),
        "users": app.user_count, "status": app.okta_status,
        "active": getattr(app, "usage_unique_users", None) if getattr(app, "usage_known", False) else None,
        "crit": app.business_criticality, "test": app.has_test_environment,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def score_app(session: Session, app: Application, weights=None) -> RiskScore | None:
    """Compute and persist if inputs changed. Returns the (new or current) RiskScore."""
    if not (app.is_saml or app.is_oidc):
        return None
    from app.services.decisions import resolved_codes
    resolved = resolved_codes(session)
    digest = _input_hash(app, resolved)
    latest = session.scalars(select(RiskScore).where(RiskScore.app_id == app.id)
                             .order_by(RiskScore.id.desc()).limit(1)).first()
    if latest and latest.input_sha256 == digest:
        return latest
    r = compute(app, weights, resolved)
    row = RiskScore(app_id=app.id, rules_version=RULES_VERSION, input_sha256=digest,
                    complexity_score=r.complexity_score, complexity_level=r.complexity_level,
                    impact_score=r.impact_score, impact_level=r.impact_level,
                    overall_level=r.overall_level, blocked=r.blocked, blockers=r.blockers,
                    suggested_wave=r.suggested_wave, breakdown=[asdict(c) for c in r.breakdown])
    session.add(row)
    app.complexity_score, app.complexity_level = r.complexity_score, r.complexity_level
    app.impact_score, app.impact_level = r.impact_score, r.impact_level
    app.overall_level, app.blocked, app.suggested_wave = r.overall_level, r.blocked, r.suggested_wave
    session.flush()
    return row


def score_all(session: Session, weights=None) -> int:
    n = 0
    for app in session.scalars(select(Application).where(
            (Application.is_saml.is_(True)) | (Application.is_oidc.is_(True)),
            Application.removed_from_okta.is_(False))):
        score_app(session, app, weights)
        n += 1
    return n


def latest_score(session: Session, app_id: str) -> RiskScore | None:
    return session.scalars(select(RiskScore).where(RiskScore.app_id == app_id)
                           .order_by(RiskScore.id.desc()).limit(1)).first()
