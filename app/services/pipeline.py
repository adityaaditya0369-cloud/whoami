"""Where each SAML app is in the end-to-end pipeline (for the board and the stepper)."""
from __future__ import annotations

from app.models.state import MigrationState as S

STAGES = [
    ("discovery", "Discovery", {S.DISCOVERED}),
    ("agents", "Agent review", {S.ASSESSED}),
    ("plan", "Plan & approval", {S.MAPPING_READY, S.PLAN_GENERATED, S.AWAITING_APPROVAL, S.REJECTED}),
    ("build", "PingFederate", {S.APPROVED}),
    ("validation", "SAML validation", {S.PF_CONFIGURED, S.VENDOR_CONFIGURED, S.TESTING, S.BUSINESS_VALIDATION}),
    ("cutover", "Cutover", {S.READY_FOR_CUTOVER, S.MIGRATED}),
    ("done", "Validated", {S.VALIDATED}),
    ("rollback", "Failed / rollback", {S.FAILED, S.ROLLBACK, S.OKTA_ACTIVE}),
]
STAGE_KEYS = [k for k, _, _ in STAGES]
NEXT_ACTION = {
    S.DISCOVERED: "Run the review agents",
    S.ASSESSED: "Run and accept the review agents",
    S.MAPPING_READY: "Generate the migration plan",
    S.PLAN_GENERATED: "Submit the plan for approval",
    S.AWAITING_APPROVAL: "Approver: approve or reject the plan",
    S.REJECTED: "Fix and regenerate the plan",
    S.APPROVED: "Create on PingFederate (dry run, then create) or confirm the manual import",
    S.PF_CONFIGURED: "Run a pre-cutover SAML validation",
    S.VENDOR_CONFIGURED: "Run a pre-cutover SAML validation",
    S.TESTING: "Pass validation, then app owner signs off",
    S.BUSINESS_VALIDATION: "Go/no-go decision",
    S.READY_FOR_CUTOVER: "Switch the SP, then record the cutover",
    S.MIGRATED: "Run the post-cutover validation",
    S.VALIDATED: "Remove the Okta app after the rollback window",
    S.FAILED: "Roll back, or fix and test again",
    S.ROLLBACK: "Confirm users sign in through Okta again",
    S.OKTA_ACTIVE: "Fix the cause, regenerate the plan",
    S.OUT_OF_SCOPE: "—",
}


def stage_of(state: str) -> str:
    st = S(state)
    for key, _, states in STAGES:
        if st in states:
            return key
    return "discovery"


def tab_for(state: str) -> str:
    return {"discovery": "agents", "agents": "agents", "plan": "plan", "build": "build", "validation": "validation",
            "cutover": "cutover", "done": "cutover", "rollback": "cutover"}[stage_of(state)]
