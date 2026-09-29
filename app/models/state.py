"""Migration state machine.

The state of every application lives in the database (applications.state)
and only moves through `transition()` in app.services.state_service, which
validates against ALLOWED_TRANSITIONS and writes an audit event.
Nothing - including AI output - may set the state column directly.
"""
from __future__ import annotations

from enum import Enum


class MigrationState(str, Enum):
    DISCOVERED = "DISCOVERED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"          # decommission / not migrating
    ASSESSED = "ASSESSED"
    MAPPING_READY = "MAPPING_READY"
    PLAN_GENERATED = "PLAN_GENERATED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    REJECTED = "REJECTED"                  # approval rejected -> remediation
    APPROVED = "APPROVED"
    PF_CONFIGURED = "PF_CONFIGURED"        # PingFederate SP connection created
    VENDOR_CONFIGURED = "VENDOR_CONFIGURED"  # SP side switched (manual step)
    TESTING = "TESTING"
    BUSINESS_VALIDATION = "BUSINESS_VALIDATION"
    READY_FOR_CUTOVER = "READY_FOR_CUTOVER"
    MIGRATED = "MIGRATED"
    VALIDATED = "VALIDATED"
    FAILED = "FAILED"
    ROLLBACK = "ROLLBACK"
    OKTA_ACTIVE = "OKTA_ACTIVE"            # rolled back, Okta still the IdP


S = MigrationState

ALLOWED_TRANSITIONS: dict[MigrationState, set[MigrationState]] = {
    S.DISCOVERED: {S.ASSESSED, S.OUT_OF_SCOPE},
    S.OUT_OF_SCOPE: {S.DISCOVERED},
    S.ASSESSED: {S.MAPPING_READY, S.OUT_OF_SCOPE, S.DISCOVERED},
    S.MAPPING_READY: {S.PLAN_GENERATED, S.ASSESSED},
    S.PLAN_GENERATED: {S.AWAITING_APPROVAL, S.MAPPING_READY},
    S.AWAITING_APPROVAL: {S.APPROVED, S.REJECTED},
    S.REJECTED: {S.MAPPING_READY, S.PLAN_GENERATED, S.OUT_OF_SCOPE},
    S.APPROVED: {S.PF_CONFIGURED, S.REJECTED},
    S.PF_CONFIGURED: {S.TESTING, S.VENDOR_CONFIGURED, S.FAILED},
    S.VENDOR_CONFIGURED: {S.TESTING, S.FAILED},
    S.TESTING: {S.BUSINESS_VALIDATION, S.FAILED},
    S.BUSINESS_VALIDATION: {S.READY_FOR_CUTOVER, S.FAILED},
    S.READY_FOR_CUTOVER: {S.MIGRATED, S.FAILED},
    S.MIGRATED: {S.VALIDATED, S.FAILED},
    S.VALIDATED: {S.FAILED},   # only within the rollback window (enforced in cutover.declare_failed)
    S.FAILED: {S.ROLLBACK, S.TESTING},
    S.ROLLBACK: {S.OKTA_ACTIVE},
    S.OKTA_ACTIVE: {S.MAPPING_READY, S.PLAN_GENERATED},
}

# States that require a named human actor (not "system") to enter.
HUMAN_GATED: set[MigrationState] = {
    S.APPROVED, S.REJECTED, S.OUT_OF_SCOPE, S.READY_FOR_CUTOVER, S.MIGRATED, S.ROLLBACK,
}


class InvalidTransition(Exception):
    pass


def check_transition(current: MigrationState, target: MigrationState, actor: str) -> None:
    if target not in ALLOWED_TRANSITIONS[current]:
        raise InvalidTransition(f"{current.value} -> {target.value} is not allowed")
    if target in HUMAN_GATED and (not actor or actor.lower() in {"system", "ai", "claude"}):
        raise InvalidTransition(f"{target.value} requires a named human actor")
