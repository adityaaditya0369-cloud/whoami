"""Shared constants — ported from lib/types.ts."""

STATUS_NOT_STARTED = "NOT_STARTED"
STATUS_LEARNING = "LEARNING"
STATUS_PRACTICED = "PRACTICED"
STATUS_COMPLETED = "COMPLETED"

STATUS_ORDER = [STATUS_NOT_STARTED, STATUS_LEARNING, STATUS_PRACTICED, STATUS_COMPLETED]

STATUS_LABELS = {
    STATUS_NOT_STARTED: "Not started",
    STATUS_LEARNING: "Learning",
    STATUS_PRACTICED: "Practiced",
    STATUS_COMPLETED: "Completed",
}

CATEGORIES = [
    "Authentication",
    "Authorization",
    "Federation",
    "Provisioning",
    "MFA",
    "Identity Governance",
    "API Security",
    "Agentic AI",
    "Security",
]

ACTIVITY_TYPES = {"VIEWED", "SEARCHED", "STATUS_CHANGED", "TRACKED", "ASKED_COPILOT", "SYSTEM"}
