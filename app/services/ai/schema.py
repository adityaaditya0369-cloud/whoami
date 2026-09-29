"""The only shape an assessment may take. Anything else is rejected."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Owner = Literal["IAM_TEAM", "DIRECTORY_TEAM", "VENDOR", "APP_OWNER", "SECURITY"]
When = Literal["BEFORE_MIGRATION", "DURING_CUTOVER", "AFTER_CUTOVER"]
Approach = Literal["STANDARD", "STANDARD_WITH_PREP", "COMPLEX", "BLOCKED", "DECOMMISSION_CANDIDATE"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FindingExplanation(_Strict):
    code: str = Field(description="A finding code from the input, verbatim")
    explanation: str = Field(max_length=800, description="Why it matters for this app's move to PingFederate")


class RecommendedAction(_Strict):
    action: str = Field(max_length=400)
    owner: Owner
    when: When
    related_codes: list[str] = Field(default_factory=list, description="Finding codes this action resolves")


class AssessmentOutput(_Strict):
    summary: str = Field(max_length=1500, description="3-5 sentences for an IAM lead. Do not restate scores as your own opinion.")
    migration_approach: Approach
    finding_explanations: list[FindingExplanation]
    recommended_actions: list[RecommendedAction] = Field(max_length=15)
    questions_for_app_owner: list[str] = Field(max_length=10)
    pingfederate_notes: list[str] = Field(max_length=10, description="Concrete SP connection configuration notes")
    confidence: Literal["LOW", "MEDIUM", "HIGH"]


def tool_schema() -> dict:
    """JSON schema for the forced tool call (Anthropic structured output)."""
    return AssessmentOutput.model_json_schema()
