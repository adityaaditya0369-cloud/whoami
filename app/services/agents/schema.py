"""The only shape an agent review may take. Anything else is rejected."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AGENTS = ["SAML_ANALYSIS", "CLAIMS_MAPPING", "GROUP_MAPPING", "RISK"]
AGENT_TITLE = {
    "SAML_ANALYSIS": "SAML analysis agent", "CLAIMS_MAPPING": "Claims mapping agent",
    "GROUP_MAPPING": "Group mapping agent", "RISK": "Risk agent",
}
Assessment = Literal["AGREE", "CONCERN", "DISAGREE"]
Verdict = Literal["AGREE", "AGREE_WITH_CONCERNS", "DISAGREE"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ItemReview(_Strict):
    key: str = Field(description="The item key from the input, verbatim")
    assessment: Assessment = Field(description="AGREE with the rule result, CONCERN (agree but something needs "
                                               "checking), or DISAGREE (the rule result looks wrong)")
    comment: str = Field(max_length=700, description="Why. Specific to this app.")
    suggestion: str | None = Field(default=None, max_length=500,
                                   description="What to change or check, if anything")
    citations: list[str] = Field(default_factory=list, max_length=4,
                                 description="Knowledge base ids (KB-n) that support this comment; only ids from the input")


class AgentReviewOutput(_Strict):
    verdict: Verdict = Field(description="DISAGREE if any item is DISAGREE, AGREE_WITH_CONCERNS if any is CONCERN, else AGREE")
    summary: str = Field(max_length=1200, description="2-4 sentences for the IAM lead")
    items: list[ItemReview]
    questions: list[str] = Field(default_factory=list, max_length=6,
                                 description="Questions for the app owner or vendor that would settle a concern")


def tool_schema() -> dict:
    return AgentReviewOutput.model_json_schema()
