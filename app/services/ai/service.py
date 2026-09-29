"""Run, validate, store and review assessments.

Flow:  context -> (mask) -> provider -> (unmask) -> schema check -> policy check -> store
A human then ACCEPTS (app moves to ASSESSED) or REJECTS. Nothing here can
change scores, findings or configuration.
"""
from __future__ import annotations

import logging
import re

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import AiProvider, Settings
from app.models.db import AiAssessment, Application, utcnow
from app.models.state import MigrationState
from app.services import risk
from app.services.ai.context import Masker, build_context, context_hash
from app.services.ai.providers import AnthropicProvider, OfflineProvider
from app.services.ai.schema import AssessmentOutput
from app.services.state_service import record_event, transition

log = logging.getLogger(__name__)

_LEVEL_CLAIM = re.compile(r"\b(low|medium|high|critical)[\s-]+(risk|complexity|impact)\b", re.I)


def get_provider(settings: Settings, name: str | None = None):
    name = name or settings.ai_provider.value
    if name == AiProvider.ANTHROPIC.value:
        if not settings.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set")
        return AnthropicProvider(settings.anthropic_api_key.get_secret_value(), settings.claude_model,
                                 settings.ai_max_tokens)
    return OfflineProvider()


def policy_errors(out: AssessmentOutput, ctx: dict) -> list[str]:
    errs: list[str] = []
    codes = {f["code"] for f in ctx["findings"]}
    must_explain = {f["code"] for f in ctx["findings"] if f["severity"] in ("WARNING", "CRITICAL")}
    explained = [e.code for e in out.finding_explanations]
    for c in set(explained) - codes:
        errs.append(f"Explains a finding that does not exist: {c}")
    for c in sorted(must_explain - set(explained)):
        errs.append(f"Missing explanation for {c}")
    for a in out.recommended_actions:
        for c in set(a.related_codes) - codes:
            errs.append(f"Action refers to unknown finding {c}")

    r = ctx.get("risk") or {}
    app = ctx["application"]
    decom = app["okta_status"] != "ACTIVE" or "NO_ASSIGNMENTS" in codes
    if r.get("blocked") and out.migration_approach not in ("BLOCKED", "DECOMMISSION_CANDIDATE"):
        errs.append("Risk engine says BLOCKED but the assessment does not")
    if not r.get("blocked") and out.migration_approach == "BLOCKED":
        errs.append("Assessment says BLOCKED but the risk engine does not")
    if out.migration_approach == "DECOMMISSION_CANDIDATE" and not decom:
        errs.append("DECOMMISSION_CANDIDATE used for an active, assigned app")

    allowed = {"risk": r.get("overall_level"), "complexity": (r.get("complexity") or {}).get("level"),
               "impact": (r.get("impact") or {}).get("level")}
    texts = [out.summary] + [e.explanation for e in out.finding_explanations]
    for t in texts:
        for level, dim in _LEVEL_CLAIM.findall(t):
            if allowed.get(dim.lower()) and level.upper() != allowed[dim.lower()]:
                errs.append(f"Text states '{level} {dim}' but the computed {dim} level is {allowed[dim.lower()]}")
    return errs


def latest_assessment(session: Session, app_id: str) -> AiAssessment | None:
    return session.scalars(select(AiAssessment).where(AiAssessment.app_id == app_id)
                           .order_by(AiAssessment.id.desc()).limit(1)).first()


def run_assessment(session: Session, app: Application, settings: Settings, actor: str,
                   provider_name: str | None = None, force: bool = False, provider=None) -> AiAssessment:
    if not app.is_saml or app.saml is None:
        raise ValueError("Only SAML apps can be assessed")
    score = risk.score_app(session, app, risk.load_weights(settings.risk_weights_file))
    provider = provider or get_provider(settings, provider_name)
    ctx = build_context(app, score, settings)
    masked = settings.ai_mask_data and provider.name != "offline"
    model_hint = getattr(provider, "model", None)
    digest = context_hash(ctx, provider.name, model_hint, masked)

    if not force:
        prev = session.scalars(select(AiAssessment).where(
            AiAssessment.app_id == app.id, AiAssessment.input_sha256 == digest,
            AiAssessment.status == "VALID").order_by(AiAssessment.id.desc()).limit(1)).first()
        if prev:
            return prev

    row = AiAssessment(app_id=app.id, risk_score_id=score.id if score else None, requested_by=actor,
                       provider=provider.name, model=model_hint, input_sha256=digest, masked=masked,
                       status="ERROR")
    masker = Masker() if masked else None
    sent = masker.mask(ctx) if masker else ctx
    try:
        result = provider.assess(sent)
        row.model = result.model
        row.input_tokens, row.output_tokens = result.input_tokens, result.output_tokens
        raw = masker.unmask(result.raw) if masker else result.raw
        row.output = raw
        try:
            out = AssessmentOutput.model_validate(raw)
        except ValidationError as exc:
            row.status = "REJECTED_SCHEMA"
            row.errors = [f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()][:30]
        else:
            errs = policy_errors(out, ctx)
            row.status = "REJECTED_POLICY" if errs else "VALID"
            row.errors = errs
            row.output = out.model_dump()
    except Exception as exc:  # network, auth, model refusal...
        log.exception("Assessment failed for %s", app.id)
        row.status, row.errors = "ERROR", [f"{type(exc).__name__}: {str(exc)[:500]}"]
    session.add(row)
    session.flush()
    record_event(session, "ASSESSMENT_GENERATED", actor, app.id,
                 {"assessment_id": row.id, "provider": row.provider, "model": row.model,
                  "status": row.status, "masked": masked})
    return row


def review(session: Session, a: AiAssessment, actor: str, decision: str, comment: str = "") -> None:
    actor = (actor or "").strip()
    if not actor or actor.lower() in {"system", "ai", "claude"}:
        raise ValueError("A named reviewer is required")
    if decision not in ("ACCEPTED", "REJECTED"):
        raise ValueError("Decision must be ACCEPTED or REJECTED")
    if a.status != "VALID" and decision == "ACCEPTED":
        raise ValueError("Only a VALID assessment can be accepted")
    if a.review_status != "PENDING":
        raise ValueError(f"Assessment already {a.review_status.lower()}")
    if decision == "REJECTED" and not comment.strip():
        raise ValueError("A comment is required when rejecting")
    a.review_status, a.reviewed_by, a.reviewed_at, a.review_comment = decision, actor, utcnow(), comment or None
    record_event(session, f"ASSESSMENT_{decision}", actor, a.app_id,
                 {"assessment_id": a.id, "comment": comment})
    app = session.get(Application, a.app_id)
    if decision == "ACCEPTED" and app.state == MigrationState.DISCOVERED.value:
        transition(session, app, MigrationState.ASSESSED, actor=actor,
                   reason=f"Assessment #{a.id} accepted", detail={"assessment_id": a.id})
