"""Run the four review agents, validate them, and let a person accept the result.

Flow per agent:  items (rule results) + knowledge passages -> (mask) -> provider
                 -> (unmask) -> schema check -> policy check -> store
The panel is accepted or rejected as a whole by a named reviewer. Every
DISAGREE needs a written resolution. Accepting moves the app to MAPPING_READY.
Agents cannot change mappings, scores or configuration.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import AiProvider, Settings
from app.models.db import AgentReview, AgentRun, Application, Group, utcnow
from app.models.state import MigrationState
from app.services import knowledge, risk
from app.services.agents import items as itm
from app.services.agents.reviewers import AnthropicReviewer, OfflineReviewer
from app.services.agents.schema import AGENTS, AgentReviewOutput
from app.services.ai.context import Masker
from app.services.state_service import record_event, transition

log = logging.getLogger(__name__)
KB_PER_ITEM = 2
KB_PER_AGENT = 8
CITE_MIN = 3.0      # offline reviewer cites a passage only above this BM25 score
_LEVEL_CLAIM = re.compile(r"\b(low|medium|high|critical)[\s-]+(risk|complexity|impact)\b", re.I)
_KB_REF = re.compile(r"\bKB-\d+\b")


def get_reviewer(settings: Settings, name: str | None = None):
    name = name or settings.ai_provider.value
    if name == AiProvider.ANTHROPIC.value:
        if not settings.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set")
        return AnthropicReviewer(settings.anthropic_api_key.get_secret_value(), settings.claude_model, settings.ai_max_tokens)
    return OfflineReviewer()


def _dedupe(items: list[itm.Item]) -> list[itm.Item]:
    seen: dict[str, int] = {}
    for i in items:
        if i.key in seen:
            seen[i.key] += 1
            i.key = f"{i.key}#{seen[i.key]}"
        else:
            seen[i.key] = 1
    return items


def _ognl(session: Session, settings: Settings) -> bool:
    from app.services.approval import ognl_allowed
    return ognl_allowed(session, settings)


def build_items(session: Session, app: Application, settings: Settings) -> dict[str, list[itm.Item]]:
    score = risk.latest_score(session, app.id)
    groups = {g.id: g for g in session.scalars(select(Group)).all()}
    return {
        "SAML_ANALYSIS": _dedupe(itm.saml_items(app, settings)),
        "CLAIMS_MAPPING": _dedupe(itm.claims_items(app, settings, _ognl(session, settings))),
        "GROUP_MAPPING": _dedupe(itm.group_items(app, settings, groups)),
        "RISK": _dedupe(itm.risk_items(app, score)),
    }


def build_context(session: Session, app: Application, agent: str, items: list[itm.Item], settings: Settings) -> dict:
    cache: dict = {}
    kb_by_item: dict[str, list[str]] = {}
    passages: dict[str, dict] = {}
    for i in items:
        hits = knowledge.search(session, f"{i.query} {i.rule_result}", k=KB_PER_ITEM, app_id=app.id, _cache=cache)
        for h in hits:
            if h.ref not in passages and len(passages) >= KB_PER_AGENT:
                continue
            passages.setdefault(h.ref, h.as_context())
            if h.score >= CITE_MIN:
                kb_by_item.setdefault(i.key, []).append(h.ref)
    score = risk.latest_score(session, app.id)
    return {
        "agent": agent,
        "application": {"label": app.label, "type": "custom SAML" if app.is_custom_saml else "OIN catalog",
                        "assigned_users": app.user_count, "business_criticality": app.business_criticality,
                        "has_test_environment": app.has_test_environment},
        "risk": None if score is None else {"overall_level": score.overall_level, "complexity": score.complexity_level,
                                            "impact": score.impact_level, "blocked": score.blocked},
        "target": {"product": "PingFederate (self-hosted)", "directory": settings.pf_directory_type.value,
                   "ognl_allowed": _ognl(session, settings)},
        "items": [i.as_context() for i in items],
        "knowledge": list(passages.values()),
        "_kb_by_item": kb_by_item,
    }


def policy_errors(out: AgentReviewOutput, ctx: dict) -> list[str]:
    errs = []
    keys = [i["key"] for i in ctx["items"]]
    got = [i.key for i in out.items]
    for k in sorted(set(got) - set(keys)):
        errs.append(f"Reviews an item that does not exist: {k}")
    for k in [k for k in keys if k not in got]:
        errs.append(f"Item not reviewed: {k}")
    for k in {k for k in got if got.count(k) > 1}:
        errs.append(f"Item reviewed more than once: {k}")
    offered = {p["id"] for p in ctx["knowledge"]}
    for i in out.items:
        for c in set(i.citations) - offered:
            errs.append(f"{i.key}: cites {c}, which was not provided")
    texts = [out.summary] + [i.comment for i in out.items] + [i.suggestion or "" for i in out.items]
    for t in texts:
        for ref in set(_KB_REF.findall(t)) - offered:
            errs.append(f"Mentions {ref}, which was not provided")
    kinds = {i.assessment for i in out.items}
    expected = "DISAGREE" if "DISAGREE" in kinds else ("AGREE_WITH_CONCERNS" if "CONCERN" in kinds else "AGREE")
    if out.verdict != expected:
        errs.append(f"Verdict {out.verdict} does not match the item assessments (expected {expected})")
    r = ctx.get("risk") or {}
    allowed = {"risk": r.get("overall_level"), "complexity": r.get("complexity"), "impact": r.get("impact")}
    for t in texts:
        for level, dim in _LEVEL_CLAIM.findall(t):
            if allowed.get(dim.lower()) and level.upper() != allowed[dim.lower()]:
                errs.append(f"Text states '{level} {dim}' but the computed {dim} level is {allowed[dim.lower()]}")
    return errs


def input_hash(contexts: dict, provider: str, model: str | None, masked: bool) -> str:
    blob = json.dumps({"c": contexts, "p": provider, "m": model, "masked": masked}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def latest_run(session: Session, app_id: str) -> AgentRun | None:
    return session.scalars(select(AgentRun).where(AgentRun.app_id == app_id).order_by(AgentRun.id.desc()).limit(1)).first()


def _urls(app) -> list[str]:
    s = app.saml
    out = []
    if s is not None:
        out += [s.audience or "", s.sso_acs_url or "", s.slo_logout_url or ""]
        out += [e.get("url") or "" for e in (s.acs_endpoints or [])]
    return [u for u in out if u.startswith("http")]


def run_panel(session: Session, app: Application, settings: Settings, actor: str,
              provider_name: str | None = None, force: bool = False, reviewer=None) -> AgentRun:
    if not app.is_saml or app.saml is None:
        raise ValueError("The review agents cover SAML apps")
    if app.state in (MigrationState.OUT_OF_SCOPE.value,):
        raise ValueError("App is out of scope")
    risk.score_app(session, app, risk.load_weights(settings.risk_weights_file))
    reviewer = reviewer or get_reviewer(settings, provider_name)
    masked = settings.ai_mask_data and reviewer.name != "offline"
    model_hint = getattr(reviewer, "model", None)
    all_items = build_items(session, app, settings)
    contexts = {a: build_context(session, app, a, all_items[a], settings) for a in AGENTS}
    digest = input_hash({a: {k: v for k, v in c.items() if k != "_kb_by_item"} for a, c in contexts.items()},
                        reviewer.name, model_hint, masked)
    if not force:
        prev = session.scalars(select(AgentRun).where(AgentRun.app_id == app.id, AgentRun.input_sha256 == digest,
                                                      AgentRun.status == "VALID").order_by(AgentRun.id.desc()).limit(1)).first()
        if prev:
            return prev

    run = AgentRun(app_id=app.id, requested_by=actor, provider=reviewer.name, model=model_hint,
                   masked=masked, input_sha256=digest, status="ERROR")
    for pos, agent in enumerate(AGENTS):
        ctx = contexts[agent]
        row = AgentReview(position=pos, agent=agent, status="ERROR", items=ctx["items"],
                          knowledge_refs=[p["id"] for p in ctx["knowledge"]])
        send = ctx if reviewer.name == "offline" else {k: v for k, v in ctx.items() if k != "_kb_by_item"}
        masker = Masker() if masked else None
        if masker:  # group names, app label and hosts -> stable tokens (reversed on the output)
            for i in ctx["items"]:
                if i["key"].startswith("assigned_group:"):
                    masker._token("group", i["key"].split(":", 1)[1])
            from app.models.db import Group  # every Okta group name, wherever it appears (samples, KB text)
            for g in session.scalars(select(Group.name)):
                if g:
                    masker._token("group", g)
            for u in _urls(app):  # register hosts first so bare mentions are caught too
                masker._mask_str(u)
            send = json.loads(json.dumps(send, default=str))
            send["application"]["label"] = masker._token("app", send["application"]["label"])
            send = masker._walk(send)
        try:
            result = reviewer.review(agent, send)
            run.model = result.model
            row.input_tokens, row.output_tokens = result.input_tokens, result.output_tokens
            raw = masker.unmask(result.raw) if masker else result.raw
            row.output = raw
            try:
                out = AgentReviewOutput.model_validate(raw)
            except ValidationError as exc:
                row.status = "REJECTED_SCHEMA"
                row.errors = [f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()][:30]
            else:
                errs = policy_errors(out, ctx)
                row.status, row.errors, row.output = ("REJECTED_POLICY" if errs else "VALID"), errs, out.model_dump()
        except Exception as exc:  # network, auth, refusal
            log.exception("Agent %s failed for %s", agent, app.id)
            row.status, row.errors = "ERROR", [f"{type(exc).__name__}: {str(exc)[:500]}"]
        run.reviews.append(row)
    statuses = {r.status for r in run.reviews}
    run.status = "VALID" if statuses == {"VALID"} else ("ERROR" if "ERROR" in statuses else "REJECTED")
    session.add(run)
    session.flush()
    record_event(session, "AGENT_REVIEW_GENERATED", actor, app.id,
                 {"run_id": run.id, "provider": run.provider, "model": run.model, "status": run.status,
                  "disagreements": len(disagreements(run)), "masked": masked})
    return run


def disagreements(run: AgentRun) -> list[tuple[str, dict]]:
    out = []
    for r in run.reviews:
        for i in (r.output or {}).get("items", []) if r.status == "VALID" else []:
            if i.get("assessment") == "DISAGREE":
                out.append((f"{r.agent}:{i['key']}", i))
    return out


def counts(run: AgentRun) -> dict:
    c = {"AGREE": 0, "CONCERN": 0, "DISAGREE": 0}
    for r in run.reviews:
        for i in (r.output or {}).get("items", []) if r.status == "VALID" else []:
            c[i.get("assessment", "AGREE")] = c.get(i.get("assessment", "AGREE"), 0) + 1
    return c


def review(session: Session, run: AgentRun, actor: str, decision: str, comment: str = "",
           resolutions: dict[str, str] | None = None) -> None:
    actor = (actor or "").strip()
    if not actor or actor.lower() in {"system", "ai", "claude"}:
        raise ValueError("A named reviewer is required")
    if decision not in ("ACCEPTED", "REJECTED"):
        raise ValueError("Decision must be ACCEPTED or REJECTED")
    if run.review_status != "PENDING":
        raise ValueError(f"Review already {run.review_status.lower()}")
    if decision == "ACCEPTED" and run.status != "VALID":
        raise ValueError("Only a run where all four agents are VALID can be accepted; re-run the agents")
    if decision == "REJECTED" and not comment.strip():
        raise ValueError("A comment is required when rejecting")
    resolutions = {k: v.strip() for k, v in (resolutions or {}).items() if v and v.strip()}
    if decision == "ACCEPTED":
        missing = [k for k, _ in disagreements(run) if k not in resolutions]
        if missing:
            raise ValueError("Write how each disagreement is resolved before accepting: " + ", ".join(missing))
    app = session.get(Application, run.app_id)
    if decision == "ACCEPTED" and app.state not in (MigrationState.DISCOVERED.value, MigrationState.ASSESSED.value,
                                                     MigrationState.MAPPING_READY.value):
        raise ValueError(f"App is in {app.state}; agent reviews can be accepted before the plan stage only")
    run.review_status, run.reviewed_by, run.reviewed_at = decision, actor, utcnow()
    run.review_comment, run.resolutions = comment or None, resolutions
    record_event(session, f"AGENT_REVIEW_{decision}", actor, app.id,
                 {"run_id": run.id, "comment": comment, "resolutions": resolutions})
    if decision == "ACCEPTED":
        if app.state == MigrationState.DISCOVERED.value:
            transition(session, app, MigrationState.ASSESSED, actor, reason=f"Agent review #{run.id} accepted")
        if app.state == MigrationState.ASSESSED.value:
            transition(session, app, MigrationState.MAPPING_READY, actor,
                       reason=f"Mapping reviewed by agents (run #{run.id}) and accepted", detail={"run_id": run.id})
