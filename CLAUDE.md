# CLAUDE.md: rules for AI assistants working in this repo

This tool supports a **real customer migration** of SAML apps from Okta to **PingFederate**
(self-hosted), with an LDAP directory (AD by default, or PingDirectory) as PingFederate's data store.

## Non-negotiables
1. **The LLM never calls Okta or the PingFederate Admin API.** AI output is structured JSON,
   validated with Pydantic, checked against policy, approved by a human, and only then run by
   deterministic Python executors.
2. **Only `app/services/state_service.transition()` changes `Application.state`.** It enforces
   `ALLOWED_TRANSITIONS` and writes an audit event. Approval states need a named human actor.
3. **Risk scoring is deterministic** (Sprint 2). Claude explains findings and scores; it never decides them.
4. **Discovery and PingFederate reading are read-only** (PingFederate: Auditor role, GET only). Okta credentials use read-only scopes and the Read-Only Admin role.
   The ONLY write is `app/integrations/pingfederate/writer.py` (create SP connection, disabled, separate
   write account), called only from `app/services/pf_write.apply` after an approved plan and a fresh dry run.
   Never add update/delete methods there.
5. **Never log or persist secrets.** Tokens are read from the environment only.
6. **`migration_events` and `raw_snapshots` are append-only.**
7. **Generated artefacts never contain secrets** (comms, build package), and scripts default to `-WhatIf`.
8. **AI narrative may not introduce numbers** that are not in the computed figures (`strategy.validate_narrative`).
9. **Review agents review; rules decide.** `app/services/agents/` output never changes mappings, scores or state.
10. **The go/no-go gate** only counts validations verified with the configured PingFederate certificate, for the
    current plan, recorded after any failure (`cutover.current_pre`, `counts_for_gate`). Keep it that way.
11. **Compatibility and strategy come only from `app/strategy_model/catalog.py` + `engine.py`** (versioned,
    deterministic). AI may explain them or suggest dependencies; suggested dependencies stay SUGGESTED until a named
    person confirms them, and never overwrite a person's decision.

## Layout
- `app/integrations/okta/client.py`: `LiveOktaClient` (API) and `FileOktaSource` (offline export), one interface
- `app/integrations/okta/parser.py`: pure raw JSON → Pydantic domain models
- `app/integrations/pingfederate/mapping.py`: where each claim/NameID comes from in PingFederate
  (DATA_STORE / TEXT / OGNL / APPUSER / UNMAPPED / GROUP_LDAP_SEARCH / GROUP_OGNL)
- `app/services/discovery.py`: persistence, snapshots, drift detection
- `app/services/findings.py`: deterministic rules (codes are a stable contract, so don't rename them)
- `app/services/risk.py`: deterministic Complexity/Impact scoring (bump `RULES_VERSION` when weights change)
- `app/services/ai/`: assessment context, masking, providers, schema + policy validation, review
- `app/services/comparison.py` / `excel_report.py`: Okta vs PingFederate comparison and the Excel report
- `app/integrations/pingfederate/client.py` / `parser.py`: read-only PingFederate Admin API / export (GET only)
- `app/services/reconcile.py`: Okta app ↔ PingFederate object matching and checks; `plan.py`: 7-step checklist
- `app/services/decisions.py` (register + what-if), `estimate.py` (effort/timeline), `strategy.py` (report + Word),
  `comms.py` (app-owner messages), `build_package.py` (PingFederate JSON + directory pack; never writes anywhere)
- `app/models/state.py`: migration state machine (`PF_CONFIGURED` = SP connection created)
- Pipeline: `app/services/agents/` (review agents), `knowledge.py` (RAG), `approval.py` (plans, four-eyes),
  `pf_write.py` + `integrations/pingfederate/writer.py` (gated write), `saml_validation.py` (pure checks),
  `cutover.py` (validation records, gate, cutover/rollback, runbook), `test_sso.py` (optional headless capture)
- Strategy model: `app/strategy_model/` (`catalog.py` capability catalog, `engine.py` features/decisions/complexity,
  `dependencies.py` graph + import + suggestions, `waves.py` dependency-aware waves, `service.py` analyse + pack,
  `export.py` Excel/Word); tenant objects come from `client.list_tenant` → `discovery._discover_tenant`
- `scripts/generate_sample_export.py`: fictional Northwind tenant used by tests

## Conventions
- Put new finding rules in `findings.evaluate()` and add a parametrised case in `tests/test_discovery.py`.
- Put mapping changes in `mapping.py` and add cases in `tests/test_pf_mapping.py`.
- Run `pytest -q` before committing.
