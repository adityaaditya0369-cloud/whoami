# IdentityBridge AI: progress and handoff notes

Last updated: 29 Sep 2026. Project folder: `C:\Claude\okta-pingfederate-migration-factory`.

## What this is
A tool for a **real customer migration of SAML (and some OIDC) apps from Okta to PingFederate**, with AD
(or PingDirectory) as PingFederate's directory. Principle: **rules decide, AI reviews, people approve, the tool checks.**

## Built so far (all tested: 171 tests pass)
1. **Discovery (Sprint 1):** Okta apps, groups, users, assignments, certificates, 90-day sign-in usage.
   Live API (read-only) or offline export. Snapshots and change detection.
2. **Assessment (Sprint 2):** ~30 findings, risk scores and waves, AI explanation with review,
   Okta vs PingFederate comparison (SAML and OIDC tabs), Excel report.
3. **Three areas:** Okta apps, PingFederate apps (read-only sync + reconciliation), Migration plan (7-step checklist).
4. **Quick-migration features:** usage analysis, decisions register + what-if, effort/timeline (Gantt),
   strategy report (Word), app-owner comms pack, PingFederate build package (ZIP).
5. **Pipeline (your diagram):**
   - 4 review agents (SAML, claims, groups, risk) that check the rules and cite a knowledge base (uploaded docs).
   - Versioned plans with four-eyes approval and Okta drift detection.
   - Gated PingFederate write: create-only, disabled, dry run first, separate write account (off by default).
   - SAML validation of a pasted/uploaded response: signature verified with `PF_SIGNING_CERT_FILE`,
     compared with the Okta baseline. Optional automated test sign-in (off by default).
   - Go/no-go gate, cutover, post-cutover check, rollback (also up to 7 days after Validated), Word runbook.
   - Independent safety review done; all findings fixed and covered by tests.

6. **Strategy pack (Phases 1-5 of the strategy model):** tenant-object discovery (policies, authenticators,
   group rules, authorization servers, hooks, IdPs, zones), a versioned PingFederate capability catalog (41 rows,
   with evidence, sources and "expert review" flags), a decision engine (Recreate / Transform / Redesign / Retire /
   Retain), complexity factors, a dependency graph (from Okta, CSV/CMDB import, manual, document suggestions with
   human confirmation), dependency-aware waves, foundation work before Wave 0, and executive / architect / engineer
   views with Excel and Word exports. Independent review done; fixes applied (185 tests).

## Settings to remember
- `PF_SIGNING_CERT_FILE` is required for pre/post-cutover validation to pass the gate.
- `AI_PROVIDER=offline` by default; with `anthropic`, set `AI_MASK_DATA=true`.
- `PF_WRITE_ENABLED=false` by default; needs `PF_SOURCE=live`, `PF_WRITE_USER`, `PF_WRITE_PASSWORD`.

## Known gaps
- Catalog rows marked "expert review" need a PingFederate architect's confirmation for the customer.
- Not yet in the catalog: desktop SSO (IWA/Kerberos), device trust, sign-in page branding; authorization-server
  policy rules (grant types, token lifetimes) are not read yet.
- No login: names are typed, so four-eyes relies on honesty.
- Single machine, SQLite.
- Users are not checked against AD before cutover.
- OIDC apps get the checklist only (no token validation or client write).
- Knowledge search is keyword-based, not semantic.

## Recommended next steps (in order)
1. **Directory user check:** read-only LDAP to AD/PingDirectory; for every assigned user check existence,
   NameID match, attributes, and `PF-<App>-Users` membership; new gate checks + Excel fix list.
2. **Group membership sync check** for Okta-only groups (gate check).
3. **Post-cutover monitoring + decommission readiness** (Okta System Log stragglers, PingFederate sign-in stats).
4. **Scheduled nightly discovery + PingFederate sync** with change alerts.
5. **Login and roles** before several people use the tool.
6. Wave-level operations, weekly steering pack, OIDC pipeline, Docker/PostgreSQL deployment.

## LinkedIn
Images in `docs/linkedin/` (architecture SAML + OIDC, SAML pipeline). Product name: IdentityBridge AI.

## Open questions for you
- Can the customer give a read-only LDAP bind account? AD or PingDirectory? Users per app?
- PingFederate version and Admin API access (read, and write if the gated write is wanted)?
- Is `okta.logs.read` approved? What is the OGNL policy?
- Team size and deadline?
- Do you want an architecture / "AI usage and data handling" document or deck for the customer?
