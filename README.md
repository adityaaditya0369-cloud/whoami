# IdentityBridge AI

**Intelligent Okta to Ping Identity Migration Platform** (SAML and OIDC apps, Okta → PingFederate)

**Sprint 1: Discovery and PingFederate readiness. Sprint 2: risk engine, AI assessment, Okta vs PingFederate comparison and Excel reporting.** Finds every SAML application in an Okta
tenant and stores its full configuration. For each app it then works out what PingFederate
needs to reproduce it: which directory attributes, which OGNL expressions, which issuance
criteria, which groups have to be created, and which issuer settings. Results appear in a
dashboard and a CSV for customer workshops.

> Guiding rule: *AI recommends, deterministic code executes, humans approve.* Sprint 1 has no AI and no
> write access to anything. See `CLAUDE.md`.

## Assumptions (change in `.env`)
- **PingFederate is self-hosted**, not PingOne.
- **Directory = Active Directory**, read by PingFederate through an LDAP data store
  (`PF_DIRECTORY_TYPE=AD`, or `PINGDIRECTORY`).
- **OGNL is not allowed** (`PF_OGNL_ALLOWED=false`). OGNL is disabled by default in PingFederate
  and many security teams forbid it, so every claim that needs OGNL is **CRITICAL**. Set
  `PF_OGNL_ALLOWED=true` if the customer permits it, and those findings drop to WARNING.

## Quick start on Windows (sample tenant, no credentials needed)

```powershell
cd C:\Claude\okta-pingfederate-migration-factory
python -m venv .venv; .venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
$env:FLASK_APP="app:create_app"
flask discover --actor "your.name"
flask run --host 127.0.0.1 --port 5000
flask assess --actor "your.name"            # score + offline assessment for every app
flask report --out report.xlsx               # Excel report from the CLI
flask pf-sync                               # read PingFederate (sample export by default)
pytest -q                                   # 144 tests
```

Then open http://127.0.0.1:5000. The sample is a **fictional** tenant (Northwind):

| App | What it exercises for PingFederate |
|---|---|
| Expense Portal | Simple; all values from LDAP; needs issuance criteria |
| Expense Portal (UAT) | Reuses the prod SP entity ID, so there's a duplicate partner entity ID |
| HR Analytics (Tableau) | Concatenation and `String.substringBefore` claims (OGNL), `appuser.costCenter`, direct users, cert expiring |
| Engineering Wiki | REGEX group claim (becomes an LDAP group search), conditional claim (OGNL), custom IdP issuer (virtual server ID), 2 ACS, SLO |
| ServiceNow, Salesforce | OIN catalog apps (partial config); Salesforce custom username template |
| Legacy Travel Booking | Inactive, unassigned, NameID = Okta user id, SHA-1, expired cert |

## How Okta concepts map to PingFederate

| Okta | PingFederate | What the tool checks |
|---|---|---|
| App assignment (groups/users) | **Issuance criteria** or authentication policy on the SP connection | `ISSUANCE_CRITERIA_REQUIRED`. Without it, any user who can sign in gets an assertion. |
| Okta-native group | Group must exist in the directory | `OKTA_NATIVE_GROUPS_ASSIGNED`, `GROUP_CLAIM_OKTA_NATIVE_GROUPS` |
| `user.X` attribute | LDAP data store attribute | Classified as `DATA_STORE`, or `UNMAPPED` if no known LDAP attribute |
| Expression (`+`, `?:`, `String.*`) | OGNL, or a value pre-computed in the directory | `CLAIM_NEEDS_OGNL` (severity depends on policy) |
| `appuser.X` | Nothing, so the value must be stored in the directory | `APPUSER_ATTRIBUTE_CLAIM` |
| Group claim filter | Chained LDAP group search (`STARTS_WITH`/`EQUALS`/`CONTAINS`/prefix REGEX); other REGEX needs OGNL | `GROUP_CLAIM`, plus a suggested LDAP filter |
| Custom `idpIssuer` | Virtual server ID on the connection | `CUSTOM_IDP_ISSUER` |
| Two apps with the same audience | Partner entity ID must be unique per SP connection | `DUPLICATE_SP_ENTITY_ID` |
| NameID `${user.id}` | Can't be produced unless the Okta id is copied into the directory | `NAMEID_IS_OKTA_USER_ID` (CRITICAL) |
| Okta signing certificate | PingFederate signing certificate (Okta won't export private keys) | SP needs the new cert/metadata at cutover |

The default Okta → LDAP attribute map is in `app/integrations/pingfederate/mapping.py`. For
example, AD maps `employeeNumber` to `employeeID`. Override it with a JSON file:
`PF_ATTRIBUTE_MAP_FILE=config/attribute_map.json` containing `{"costCenter": "extensionAttribute5"}`.

## Connecting to the customer's Okta tenant

### Option A: Offline export (easiest to get approved)
The customer runs the export against their own tenant and gives you the folder:
```powershell
# with OKTA_SOURCE=live and credentials in .env
flask okta-export --out data\exports\customer-2026-10-01
```
Then set `OKTA_SOURCE=file` and `OKTA_EXPORT_DIR=data/exports/customer-2026-10-01`.

### Option B: Live API
1. In Okta Admin, go to **Applications → Create App Integration → API Services** and create a service app.
2. Under **Client Credentials**, choose *Public key / Private key*. Save the private key PEM.
3. Grant these **Okta API Scopes**: `okta.apps.read`, `okta.groups.read`, `okta.users.read`, and `okta.logs.read` for usage analysis.
4. Under **Admin roles**, assign **Read-Only Administrator**.
5. This client doesn't implement DPoP. If "Require DPoP" is enabled on the service app, turn it off for this app.
6. Set `OKTA_SOURCE=live`, `OKTA_AUTH_MODE=oauth`, `OKTA_ORG_URL`, `OKTA_CLIENT_ID`, `OKTA_PRIVATE_KEY_PATH`.

For a short pilot, a Read-Only Administrator API token also works (`OKTA_AUTH_MODE=ssws`).

## Outputs
- **Dashboard**: SAML inventory, PingFederate readiness totals (issuance criteria, OGNL, groups to
  create, LDAP attributes needed, virtual server IDs, duplicate entity IDs), findings, expiring certs.
- **App page**: full SAML config, a PingFederate source for every claim and for the NameID,
  a readiness checklist, assignments, certificates, business context, and history.
- **CSV** (`/export/inventory.csv`): one row per SAML app with `pf_*` readiness columns.
- **Audit log** and immutable raw snapshots per discovery run.

## Known limitations (check these with the customer)
- **OIN catalog apps**: Okta's API does not return the SP's ACS URL, entity ID or built-in claims.
  Get the SP metadata from the vendor.
- **Okta sign-on / MFA policies aren't discovered yet.** They decide the PingFederate
  authentication policy. This is the proposed next addition.
- **Nested groups**: the suggested LDAP group filter checks direct membership only. For AD nested
  groups, use the `LDAP_MATCHING_RULE_IN_CHAIN` rule (1.2.840.113556.1.4.1941) if the SP expects them.
- **Group filter matching** approximates Okta's semantics: case-insensitive for STARTS_WITH, EQUALS
  and CONTAINS, and REGEX must match the whole name.
- **The UI has no login.** Keep it bound to `127.0.0.1`.

## Data handling
The database holds customer configuration and user logins/emails of assigned users. To store
counts only, set `STORE_USER_DETAILS=false`. `.gitignore` keeps `data/` and `.env` out of source control.

## Sprint 2

### Risk engine (deterministic, `app/services/risk.py`)
Each app gets two scores, because one number hides the trade-off that drives wave planning:

| Dimension | From | Levels |
|---|---|---|
| **Complexity** | Points per finding (e.g. `CLAIM_NEEDS_OGNL` +3 each, `CATALOG_APP_PARTIAL_CONFIG` +5, `NAMEID_IS_OKTA_USER_ID` +5), with a cap on repeats | 0–4 Low · 5–9 Medium · 10–15 High · 16+ Critical |
| **Impact** | Assigned users (0/1/2/4/6 pts), business criticality (High 5, Medium 2, Low 0, unknown 2), SP test environment (No 5, unknown 2, Yes 0) | 0–3 Low · 4–7 Medium · 8–11 High · 12+ Critical |

- **Overall** is the higher of the two, raised one level when both are High or worse.
- **Blocked** means a CRITICAL finding or a duplicate SP entity ID. With OGNL not allowed, every OGNL claim blocks the app.
- **Suggested wave**: Wave 0 (pilot) = Low/Low; Wave 1 = both at most Medium; Wave 2 = impact at most Medium; Wave 3 = high impact; plus Blocked and Decommission review.
- Every score is stored with its breakdown and `RULES_VERSION`. Scores are recalculated after discovery and whenever you save business context.
- Weights can be overridden with `RISK_WEIGHTS_FILE`.

### Assessment (`app/services/ai/`)
- **Offline** (default): a template engine, so no data leaves the machine. It produces a summary, explanations, an action plan with owner and timing, owner questions and connection notes.
- **Claude** (`AI_PROVIDER=anthropic`, `ANTHROPIC_API_KEY`): forced tool use with a strict JSON schema. The model has no tools that can change anything.
- **What's sent**: config, claims, group names, counts, findings and scores. **Never** user names, emails, ids, certificates or raw payloads. Set `AI_MASK_DATA=true` to also replace hostnames, URLs, group names and app names with tokens. They're swapped back locally.
- **Validation**: output is rejected (`REJECTED_SCHEMA` / `REJECTED_POLICY`) if it doesn't match the schema, invents or skips finding codes, or contradicts the risk engine (e.g. calls a blocked app "standard" or states a different risk level).
- **Review**: a named person accepts or rejects. Rejecting needs a comment. Accepting moves the app from Discovered to **Assessed**. Everything is in the audit log.
- Unchanged apps aren't re-assessed (cached by an input hash) unless you tick "re-run".

### Okta vs PingFederate comparison (`app/services/comparison.py`)
Field by field for each app: SP connection, IdP identity, assertion, attributes and access control. Each field has one of these statuses:

| Status | Meaning |
|---|---|
| **SAME** | carried over unchanged |
| **CONFIGURE** | standard PingFederate setting derived from Okta |
| **SP_UPDATE** | changes by design; the SP must be updated at cutover (issuer, SSO URL, certificate, metadata) |
| **ACTION** | preparation needed first (OGNL, directory attributes, groups, issuance criteria, duplicates) |
| **UNKNOWN** | not exposed by Okta's API; get it from the vendor |
| **N/A** | not used |

Set `PF_BASE_URL` and `PF_ENTITY_ID` so the PingFederate values (`/idp/SSO.saml2`, `/idp/startSSO.ping`,
`/pf/federation_metadata.ping`, `/idp/SLO.saml2`) show your real host.

### Excel report
Get it from **Reports → Download .xlsx**, **Dashboard → Excel report**, or `flask report`. It has 9 sheets:
Summary (live COUNTIF formulas), Applications, **Okta vs PingFederate**, Attribute mapping,
Directory prep, Action plan, Owner questions (with a yellow answer column to fill in), Findings and Risk breakdown.
Each app also has its own Excel and a printable page (Print → Save as PDF).

## Sprint 2.5: protocol tabs, OIDC, side-by-side comparison
- **SAML | OIDC | Other** tabs on Applications (each with its own columns). The dashboard has a
  **SAML + OIDC / SAML / OIDC** switch. "Other" = bookmark, SWA and similar apps (out of scope).
- **OIDC discovery**: client ID, application type, grant and response types, redirect / post-logout
  URIs, client authentication, PKCE and assignments. **OIDC findings**:
  - `OIDC_NEW_CLIENT_SECRET`
  - `OIDC_IMPLICIT_GRANT`
  - `OIDC_PKCE_NOT_REQUIRED`
  - `OIDC_WILDCARD_REDIRECT`
  - `OIDC_REFRESH_TOKENS`
  - `OIDC_ACCESS_CONTROL_REQUIRED`
  - `OIDC_MACHINE_CLIENT`
  - `OIDC_ISSUER_CHANGE`
  - …
  
  OIDC apps are scored too.
- **Okta vs PingFederate tab**: two columns side by side (Okta current, PingFederate target) with a status in
  the middle. It has section filters, a **Show only differences** toggle and search. For values that change at
  cutover, the changed part is highlighted (red = old, green = new).
  - SAML sections: SP connection · IdP identity · Assertion · Attributes · Access control.
  - OIDC sections: OAuth client · Redirects · Grants & tokens · Endpoints (`/as/authorization.oauth2`,
    `/as/token.oauth2`, `/idp/userinfo.openid`, `/pf/JWKS`, …) · Scopes & claims · Access control.
  - PingFederate lets you keep the Okta **client ID**. Shared **client secrets** need a new value.
- **Excel**: separate **SAML - Okta vs PingFederate** and **OIDC - Okta vs PingFederate** sheets. There's a Protocol
  column in Applications, and the Summary is split by SAML / OIDC.
  Use `/export/report.xlsx?protocol=OIDC` for an OIDC-only workbook.
- **Not yet**: Okta authorization-server scopes, claims and access policies (marked UNKNOWN), and AI assessment for OIDC.
  Both come in the next sprint. Set `OKTA_ORG_URL` to show real Okta endpoint URLs in the OIDC comparison.

## Okta apps · PingFederate apps · Migration plan
The sidebar has three areas under **Migration**:

**Okta apps** (source). Everything discovered in Okta, with SAML | OIDC | Other tabs.

**PingFederate apps** (target):
- **Planned**: what each Okta app becomes (SP connection or OAuth client), its match key, what it needs, and a
  build status: *Blocked / Ready to build / Built - differs / Built / Verified*.
- **Found in PingFederate**: SP connections and OAuth clients read from PingFederate, **read-only**. Objects not linked
  to any Okta app are marked *Only on PingFederate*.
- **Reconciliation**: each Okta app compared with its PingFederate object. The match is by entity ID or client ID,
  or by exact name for catalog apps.
  - SAML checks: ACS URLs, attribute contract, assertion signing, virtual server ID, **issuance criteria** (flagged as
    security) and SLO.
  - OIDC checks: redirect URIs, grant types, client authentication and PKCE.
  - Two Okta apps sharing one entity ID are flagged.

Reading PingFederate works like reading Okta:
- `PF_SOURCE=file`: an export folder containing `sp_connections.json` and `oauth_clients.json` (the Admin API shapes).
- `PF_SOURCE=live`: the Admin API with `PF_ADMIN_URL`, `PF_ADMIN_USER` and `PF_ADMIN_PASSWORD`.
  - Use an admin account with the read-only **Auditor** role.
  - The tool only sends GET requests, with the `X-XSRF-Header` the API requires.
  - `flask pf-export --out folder` produces the offline export.
- To refresh, click **Read PingFederate** on the page or run `flask pf-sync`.

**Migration plan**:
- **Waves board**: one column per wave (the assigned wave, or the suggested one if none is set). Each card shows the
  build status, risk, next step and the 7 step markers.
- **Checklist**: an apps × steps grid with owners and due dates. Overdue dates are shown in red.
- **Progress**: completion by wave and by step, plus the list of overdue steps.
- **Each app's "Migration plan" tab**: the PingFederate reconciliation checks, plus the 7-step checklist with status,
  owner, due date and notes. The steps are:
  1. Prepare directory & decisions
  2. Build in PingFederate
  3. Test with pilot users
  4. Update the SP / app
  5. Cutover
  6. Verify
  7. Remove from Okta
- Every change is written to the audit log. The checklist tracks work only; it does **not** change the migration
  state, which stays behind the approval workflow.

The Excel report adds a **PingFederate reconciliation** sheet, a **Migration plan** sheet, build and plan columns in
Applications, and Summary blocks for build status and plan steps.

## Strategy & delivery (quick-migration features)

**1. Usage analysis.** Discovery reads the Okta System Log (`okta.logs.read`, last `OKTA_USAGE_DAYS`, default 90).
For each app it records successful sign-ins, distinct active users and the last sign-in.
- `UNUSED_IN_WINDOW` means no sign-ins in the window. The app goes to *Decommission review*.
- `LOW_USAGE` means fewer than 10% of assigned users signed in.
- **Impact now uses active users** instead of assignments. Machine-to-machine clients are never marked unused.
- If the log can't be read, discovery still succeeds and falls back to assignment counts.
- The offline export includes `apps/<id>/logs.json`.

**2. Decisions register + what-if** (*Strategy → Decisions / What-if*). Eight migration-wide decisions are
generated from the findings, each showing the apps it affects and how many it would unblock:
- OGNL policy
- duplicate entity IDs
- Okta user ID as NameID
- decommissioning unused apps
- Okta-only groups
- app-specific attributes
- implicit grant
- client secret delivery

Recording a decision (named person, audited) removes its blockers and recalculates scores and waves. *What-if*
simulates any set of open decisions and shows which apps move, plus the new finish date and effort. Nothing is saved.

**3. Strategy report** (*Strategy → Strategy report*, **Word download**, or print to PDF). It covers:
- executive summary
- scope funnel (Okta → in scope → decommission → migrate)
- approach
- waves with effort and cutover dates
- decisions needed
- key risks, including *Okta certificate expires before the planned cutover*
- directory prep
- next two weeks

All figures are computed by the tool. An optional **Claude narrative** is rejected if it contains any number that
isn't in the figures.

**4. Effort & timeline** (*Strategy → Timeline & effort*):
- Hours per app = base (custom SAML 3h, catalog 4h, OIDC 2h) + hours per finding + 4.5h test/cutover.
- Shared directory work (1h per group, 3h per attribute) is counted once.
- A buffer % is applied.
- Editable assumptions (audited): start date, engineers, hours/week, vendor lead time, pilot, hypercare,
  decision lead time.
- Output: a Gantt chart per wave (build, vendor lead time, pilot, cutover, hypercare).

**5. App-owner / vendor communication pack** (*Delivery kit → App-owner messages*, **mail-merge Excel**). One ready
message per app, with the proposed pilot and cutover dates, the new PingFederate values the SP must configure, what
stays the same, and the app's open questions.
- OIDC messages say the client ID stays the same, and that a new secret goes through the chosen secure channel.
- **Secrets are never included.**

**6. PingFederate build package** (*Delivery kit*, ZIP for all apps / per wave / per app):
- `sp-connections/*.json` and `oauth-clients/*.json`: Admin API JSON, created **disabled**.
- `variables.json`: environment IDs as `{{VARIABLES}}`.
- `TODO.md`: everything that needs a person (OGNL, catalog unknowns, SP certificates, scopes/claims).
- `directory/`: groups.csv, attributes.csv, and a PowerShell script (`create-groups.ps1`) that runs with
  **-WhatIf unless `-Apply`** is given.
- Access control uses one `PF-<App>-Users` group per app. The package itself writes nothing; the only write path is
  the gated one in the Pipeline (below). Check the JSON field names against your PingFederate version's
  `/pf-admin-api/api-docs`.

## Strategy pack (migration strategy model)

Open **Strategy pack** in the sidebar, or run `flask strategy-pack --out reports/`. It answers five questions
before anyone rebuilds anything: **what do we have, what can move, what needs transformation, what moves first,
and how do we validate it.** It covers SAML, OIDC and the tenant around them.

| Tab | What it shows |
|---|---|
| Executive | Totals, strategy per app, wave plan with cutover dates, foundation work before Wave 0, what needs attention |
| Architect | Per app: strategy, compatibility, complexity, risk, wave (and why it moved), dependencies, owner, tests, effort |
| Engineer | Per app: NameID and attribute mapping, certificate, OIDC settings, detected features, validation checklist, architecture override |
| Compatibility | Every Okta feature found, the PingFederate capability, equivalent / partial / none, evidence and sources |
| Dependencies | Graph from Okta (sign-in policies, authorization servers), CSV / CMDB import, manual links, suggestions from documents |
| Tenant objects | Policies, authenticators, group rules, authorization servers, hooks, IdPs, network zones, with their strategy |
| Capability catalog | The versioned rules behind every compatibility call |

**How a strategy is chosen (deterministic):** each app's features are looked up in the capability catalog
(`app/strategy_model/catalog.py`, versioned). Then RETIRE > RETAIN > REDESIGN > TRANSFORM > RECREATE:
inactive, unused or bookmark apps retire; apps blocked by an open decision stay on Okta for now; any feature with
no PingFederate equivalent means redesign; any partial feature means transform; otherwise recreate. An architect
can override per app (name + reason, audited). Tenant-level designs (sign-in policies, MFA, authorization servers)
are **foundation work** scheduled before Wave 0.

**Waves:** start from the risk engine's wave, then confirmed dependencies are applied: an app never moves before
an app it depends on; apps that depend on each other move together; depending on a retiring app is flagged.
Suggested dependencies (from documents) change nothing until a named person confirms them.

**Tenant objects need extra read scopes** (live mode): `okta.policies.read okta.authenticators.read
okta.authorizationServers.read okta.inlineHooks.read okta.eventHooks.read okta.idps.read okta.networkZones.read`
(group rules use `okta.groups.read`). Add them to `OKTA_SCOPES` and grant them on the service app. A kind that
can't be read is shown as "not read" and its previous results are kept; it never fails discovery.
`flask okta-export` writes them to `tenant/<kind>.json`.

**Catalog accuracy:** rows marked *expert review* (licensing, versions: MFA provider, provisioning connectors,
wildcard redirects, social login, event hooks) must be confirmed by a PingFederate architect for the customer.
Override or add rows with `CAPABILITY_CATALOG_FILE` (JSON list of partial rows keyed by `key`).

Sample inputs: `data/samples/dependencies.csv` (CMDB-style) and `data/knowledge/northwind-architecture-notes.md`
(`flask kb-add … --actor NAME`, then *Find dependencies*). Both are fictional.

## Pipeline: agents → plan & approval → PingFederate → SAML validation → cutover / rollback

Open **Pipeline** in the sidebar. Each SAML app moves through five tabs; every step needs the previous one,
every action needs a named person, and everything is in the audit log.

| Step | What happens | Who decides |
|---|---|---|
| 1 · Review agents | Four AI agents (SAML analysis, claims mapping, group mapping, risk) **review what the rules decided** and say agree / concern / disagree, citing the knowledge base (`KB-n`). Output is schema- and policy-checked; agents cannot change a mapping, score or state. | Reviewer accepts the panel; every disagreement needs a written resolution |
| 2 · Plan & approval | A versioned plan (PingFederate payload, validation and rollback values) is generated and submitted. Four-eyes: the approver must differ from the submitter. If Okta changes after approval, the plan shows drift and must be regenerated. | Approver |
| 3 · PingFederate | **Gated write** (off by default): dry run (entity ID not already there, referenced adapter / data store / key pair exist, no unresolved `{{VARIABLES}}`) → create the SP connection **disabled**. Create only; there is no update or delete code. Or: admins import it and you confirm after a PingFederate sync. | Named person; separate write account |
| 4 · SAML validation | Paste or upload a captured SAML response (SAML-tracer). Checks issuer, destination, audience, recipient, NameID, attributes, and the signature (verified with the configured certificate, never the one inside the response), comparing with the Okta baseline for the same test user. The raw response is not stored. | Tester, then app owner signs off |
| 5 · Cutover & rollback | Go/no-go gate, cutover record, post-cutover validation (PASS → Validated, FAIL → Failed), rollback with the captured Okta values, and a Word runbook per app. | IAM lead / change owner |

**Knowledge base** (sidebar): upload runbooks, vendor SSO guides and past migration notes (md, txt, docx, pdf, html),
or `flask kb-add FILE --actor NAME`. Only extracted text is stored. Search is local (no embeddings service).

### Safeguards worth knowing (from an independent review)
- The go/no-go gate only counts a pre-cutover validation that passed **with the configured `PF_SIGNING_CERT_FILE`**,
  was made against the **current approved plan**, and was recorded **after any failure**. After "fix and test again",
  a new test is required.
- Without a configured certificate, pre/post-cutover validation is a FAIL (the signature cannot be verified).
  Encrypted assertions are a FAIL in those stages too (turn encryption off in the test environment).
- The same response cannot be recorded twice; a post-cutover response must be issued after the cutover was recorded;
  "recent" is measured from the response's IssueInstant.
- Every PingFederate write attempt is committed to the audit log before the POST; a timeout is reported as
  "may or may not have been created, run a sync".
- Rollback stays possible for 7 days after an app is Validated.
- **There is no login.** Names are typed, so four-eyes and sign-offs rely on honesty. Run the tool on a restricted
  machine, or put it behind the customer's SSO before several people use it.
- With `AI_PROVIDER=anthropic`, set `AI_MASK_DATA=true`: group names, hosts and domains (including in knowledge-base
  passages) are replaced by tokens before anything is sent.

### Try it with the sample tenant
```powershell
flask discover
flask pf-sync
flask kb-add data/knowledge/northwind-sso-standards.md --actor "Your Name"
python scripts/generate_demo_saml.py        # throw-away keys + sample responses in data/demo/
# .env: PF_SIGNING_CERT_FILE=data/demo/pf-signing-demo.crt, then restart and open Pipeline → Engineering Wiki
```
Paste `engineering-okta-baseline.txt` as the Okta baseline (with `okta-signing-demo.crt` as the certificate), then
`engineering-pingfederate-broken.txt` (FAIL) and `engineering-pingfederate-ok.txt` (PASS) as pre-cutover tests.
The sample PingFederate export deliberately differs from the plan, so the gate stays red until the connection matches.

## Next
- Put the tool behind SSO (named identities for four-eyes and sign-offs).
- OIDC validation (token inspection) and an OAuth client write path.
