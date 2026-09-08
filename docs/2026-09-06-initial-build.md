# 2026-09-06 — Initial Build

## What was built

A single-page IAM Copilot web app: a searchable catalog of 27 Okta/IAM
capabilities, a feature detail view, per-feature learning-status tracking,
and a persistent daily activity log. Built with Next.js 14 (App Router),
TypeScript, Tailwind CSS, and a local SQLite database. Verified end-to-end
in this environment: dependency install, database seed, production build,
dev server boot, and a full manual test pass (search, category filtering,
feature detail + view logging, status updates + logged status changes,
activity feed ordering, and persistence across a server restart).

## Architecture decisions

**Single-page client dashboard, thin API layer.** `app/page.tsx` is one
client component holding all UI state (query, category, selected feature,
activity list, active tab). It talks to a small set of Next.js Route
Handlers (`app/api/features`, `app/api/features/[id]`,
`app/api/features/[id]/status`, `app/api/activity`), which are the only code
that touches the database. This keeps the request/response shape explicit
and makes the backend independently testable (verified directly with curl
during this build) without needing the UI running.

**Repository modules over inline SQL.** `lib/db/features.ts` and
`lib/db/activity.ts` are the only files that reference table and column
names. Route handlers call plain functions (`listFeatures`,
`getFeatureByIdOrSlug`, `updateFeatureStatus`, `logActivity`,
`listActivity`) and never see SQL. This is the "database abstraction" layer
requested in the brief, sized appropriately for a local prototype rather
than pulling in a full ORM (see Database choice below for why).

**In-process search rather than SQL search.** Feature fields like protocols,
use cases, and security considerations are stored as JSON-encoded TEXT
columns (SQLite has no native array type). Matching a search term inside a
JSON string via SQL `LIKE` would require the same string parsing anyway, so
`app/api/features/route.ts` fetches the (small — tens of rows) candidate set
by category/status first, then filters in JavaScript across all documented
searchable fields. This is simple, correct, and fast at this catalog size;
a real deployment with a much larger catalog would move to SQLite FTS5 or an
external search index instead.

## Technology choices

- **Next.js 14 + TypeScript + Tailwind**: required by the brief; App Router
  Route Handlers double as the "server-side APIs using Next.js" requirement
  without a separate backend process.
- **State management**: plain React `useState`/`useEffect`, no external
  state library. The state graph is shallow (a handful of primitives and one
  list), and introducing Redux/Zustand/etc. would add indirection without
  solving a real problem here.
- **Debounced, logged search**: the UI calls the search API on every
  keystroke for instant filtering, but only logs a `SEARCHED` activity 900ms
  after typing pauses (and only for queries longer than one character). This
  keeps the activity log meaningful (one entry per real search) instead of
  one entry per keystroke.

## Database choice

**better-sqlite3 instead of Prisma.** The original plan was Prisma with
SQLite, since Prisma is the most common "ORM where appropriate" choice for a
Next.js + SQLite app. During this build, `prisma generate`'s postinstall
step failed: it needs to download a query-engine binary from
`binaries.prisma.sh`, and that domain was not reachable from this build
environment's network allowlist (a 403 on the checksum fetch). Rather than
hand over a project that fails on a fresh `npm install`, the database layer
was rewritten around `better-sqlite3`, which ships a prebuilt native binary
through npm itself — no separate engine download at install or build time.

This is a straightforward local-prototype trade: `better-sqlite3` gives up
Prisma's schema migrations and generated type-safe client, but the
`lib/db/` repository module boundary means a future move to Prisma/Postgres
only touches `lib/db/client.ts`, `features.ts`, and `activity.ts` — the API
routes and every UI component are unaffected, since they only ever import
functions like `listFeatures()` and `logActivity()`.

## UI decisions

The brief asked for a "clean, modern enterprise IAM dashboard." Rather than
defaulting to a generic SaaS-card look (rounded cards, soft grey shadows,
gradient accents), the design leans into the subject matter: a dark
`#101820` header against a warm `#F6F5F1` parchment background, sharp
(`3px`) corners instead of heavy rounding, a serif display face for headings
(evoking a reference/handbook feel appropriate for a "knowledge hub"), and a
monospace face specifically for protocol badges and timestamps, since those
are the app's data labels. A single signal-blue (`#2F6DF6`) accent is
reserved for interactive/focus states so it stays meaningful rather than
decorative. The feature detail view is a slide-over drawer rather than a
route change, keeping the app feeling like a single continuous page as
specified, and it closes on `Escape` or backdrop click for basic
accessibility.

## Search implementation

See "In-process search" above. Search covers feature name, description,
category, Okta capability, agent type, protocols, use cases, and security
considerations, exactly as specified. Results update on every keystroke via
`fetch` with no full page reload.

## Data model

Two tables:

- `iam_feature`: id, name, slug (unique, used for readable API URLs and
  cross-linking related features), description, category, okta_capability,
  protocols/use_cases/security_considerations/related_feature_slugs (all
  JSON-encoded TEXT), status, created_at, updated_at.
- `activity_log`: id, feature_id (nullable FK, `ON DELETE SET NULL` so
  history survives a feature being removed), feature_name (denormalized so
  the log stays readable even if the feature record changes), activity_type,
  description, metadata (nullable JSON TEXT), created_at.

`slug` is unique and used interchangeably with `id` in the `[id]` dynamic
routes, so both `/api/features/mfa` and `/api/features/<uuid>` resolve the
same record — useful for readable manual testing and future deep links.

## Security decisions

- No secrets in client code; the only server-side env var currently read is
  `DATABASE_URL`. All other `.env` entries are placeholders for future
  integrations and are not wired into any code path yet.
- Input validation on the one write endpoint (`PATCH .../status`): the
  status value is checked against a fixed enum before touching the
  database; invalid input returns `400` with the allowed values listed.
- Read and write operations are already separated by HTTP method (`GET` for
  reads, `PATCH` for the one write path), which will matter more once real
  Okta write operations (e.g., access requests) are added — those should
  require explicit, scoped, user-consented tool calls, not implicit access.

## Future Claude/MCP/Okta integration approach

Two catalog entries — `okta-mcp-server` and `conversational-access-copilot`
— document the intended future architecture:

```
User → IAM Copilot UI → Claude → MCP → Okta
```

Concretely: an Okta MCP Server would expose Okta Management API operations
(read assignments, read groups, submit access requests) as scoped MCP
tools. Claude would be given access to only the tools appropriate to the
question being asked, and every tool call would carry the *end user's own*
OAuth-scoped token rather than a shared admin credential, so an agent can
never see or do more than the human it's acting for. Every agent-initiated
action would be written to the same `activity_log` table used today, so
there is one unified audit trail regardless of whether a human or an agent
made the change.

## Known limitations

- Single-user, no authentication — appropriate for a local prototype, not
  for shared/multi-user use
- In-process search won't scale past a few hundred catalog entries without
  moving to FTS5 or an external index
- No automated tests yet; verification for this build was a manual pass
  (documented in `CLAUDE.md`) covering every required user flow
- SQLite is not suitable for concurrent multi-process writes; fine for a
  single local dev server

## Future improvements

- Add integration tests around the API routes (they're already pure
  functions over a repository layer, so this is straightforward)
- Real Okta org connection behind the existing `OKTA_*` env vars
- The actual Claude + MCP conversational copilot described above
- SQLite FTS5 (or a small search index) if the catalog grows substantially
- Optional CSV/JSON export of the activity log for reporting
