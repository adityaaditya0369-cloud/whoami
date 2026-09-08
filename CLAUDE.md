# IAM Copilot

## Overview

IAM Copilot is a local, single-page web app that acts as a searchable
knowledge hub for Okta and enterprise Identity & Access Management (IAM)
concepts. It catalogs 27 IAM/Okta capabilities with their protocols, agents,
use cases, and security considerations; lets you track your own learning
progress per feature; keeps a persistent daily activity log of what you
searched, viewed, and updated; and includes an AI copilot chat (Google
Gemini) grounded in the local catalog.

It is a knowledge/learning tool, not a real Okta admin console — there is no
live Okta connection, so the copilot cannot look up a real user's access
(see "Future enhancements").

## What it does

- Browse and search a catalog of 27 Okta/IAM features across 9 categories
- Filter by category (Authentication, MFA, Federation, Provisioning, etc.)
- Open a feature to see its protocols, Okta capability, agent/integration
  type, use cases, security considerations, and related features
- Mark each feature's learning status: Not started → Learning → Practiced →
  Completed
- Ask the AI copilot IAM/Okta questions; answers are grounded in the local
  catalog and calls run server-side against the Gemini API, with automatic
  retry/fallback across models (see "Copilot resilience")
- Every search, feature view, status change, and copilot question is written
  to a daily activity log, grouped by date, most recent first
- All data (feature catalog + activity log + your progress) is stored
  locally in SQLite and survives restarts

## Tech stack

- **Next.js 14** (App Router) + **TypeScript** + **Tailwind CSS**
- **better-sqlite3** as the local database — prebuilt binary, no Prisma
  postinstall fetch needed
- **Google Gemini** via REST for the copilot (server-side only, with
  retry + model fallback — see "Copilot resilience")
- No database engine or extra services to install — `npm install` is enough;
  the copilot additionally needs `GEMINI_API_KEY` in `.env` plus network

## Install & run

```bash
npm install         # better-sqlite3 installs a prebuilt binary (no compiler)
npm run db:seed     # creates data/iam-copilot.db and seeds the 27 features
npm run dev         # starts the app at http://localhost:3000
```

Open **http://localhost:3000**. The catalog, search, status tracking, and
activity log work with no further setup. The Copilot tab needs
`GEMINI_API_KEY` set in `.env` (already present in this checkout).

To rebuild the database from scratch (wipes your progress and activity log):

```bash
npm run db:reset
```

## Environment variables

Defined in `.env`. `GEMINI_API_KEY` / `GEMINI_MODEL` power the copilot; the
rest are documented placeholders for future integrations and are not read by
the current codebase. `DATABASE_URL` is kept for a future Prisma/Postgres
move — the app uses a fixed path (`data/iam-copilot.db`).

| Variable | Used today? | Purpose |
|---|---|---|
| `GEMINI_API_KEY` | Yes | Server-side auth for the copilot's Gemini calls |
| `GEMINI_MODEL` | Yes | Preferred Gemini model (falls back automatically) |
| `DATABASE_URL` | No | Future Prisma/Postgres connection string |
| `OKTA_ORG_URL`, `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET`, `OKTA_API_TOKEN` | No | Future real Okta org connection |
| `OAUTH_REDIRECT_URI` | No | Future OAuth 2.0/OIDC login flow |
| `MCP_SERVER_URL` | No | Future Okta MCP server endpoint |

No secrets are hard-coded in the app. `GEMINI_API_KEY` is read only in
`lib/ai/gemini.ts` (server) and is never sent to the browser or returned in
an API response. `.env` is gitignored.

## Folder structure

```
IAM-Copilot/
├── app/
│   ├── page.tsx                       # single-page dashboard (client component)
│   ├── layout.tsx, globals.css
│   └── api/                           # features/, features/[id]/, features/[id]/status/,
│                                       # activity/, chat/ — one route.ts each
├── components/                        # Header, SearchBar, CategoryFilter, FeatureCard,
│                                       # FeatureDetailPanel, ActivityTimeline, CopilotPanel, badges
├── lib/
│   ├── types.ts                       # shared DTOs, enums, JSON helpers
│   ├── ai/gemini.ts, context.ts       # Gemini client (retry/fallback) + grounding prompt
│   └── db/                            # client.ts, features.ts, activity.ts, seed(-data).ts
├── data/                              # SQLite file lives here (gitignored)
├── instrumentation.ts                 # server-startup DNS fix for the copilot (see below)
└── docs/                              # dated decision logs
```

## Important commands

| Command | What it does |
|---|---|
| `npm run dev` | Start the app at localhost:3000 with hot reload |
| `npm run build` / `npm start` | Production build + run |
| `npm run db:seed` | Seed/update the catalog (safe to re-run — upserts by slug) |
| `npm run db:reset` | Delete the DB file and reseed from scratch |

## Architecture summary

- **Frontend**: one client-rendered page (`app/page.tsx`) holding all UI
  state in plain React `useState`/`useEffect`. No external state library.
- **Backend**: Next.js Route Handlers under `app/api/*` call functions in
  `lib/db/*`, the only files that know table/column names. The copilot route
  calls `lib/ai/gemini.ts`, the only file that reads `GEMINI_API_KEY`.
- **Search**: client calls `GET /api/features?q=...` on every keystroke, and
  900ms after typing stops refetches with `logSearch=true` to log the search.
- **Copilot**: `POST /api/chat` validates the message list, prepends a
  regenerated catalog snapshot as grounding, calls Gemini, logs an
  `ASKED_COPILOT` activity, and returns only `{ reply }` or a sanitized
  `{ error }`.
- **Persistence**: a single SQLite file via `better-sqlite3` in WAL mode.

## Copilot resilience (added 2026-09-08)

The Copilot tab used to fail with "Could not reach the Gemini API (The
operation was aborted due to timeout)" on some networks. Two fixes, in
`instrumentation.ts` and `lib/ai/gemini.ts` — details and root-cause
analysis in `docs/2026-09-08-gemini-copilot.md`:

1. **IPv4-first DNS.** `instrumentation.ts` forces Node to try IPv4 before
   IPv6 for all outbound lookups. On some networks (seen on Windows), Node's
   fetch stalls for the full timeout trying IPv6 to Google's API before ever
   trying IPv4, even when only IPv4 works.
2. **Retry + model fallback.** `callGemini()` retries the configured
   `GEMINI_MODEL` once, then tries `gemini-flash-latest` and
   `gemini-3.5-flash-lite` (one attempt each) before giving up — bounded to
   roughly 40s worst case. Every attempt is logged server-side
   (`[gemini] ...`) so a real outage is easy to tell from a one-off blip.
   The Copilot tab also gained a "Try again" button that resends the same
   question without retyping it.

## Known limitations

- No authentication/accounts — single-user local prototype
- Search runs in application code, not SQL FTS (fine at this catalog size)
- No live Okta connection — all Okta data is reference content
- Copilot is catalog Q&A only — no tool-calling, no Okta/MCP actions yet
- `npm audit` flags Next.js 14.2.33 (pinned by the original build) for
  several advisories, patched only in Next 15/16, which need code changes
  (e.g. async route `params`) — recommended as a separate, deliberate upgrade
  rather than folded into this fix; low risk meanwhile since this only runs
  on `localhost`, never deployed or exposed
- No automated test suite yet (verified manually end-to-end, including a
  mocked-fetch test of the retry/fallback logic — see the decision log)

## Future enhancements

Architected for, not yet built: an **Okta MCP Server** exposing scoped
read-only Okta Management API operations as MCP tools; **copilot
tool-calling** against those tools with the end user's own token; real
**OAuth 2.0/2.1 + OIDC login**; and agent- or self-service **access request
workflows**. Intended flow: `User → IAM Copilot UI → LLM → MCP → Okta`, every
agent action scoped to the end user's token and logged like a human action.

## Development guidelines

- Keep all SQL inside `lib/db/`; route handlers call those functions
- Keep `GEMINI_API_KEY` reads inside `lib/ai/gemini.ts` — never in a client
  component, never returned in a response
- Add features to `lib/db/seed-data.ts` and re-run `npm run db:seed`
- Keep JSON-shaped feature fields as string arrays in TS; the DB layer
  handles JSON encode/decode
