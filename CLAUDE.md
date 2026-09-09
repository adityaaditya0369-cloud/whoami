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

As of 2026-09-09 the app is **Python** (Flask + Jinja2 + vanilla JS), a
1:1 rewrite of the original Next.js/TypeScript app — same features, same
data, same behavior. See
[docs/2026-09-09-python-rewrite.md](./docs/2026-09-09-python-rewrite.md) for
the full rationale.

## What it does

- Browse and search a catalog of 27 Okta/IAM features across 9 categories
- Filter by category (Authentication, MFA, Federation, Provisioning, etc.)
- Open a feature to see its protocols, Okta capability, agent/integration
  type, use cases, security considerations, and related features
- Mark each feature's learning status: Not started → Learning → Practiced →
  Completed
- Ask the AI copilot IAM/Okta questions; answers are grounded in the local
  catalog and calls run server-side against the Gemini API
- Every search, feature view, status change, and copilot question is written
  to a daily activity log, grouped by date, most recent first
- All data (feature catalog + activity log + your progress) is stored
  locally in SQLite and survives restarts

## Tech stack

- **Flask 3** + **Jinja2** server-rendered templates + light vanilla JS for
  interactivity (tabs, search debounce, the copilot chat widget's state)
- **sqlite3** (Python standard library) as the local database — no ORM
- **Google Gemini** via REST for the copilot (server-side only)
- No database engine or extra services to install — `pip install` is
  enough; the copilot additionally needs `GEMINI_API_KEY` in `.env` plus
  network

## Install & run

```bash
pip install -r requirements.txt   # Flask, requests, python-dotenv
python seed.py                    # creates data/iam-copilot.db and seeds the 27 features
python app.py                     # starts the app at http://localhost:3000
```

Open **http://localhost:3000**. The catalog, search, status tracking, and
activity log work with no further setup. The Copilot tab needs
`GEMINI_API_KEY` set in `.env` (already present in this checkout).

To rebuild the database from scratch (wipes your progress and activity log),
delete the file and reseed:

```bash
# Windows PowerShell
Remove-Item data\iam-copilot.db, data\iam-copilot.db-shm, data\iam-copilot.db-wal -ErrorAction SilentlyContinue
python seed.py
```

## Environment variables

Defined in `.env` — unchanged from the Next.js version; nothing needed to
migrate. `GEMINI_API_KEY` / `GEMINI_MODEL` power the copilot; the rest are
documented placeholders for future integrations and are not read by the
current codebase. `DATABASE_URL` is a legacy placeholder from the original
Prisma-considered design — the app uses a fixed path (`data/iam-copilot.db`)
and never reads it.

| Variable | Used today? | Purpose |
|---|---|---|
| `GEMINI_API_KEY` | Yes | Server-side auth for the copilot's Gemini calls |
| `GEMINI_MODEL` | Yes | Gemini model id (default `gemini-3.6-flash`) |
| `DATABASE_URL` | No | Legacy placeholder, not read |
| `OKTA_ORG_URL`, `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET`, `OKTA_API_TOKEN` | No | Future real Okta org connection |
| `OAUTH_REDIRECT_URI` | No | Future OAuth 2.0/OIDC login flow |
| `MCP_SERVER_URL` | No | Future Okta MCP server endpoint |

No secrets are hard-coded in the app. `GEMINI_API_KEY` is read only in
`iam_copilot/gemini.py` (server) and is never sent to the browser or
returned in an API response. `.env` is gitignored.

## Folder structure

```
IAM-Copilot/
├── app.py                          # Flask app: routes + wiring
├── seed.py                         # seed runner (python seed.py)
├── iam_copilot/
│   ├── types.py                    # status/category/activity-type constants
│   ├── db.py                       # sqlite3 connection (thread-local) + schema
│   ├── features.py                 # feature repository (list/get/update/upsert)
│   ├── activity.py                 # activity log repository + display grouping
│   ├── seed_data.py                # the 27 seed features
│   ├── context.py                  # catalog grounding + COPILOT_SYSTEM_PROMPT
│   └── gemini.py                   # server-only Gemini client (reads GEMINI_API_KEY)
├── templates/                      # Jinja2: base.html, index.html,
│                                    # _catalog_results.html, _feature_detail.html,
│                                    # _activity_timeline.html
├── static/
│   ├── styles.css                  # plain CSS (ported from the Tailwind design)
│   └── app.js                      # tabs, search, filters, detail panel, copilot chat
├── data/                           # SQLite file lives here (gitignored)
└── docs/                           # dated decision logs
```

## Important commands

| Command | What it does |
|---|---|
| `python app.py` | Start the app at localhost:3000 (debug mode, no reloader) |
| `python seed.py` | Seed/update the catalog (safe to re-run — upserts by slug) |

## Architecture summary

- **Frontend**: server-rendered Jinja2 pages. `app.js` handles tab
  switching, live search (debounced), category filtering, and the feature
  detail overlay by fetching small HTML *fragments* from Flask and swapping
  `innerHTML` — the rendering logic (how a feature card or activity row
  looks) lives once, in Python/Jinja, not duplicated in JS templates. The
  one exception is the copilot chat widget, which keeps its own JS state
  for the message list, loading, and retry UX, since that's inherently
  client-driven.
- **Backend**: Flask routes in `app.py` are a thin layer. They never touch
  SQL directly — they call functions in `iam_copilot/*`, the only files that
  know table/column names. The chat route calls `iam_copilot/gemini.py`,
  the only file that reads `GEMINI_API_KEY`.
- **Search**: client calls `GET /api/features/fragment?q=...` on every
  keystroke for live filtering, and 900ms after typing stops refetches with
  `logView`-style logging so only finished searches are logged.
- **Copilot**: `POST /api/chat` validates the message list, prepends a
  regenerated catalog snapshot as grounding, calls Gemini, logs an
  `ASKED_COPILOT` activity, and returns only `{ reply }` or a sanitized
  `{ error }`.
- **Persistence**: a single SQLite file via the standard-library `sqlite3`
  module, one connection per thread (Flask's dev server is threaded).
  JSON-shaped fields are stored as JSON TEXT and parsed at the repository
  boundary, so the rest of the app only sees real Python lists/dicts.

### Why stdlib `sqlite3` instead of an ORM

Same reasoning as the original's choice of `better-sqlite3` over Prisma:
zero extra install, zero native build step, and the schema is simple enough
(two tables) that raw SQL in `iam_copilot/db.py`/`features.py`/`activity.py`
is easier to read and audit than an ORM layer would be. Data-access code is
isolated in `iam_copilot/`, so a later move to SQLAlchemy/Postgres only
touches that directory.

## Current capabilities

- Search across name, description, category, Okta capability, agent type,
  protocols, use cases, and security notes; category filtering with counts
- Feature detail overlay with every required field
- Per-feature learning status tracking, persisted and logged on change
- AI copilot chat grounded in the catalog, with the "no live Okta" boundary
  enforced in the system prompt (it explains the future MCP flow instead of
  guessing at real access)
- Daily activity log (search / view / status-change / copilot events),
  grouped by date, persisted, survives refresh and restart
- Responsive layout (mobile, tablet, desktop)

## Known limitations

- No authentication/accounts — single-user local prototype
- Search runs in application code, not SQL FTS (fine at this catalog size)
- No live Okta connection — all Okta data is reference content
- Copilot needs network + a valid `GEMINI_API_KEY`; on failure the Copilot
  tab shows a clean error and a "Try again" retry, and the rest of the app
  is unaffected
- Copilot is catalog Q&A only — no tool-calling, no Okta/MCP actions yet
- No automated test suite yet (verified manually in the build sandbox:
  seed, search, filtering, detail view, status updates, activity logging,
  persistence across a server restart, and the copilot's error/retry path;
  a live Gemini reply could not be exercised from that sandbox because its
  network policy blocks outbound calls to the Gemini API — this is a
  sandbox restriction, not an app issue, and the same retry/fallback logic
  that worked in the Next.js version is preserved unchanged)
- Flask's built-in dev server (`app.run(debug=True)`) is fine for local use
  but is not a production WSGI server — matches the original's Next.js dev
  server, which also wasn't hardened for production

## Future enhancements

Architected for, not yet built:

- **Okta MCP Server** (`okta-mcp-server` feature entry): expose real Okta
  Management API operations as scoped, read-only MCP tools
- **Copilot tool-calling**: let the copilot call those MCP tools with the
  end user's own scoped token to answer real access questions
- **OAuth 2.0/2.1 + OIDC login**: real user auth against an Okta org
- **Access request workflows**: agent- or self-service-initiated requests
  through real approval flows

Intended future flow: `User → IAM Copilot UI → LLM → MCP → Okta`, with every
agent action scoped to the end user's token and logged like a human action.

## Development guidelines

- Keep all SQL inside `iam_copilot/db.py` / `features.py` / `activity.py`;
  Flask routes in `app.py` call those functions
- Keep `GEMINI_API_KEY` reads inside `iam_copilot/gemini.py` — never
  returned in a response, never logged
- Add features to `iam_copilot/seed_data.py` and re-run `python seed.py`
  (upsert-by-slug, safe to repeat)
- Keep JSON-shaped feature fields as Python lists in application code; the
  DB layer handles JSON encode/decode
- Keep catalog/activity *rendering* logic in Jinja templates and the
  Python functions that feed them, not duplicated in `app.js` — the JS
  layer's job is fetching fragments and swapping them in, plus the copilot
  chat's own client-side state
