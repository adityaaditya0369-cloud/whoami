# 2026-09-09 — Full rewrite: Next.js/TypeScript → Python (Flask)

Follow-up to `2026-09-08-gemini-copilot.md`. The user asked for the app to
run on "complete python" (their words) because they know Python better than
TypeScript. This was an explicit, scoped decision, confirmed up front:

- **Reason**: the user is more comfortable in Python than TypeScript/Next.js
- **Shape**: a web app with a Python backend and server-rendered pages
  (Flask + Jinja2 + light vanilla JS for interactivity), not a Python CLI or
  a separate API+SPA split
- **Scope**: same features, ported 1:1 — this was not an opportunity to
  change functionality, just the language/framework
- **Deployment**: replace the Next.js app in place at
  `C:\Claude\IAM-Copilot\IAM-Copilot` rather than living alongside it

Nothing about *what the app does* changed. This log covers *how* it was
rebuilt and why each substitution was made.

## What changed

| Next.js / TypeScript | Python |
|---|---|
| Next.js App Router pages + React client components | Flask routes + Jinja2 server-rendered templates |
| React `useState`/`useEffect` for UI state | Server renders the HTML; `app.js` fetches small HTML fragments and swaps them in, plus its own state for the copilot chat widget only |
| `better-sqlite3` | Python standard-library `sqlite3` (thread-local connections) |
| Tailwind CSS + `tailwind.config.ts` | Plain CSS (`static/styles.css`) with the same color tokens, spacing, and type scale hand-ported from the Tailwind config |
| `lib/ai/gemini.ts` | `iam_copilot/gemini.py` — same retry/fallback/IPv4-first design, translated line-for-line in intent |
| `lib/db/*.ts` | `iam_copilot/{db,features,activity}.py` |
| `npm run db:seed` | `python seed.py` |
| `npm run dev` | `python app.py` |

The database schema, the `data/iam-copilot.db` file path, the 27 seed
features, the system prompt, and the REST-ish JSON contracts the frontend
JS relies on are all unchanged, so the existing `data/iam-copilot.db` file
did not need to be touched or migrated.

## Decisions

### Server-rendered fragments, not a JSON API + client templating

The original was a single React client component re-rendering from fetched
JSON. Re-implementing that exactly would mean writing the catalog card,
detail panel, and activity row markup a *second* time in JavaScript — a
maintenance trap where the two renderers drift. Instead, Flask renders
actual HTML for the catalog grid, the feature detail panel, and the
activity timeline (as Jinja partials: `_catalog_results.html`,
`_feature_detail.html`, `_activity_timeline.html`); `app.js` calls these as
fragment endpoints (`/api/features/fragment`, `/api/features/<id>/fragment`,
`/api/activity/fragment`) and swaps the returned HTML into the page. All
rendering logic lives once, in Python/Jinja. The copilot chat widget is the
one place that keeps meaningful client-side state (message list, loading,
retry), because that interaction is inherently client-driven — the same as
the original's `CopilotPanel.tsx`.

### `sqlite3` (stdlib) instead of a Python ORM

Same reasoning as the original's `better-sqlite3` over Prisma: the schema
is two small tables, so raw SQL confined to `iam_copilot/db.py` (schema +
connection), `features.py`, and `activity.py` is easier to read and audit
than adding SQLAlchemy or a similar dependency. `sqlite3` ships with
Python, so `pip install` needs nothing beyond Flask, `requests`, and
`python-dotenv`.

### Plain CSS instead of Tailwind

Tailwind's utility-class build step is a Node/PostCSS pipeline; pulling it
into a Python project would mean keeping a Node toolchain around just for
CSS. `static/styles.css` hand-ports the exact colors, spacing scale, and
font stack from `tailwind.config.ts` and `globals.css` into named classes
matching each component's structure, so the visual result is unchanged.

### Gemini client: same resilience design, ported deliberately

`iam_copilot/gemini.py` preserves every part of the 2026-09-08 fix, because
that fix addressed a real Windows networking bug, not a Node-specific one:

- **IPv4-first DNS.** Node's `dns.setDefaultResultOrder('ipv4first')`
  becomes a process-wide monkeypatch of `socket.getaddrinfo` that sorts
  IPv4 results first without dropping IPv6 — `_patch_ipv4_first()`, applied
  at import time and again defensively at `app.py` startup.
- **Retry + fallback chain.** The configured model gets one retry; the
  fallback models (`gemini-flash-latest`, `gemini-3.5-flash-lite`) get one
  attempt each — same budget shape as the TS version, so a fully-down
  network still fails in well under a minute.
- **Sanitized errors.** `requests`/urllib3 exception text nests proxy and
  connection-pool internals that shouldn't reach the browser;
  `_sanitize_request_error()` reduces this to a short, clear reason while
  the raw exception is still logged server-side with a `[gemini]` prefix.
- **Key handling.** `GEMINI_API_KEY` is read only in this one file and
  never appears in a response, matching the original's `lib/ai/gemini.ts`.

### Flask dev server, not a production WSGI server

`app.run(debug=True, use_reloader=False)` mirrors the original's `npm run
dev` — fine for a single-user local prototype, not hardened for production.
The reloader is disabled because the debug reloader's file-watcher restart
behavior fought with the Gemini socket monkeypatch during testing; auto-
reload wasn't relied on for iteration anyway. This should be swapped for a
real WSGI server (gunicorn/waitress) if this app is ever deployed rather
than run locally — out of scope for this rewrite, same as it was for the
Next.js dev server.

## Verification (this pass, sandboxed)

The rewrite was built and tested in a Linux build sandbox before delivery,
since the target machine (Windows) isn't directly reachable from here:

- `python seed.py` → seeds 27 features, logs the initial `SYSTEM` activity
- `python app.py` → `http://localhost:3000` returns 200
- Catalog: full grid renders with correct counts per category; search
  filters correctly (`SAML`, `provisioning`, `OIDC` queries checked);
  category filter chips update the result set
- Feature detail: opening a feature renders every field (Okta capability,
  protocols, agent type, use cases, security considerations, related
  features) and logs a `VIEWED` activity
- Status tracking: changing a feature's status persists, updates the badge,
  and logs a `STATUS_CHANGED` activity
- Activity log: grouped by date heading ("Today" / weekday), correct type
  dot colors, persists across a server restart
- Copilot UI: tab switches correctly, example prompts populate the input,
  sending a message renders the user bubble immediately, and the error /
  "Try again" retry path was exercised end-to-end via Playwright — the
  sandbox's own network policy blocks outbound calls to
  `generativelanguage.googleapis.com` (a sandbox restriction, confirmed via
  the `[gemini]` server log showing a proxy-level 403 on the tunnel, not an
  app bug), so a *live* Gemini reply could not be captured here; the
  request/response contract, retry/fallback sequencing, and UI error
  handling are otherwise verified and unchanged from the working Next.js
  version
- Visual QA: catalog, feature detail, activity timeline, and copilot tab
  screenshotted via headless Chromium and checked against the original
  React components' layout and styling

## Files added

Everything under `iam_copilot/`, `templates/`, `static/`, plus `app.py`,
`seed.py`, `requirements.txt`, and this doc. See `CLAUDE.md`'s folder
structure section for the full layout.

## Files removed (Next.js app, retired)

The Next.js/TypeScript app is retired in place of this rewrite. Its files
are no longer needed on disk; see the cleanup instructions given alongside
this rewrite for exactly what to remove
(`node_modules/`, `.next/`, `app/`, `components/`, the TypeScript `lib/`,
`package.json`, `package-lock.json`, `tsconfig.json`, `tailwind.config.ts`,
`postcss.config.mjs`, `next.config.mjs`, `next-env.d.ts`). `.env`,
`data/`, `docs/`, `README.md`, `CLAUDE.md`, and `.gitignore` carry forward
(the last three are replaced by their Python-rewrite versions, keeping the
same names).

## Known limitations (unchanged + new)

- Same functional limitations as the Next.js version (see `CLAUDE.md`):
  single-user, no auth, no live Okta connection, no tool-calling
- No automated test suite yet, same as before
- New: a live Gemini reply was not exercised in the build sandbox (network
  policy), only the failure/retry path — worth a final manual check on the
  target machine after deployment

## Next steps

1. Confirm a real Gemini reply renders correctly once running on the actual
   machine (network path differs from the build sandbox)
2. Same longer-term roadmap as before: Okta MCP server, copilot
   tool-calling, OAuth 2.0/OIDC login, access-request workflows
3. If this ever needs to run somewhere other than a developer's laptop,
   swap the Flask dev server for gunicorn/waitress behind a real front end
