# 2026-09-08 — Node 24 fix + Gemini copilot

Follow-up to `2026-09-06-initial-build.md`. That build was never installed or
run in the current environment; this pass got it running, added a working AI
copilot, and re-verified everything end to end.

## What was built / changed

- **Got the existing app running on Node 24.** A fresh `npm install` failed:
  `better-sqlite3@11.3.0` has no Node 24 (ABI 137) prebuilt binary and fell
  back to `node-gyp`, which failed with no MSVC toolchain on the machine.
- **Added an AI copilot chat** (new "Copilot" tab) backed by Google Gemini,
  grounded in the local feature catalog, server-side only.
- **Re-verified** build, seed, all feature/status/activity APIs, the new chat
  API (real Gemini calls), and persistence across a dev-server restart.
- Reconciled minor mismatches: cross-platform `db:reset`, `.gitignore` now
  ignores `/data`, `.env` comments corrected.

## Decisions

### better-sqlite3 11.3.0 → 13.0.3 (pinned)

Bumping the same library to a version with Node 24 prebuilds was the smallest
possible change — the `better-sqlite3` API is unchanged, so `lib/db/*` and the
production build were untouched. Rejected alternatives: installing a C++
toolchain (heavy, machine-specific, still fragile), or switching to
`node:sqlite` / a WASM SQLite (rewrites the whole data layer and, for
`node:sqlite`, needs a Node flag that is awkward to pass through
`next dev`/`next build`). Also bumped `next` 14.2.15 → 14.2.33 (the 14.2.15
advisory) and dev tooling (`postcss`, `autoprefixer`, `tsx`, `tailwindcss`,
`typescript`) to current patches. Stayed on the Next 14.2.x line — a Next 16
major upgrade is out of scope for this prototype.

### Gemini, not Anthropic, for the copilot

The original brief framed AI as "future Claude integration". The `.env` in
this checkout instead contains a real `GEMINI_API_KEY` (and no Anthropic
key), and the user confirmed they want the chat wired up now. So the copilot
calls the Google Generative Language REST API. The provider is a thin,
swappable layer (`lib/ai/gemini.ts`); the route and UI are provider-agnostic.
`GEMINI_MODEL` is configurable and defaults to `gemini-3.6-flash`. During
verification `gemini-2.0-flash` and `gemini-2.5-flash` were already retired by
Google (clear 404), and the `gemini-flash-latest` alias was intermittently
capacity-throttled ("high demand"), so the default is pinned to a specific
model with documented fallbacks (`gemini-flash-lite-latest`,
`gemini-flash-latest`).

### Copilot design: server-side, read-only, catalog-grounded

- **Key never leaves the server.** `GEMINI_API_KEY` is read only in
  `lib/ai/gemini.ts`. `POST /api/chat` returns only `{ reply }` or a
  sanitized `{ error }` (Google's message, never headers/stack/key).
- **Grounding.** `lib/ai/context.ts` regenerates a compact catalog snapshot
  from the DB per request and prepends it as a synthetic first turn, so new
  seed features are reflected without code changes.
- **Boundary enforced in the system prompt.** There is no live Okta
  connection, so for "why don't I have access to X?" style questions the
  model is instructed to say it cannot look that up here and to describe how
  the planned Okta MCP integration would answer it. Verified: it names the
  relevant catalog entries (`okta-mcp-server`, Application Assignment, Group
  Rules, Access Policies, Access Requests) instead of inventing an answer.
- **Input validation.** Role must be `user`/`model`, ≤ 20 messages, ≤ 4000
  chars each, last message must be from the user; otherwise `400`.
- **Audited like everything else.** Each question logs an `ASKED_COPILOT`
  activity (new type) with the question text in `metadata`, so copilot use
  shows up in the same daily activity timeline as searches and views.
- **No tool-calling.** The copilot cannot take actions. Okta/MCP
  tool-calling with the end user's scoped token is the documented next step.

## Files added

- `lib/ai/gemini.ts` — server-only Gemini client, typed `GeminiError`
- `lib/ai/context.ts` — catalog grounding string + `COPILOT_SYSTEM_PROMPT`
- `app/api/chat/route.ts` — `POST` chat endpoint (validate → ground → call →
  log → reply)
- `components/CopilotPanel.tsx` — chat UI (message list, examples, loading /
  error states, "no live Okta connection" note)
- `docs/2026-09-08-gemini-copilot.md` — this log

## Files changed

- `package.json` — dependency bumps; cross-platform `db:reset`
- `.gitignore` — ignore `/data`
- `.env` — corrected comments; documented `GEMINI_API_KEY` + `GEMINI_MODEL`
- `lib/db/activity.ts` — `ASKED_COPILOT` added to `ActivityType`
- `components/ActivityTimeline.tsx` — colour for `ASKED_COPILOT`
- `app/page.tsx` — third "Copilot" tab wired to `CopilotPanel`
- `CLAUDE.md` — copilot capability, env vars, folder tree, limitations

## Verification (this pass, all green)

- `npm install` clean; `require('better-sqlite3')` loads a prebuilt binary
- `npm run db:seed` → "Catalog now has 27 features"; DB has 27 features + 1
  activity row
- `npm run build` → compiles, type-checks, 0 errors; `/api/chat` in the route
  list
- `npm run dev` → `http://localhost:3000` returns 200
- `GET /api/features?q=SAML` → 3; `?q=provisioning` → 6; `?q=OIDC` → 13;
  unknown feature → 404
- `GET /api/features/mfa?logView=true` → logs `VIEWED`
- `PATCH /api/features/mfa/status {"status":"LEARNING"}` → updates + logs
  `STATUS_CHANGED`; `{"status":"BOGUS"}` → 400
- `POST /api/chat` with a real question → grounded Gemini reply, logs
  `ASKED_COPILOT`; empty `messages` → 400; retired model → clean 400 with
  Google's message, no key leak
- Restart `npm run dev` → activity rows, MFA = `LEARNING`, and all 27
  features persist

## Known limitations (unchanged + new)

- Copilot depends on network + a valid key; degrades to an inline error
- Copilot is Q&A only — no tool-calling / Okta actions yet
- Still no automated test suite; still single-user, no auth
- Remaining `npm audit` items are dev-time Next/postcss/esbuild advisories
  that only fully clear with a Next 16 major upgrade (deferred)

## Next steps

1. Okta MCP server exposing scoped, read-only Management API tools
2. Give the copilot those tools, called with the end user's own token
3. OAuth 2.0/OIDC login; then access-request workflows
4. Integration tests over the API routes (already pure functions over the
   repository layer)

---

## Addendum (same day) — fixing the frequent timeout

Despite the "all green" verification above, the copilot started failing
frequently in normal use with:

> Could not reach the Gemini API (The operation was aborted due to timeout).

That's the exact string `lib/ai/gemini.ts` throws when `fetch`'s
`AbortSignal.timeout(20_000)` fires — the request to
`generativelanguage.googleapis.com` never got a response within 20s. Not a
rejected key or a 4xx/5xx from Google; a connection that never completed.

### Investigation

- Re-confirmed every non-copilot part of the app still works: rebuilt,
  reseeded, and exercised every endpoint (`/`, `/api/features`,
  `/api/features/[id]`, `/api/features/[id]/status`, `/api/activity`) — all
  fine. The bug is isolated to the Gemini call itself.
- `gemini-3.6-flash` (the pinned model) is still a real, current model — not
  the cause.
- The app runs on Windows. Node's `fetch` (undici) resolves hostnames via the
  OS resolver and, since Node 18 removed the old IPv4-preferring default,
  will try an IPv6 address first if DNS returns one. On networks where an
  IPv6 route to a host exists in DNS but doesn't actually work end-to-end
  (common on consumer/corporate Windows setups), that connection attempt
  hangs rather than failing fast — often 10-30+ seconds — before Node falls
  back to IPv4. That alone can exceed a 20s budget. This is a well-documented
  issue, including reports against Google's own `gemini-cli` hitting the
  same thing against the same Google API family:
  - https://x.com/matteocollina/status/1640384245834055680 (Node maintainer
    on the IPv6 default-order change and the standard workaround)
  - https://github.com/google-gemini/gemini-cli/issues/17945
  - https://github.com/actions/runner-images/issues/9540
- Tried to reproduce a live Gemini call independently from the build
  sandbox used for this fix; that sandbox's own egress proxy blocks
  `generativelanguage.googleapis.com` (403 at the TLS tunnel), so a live
  end-to-end call couldn't be verified there either. What *was* verified in
  that sandbox: the app builds and runs, every non-copilot endpoint works,
  the chat route's error handling returns a clean sanitized JSON error (no
  crash, no hang) when the upstream call fails, and the new retry/fallback
  control flow behaves correctly under a mocked `fetch` that simulates
  timeouts then recovery (confirmed both the "recovers on fallback model"
  and "every model times out" paths, with the logging each path produces).

### Fix

1. **`instrumentation.ts`** (new) + `experimental.instrumentationHook` in
   `next.config.mjs`: on server startup, calls
   `dns.setDefaultResultOrder("ipv4first")` so Node tries IPv4 before IPv6 for
   every outbound lookup in the process. Guarded behind
   `NEXT_RUNTIME === "nodejs"` because `instrumentation.ts` is also bundled
   for the Edge runtime, which can't handle `node:dns` at all — hit that
   build failure during verification and fixed it before shipping this.
2. **`lib/ai/gemini.ts`** rewritten: per-attempt timeout down from 20s to
   10s; the configured model gets one retry on a retriable failure (network
   error, timeout, 404, 429, 5xx, or an empty response); if it keeps
   failing, falls back to `gemini-flash-latest` then `gemini-3.5-flash-lite`
   (one attempt each — these were already the documented fallbacks, now
   actually wired up instead of living only in a `.env` comment). Worst case
   (every model, every attempt, fails) is bounded to roughly 40s instead of
   a single 20s shot or an unbounded hang. Every attempt and the final
   outcome are logged server-side (`[gemini] ...`) so a real outage is easy
   to tell from a one-off blip from the `npm run dev` terminal; the client
   still only ever sees a sanitized message, now pointing here when every
   attempt was a timeout.
3. **`components/CopilotPanel.tsx`**: added a "Try again" button on error
   that resends the same question without retyping it.
4. **`.env`**: updated the comment above `GEMINI_MODEL` to describe the real
   fallback behavior.

### Why not just raise the timeout?

A longer timeout makes a genuinely broken connection take even longer to
fail — it doesn't fix anything. The IPv6 route either works (the original
20s was already plenty) or it doesn't (no timeout length helps); the actual
fix is making Node prefer the route that works. Retry + model fallback cover
the separate, always-possible case of a transient blip or one overloaded
model, independent of the DNS issue.

### Other findings, not changed (flagged for a separate pass)

`npm install` reports 2 high-severity advisories against the pinned
`next@14.2.33` (and its bundled `postcss`) — already noted above as
deferred, patched only in Next 15/16. Next 15+ makes route handler `params`
async, among other breaking changes, so this touches every API route; out
of scope for a timeout fix and not something to fold in silently. Risk today
is low since the app only runs on `localhost` and is never deployed, but a
dedicated upgrade pass is worth scheduling.
