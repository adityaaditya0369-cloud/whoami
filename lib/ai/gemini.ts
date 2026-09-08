// Server-only Gemini client. The API key is read from process.env here and
// never returned to the caller — route handlers get back only text or a
// sanitized error. Keeping this the single place that touches
// GEMINI_API_KEY makes it easy to audit that the secret stays server-side.
//
// Resilience notes (2026-09-08): this client used to make a single fetch with
// a 20s abort and no retry. On some machines (observed on Windows) Node's
// fetch can stall for the full timeout trying IPv6 before giving up on a
// route that only works over IPv4 — see the DNS fix in instrumentation.ts.
// Even with that fixed, any HTTP call can hit a transient network blip or a
// momentarily overloaded model, so this now retries with backoff and falls
// back across a short list of models before giving up.

import dns from "node:dns";

// Defensive: also force IPv4-first resolution here in case this module is
// ever imported before instrumentation.ts runs. Cheap and idempotent.
try {
  dns.setDefaultResultOrder("ipv4first");
} catch {
  /* older Node without this API — instrumentation.ts covers it too */
}

const GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models";

// Per-attempt network timeout. Kept short so a single stalled connection
// doesn't eat the whole retry budget — a real Gemini flash response is
// normally a couple of seconds.
const ATTEMPT_TIMEOUT_MS = 10_000;
// Only the configured/primary model gets a retry (a transient blip is worth
// one more try on the model the user actually asked for); fallback models
// get a single attempt each so a fully-down network fails in well under a
// minute instead of compounding retries across every model.
const RETRIES_FOR_PRIMARY_MODEL = 1;
const RETRY_DELAY_MS = 600;

export interface ChatTurn {
  role: "user" | "model";
  content: string;
}

export class GeminiError extends Error {
  status: number;
  constructor(message: string, status = 502) {
    super(message);
    this.name = "GeminiError";
    this.status = status;
  }
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Models to try in order. The configured GEMINI_MODEL goes first; these are
 * known-good fallbacks if it 404s, is overloaded, or times out. Kept here
 * (rather than only in a .env comment) so the fallback actually runs. */
function modelCandidates(): string[] {
  const configured = process.env.GEMINI_MODEL?.trim() || "gemini-flash-latest";
  const fallbacks = ["gemini-flash-latest", "gemini-3.5-flash-lite"];
  return [configured, ...fallbacks.filter((m) => m !== configured)];
}

interface AttemptFailure {
  model: string;
  reason: string;
  retriable: boolean;
}

async function attemptOnce(
  model: string,
  history: ChatTurn[],
  systemPrompt: string
): Promise<{ text: string } | { failure: AttemptFailure }> {
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (!apiKey) {
    throw new GeminiError(
      "GEMINI_API_KEY is not set. Add it to .env to enable the copilot.",
      503
    );
  }

  const body = {
    system_instruction: { parts: [{ text: systemPrompt }] },
    contents: history.map((t) => ({
      role: t.role,
      parts: [{ text: t.content }],
    })),
    generationConfig: {
      temperature: 0.4,
      maxOutputTokens: 900,
    },
  };

  let res: Response;
  try {
    res = await fetch(`${GEMINI_BASE}/${model}:generateContent`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": apiKey,
      },
      body: JSON.stringify(body),
      // Fail fast per attempt rather than hanging one request for a long time.
      signal: AbortSignal.timeout(ATTEMPT_TIMEOUT_MS),
    });
  } catch (err) {
    const reason = err instanceof Error ? err.message : "unknown error";
    // Network errors and timeouts are always worth retrying / falling back.
    return { failure: { model, reason: `Could not reach Gemini (${reason})`, retriable: true } };
  }

  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const j = (await res.json()) as { error?: { message?: string } };
      if (j.error?.message) detail = j.error.message;
    } catch {
      /* keep the status-line detail */
    }
    // 404 (bad/retired model name), 429 (rate limited), and 5xx (overloaded)
    // are all reasons to try the next model/attempt rather than give up.
    const retriable = res.status === 404 || res.status === 429 || res.status >= 500;
    return { failure: { model, reason: `${res.status} ${detail}`, retriable } };
  }

  const data = (await res.json()) as {
    candidates?: {
      content?: { parts?: { text?: string }[] };
      finishReason?: string;
    }[];
    promptFeedback?: { blockReason?: string };
  };

  if (data.promptFeedback?.blockReason) {
    throw new GeminiError(
      `The prompt was blocked by Gemini safety filters (${data.promptFeedback.blockReason}).`,
      400
    );
  }

  const parts = data.candidates?.[0]?.content?.parts ?? [];
  const text = parts.map((p) => p.text ?? "").join("").trim();

  if (!text) {
    const finish = data.candidates?.[0]?.finishReason;
    return {
      failure: {
        model,
        reason: finish ? `empty response (finish reason: ${finish})` : "empty response",
        retriable: true,
      },
    };
  }

  return { text };
}

/**
 * Send a conversation to Gemini and return the assistant's reply text.
 * `history` must end with the latest user turn. Retries transient failures
 * and falls back across `modelCandidates()` before giving up.
 */
export async function callGemini(
  history: ChatTurn[],
  systemPrompt: string
): Promise<string> {
  const models = modelCandidates();
  const failures: AttemptFailure[] = [];

  for (const [modelIndex, model] of models.entries()) {
    const retriesForThisModel = modelIndex === 0 ? RETRIES_FOR_PRIMARY_MODEL : 0;

    for (let attempt = 0; attempt <= retriesForThisModel; attempt++) {
      const result = await attemptOnce(model, history, systemPrompt);
      if ("text" in result) {
        if (failures.length > 0) {
          // Recovered after a retry/fallback — worth a server-side note so
          // patterns (e.g. one model always failing) are visible in the logs.
          console.warn(
            `[gemini] Recovered on model "${model}" after ${failures.length} prior failure(s):`,
            failures
          );
        }
        return result.text;
      }

      failures.push(result.failure);
      console.error(`[gemini] Attempt failed (model=${model}, attempt=${attempt + 1}):`, result.failure.reason);

      if (!result.failure.retriable) break; // non-retriable: skip straight to next model
      if (attempt < retriesForThisModel) await sleep(RETRY_DELAY_MS * (attempt + 1));
    }
  }

  // Every model/attempt failed. Summarize clearly for the terminal, and
  // return a sanitized-but-useful message to the client.
  const last = failures[failures.length - 1];
  console.error("[gemini] All models/attempts exhausted:", failures);

  const allTimeouts = failures.every((f) => /timeout|aborted/i.test(f.reason));
  if (allTimeouts) {
    throw new GeminiError(
      "Could not reach the Gemini API — every attempt timed out. This is usually a local network/DNS " +
        "issue rather than Gemini itself being down (see docs/2026-09-08-gemini-copilot.md for the Windows " +
        "IPv6 fix this app applies). Check your internet connection and try again.",
      502
    );
  }

  throw new GeminiError(
    `Gemini API error: ${last?.reason ?? "unknown failure"}`,
    last?.reason.startsWith("429") ? 429 : 502
  );
}
