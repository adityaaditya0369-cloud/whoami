"""Server-only Gemini client — ported from lib/ai/gemini.ts, including the
2026-09-08 resilience fix (see docs/2026-09-08-gemini-copilot.md): the
original single-shot 20s fetch on Windows could stall trying Gemini's IPv6
address before ever trying IPv4, producing "aborted due to timeout" even
though IPv4 worked fine. This module:

  1. Forces IPv4-first DNS resolution, process-wide (the Python equivalent of
     Node's `dns.setDefaultResultOrder('ipv4first')`).
  2. Retries the configured model once on a transient failure, then falls
     back across a short list of known-good models before giving up.
  3. Logs every attempt and the final outcome to stderr so a real outage is
     easy to tell from a one-off blip.

The API key is read from the environment here and nowhere else; callers get
back only reply text or a sanitized GeminiError — never the key, headers, or
raw Google response.
"""

import os
import socket
import sys
import time

import requests

GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

# Per-attempt network timeout. Kept short so one stalled connection can't
# eat the whole retry budget — a real Gemini flash response is normally a
# couple of seconds.
ATTEMPT_TIMEOUT_S = 10
# Only the configured/primary model gets a retry; fallback models get one
# attempt each, so a fully-down network fails in well under a minute instead
# of compounding retries across every model.
RETRIES_FOR_PRIMARY_MODEL = 1
RETRY_DELAY_S = 0.6


def _patch_ipv4_first() -> None:
    """Monkeypatch socket.getaddrinfo, process-wide, so IPv4 addresses sort
    before IPv6 ones for every DNS lookup — without dropping IPv6 entirely.
    Idempotent; safe to call more than once (app.py also calls this at
    startup, same belt-and-suspenders pattern as the original TS version).
    """
    if getattr(socket.getaddrinfo, "_ipv4_first_patched", False):
        return

    original_getaddrinfo = socket.getaddrinfo

    def ipv4_first_getaddrinfo(*args, **kwargs):
        results = original_getaddrinfo(*args, **kwargs)
        return sorted(results, key=lambda r: 0 if r[0] == socket.AF_INET else 1)

    ipv4_first_getaddrinfo._ipv4_first_patched = True
    socket.getaddrinfo = ipv4_first_getaddrinfo


_patch_ipv4_first()


class GeminiError(Exception):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def _model_candidates() -> list[str]:
    configured = (os.environ.get("GEMINI_MODEL") or "").strip() or "gemini-flash-latest"
    fallbacks = ["gemini-flash-latest", "gemini-3.5-flash-lite"]
    return [configured] + [m for m in fallbacks if m != configured]


def _log(msg: str) -> None:
    print(f"[gemini] {msg}", file=sys.stderr)


def _sanitize_request_error(err: Exception) -> str:
    """`requests`/urllib3 exception messages nest the whole retry/proxy
    chain (connection pool internals, proxy state) — fine for the
    `[gemini]` server log, too verbose and too revealing of local network
    topology for a client-facing message. Reduce to a short, clear reason;
    the full exception is still logged server-side by the caller.
    """
    if isinstance(err, requests.exceptions.Timeout):
        return "timed out"
    if isinstance(err, requests.exceptions.ConnectionError):
        return "connection failed (network or DNS issue)"
    text = str(err)
    return text if len(text) <= 120 else text[:117] + "..."


def _attempt_once(model: str, history: list[dict], system_prompt: str):
    """Returns {"text": str} on success or {"failure": {...}} on a handled
    failure. Raises GeminiError only for the key-missing and safety-block
    cases, which are never worth retrying."""
    api_key = (os.environ.get("GEMINI_API_KEY") or "").strip()
    if not api_key:
        raise GeminiError("GEMINI_API_KEY is not set. Add it to .env to enable the copilot.", 503)

    body = {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": t["role"], "parts": [{"text": t["content"]}]} for t in history],
        "generationConfig": {"temperature": 0.4, "maxOutputTokens": 900},
    }

    try:
        res = requests.post(
            f"{GEMINI_BASE}/{model}:generateContent",
            headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
            json=body,
            timeout=ATTEMPT_TIMEOUT_S,
        )
    except requests.exceptions.RequestException as err:
        _log(f"(raw) model={model}: {err}")
        return {"failure": {"model": model, "reason": f"Could not reach Gemini ({_sanitize_request_error(err)})", "retriable": True}}

    if not res.ok:
        detail = f"{res.status_code} {res.reason}"
        try:
            j = res.json()
            if j.get("error", {}).get("message"):
                detail = j["error"]["message"]
        except ValueError:
            pass
        retriable = res.status_code in (404, 429) or res.status_code >= 500
        return {"failure": {"model": model, "reason": f"{res.status_code} {detail}", "retriable": retriable}}

    data = res.json()
    block_reason = data.get("promptFeedback", {}).get("blockReason")
    if block_reason:
        raise GeminiError(f"The prompt was blocked by Gemini safety filters ({block_reason}).", 400)

    candidates = data.get("candidates") or []
    parts = (candidates[0].get("content", {}).get("parts") if candidates else None) or []
    text = "".join(p.get("text", "") for p in parts).strip()

    if not text:
        finish = candidates[0].get("finishReason") if candidates else None
        reason = f"empty response (finish reason: {finish})" if finish else "empty response"
        return {"failure": {"model": model, "reason": reason, "retriable": True}}

    return {"text": text}


def call_gemini(history: list[dict], system_prompt: str) -> str:
    """Send a conversation to Gemini and return the assistant's reply text.
    `history` must end with the latest user turn. Retries transient failures
    and falls back across `_model_candidates()` before giving up.
    """
    models = _model_candidates()
    failures = []

    for model_index, model in enumerate(models):
        retries_for_this_model = RETRIES_FOR_PRIMARY_MODEL if model_index == 0 else 0

        for attempt in range(retries_for_this_model + 1):
            result = _attempt_once(model, history, system_prompt)
            if "text" in result:
                if failures:
                    _log(f"Recovered on model \"{model}\" after {len(failures)} prior failure(s): {failures}")
                return result["text"]

            failure = result["failure"]
            failures.append(failure)
            _log(f"Attempt failed (model={model}, attempt={attempt + 1}): {failure['reason']}")

            if not failure["retriable"]:
                break  # non-retriable: skip straight to next model
            if attempt < retries_for_this_model:
                time.sleep(RETRY_DELAY_S * (attempt + 1))

    _log(f"All models/attempts exhausted: {failures}")

    all_timeouts = all("timeout" in f["reason"].lower() or "timed out" in f["reason"].lower() for f in failures)
    if all_timeouts and failures:
        raise GeminiError(
            "Could not reach the Gemini API — every attempt timed out. This is usually a local "
            "network/DNS issue rather than Gemini itself being down (see "
            "docs/2026-09-08-gemini-copilot.md for the IPv4-first fix this app applies). "
            "Check your internet connection and try again.",
            502,
        )

    last = failures[-1] if failures else None
    status = 429 if last and last["reason"].startswith("429") else 502
    raise GeminiError(f"Gemini API error: {last['reason'] if last else 'unknown failure'}", status)
