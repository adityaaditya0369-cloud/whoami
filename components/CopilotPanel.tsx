"use client";

import { useEffect, useRef, useState } from "react";

interface Msg {
  role: "user" | "model";
  content: string;
}

const EXAMPLES = [
  "What is the difference between SAML and OIDC?",
  "When should I use SCIM vs Okta Workflows for provisioning?",
  "Why don't I have access to Salesforce?",
  "How does adaptive MFA decide when to challenge me?",
];

export default function CopilotPanel({ onActivity }: { onActivity?: () => void }) {
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The user turn a failed request was for, so "Try again" can resend it
  // without making the user retype the question.
  const [lastFailedTurn, setLastFailedTurn] = useState<Msg[] | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, loading]);

  async function sendTurn(next: Msg[]) {
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: next }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? `Request failed (${res.status}).`);
        setLastFailedTurn(next);
      } else {
        setMessages((prev) => [...prev, { role: "model", content: data.reply }]);
        setLastFailedTurn(null);
        onActivity?.();
      }
    } catch {
      setError("Network error — is the dev server still running?");
      setLastFailedTurn(next);
    } finally {
      setLoading(false);
    }
  }

  async function send(text: string) {
    const trimmed = text.trim();
    if (!trimmed || loading) return;

    const next: Msg[] = [...messages, { role: "user", content: trimmed }];
    setMessages(next);
    setInput("");
    await sendTurn(next);
  }

  async function retry() {
    if (!lastFailedTurn || loading) return;
    await sendTurn(lastFailedTurn);
  }

  return (
    <div className="mx-auto max-w-2xl">
      <div className="mb-4 border border-[#E4E2DA] bg-white p-4">
        <p className="text-[13px] leading-relaxed text-[#5B5F63]">
          Ask about any Okta or IAM concept in the catalog. Answers come from
          Google Gemini, grounded in the local feature catalog.{" "}
          <span className="text-[#9B9A90]">
            This is a knowledge prototype — there is no live Okta connection, so
            it cannot look up your real access (yet).
          </span>
        </p>
      </div>

      <div
        ref={scrollRef}
        className="thin-scroll min-h-[240px] max-h-[52vh] overflow-y-auto border border-[#E4E2DA] bg-[#FBFAF7] p-4"
      >
        {messages.length === 0 && !loading ? (
          <div className="space-y-2">
            <p className="text-[12.5px] text-[#9B9A90]">Try asking:</p>
            {EXAMPLES.map((ex) => (
              <button
                key={ex}
                onClick={() => send(ex)}
                className="block w-full border border-[#E4E2DA] bg-white px-3 py-2 text-left text-[13px] text-[#3A4048] transition-colors hover:border-[#2F6DF6] hover:text-[#2F6DF6]"
              >
                {ex}
              </button>
            ))}
          </div>
        ) : (
          <ul className="space-y-4">
            {messages.map((m, i) => (
              <li key={i} className={m.role === "user" ? "text-right" : "text-left"}>
                <div
                  className={`inline-block max-w-[85%] whitespace-pre-wrap border px-3 py-2 text-[13.5px] leading-relaxed ${
                    m.role === "user"
                      ? "border-[#101820] bg-[#101820] text-[#F6F5F1]"
                      : "border-[#E4E2DA] bg-white text-[#3A4048]"
                  }`}
                >
                  {m.content}
                </div>
              </li>
            ))}
            {loading && (
              <li className="text-left">
                <div className="inline-block border border-[#E4E2DA] bg-white px-3 py-2 text-[13.5px] text-[#9B9A90]">
                  Thinking…
                </div>
              </li>
            )}
          </ul>
        )}
      </div>

      {error && (
        <div className="mt-2 flex items-start justify-between gap-3 border border-[#EFD9AE] bg-[#FBF0DE] px-3 py-2 text-[12.5px] text-[#8A5A15]">
          <p>{error}</p>
          {lastFailedTurn && (
            <button
              onClick={retry}
              disabled={loading}
              className="shrink-0 whitespace-nowrap border border-[#8A5A15] px-2 py-1 text-[12px] text-[#8A5A15] transition-opacity hover:bg-[#8A5A15] hover:text-white disabled:opacity-40"
            >
              Try again
            </button>
          )}
        </div>
      )}

      <form
        onSubmit={(e) => {
          e.preventDefault();
          send(input);
        }}
        className="mt-3 flex gap-2"
      >
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask the IAM Copilot…"
          aria-label="Ask the IAM Copilot a question"
          className="flex-1 border border-[#D8D5CB] bg-white px-3 py-2.5 text-[14px] text-[#101820] placeholder:text-[#9B9A90] focus:border-[#2F6DF6]"
        />
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="border border-[#101820] bg-[#101820] px-4 py-2.5 text-[13px] text-[#F6F5F1] transition-opacity disabled:opacity-40"
        >
          Send
        </button>
      </form>
    </div>
  );
}
