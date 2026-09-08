import { NextRequest, NextResponse } from "next/server";
import { callGemini, GeminiError, ChatTurn } from "@/lib/ai/gemini";
import { buildCatalogContext, COPILOT_SYSTEM_PROMPT } from "@/lib/ai/context";
import { logActivity } from "@/lib/db/activity";

export const dynamic = "force-dynamic";

const MAX_MESSAGES = 20;
const MAX_CHARS = 4000;

interface IncomingMessage {
  role: unknown;
  content: unknown;
}

function validate(messages: unknown): ChatTurn[] | { error: string } {
  if (!Array.isArray(messages) || messages.length === 0) {
    return { error: "`messages` must be a non-empty array." };
  }
  if (messages.length > MAX_MESSAGES) {
    return { error: `Too many messages (max ${MAX_MESSAGES}).` };
  }

  const clean: ChatTurn[] = [];
  for (const m of messages as IncomingMessage[]) {
    if (m.role !== "user" && m.role !== "model") {
      return { error: "Each message role must be 'user' or 'model'." };
    }
    if (typeof m.content !== "string" || m.content.trim().length === 0) {
      return { error: "Each message needs non-empty string content." };
    }
    if (m.content.length > MAX_CHARS) {
      return { error: `Message too long (max ${MAX_CHARS} characters).` };
    }
    clean.push({ role: m.role, content: m.content.trim() });
  }

  if (clean[clean.length - 1].role !== "user") {
    return { error: "The last message must be from the user." };
  }
  return clean;
}

export async function POST(req: NextRequest) {
  let body: { messages?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const validated = validate(body.messages);
  if ("error" in validated) {
    return NextResponse.json({ error: validated.error }, { status: 400 });
  }

  // Prepend the catalog snapshot as a synthetic first user turn so the model
  // is grounded without us persisting the context in the client conversation.
  const grounded: ChatTurn[] = [
    { role: "user", content: buildCatalogContext() },
    { role: "model", content: "Understood. I'll use this catalog to answer IAM and Okta questions." },
    ...validated,
  ];

  const question = validated[validated.length - 1].content;

  try {
    const reply = await callGemini(grounded, COPILOT_SYSTEM_PROMPT);

    logActivity({
      featureName: "IAM Copilot",
      activityType: "ASKED_COPILOT",
      description: `Asked the copilot: "${question.slice(0, 120)}${question.length > 120 ? "…" : ""}"`,
      metadata: { question, replyChars: reply.length },
    });

    return NextResponse.json({ reply });
  } catch (err) {
    if (err instanceof GeminiError) {
      return NextResponse.json({ error: err.message }, { status: err.status });
    }
    return NextResponse.json(
      { error: "Unexpected error handling the chat request." },
      { status: 500 }
    );
  }
}
