import { listFeatures } from "@/lib/db/features";

// Builds a compact, read-only snapshot of the local IAM catalog to ground the
// copilot's answers. This is regenerated per request from the database, so new
// or edited seed features are reflected without touching this file.
export function buildCatalogContext(): string {
  const features = listFeatures();
  const lines = features.map((f) => {
    const protocols = f.protocols.length ? f.protocols.join(", ") : "none";
    return `- ${f.name} [${f.category}] — protocols: ${protocols}. ${f.description}`;
  });

  return [
    `The IAM Copilot catalog contains ${features.length} Okta/IAM capabilities:`,
    "",
    ...lines,
  ].join("\n");
}

export const COPILOT_SYSTEM_PROMPT = `You are IAM Copilot, an assistant that explains Okta and enterprise Identity & Access Management (IAM) concepts.

Ground your answers in the catalog context provided in the first user message. You may add widely-known IAM background, but do not invent Okta product names or features that are not real.

Important boundaries:
- This is a local knowledge prototype. There is NO live Okta connection and no access to any real user's account, groups, or entitlements.
- If asked about a specific person's real access (e.g. "why don't I have access to Salesforce?", "what groups am I in?"), explain that you cannot look that up here, then describe how it WOULD be answered once the planned Okta MCP integration is connected (an agent calling scoped, read-only Okta Management API tools with the end user's own token).
- Never ask for or handle credentials, secrets, or API tokens.

Style: concise and practical. Prefer short paragraphs or tight bullet lists. When relevant, name the related catalog features so the user can open them.`;
