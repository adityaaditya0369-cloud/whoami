// Next.js server startup hook (runs once, before any request is handled).
// See: https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation
//
// Fix for frequent "Could not reach the Gemini API (The operation was
// aborted due to timeout)" errors from the Copilot tab: Node's fetch will,
// on some networks (observed on Windows), try the IPv6 address for
// generativelanguage.googleapis.com first and stall on it for the full
// request timeout before ever trying IPv4 — even when IPv4 works fine and
// IPv6 doesn't. This forces Node to try IPv4 first for all DNS lookups in
// this process, which is the standard workaround (see
// docs/2026-09-08-gemini-copilot.md for details and sources).
export async function register() {
  // instrumentation.ts is bundled for both the Node and Edge runtimes; the
  // Edge bundler can't handle `node:dns` at all, so this must only import it
  // when actually running under Node (see Next.js instrumentation docs).
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const dns = await import("node:dns");
    try {
      dns.setDefaultResultOrder("ipv4first");
    } catch {
      // Node too old to have this API — not expected on supported versions.
    }
  }
}
