/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Enables instrumentation.ts (runs once at server startup). Used to force
  // IPv4-first DNS resolution — see instrumentation.ts and
  // docs/2026-09-08-gemini-copilot.md for why.
  experimental: {
    instrumentationHook: true,
  },
};

export default nextConfig;
