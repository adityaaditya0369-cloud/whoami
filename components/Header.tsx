export default function Header() {
  return (
    <header className="border-b border-[#E4E2DA] bg-[#101820]">
      <div className="mx-auto max-w-6xl px-6 py-6">
        <div className="flex items-baseline gap-3">
          <h1 className="font-display text-[28px] leading-none text-[#F6F5F1]">
            IAM Copilot
          </h1>
          <span className="font-mono text-[11px] text-[#7C8998]">v0.1 · local</span>
        </div>
        <p className="mt-1.5 text-[13px] text-[#AEB8C2]">
          AI-Powered Identity &amp; Access Management Knowledge Hub
        </p>
      </div>
    </header>
  );
}
