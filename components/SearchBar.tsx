"use client";

interface Props {
  value: string;
  onChange: (v: string) => void;
}

export default function SearchBar({ value, onChange }: Props) {
  return (
    <div className="relative">
      <svg
        aria-hidden="true"
        viewBox="0 0 20 20"
        className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-[#8A8A80]"
        fill="none"
      >
        <circle cx="8.5" cy="8.5" r="6" stroke="currentColor" strokeWidth="1.6" />
        <path d="M13.5 13.5L17 17" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      </svg>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Search SAML, OIDC, MFA, SCIM, provisioning, agent..."
        aria-label="Search the IAM and Okta feature catalog"
        className="w-full rounded-sm border border-[#D8D5CB] bg-white py-3.5 pl-12 pr-4 text-[15px] text-[#101820] placeholder:text-[#9B9A90] shadow-[0_1px_0_rgba(16,24,32,0.03)] focus:border-[#2F6DF6]"
      />
    </div>
  );
}
