export default function ProtocolBadge({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center rounded-sm border border-[#D8D5CB] bg-white px-2 py-0.5 text-[11px] font-mono text-[#3A4048] whitespace-nowrap">
      {label}
    </span>
  );
}
