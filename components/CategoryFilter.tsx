"use client";

import { CATEGORIES } from "@/lib/types";

interface Props {
  active: string;
  onChange: (category: string) => void;
  counts: Record<string, number>;
}

export default function CategoryFilter({ active, onChange, counts }: Props) {
  const all = ["All", ...CATEGORIES];
  return (
    <div className="flex flex-wrap gap-2" role="tablist" aria-label="Filter by category">
      {all.map((cat) => {
        const isActive = cat === "All" ? active === "" : active === cat;
        const key = cat === "All" ? "" : cat;
        const count = cat === "All" ? undefined : counts[cat];
        return (
          <button
            key={cat}
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(key)}
            className={`rounded-sm border px-3 py-1.5 text-[13px] transition-colors ${
              isActive
                ? "border-[#101820] bg-[#101820] text-[#F6F5F1]"
                : "border-[#D8D5CB] bg-white text-[#3A4048] hover:border-[#101820]"
            }`}
          >
            {cat}
            {typeof count === "number" && (
              <span className={isActive ? "text-[#AEB8C2]" : "text-[#9B9A90]"}> {count}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}
