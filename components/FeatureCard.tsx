"use client";

import { FeatureDTO } from "@/lib/types";
import ProtocolBadge from "./ProtocolBadge";
import StatusBadge from "./StatusBadge";

interface Props {
  feature: FeatureDTO;
  onSelect: (feature: FeatureDTO) => void;
}

export default function FeatureCard({ feature, onSelect }: Props) {
  return (
    <button
      onClick={() => onSelect(feature)}
      className="flex h-full flex-col items-start gap-3 border border-[#E4E2DA] bg-white p-5 text-left transition-colors hover:border-[#2F6DF6]"
    >
      <div className="flex w-full items-start justify-between gap-2">
        <h3 className="font-display text-[18px] leading-snug text-[#101820]">
          {feature.name}
        </h3>
      </div>
      <p className="text-[13.5px] leading-relaxed text-[#5B5F63] line-clamp-3">
        {feature.description}
      </p>
      <div className="flex flex-wrap gap-1.5">
        {feature.protocols.slice(0, 3).map((p) => (
          <ProtocolBadge key={p} label={p} />
        ))}
      </div>
      <div className="mt-auto flex w-full items-center justify-between pt-2">
        <span className="text-[12px] text-[#9B9A90]">{feature.category}</span>
        <StatusBadge status={feature.status} />
      </div>
    </button>
  );
}
