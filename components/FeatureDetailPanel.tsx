"use client";

import { useEffect } from "react";
import { FeatureDTO, LearningStatus, STATUS_LABELS, STATUS_ORDER } from "@/lib/types";
import ProtocolBadge from "./ProtocolBadge";
import StatusBadge from "./StatusBadge";

interface Props {
  feature: FeatureDTO;
  onClose: () => void;
  onStatusChange: (featureId: string, status: LearningStatus) => void;
}

export default function FeatureDetailPanel({ feature, onClose, onStatusChange }: Props) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div
        className="absolute inset-0 bg-[#101820]/40"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={`${feature.name} details`}
        className="thin-scroll relative z-10 h-full w-full max-w-lg overflow-y-auto border-l border-[#E4E2DA] bg-[#F6F5F1] p-7"
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="text-[12px] text-[#9B9A90]">{feature.category}</div>
            <h2 className="font-display text-[26px] leading-tight text-[#101820]">
              {feature.name}
            </h2>
          </div>
          <button
            onClick={onClose}
            aria-label="Close details"
            className="rounded-sm border border-[#D8D5CB] bg-white px-2.5 py-1.5 text-[#3A4048] hover:border-[#101820]"
          >
            Close
          </button>
        </div>

        <p className="mt-4 text-[14.5px] leading-relaxed text-[#3A4048]">
          {feature.description}
        </p>

        <Section title="Okta capability">
          <p className="text-[14px] text-[#3A4048]">{feature.oktaCapability}</p>
        </Section>

        <Section title="Protocols">
          <div className="flex flex-wrap gap-1.5">
            {feature.protocols.map((p) => (
              <ProtocolBadge key={p} label={p} />
            ))}
          </div>
        </Section>

        <Section title="Agent / integration">
          <p className="text-[14px] text-[#3A4048]">{feature.agentType}</p>
        </Section>

        <Section title="Use cases">
          <ul className="space-y-1.5">
            {feature.useCases.map((u) => (
              <li key={u} className="flex gap-2 text-[14px] text-[#3A4048]">
                <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-[#9B9A90]" />
                {u}
              </li>
            ))}
          </ul>
        </Section>

        <Section title="Security considerations">
          <ul className="space-y-1.5">
            {feature.securityConsiderations.map((s) => (
              <li key={s} className="flex gap-2 text-[14px] text-[#3A4048]">
                <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-[#C77D22]" />
                {s}
              </li>
            ))}
          </ul>
        </Section>

        {feature.relatedFeatureSlugs.length > 0 && (
          <Section title="Related features">
            <div className="flex flex-wrap gap-1.5">
              {feature.relatedFeatureSlugs.map((slug) => (
                <span
                  key={slug}
                  className="rounded-sm border border-[#D8D5CB] bg-white px-2 py-1 text-[12.5px] text-[#5B5F63]"
                >
                  {slug.replace(/-/g, " ")}
                </span>
              ))}
            </div>
          </Section>
        )}

        <Section title="Learning status">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={feature.status} />
            <div className="flex flex-wrap gap-1.5">
              {STATUS_ORDER.filter((s) => s !== feature.status).map((s) => (
                <button
                  key={s}
                  onClick={() => onStatusChange(feature.id, s)}
                  className="rounded-sm border border-[#D8D5CB] bg-white px-2.5 py-1 text-[12.5px] text-[#3A4048] hover:border-[#2F6DF6] hover:text-[#2F6DF6]"
                >
                  Mark {STATUS_LABELS[s]}
                </button>
              ))}
            </div>
          </div>
        </Section>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mt-6 border-t border-[#E4E2DA] pt-5">
      <h3 className="mb-2.5 font-display text-[14px] text-[#101820]">{title}</h3>
      {children}
    </div>
  );
}
