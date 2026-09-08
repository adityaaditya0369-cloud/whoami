"use client";

import { ActivityDTO } from "@/lib/types";

const TYPE_STYLES: Record<string, string> = {
  VIEWED: "bg-[#2F6DF6]",
  SEARCHED: "bg-[#9B9A90]",
  STATUS_CHANGED: "bg-[#1F8A5F]",
  TRACKED: "bg-[#C77D22]",
  ASKED_COPILOT: "bg-[#7A3FF2]",
  SYSTEM: "bg-[#101820]",
};

function formatTime(iso: string) {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function formatDateHeading(iso: string) {
  const date = new Date(iso);
  const today = new Date();
  const isToday = date.toDateString() === today.toDateString();
  if (isToday) return "Today";
  return date.toLocaleDateString(undefined, {
    weekday: "long",
    month: "long",
    day: "numeric",
  });
}

export default function ActivityTimeline({ activities }: { activities: ActivityDTO[] }) {
  if (activities.length === 0) {
    return (
      <p className="text-[13.5px] text-[#9B9A90]">
        No activity yet — search the catalog or open a feature to start the log.
      </p>
    );
  }

  const groups: { heading: string; items: ActivityDTO[] }[] = [];
  for (const a of activities) {
    const heading = formatDateHeading(a.createdAt);
    const last = groups[groups.length - 1];
    if (last && last.heading === heading) {
      last.items.push(a);
    } else {
      groups.push({ heading, items: [a] });
    }
  }

  return (
    <div className="space-y-6">
      {groups.map((group) => (
        <div key={group.heading}>
          <h4 className="mb-2.5 text-[12.5px] text-[#9B9A90]">{group.heading}</h4>
          <ul className="space-y-0">
            {group.items.map((a) => (
              <li
                key={a.id}
                className="flex gap-3 border-l border-[#E4E2DA] py-2.5 pl-4"
              >
                <span
                  className={`mt-1.5 h-1.5 w-1.5 shrink-0 -ml-[19px] rounded-full ${
                    TYPE_STYLES[a.activityType] ?? "bg-[#9B9A90]"
                  }`}
                />
                <div className="flex min-w-0 flex-1 items-baseline justify-between gap-3">
                  <p className="text-[13.5px] text-[#3A4048]">{a.description}</p>
                  <span className="shrink-0 font-mono text-[11.5px] text-[#9B9A90]">
                    {formatTime(a.createdAt)}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
