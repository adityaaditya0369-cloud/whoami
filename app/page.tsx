"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Header from "@/components/Header";
import SearchBar from "@/components/SearchBar";
import CategoryFilter from "@/components/CategoryFilter";
import FeatureCard from "@/components/FeatureCard";
import FeatureDetailPanel from "@/components/FeatureDetailPanel";
import ActivityTimeline from "@/components/ActivityTimeline";
import CopilotPanel from "@/components/CopilotPanel";
import { ActivityDTO, CATEGORIES, FeatureDTO, LearningStatus } from "@/lib/types";

type Tab = "catalog" | "activity" | "copilot";

export default function Dashboard() {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("");
  const [features, setFeatures] = useState<FeatureDTO[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<FeatureDTO | null>(null);
  const [activities, setActivities] = useState<ActivityDTO[]>([]);
  const [tab, setTab] = useState<Tab>("catalog");

  const searchLogTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchFeatures = useCallback(async (q: string, cat: string, logSearch: boolean) => {
    const params = new URLSearchParams();
    if (q) params.set("q", q);
    if (cat) params.set("category", cat);
    if (logSearch) params.set("logSearch", "true");
    const res = await fetch(`/api/features?${params.toString()}`);
    const data = await res.json();
    setFeatures(data.features ?? []);
  }, []);

  const fetchActivities = useCallback(async () => {
    const res = await fetch("/api/activity?limit=200");
    const data = await res.json();
    setActivities(data.activities ?? []);
  }, []);

  // Initial load
  useEffect(() => {
    (async () => {
      setLoading(true);
      await Promise.all([fetchFeatures("", "", false), fetchActivities()]);
      setLoading(false);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Live filtering as the user types/filters; log the search after a pause
  useEffect(() => {
    fetchFeatures(query, category, false);

    if (searchLogTimer.current) clearTimeout(searchLogTimer.current);
    if (query.trim().length > 1) {
      searchLogTimer.current = setTimeout(async () => {
        await fetchFeatures(query, category, true);
        fetchActivities();
      }, 900);
    }
    return () => {
      if (searchLogTimer.current) clearTimeout(searchLogTimer.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, category]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const cat of CATEGORIES) c[cat] = 0;
    for (const f of features) c[f.category] = (c[f.category] ?? 0) + 1;
    return c;
  }, [features]);

  async function openFeature(feature: FeatureDTO) {
    setSelected(feature);
    const res = await fetch(`/api/features/${feature.id}?logView=true`);
    const data = await res.json();
    if (data.feature) setSelected(data.feature);
    fetchActivities();
  }

  async function handleStatusChange(featureId: string, status: LearningStatus) {
    const res = await fetch(`/api/features/${featureId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    const data = await res.json();
    if (data.feature) {
      setSelected(data.feature);
      setFeatures((prev) => prev.map((f) => (f.id === featureId ? data.feature : f)));
    }
    fetchActivities();
  }

  return (
    <main className="min-h-screen bg-[#F6F5F1]">
      <Header />

      <div className="mx-auto max-w-6xl px-6 py-8">
        <div className="mb-6 flex gap-1 border-b border-[#E4E2DA]">
          <TabButton active={tab === "catalog"} onClick={() => setTab("catalog")}>
            Catalog
          </TabButton>
          <TabButton active={tab === "activity"} onClick={() => setTab("activity")}>
            Daily activity log
          </TabButton>
          <TabButton active={tab === "copilot"} onClick={() => setTab("copilot")}>
            Copilot
          </TabButton>
        </div>

        {tab === "catalog" ? (
          <>
            <div className="mb-5">
              <SearchBar value={query} onChange={setQuery} />
            </div>
            <div className="mb-7">
              <CategoryFilter active={category} onChange={setCategory} counts={counts} />
            </div>

            {loading ? (
              <p className="text-[13.5px] text-[#9B9A90]">Loading catalog…</p>
            ) : features.length === 0 ? (
              <p className="text-[13.5px] text-[#9B9A90]">
                No features match &ldquo;{query}&rdquo;. Try a different protocol, category, or keyword.
              </p>
            ) : (
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {features.map((f) => (
                  <FeatureCard key={f.id} feature={f} onSelect={openFeature} />
                ))}
              </div>
            )}
          </>
        ) : tab === "activity" ? (
          <div className="max-w-2xl">
            <ActivityTimeline activities={activities} />
          </div>
        ) : (
          <CopilotPanel onActivity={fetchActivities} />
        )}
      </div>

      {selected && (
        <FeatureDetailPanel
          feature={selected}
          onClose={() => setSelected(null)}
          onStatusChange={handleStatusChange}
        />
      )}
    </main>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`-mb-px border-b-2 px-4 py-3 text-[14px] transition-colors ${
        active
          ? "border-[#101820] text-[#101820]"
          : "border-transparent text-[#9B9A90] hover:text-[#3A4048]"
      }`}
    >
      {children}
    </button>
  );
}
