import { NextRequest, NextResponse } from "next/server";
import { listFeatures } from "@/lib/db/features";
import { logActivity } from "@/lib/db/activity";
import { FeatureDTO } from "@/lib/types";

export const dynamic = "force-dynamic";

// Search is performed in-process rather than in SQL, since matching inside
// JSON-encoded array columns requires parsing anyway. The catalog is small
// (tens of rows), so this stays fast and simple.
function matchesQuery(feature: FeatureDTO, query: string): boolean {
  const q = query.toLowerCase();
  const haystacks = [
    feature.name,
    feature.description,
    feature.category,
    feature.oktaCapability,
    feature.agentType,
    ...feature.protocols,
    ...feature.useCases,
    ...feature.securityConsiderations,
  ];
  return haystacks.some((h) => h.toLowerCase().includes(q));
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const query = searchParams.get("q")?.trim() ?? "";
  const category = searchParams.get("category")?.trim() ?? "";
  const status = searchParams.get("status")?.trim() ?? "";
  const logSearch = searchParams.get("logSearch") === "true";

  const rows = listFeatures({
    category: category || undefined,
    status: status || undefined,
  });

  const filtered = query ? rows.filter((f) => matchesQuery(f, query)) : rows;

  if (logSearch && query.length > 1) {
    logActivity({
      featureName: query,
      activityType: "SEARCHED",
      description: `Searched the catalog for "${query}"`,
      metadata: { resultCount: filtered.length, category: category || null },
    });
  }

  return NextResponse.json({ features: filtered, total: filtered.length });
}
