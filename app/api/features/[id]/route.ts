import { NextRequest, NextResponse } from "next/server";
import { getFeatureByIdOrSlug } from "@/lib/db/features";
import { logActivity } from "@/lib/db/activity";

export const dynamic = "force-dynamic";

export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  const feature = getFeatureByIdOrSlug(params.id);

  if (!feature) {
    return NextResponse.json({ error: "Feature not found" }, { status: 404 });
  }

  const { searchParams } = new URL(req.url);
  if (searchParams.get("logView") === "true") {
    logActivity({
      featureId: feature.id,
      featureName: feature.name,
      activityType: "VIEWED",
      description: `${feature.name} feature viewed`,
    });
  }

  return NextResponse.json({ feature });
}
