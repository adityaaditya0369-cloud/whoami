import { NextRequest, NextResponse } from "next/server";
import { getFeatureByIdOrSlug, updateFeatureStatus } from "@/lib/db/features";
import { logActivity } from "@/lib/db/activity";
import { STATUS_LABELS, STATUS_ORDER, LearningStatus } from "@/lib/types";

export const dynamic = "force-dynamic";

export async function PATCH(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  let body: { status?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const status = body.status;
  if (!status || !STATUS_ORDER.includes(status as LearningStatus)) {
    return NextResponse.json(
      { error: `status must be one of: ${STATUS_ORDER.join(", ")}` },
      { status: 400 }
    );
  }

  const existing = getFeatureByIdOrSlug(params.id);
  if (!existing) {
    return NextResponse.json({ error: "Feature not found" }, { status: 404 });
  }

  const updated = updateFeatureStatus(params.id, status as LearningStatus);
  if (!updated) {
    return NextResponse.json({ error: "Feature not found" }, { status: 404 });
  }

  logActivity({
    featureId: updated.id,
    featureName: updated.name,
    activityType: "STATUS_CHANGED",
    description: `${updated.name} marked as ${STATUS_LABELS[status as LearningStatus]}`,
    metadata: { from: existing.status, to: status },
  });

  return NextResponse.json({ feature: updated });
}
