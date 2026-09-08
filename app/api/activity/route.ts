import { NextRequest, NextResponse } from "next/server";
import { listActivity } from "@/lib/db/activity";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const limit = Math.min(Number(searchParams.get("limit") ?? "100"), 500);
  const activities = listActivity(limit);
  return NextResponse.json({ activities });
}
