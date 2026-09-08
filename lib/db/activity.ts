import { randomUUID } from "node:crypto";
import { db } from "./client";
import { ActivityDTO, safeParseObject } from "../types";

interface ActivityRow {
  id: string;
  feature_id: string | null;
  feature_name: string;
  activity_type: string;
  description: string;
  metadata: string | null;
  created_at: string;
}

function toDTO(row: ActivityRow): ActivityDTO {
  return {
    id: row.id,
    featureId: row.feature_id,
    featureName: row.feature_name,
    activityType: row.activity_type,
    description: row.description,
    metadata: safeParseObject(row.metadata),
    createdAt: row.created_at,
  };
}

export type ActivityType =
  | "VIEWED"
  | "SEARCHED"
  | "STATUS_CHANGED"
  | "TRACKED"
  | "ASKED_COPILOT"
  | "SYSTEM";

export function logActivity(params: {
  featureId?: string | null;
  featureName: string;
  activityType: ActivityType;
  description: string;
  metadata?: Record<string, unknown>;
}): ActivityDTO {
  const row = {
    id: randomUUID(),
    feature_id: params.featureId ?? null,
    feature_name: params.featureName,
    activity_type: params.activityType,
    description: params.description,
    metadata: params.metadata ? JSON.stringify(params.metadata) : null,
  };

  db.prepare(
    `INSERT INTO activity_log (id, feature_id, feature_name, activity_type, description, metadata)
     VALUES (@id, @feature_id, @feature_name, @activity_type, @description, @metadata)`
  ).run(row);

  return toDTO({ ...row, created_at: new Date().toISOString() });
}

export function listActivity(limit = 100): ActivityDTO[] {
  const rows = db
    .prepare<{ limit: number }, ActivityRow>(
      "SELECT * FROM activity_log ORDER BY created_at DESC LIMIT @limit"
    )
    .all({ limit });
  return rows.map(toDTO);
}

export function countActivity(): number {
  const row = db.prepare<[], { count: number }>("SELECT COUNT(*) as count FROM activity_log").get();
  return row?.count ?? 0;
}
