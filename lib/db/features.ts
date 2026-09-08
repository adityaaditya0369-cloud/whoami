import { randomUUID } from "node:crypto";
import { db } from "./client";
import { FeatureDTO, LearningStatus, safeParseArray } from "../types";

interface FeatureRow {
  id: string;
  name: string;
  slug: string;
  description: string;
  category: string;
  okta_capability: string;
  protocols: string;
  agent_type: string;
  use_cases: string;
  security_considerations: string;
  related_feature_slugs: string;
  status: string;
  created_at: string;
  updated_at: string;
}

function toDTO(row: FeatureRow): FeatureDTO {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    description: row.description,
    category: row.category,
    oktaCapability: row.okta_capability,
    protocols: safeParseArray(row.protocols),
    agentType: row.agent_type,
    useCases: safeParseArray(row.use_cases),
    securityConsiderations: safeParseArray(row.security_considerations),
    relatedFeatureSlugs: safeParseArray(row.related_feature_slugs),
    status: row.status as LearningStatus,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export interface FeatureFilter {
  category?: string;
  status?: string;
}

export function listFeatures(filter: FeatureFilter = {}): FeatureDTO[] {
  const clauses: string[] = [];
  const args: Record<string, string> = {};

  if (filter.category) {
    clauses.push("category = @category");
    args.category = filter.category;
  }
  if (filter.status) {
    clauses.push("status = @status");
    args.status = filter.status;
  }

  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = db
    .prepare<Record<string, string>, FeatureRow>(
      `SELECT * FROM iam_feature ${where} ORDER BY name ASC`
    )
    .all(args);

  return rows.map(toDTO);
}

export function getFeatureByIdOrSlug(idOrSlug: string): FeatureDTO | null {
  const row = db
    .prepare<{ idOrSlug: string }, FeatureRow>(
      "SELECT * FROM iam_feature WHERE id = @idOrSlug OR slug = @idOrSlug LIMIT 1"
    )
    .get({ idOrSlug });
  return row ? toDTO(row) : null;
}

export function updateFeatureStatus(idOrSlug: string, status: LearningStatus): FeatureDTO | null {
  const existing = getFeatureByIdOrSlug(idOrSlug);
  if (!existing) return null;

  db.prepare(
    `UPDATE iam_feature
     SET status = @status, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
     WHERE id = @id`
  ).run({ status, id: existing.id });

  return getFeatureByIdOrSlug(existing.id);
}

export interface SeedFeatureInput {
  name: string;
  slug: string;
  description: string;
  category: string;
  oktaCapability: string;
  protocols: string[];
  agentType: string;
  useCases: string[];
  securityConsiderations: string[];
  relatedFeatureSlugs: string[];
}

export function upsertFeature(input: SeedFeatureInput): void {
  const existing = db
    .prepare<{ slug: string }, { id: string }>("SELECT id FROM iam_feature WHERE slug = @slug")
    .get({ slug: input.slug });

  const payload = {
    id: existing?.id ?? randomUUID(),
    name: input.name,
    slug: input.slug,
    description: input.description,
    category: input.category,
    okta_capability: input.oktaCapability,
    protocols: JSON.stringify(input.protocols),
    agent_type: input.agentType,
    use_cases: JSON.stringify(input.useCases),
    security_considerations: JSON.stringify(input.securityConsiderations),
    related_feature_slugs: JSON.stringify(input.relatedFeatureSlugs),
  };

  if (existing) {
    db.prepare(
      `UPDATE iam_feature SET
        name = @name, description = @description, category = @category,
        okta_capability = @okta_capability, protocols = @protocols,
        agent_type = @agent_type, use_cases = @use_cases,
        security_considerations = @security_considerations,
        related_feature_slugs = @related_feature_slugs,
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
       WHERE id = @id`
    ).run(payload);
  } else {
    db.prepare(
      `INSERT INTO iam_feature
        (id, name, slug, description, category, okta_capability, protocols,
         agent_type, use_cases, security_considerations, related_feature_slugs)
       VALUES
        (@id, @name, @slug, @description, @category, @okta_capability, @protocols,
         @agent_type, @use_cases, @security_considerations, @related_feature_slugs)`
    ).run(payload);
  }
}

export function countFeatures(): number {
  const row = db.prepare<[], { count: number }>("SELECT COUNT(*) as count FROM iam_feature").get();
  return row?.count ?? 0;
}
