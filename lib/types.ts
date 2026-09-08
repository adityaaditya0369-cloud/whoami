export type LearningStatus =
  | "NOT_STARTED"
  | "LEARNING"
  | "PRACTICED"
  | "COMPLETED";

export const STATUS_LABELS: Record<LearningStatus, string> = {
  NOT_STARTED: "Not started",
  LEARNING: "Learning",
  PRACTICED: "Practiced",
  COMPLETED: "Completed",
};

export const STATUS_ORDER: LearningStatus[] = [
  "NOT_STARTED",
  "LEARNING",
  "PRACTICED",
  "COMPLETED",
];

export const CATEGORIES = [
  "Authentication",
  "Authorization",
  "Federation",
  "Provisioning",
  "MFA",
  "Identity Governance",
  "API Security",
  "Agentic AI",
  "Security",
] as const;

export type Category = (typeof CATEGORIES)[number];

// Shape returned to the client: JSON string columns are parsed into arrays.
export interface FeatureDTO {
  id: string;
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
  status: LearningStatus;
  createdAt: string;
  updatedAt: string;
}

export interface ActivityDTO {
  id: string;
  featureId: string | null;
  featureName: string;
  activityType: string;
  description: string;
  metadata: Record<string, unknown> | null;
  createdAt: string;
}

export function safeParseArray(value: string | null | undefined): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function safeParseObject(
  value: string | null | undefined
): Record<string, unknown> | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value);
    return typeof parsed === "object" && parsed !== null ? parsed : null;
  } catch {
    return null;
  }
}
