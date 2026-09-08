import Database from "better-sqlite3";
import path from "node:path";
import fs from "node:fs";

// Lightweight database abstraction: a single better-sqlite3 connection,
// initialized once and reused across requests (Next.js dev-mode hot reload
// safe via the globalThis cache, same pattern as a Prisma client singleton).
//
// Chosen over Prisma for this local prototype because better-sqlite3 ships
// a prebuilt native binary through npm with no separate engine-binary fetch
// step at install/build time — one less moving part for a "clone and
// `npm run dev`" experience. Swapping to Postgres/Prisma later only touches
// this file and the two repository modules (features.ts, activity.ts); API
// routes and components never talk to SQL directly.

const DB_DIR = path.join(process.cwd(), "data");
const DB_PATH = path.join(DB_DIR, "iam-copilot.db");

const globalForDb = globalThis as unknown as { __iamCopilotDb?: Database.Database };

function createConnection(): Database.Database {
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  db.exec(`
    CREATE TABLE IF NOT EXISTS iam_feature (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL,
      category TEXT NOT NULL,
      okta_capability TEXT NOT NULL,
      protocols TEXT NOT NULL DEFAULT '[]',
      agent_type TEXT NOT NULL,
      use_cases TEXT NOT NULL DEFAULT '[]',
      security_considerations TEXT NOT NULL DEFAULT '[]',
      related_feature_slugs TEXT NOT NULL DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'NOT_STARTED',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );

    CREATE INDEX IF NOT EXISTS idx_iam_feature_category ON iam_feature(category);

    CREATE TABLE IF NOT EXISTS activity_log (
      id TEXT PRIMARY KEY,
      feature_id TEXT,
      feature_name TEXT NOT NULL,
      activity_type TEXT NOT NULL,
      description TEXT NOT NULL,
      metadata TEXT,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      FOREIGN KEY (feature_id) REFERENCES iam_feature(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_activity_log_created_at ON activity_log(created_at);
  `);

  return db;
}

export const db = globalForDb.__iamCopilotDb ?? createConnection();

if (process.env.NODE_ENV !== "production") globalForDb.__iamCopilotDb = db;
