"""SQLite connection + schema. Ported from lib/db/client.ts.

Same table/column names and same on-disk path (data/iam-copilot.db) as the
original Next.js app, so an existing database file from that version works
here unchanged — nothing needs reseeding after switching backends.

sqlite3 is in the Python standard library: no extra dependency, no native
binary to fetch (the exact problem better-sqlite3 solved on the Node side,
solved here for free).
"""

import os
import sqlite3
import threading

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DB_DIR, "iam-copilot.db")

SCHEMA = """
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
"""

_local = threading.local()


def get_db() -> sqlite3.Connection:
    """One connection per thread (Flask's dev server is multi-threaded by
    default). Each connection gets the schema ensured and row access by
    column name, matching the DTO-shaping pattern from the TS repositories.
    """
    conn = getattr(_local, "conn", None)
    if conn is not None:
        return conn

    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    conn.commit()

    _local.conn = conn
    return conn
