"""Feature repository — ported from lib/db/features.ts. Route handlers call
only these functions; nothing outside this module and activity.py touches
SQL directly.
"""

import json
import uuid
from typing import Optional

from .db import get_db


def _parse_array(value):
    if not value:
        return []
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return []


def _to_dto(row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "slug": row["slug"],
        "description": row["description"],
        "category": row["category"],
        "oktaCapability": row["okta_capability"],
        "protocols": _parse_array(row["protocols"]),
        "agentType": row["agent_type"],
        "useCases": _parse_array(row["use_cases"]),
        "securityConsiderations": _parse_array(row["security_considerations"]),
        "relatedFeatureSlugs": _parse_array(row["related_feature_slugs"]),
        "status": row["status"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def list_features(category: Optional[str] = None, status: Optional[str] = None) -> list[dict]:
    clauses, args = [], {}
    if category:
        clauses.append("category = :category")
        args["category"] = category
    if status:
        clauses.append("status = :status")
        args["status"] = status

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = get_db().execute(f"SELECT * FROM iam_feature {where} ORDER BY name ASC", args).fetchall()
    return [_to_dto(r) for r in rows]


def get_feature_by_id_or_slug(id_or_slug: str) -> Optional[dict]:
    row = get_db().execute(
        "SELECT * FROM iam_feature WHERE id = :v OR slug = :v LIMIT 1", {"v": id_or_slug}
    ).fetchone()
    return _to_dto(row) if row else None


def update_feature_status(id_or_slug: str, status: str) -> Optional[dict]:
    existing = get_feature_by_id_or_slug(id_or_slug)
    if not existing:
        return None

    db = get_db()
    db.execute(
        "UPDATE iam_feature SET status = :status, "
        "updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = :id",
        {"status": status, "id": existing["id"]},
    )
    db.commit()
    return get_feature_by_id_or_slug(existing["id"])


def upsert_feature(feature: dict) -> None:
    db = get_db()
    existing = db.execute(
        "SELECT id FROM iam_feature WHERE slug = :slug", {"slug": feature["slug"]}
    ).fetchone()

    payload = {
        "id": existing["id"] if existing else str(uuid.uuid4()),
        "name": feature["name"],
        "slug": feature["slug"],
        "description": feature["description"],
        "category": feature["category"],
        "okta_capability": feature["okta_capability"],
        "protocols": json.dumps(feature["protocols"]),
        "agent_type": feature["agent_type"],
        "use_cases": json.dumps(feature["use_cases"]),
        "security_considerations": json.dumps(feature["security_considerations"]),
        "related_feature_slugs": json.dumps(feature["related_feature_slugs"]),
    }

    if existing:
        db.execute(
            """UPDATE iam_feature SET
                name = :name, description = :description, category = :category,
                okta_capability = :okta_capability, protocols = :protocols,
                agent_type = :agent_type, use_cases = :use_cases,
                security_considerations = :security_considerations,
                related_feature_slugs = :related_feature_slugs,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
               WHERE id = :id""",
            payload,
        )
    else:
        db.execute(
            """INSERT INTO iam_feature
                (id, name, slug, description, category, okta_capability, protocols,
                 agent_type, use_cases, security_considerations, related_feature_slugs)
               VALUES
                (:id, :name, :slug, :description, :category, :okta_capability, :protocols,
                 :agent_type, :use_cases, :security_considerations, :related_feature_slugs)""",
            payload,
        )
    db.commit()


def count_features() -> int:
    row = get_db().execute("SELECT COUNT(*) AS count FROM iam_feature").fetchone()
    return row["count"] if row else 0


def matches_query(feature: dict, query: str) -> bool:
    """In-process search across the same fields as the original app's
    matchesQuery() in app/api/features/route.ts. The catalog is small (tens
    of rows), so scanning in Python is simple and fast enough — no need for
    SQL FTS.
    """
    q = query.lower()
    haystacks = [
        feature["name"],
        feature["description"],
        feature["category"],
        feature["oktaCapability"],
        feature["agentType"],
        *feature["protocols"],
        *feature["useCases"],
        *feature["securityConsiderations"],
    ]
    return any(q in h.lower() for h in haystacks)
