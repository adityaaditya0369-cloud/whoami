"""Activity log repository — ported from lib/db/activity.ts."""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from .db import get_db

TYPE_DOT_CLASS = {
    "VIEWED": "dot-blue",
    "SEARCHED": "dot-grey",
    "STATUS_CHANGED": "dot-green",
    "TRACKED": "dot-orange",
    "ASKED_COPILOT": "dot-purple",
    "SYSTEM": "dot-ink",
}


def _parse_object(value):
    if not value:
        return None
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else None
    except (TypeError, ValueError):
        return None


def _to_dto(row) -> dict:
    return {
        "id": row["id"],
        "featureId": row["feature_id"],
        "featureName": row["feature_name"],
        "activityType": row["activity_type"],
        "description": row["description"],
        "metadata": _parse_object(row["metadata"]),
        "createdAt": row["created_at"],
    }


def log_activity(
    feature_name: str,
    activity_type: str,
    description: str,
    feature_id: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> dict:
    db = get_db()
    row = {
        "id": str(uuid.uuid4()),
        "feature_id": feature_id,
        "feature_name": feature_name,
        "activity_type": activity_type,
        "description": description,
        "metadata": json.dumps(metadata) if metadata is not None else None,
    }
    db.execute(
        """INSERT INTO activity_log
            (id, feature_id, feature_name, activity_type, description, metadata)
           VALUES (:id, :feature_id, :feature_name, :activity_type, :description, :metadata)""",
        row,
    )
    db.commit()
    return {
        "id": row["id"],
        "featureId": row["feature_id"],
        "featureName": row["feature_name"],
        "activityType": row["activity_type"],
        "description": row["description"],
        "metadata": metadata,
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }


def list_activity(limit: int = 100) -> list[dict]:
    rows = get_db().execute(
        "SELECT * FROM activity_log ORDER BY created_at DESC LIMIT :limit", {"limit": limit}
    ).fetchall()
    return [_to_dto(r) for r in rows]


def count_activity() -> int:
    row = get_db().execute("SELECT COUNT(*) AS count FROM activity_log").fetchone()
    return row["count"] if row else 0


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def group_for_display(activities: list[dict]) -> list[dict]:
    """Group activities by date heading ("Today" or "Weekday, Month Day"),
    most recent first (the query already orders that way) — ported from
    ActivityTimeline.tsx's grouping loop. Each item also gets a formatted
    local time string and a CSS class for its type dot, computed once here
    instead of in the template.
    """
    today_local = datetime.now().astimezone().date()
    groups: list[dict] = []

    for a in activities:
        dt_local = _parse_iso(a["createdAt"]).astimezone()
        if dt_local.date() == today_local:
            heading = "Today"
        else:
            heading = f"{dt_local.strftime('%A')}, {dt_local.strftime('%B')} {dt_local.day}"

        item = {
            **a,
            "time": dt_local.strftime("%I:%M %p"),
            "dot_class": TYPE_DOT_CLASS.get(a["activityType"], "dot-grey"),
        }

        if groups and groups[-1]["heading"] == heading:
            groups[-1]["entries"].append(item)
        else:
            groups.append({"heading": heading, "entries": [item]})

    return groups
