"""IAM Copilot — Flask entry point.

Run with: python app.py   (serves http://localhost:3000)
Seed/reset the catalog first with: python seed.py

Route map:
  GET  /                                    full page (catalog tab active)
  GET  /api/features/fragment               HTML fragment: filter bar + cards
  GET  /api/features/<id>/fragment           HTML fragment: feature detail panel
  POST /api/features/<id>/status             update status -> detail fragment
  GET  /api/activity/fragment                HTML fragment: activity timeline
  POST /api/chat                             JSON {reply} or {error} (copilot)
"""

import os
import socket

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

# Load .env before anything reads os.environ (mirrors Next.js auto-loading .env).
load_dotenv()

# IPv4-first DNS, process-wide, applied as early as possible — see
# iam_copilot/gemini.py and docs/2026-09-08-gemini-copilot.md. gemini.py
# patches this too at import time; doing it here as well just means it's
# definitely in place before the first request, regardless of import order.
_original_getaddrinfo = socket.getaddrinfo


def _ipv4_first_getaddrinfo(*args, **kwargs):
    results = _original_getaddrinfo(*args, **kwargs)
    return sorted(results, key=lambda r: 0 if r[0] == socket.AF_INET else 1)


socket.getaddrinfo = _ipv4_first_getaddrinfo

from iam_copilot import features as features_repo  # noqa: E402
from iam_copilot import activity as activity_repo  # noqa: E402
from iam_copilot import context as copilot_context  # noqa: E402
from iam_copilot import gemini  # noqa: E402
from iam_copilot.types import CATEGORIES, STATUS_LABELS, STATUS_ORDER  # noqa: E402

app = Flask(__name__)

MAX_MESSAGES = 20
MAX_CHARS = 4000


# ---------------------------------------------------------------- helpers --

def _filtered_features(q: str, category: str):
    rows = features_repo.list_features(category=category or None)
    if q:
        rows = [f for f in rows if features_repo.matches_query(f, q)]
    return rows


def _category_counts(features: list[dict]) -> dict:
    counts = {c: 0 for c in CATEGORIES}
    for f in features:
        counts[f["category"]] = counts.get(f["category"], 0) + 1
    return counts


def _catalog_fragment_context(q: str, category: str):
    rows = _filtered_features(q, category)
    return {
        "features": rows,
        "query": q,
        "active_category": category,
        "categories": CATEGORIES,
        "counts": _category_counts(rows),
        "status_labels": STATUS_LABELS,
    }


# -------------------------------------------------------------------- page --

@app.route("/")
def index():
    catalog_ctx = _catalog_fragment_context("", "")
    activity_groups = activity_repo.group_for_display(activity_repo.list_activity(200))
    return render_template(
        "index.html",
        **catalog_ctx,
        activity_groups=activity_groups,
        status_order=STATUS_ORDER,
    )


# ------------------------------------------------------------ feature API --

@app.route("/api/features/fragment")
def features_fragment():
    q = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip()
    log_search = request.args.get("logSearch") == "true"

    ctx = _catalog_fragment_context(q, category)

    if log_search and len(q) > 1:
        activity_repo.log_activity(
            feature_name=q,
            activity_type="SEARCHED",
            description=f'Searched the catalog for "{q}"',
            metadata={"resultCount": len(ctx["features"]), "category": category or None},
        )

    return render_template("_catalog_results.html", **ctx)


@app.route("/api/features/<id_or_slug>/fragment")
def feature_detail_fragment(id_or_slug):
    feature = features_repo.get_feature_by_id_or_slug(id_or_slug)
    if not feature:
        return "<p class='detail-error'>Feature not found.</p>", 404

    if request.args.get("logView") == "true":
        activity_repo.log_activity(
            feature_id=feature["id"],
            feature_name=feature["name"],
            activity_type="VIEWED",
            description=f"{feature['name']} feature viewed",
        )

    return render_template(
        "_feature_detail.html", feature=feature, status_order=STATUS_ORDER, status_labels=STATUS_LABELS
    )


@app.route("/api/features/<id_or_slug>/status", methods=["POST"])
def update_status(id_or_slug):
    body = request.get_json(silent=True) or {}
    status = body.get("status")
    if not status or status not in STATUS_ORDER:
        return jsonify({"error": f"status must be one of: {', '.join(STATUS_ORDER)}"}), 400

    existing = features_repo.get_feature_by_id_or_slug(id_or_slug)
    if not existing:
        return jsonify({"error": "Feature not found"}), 404

    updated = features_repo.update_feature_status(id_or_slug, status)
    if not updated:
        return jsonify({"error": "Feature not found"}), 404

    activity_repo.log_activity(
        feature_id=updated["id"],
        feature_name=updated["name"],
        activity_type="STATUS_CHANGED",
        description=f"{updated['name']} marked as {STATUS_LABELS[status]}",
        metadata={"from": existing["status"], "to": status},
    )

    return render_template(
        "_feature_detail.html", feature=updated, status_order=STATUS_ORDER, status_labels=STATUS_LABELS
    )


# ------------------------------------------------------------ activity API --

@app.route("/api/activity/fragment")
def activity_fragment():
    limit = min(int(request.args.get("limit", 100)), 500)
    groups = activity_repo.group_for_display(activity_repo.list_activity(limit))
    return render_template("_activity_timeline.html", activity_groups=groups)


# --------------------------------------------------------------- chat API --

def _validate_messages(messages):
    if not isinstance(messages, list) or len(messages) == 0:
        return None, "`messages` must be a non-empty array."
    if len(messages) > MAX_MESSAGES:
        return None, f"Too many messages (max {MAX_MESSAGES})."

    clean = []
    for m in messages:
        role = m.get("role") if isinstance(m, dict) else None
        content = m.get("content") if isinstance(m, dict) else None
        if role not in ("user", "model"):
            return None, "Each message role must be 'user' or 'model'."
        if not isinstance(content, str) or not content.strip():
            return None, "Each message needs non-empty string content."
        if len(content) > MAX_CHARS:
            return None, f"Message too long (max {MAX_CHARS} characters)."
        clean.append({"role": role, "content": content.strip()})

    if clean[-1]["role"] != "user":
        return None, "The last message must be from the user."
    return clean, None


@app.route("/api/chat", methods=["POST"])
def chat():
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "Invalid JSON body"}), 400

    validated, error = _validate_messages(body.get("messages"))
    if error:
        return jsonify({"error": error}), 400

    grounded = [
        {"role": "user", "content": copilot_context.build_catalog_context()},
        {"role": "model", "content": "Understood. I'll use this catalog to answer IAM and Okta questions."},
        *validated,
    ]
    question = validated[-1]["content"]

    try:
        reply = gemini.call_gemini(grounded, copilot_context.COPILOT_SYSTEM_PROMPT)
    except gemini.GeminiError as err:
        return jsonify({"error": str(err)}), err.status

    activity_repo.log_activity(
        feature_name="IAM Copilot",
        activity_type="ASKED_COPILOT",
        description=f"Asked the copilot: \"{question[:120]}{'…' if len(question) > 120 else ''}\"",
        metadata={"question": question, "replyChars": len(reply)},
    )

    return jsonify({"reply": reply})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)
