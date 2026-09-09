#!/usr/bin/env python3
"""Seed/update the catalog. Safe to re-run — upserts by slug, same as the
original `npm run db:seed`. Run with: python seed.py
"""

from iam_copilot.seed_data import SEED_FEATURES
from iam_copilot.features import upsert_feature, count_features
from iam_copilot.activity import log_activity, count_activity


def main():
    print(f"Seeding {len(SEED_FEATURES)} IAM/Okta features...")
    for feature in SEED_FEATURES:
        upsert_feature(feature)

    total = count_features()
    print(f"Catalog now has {total} features.")

    if count_activity() == 0:
        log_activity(
            feature_name="IAM Copilot",
            activity_type="SYSTEM",
            description="Database seeded with the initial IAM/Okta feature catalog",
        )
        print("Logged initial seed activity.")

    print("Seed complete.")


if __name__ == "__main__":
    main()
