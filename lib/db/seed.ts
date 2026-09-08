import { upsertFeature, countFeatures } from "./features";
import { logActivity, countActivity } from "./activity";
import { seedFeatures } from "./seed-data";

function main() {
  console.log(`Seeding ${seedFeatures.length} IAM/Okta features...`);
  for (const f of seedFeatures) {
    upsertFeature(f);
  }
  console.log(`Catalog now has ${countFeatures()} features.`);

  if (countActivity() === 0) {
    logActivity({
      featureName: "IAM Copilot",
      activityType: "SYSTEM",
      description: "Database seeded with the initial IAM/Okta feature catalog",
      metadata: { featureCount: seedFeatures.length },
    });
    console.log("Logged initial seed activity.");
  }

  console.log("Seed complete.");
}

main();
