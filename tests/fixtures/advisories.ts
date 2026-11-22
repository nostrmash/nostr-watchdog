import type { AdvisoryRef } from "../../src/updates/advisories";

export const affectedAdvisory: AdvisoryRef = {
  id: "GHSA-1111-2222-3333",
  url: "https://github.com/getAlby/hub/security/advisories/GHSA-1111-2222-3333",
  severity: "high",
  ranges: [">= 1.0.0, < 2.0.0"],
};

export const reviewAdvisory: AdvisoryRef = {
  id: "GHSA-4444-5555-6666",
  url: "https://github.com/advisories/GHSA-4444-5555-6666",
  severity: "moderate",
  ranges: [">= 1.0.0 || < 0.1.0"],
};

export const githubAffected = [
  {
    ghsa_id: "GHSA-1111-2222-3333",
    html_url: "https://github.com/getAlby/hub/security/advisories/GHSA-1111-2222-3333",
    state: "published",
    severity: "high",
    vulnerabilities: [{ vulnerable_version_range: ">= 1.0.0, < 2.0.0" }],
  },
];
