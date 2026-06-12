// src/sources/github.js
// Fetches npm vulnerabilities from the GitHub Advisory Database via GraphQL.
// Docs: https://docs.github.com/en/graphql/reference/objects#securityadvisory

import fetch from "node-fetch";
import { scoreToSeverity, passesFilter } from "../utils.js";

const GH_GRAPHQL = "https://api.github.com/graphql";

// GraphQL query — paginates with a cursor.
// NOTE: 'ecosystem' was removed from securityAdvisories arguments in a 2025
// GitHub schema update. Ecosystem filtering is applied on the nested
// vulnerabilities field, which still accepts it.
const QUERY = `
query($cursor: String) {
  securityAdvisories(
    orderBy: { field: PUBLISHED_AT, direction: DESC }
    first: 100
    after: $cursor
  ) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId
      summary
      publishedAt
      severity
      cvss { score vectorString }
      cwes(first: 5) { nodes { cweId name } }
      vulnerabilities(ecosystem: NPM, first: 20) {
        nodes {
          package { name ecosystem }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  }
}`;

/**
 * Map GitHub severity strings to our standard labels.
 */
function mapSeverity(ghSev) {
  const map = {
    CRITICAL: "CRITICAL",
    HIGH: "HIGH",
    MODERATE: "MEDIUM",
    LOW: "LOW",
  };
  return map[ghSev] ?? "UNKNOWN";
}

/**
 * Fetch all npm advisories from GitHub within [fromDate, toDate].
 * Returns an array of normalised finding objects.
 */
export async function fetchGitHubAdvisories(fromDate, toDate, cvssConf, token) {
  const headers = {
    "Content-Type": "application/json",
    "User-Agent": "npm-vuln-scanner/1.0",
  };
  if (token) headers["Authorization"] = `bearer ${token}`;

  const findings = [];
  let cursor = null;
  let page = 0;

  console.log("  [GitHub] Querying GitHub Advisory Database…");

  while (true) {
    page++;
    const body = JSON.stringify({
      query: QUERY,
      variables: { cursor },
    });

    const res = await fetch(GH_GRAPHQL, { method: "POST", headers, body });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`GitHub GraphQL error ${res.status}: ${text}`);
    }

    const json = await res.json();

    if (json.errors) {
      throw new Error(
        `GitHub GraphQL errors: ${json.errors.map((e) => e.message).join("; ")}`
      );
    }

    const { nodes, pageInfo } = json.data.securityAdvisories;

    let stopPagination = false;

    for (const advisory of nodes) {
      const publishedAt = new Date(advisory.publishedAt);

      // Advisory list is ordered newest-first; stop when we go before fromDate.
      if (publishedAt < fromDate) {
        stopPagination = true;
        break;
      }

      // Skip advisories outside our time window (too new would be impossible
      // given DESC order, but guard against edge cases anyway).
      if (publishedAt > toDate) continue;

      const vulnNodes = advisory.vulnerabilities?.nodes ?? [];

      // Skip advisories that have no npm-ecosystem entries
      // (happens because we can't pre-filter by ecosystem at the top level anymore)
      if (vulnNodes.length === 0) continue;

      const cvssScore =
        advisory.cvss?.score != null ? Number(advisory.cvss.score) : null;
      const severity = mapSeverity(advisory.severity);
      const cwes = (advisory.cwes?.nodes ?? []).map((c) => c.cweId).join(", ");

      for (const vuln of vulnNodes) {
        const pkgName = vuln.package?.name;
        if (!pkgName) continue;

        const finding = {
          source: "github_advisory",
          vuln_id: advisory.ghsaId,
          package_name: pkgName,
          package_version: vuln.vulnerableVersionRange ?? "unspecified",
          cvss_score: cvssScore,
          cvss_severity: severity,
          cvss_vector: advisory.cvss?.vectorString ?? null,
          vuln_type: cwes || "N/A",
          date_published: advisory.publishedAt,
          summary: advisory.summary,
          patched_version:
            vuln.firstPatchedVersion?.identifier ?? "no patch available",
        };

        if (passesFilter(finding, cvssConf)) {
          findings.push(finding);
        }
      }
    }

    if (stopPagination || !pageInfo.hasNextPage) break;
    cursor = pageInfo.endCursor;

    // Polite delay between pages to avoid hammering the API.
    await new Promise((r) => setTimeout(r, 200));
  }

  console.log(`  [GitHub] Found ${findings.length} matching findings (${page} page(s) fetched).`);
  return findings;
}
