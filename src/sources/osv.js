// src/sources/osv.js
// Fetches npm vulnerabilities from the OSV (Open Source Vulnerabilities) API.
// Docs: https://osv.dev/docs/
// No API key required.

import fetch from "node-fetch";
import { scoreToSeverity, passesFilter } from "../utils.js";

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";
const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";

/**
 * Extract CVSS info from OSV severity array.
 * OSV severity entries: { type: "CVSS_V3" | "CVSS_V4", score: "<vector>" }
 */
function extractCvss(severities, preferredVersion) {
  if (!severities || severities.length === 0) {
    return { score: null, severity: "UNKNOWN", vector: null };
  }

  // Prefer the requested version, fall back to whatever is available.
  const order =
    preferredVersion === "v4"
      ? ["CVSS_V4", "CVSS_V3"]
      : preferredVersion === "v3"
      ? ["CVSS_V3", "CVSS_V4"]
      : ["CVSS_V4", "CVSS_V3"];

  for (const type of order) {
    const entry = severities.find((s) => s.type === type);
    if (entry) {
      // The score field in OSV is actually the CVSS vector string.
      const vector = entry.score;
      // Parse base score from vector, e.g. "CVSS:3.1/.../8.8"
      // The base score is encoded as the last ":<number>" segment of the vector.
      const numMatch = vector.match(/([\d.]+)$/);
      const score = numMatch ? parseFloat(numMatch[1]) : null;
      return {
        score,
        severity: scoreToSeverity(score),
        vector,
      };
    }
  }

  return { score: null, severity: "UNKNOWN", vector: null };
}

/**
 * OSV supports querying by ecosystem. We page through results using
 * the modified_since parameter via a POST to /v1/query.
 */
export async function fetchOSV(fromDate, toDate, cvssConf) {
  const findings = [];
  let pageToken = null;
  let page = 0;

  console.log("  [OSV] Querying OSV (osv.dev)…");

  do {
    page++;
    const body = {
      package: { ecosystem: "npm" },
      // OSV doesn't have a date-range filter in the query endpoint;
      // we fetch all and filter client-side. page_token handles pagination.
    };
    if (pageToken) body.page_token = pageToken;

    const res = await fetch(OSV_QUERY_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "npm-vuln-scanner/1.0",
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`OSV API error ${res.status}: ${text}`);
    }

    const json = await res.json();
    pageToken = json.next_page_token ?? null;

    let exitEarly = false;

    for (const vuln of json.vulns ?? []) {
      const publishedAt = new Date(vuln.published);

      // OSV returns newest-first; stop early if we've gone past our window.
      if (publishedAt < fromDate) {
        exitEarly = true;
        break;
      }
      if (publishedAt > toDate) continue;

      const cvss = extractCvss(vuln.severity, cvssConf.version);

      // Affected packages
      for (const affected of vuln.affected ?? []) {
        if (affected.package?.ecosystem !== "npm") continue;

        const pkgName = affected.package.name;
        const versions =
          affected.ranges
            ?.flatMap((r) =>
              r.events
                ?.filter((e) => e.introduced)
                .map((e) => e.introduced)
            )
            .filter(Boolean)
            .join(", ") || "unspecified";

        const patchedVersion =
          affected.ranges
            ?.flatMap((r) =>
              r.events?.filter((e) => e.fixed).map((e) => e.fixed)
            )
            .filter(Boolean)
            .join(", ") || "no patch available";

        const cweTypes = (vuln.database_specific?.cwe_ids ?? []).join(", ");

        const finding = {
          source: "osv",
          vuln_id: vuln.id,
          package_name: pkgName,
          package_version: versions,
          cvss_score: cvss.score,
          cvss_severity: cvss.severity,
          cvss_vector: cvss.vector,
          vuln_type: cweTypes || "N/A",
          date_published: vuln.published,
          summary: vuln.summary ?? vuln.details?.split("\n")[0] ?? "N/A",
          patched_version: patchedVersion,
        };

        if (passesFilter(finding, cvssConf)) {
          findings.push(finding);
        }
      }
    }

    if (exitEarly) break;

    // Polite delay
    if (pageToken) await new Promise((r) => setTimeout(r, 300));
  } while (pageToken);

  console.log(`  [OSV] Found ${findings.length} matching findings (${page} page(s) fetched).`);
  return findings;
}
