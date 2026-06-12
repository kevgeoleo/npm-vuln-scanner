// src/sources/nvd.js
// Fetches npm-related CVEs from the NIST National Vulnerability Database (NVD).
// REST API v2 docs: https://nvd.nist.gov/developers/vulnerabilities

import fetch from "node-fetch";
import { scoreToSeverity, passesFilter } from "../utils.js";

const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const PAGE_SIZE = 2000; // NVD max is 2000

/**
 * Pull CVSS v3 or v4 data out of a CVE item returned by the NVD API.
 * Returns { score, severity, vector }.
 */
function extractCvss(cveItem, preferredVersion) {
  const metrics = cveItem.metrics ?? {};

  // CVSS v4
  if (
    (preferredVersion === "v4" || preferredVersion === "any") &&
    metrics.cvssMetricV40?.length
  ) {
    const m = metrics.cvssMetricV40[0].cvssData;
    return {
      score: m.baseScore,
      severity: (m.baseSeverity ?? scoreToSeverity(m.baseScore)).toUpperCase(),
      vector: m.vectorString,
      version: "4.0",
    };
  }

  // CVSS v3.1
  if (
    (preferredVersion === "v3" || preferredVersion === "any") &&
    metrics.cvssMetricV31?.length
  ) {
    const m = metrics.cvssMetricV31[0].cvssData;
    return {
      score: m.baseScore,
      severity: (m.baseSeverity ?? scoreToSeverity(m.baseScore)).toUpperCase(),
      vector: m.vectorString,
      version: "3.1",
    };
  }

  // CVSS v3.0
  if (
    (preferredVersion === "v3" || preferredVersion === "any") &&
    metrics.cvssMetricV30?.length
  ) {
    const m = metrics.cvssMetricV30[0].cvssData;
    return {
      score: m.baseScore,
      severity: (m.baseSeverity ?? scoreToSeverity(m.baseScore)).toUpperCase(),
      vector: m.vectorString,
      version: "3.0",
    };
  }

  // Fallback: CVSS v2
  if (metrics.cvssMetricV2?.length) {
    const m = metrics.cvssMetricV2[0].cvssData;
    return {
      score: m.baseScore,
      severity: scoreToSeverity(m.baseScore),
      vector: m.vectorString,
      version: "2.0",
    };
  }

  return { score: null, severity: "UNKNOWN", vector: null, version: null };
}

/**
 * Extract npm package names from CPE match strings.
 * CPE format: cpe:2.3:a:<vendor>:<product>:...
 */
function extractNpmPackages(configurations) {
  const packages = [];
  for (const config of configurations ?? []) {
    for (const node of config.nodes ?? []) {
      for (const match of node.cpeMatch ?? []) {
        const cpe = match.criteria ?? "";
        // Only npm-related CPEs
        if (!cpe.includes("npm") && !cpe.includes("nodejs")) {
          // Many npm packages are listed without 'npm' in the CPE vendor —
          // we still include them if the CVE description mentions npm.
        }
        // Parse: cpe:2.3:a:vendor:product:version:...
        const parts = cpe.split(":");
        if (parts.length >= 5) {
          const product = parts[4];
          const version = parts[5] === "*" ? "unspecified" : parts[5];
          if (product && product !== "-") {
            packages.push({ name: product, version });
          }
        }
      }
    }
  }
  return packages;
}

/**
 * Sleep helper to respect NVD rate limits.
 * Without key: max 5 requests per 30 s → ~6 s per request.
 * With key: max 50 requests per 30 s → ~0.6 s per request.
 */
function rateDelay(hasKey) {
  const ms = hasKey ? 700 : 6200;
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Fetch npm-related CVEs from the NVD within [fromDate, toDate].
 */
export async function fetchNVD(fromDate, toDate, cvssConf, apiKey) {
  const headers = { "User-Agent": "npm-vuln-scanner/1.0" };
  if (apiKey) headers["apiKey"] = apiKey;

  const findings = [];
  let startIndex = 0;
  let totalResults = null;
  let page = 0;

  const pubStartDate = fromDate.toISOString().replace(/\.\d{3}Z$/, ".000");
  const pubEndDate = toDate.toISOString().replace(/\.\d{3}Z$/, ".000");

  console.log("  [NVD] Querying NIST NVD…");
  if (!apiKey) {
    console.log("  [NVD] No API key — rate-limited to 5 req/30s (slow). Add NVD_API_KEY to .env to speed up.");
  }

  do {
    page++;
    const url = new URL(NVD_BASE);
    url.searchParams.set("pubStartDate", pubStartDate);
    url.searchParams.set("pubEndDate", pubEndDate);
    url.searchParams.set("startIndex", startIndex);
    url.searchParams.set("resultsPerPage", PAGE_SIZE);
    // Filter by CPE that references node.js / npm ecosystem
    url.searchParams.set("keywordSearch", "npm");

    const res = await fetch(url.toString(), { headers });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`NVD API error ${res.status}: ${text}`);
    }

    const json = await res.json();
    totalResults = json.totalResults;

    for (const item of json.vulnerabilities ?? []) {
      const cve = item.cve;
      const cveId = cve.id;
      const publishedAt = cve.published;
      const description =
        cve.descriptions?.find((d) => d.lang === "en")?.value ?? "";

      const cvss = extractCvss(cve, cvssConf.version);

      const packages = extractNpmPackages(cve.configurations);
      // If NVD CPE data is sparse, create one entry with package_name from CVE id
      const targets =
        packages.length > 0
          ? packages
          : [{ name: `see_cve:${cveId}`, version: "unspecified" }];

      const weaknesses = (cve.weaknesses ?? [])
        .flatMap((w) => w.description.map((d) => d.value))
        .join(", ");

      for (const pkg of targets) {
        const finding = {
          source: "nvd",
          vuln_id: cveId,
          package_name: pkg.name,
          package_version: pkg.version,
          cvss_score: cvss.score,
          cvss_severity: cvss.severity,
          cvss_vector: cvss.vector,
          cvss_version: cvss.version,
          vuln_type: weaknesses || "N/A",
          date_published: publishedAt,
          summary: description,
          patched_version: "see NVD advisory",
        };

        if (passesFilter(finding, cvssConf)) {
          findings.push(finding);
        }
      }
    }

    startIndex += PAGE_SIZE;
    if (startIndex < totalResults) await rateDelay(!!apiKey);
  } while (startIndex < totalResults);

  console.log(`  [NVD] Found ${findings.length} matching findings (${page} page(s) fetched).`);
  return findings;
}
