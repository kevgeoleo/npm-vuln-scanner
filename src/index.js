// src/index.js
// Entry point — orchestrates config loading, source fetching, dedup, and output.

import "dotenv/config";
import { writeFileSync, mkdirSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { loadConfig } from "./config.js";
import { deduplicateFindings, toISO } from "./utils.js";
import { fetchGitHubAdvisories } from "./sources/github.js";
import { fetchNVD } from "./sources/nvd.js";
import { fetchOSV } from "./sources/osv.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Banner ────────────────────────────────────────────────────────────────────
console.log("╔══════════════════════════════════════════╗");
console.log("║       npm-vuln-scanner  v1.0             ║");
console.log("╚══════════════════════════════════════════╝\n");

// ── Load config ───────────────────────────────────────────────────────────────
let cfg;
try {
  cfg = loadConfig(resolve(__dirname, "../config.json"));
} catch (err) {
  console.error("❌  Config error:", err.message);
  process.exit(1);
}

console.log("⏱  Time window:");
console.log(`     From : ${toISO(cfg.fromDate)}`);
console.log(`     To   : ${toISO(cfg.toDate)}`);

const enabledSources = Object.entries(cfg.databases)
  .filter(([, v]) => v)
  .map(([k]) => k)
  .join(", ");
console.log(`\n🗄  Sources   : ${enabledSources}`);

if (cfg.cvss.minScore !== null) {
  console.log(`🔢  CVSS filter: score >= ${cfg.cvss.minScore} (version: ${cfg.cvss.version})`);
} else {
  console.log(
    `⚠️  Severity filter: ${cfg.cvss.severityFilter.join(", ")} (CVSS version: ${cfg.cvss.version})`
  );
}
console.log("");

// ── Fetch from each source ────────────────────────────────────────────────────
const allFindings = [];

try {
  if (cfg.databases.github_advisory) {
    const token = process.env.GITHUB_TOKEN || null;
    if (!token) {
      console.warn(
        "  [GitHub] ⚠️  No GITHUB_TOKEN found. Unauthenticated GraphQL has a low rate limit (60 req/hr). Add your token to .env for better reliability.\n"
      );
    }
    const results = await fetchGitHubAdvisories(
      cfg.fromDate,
      cfg.toDate,
      cfg.cvss,
      token
    );
    allFindings.push(...results);
  }

  if (cfg.databases.nvd) {
    const nvdKey = process.env.NVD_API_KEY || null;
    const results = await fetchNVD(cfg.fromDate, cfg.toDate, cfg.cvss, nvdKey);
    allFindings.push(...results);
  }

  if (cfg.databases.osv) {
    const results = await fetchOSV(cfg.fromDate, cfg.toDate, cfg.cvss);
    allFindings.push(...results);
  }
} catch (err) {
  console.error("\n❌  Fetch error:", err.message);
  process.exit(1);
}

// ── Deduplicate ───────────────────────────────────────────────────────────────
const unique = deduplicateFindings(allFindings);
console.log(`\n✅  Total findings: ${allFindings.length} (${unique.length} after deduplication)`);

// ── Build output structure ────────────────────────────────────────────────────
const output = {
  meta: {
    generated_at: new Date().toISOString(),
    time_window: {
      from: toISO(cfg.fromDate),
      to: toISO(cfg.toDate),
    },
    sources_queried: Object.entries(cfg.databases)
      .filter(([, v]) => v)
      .map(([k]) => k),
    cvss_filter: cfg.cvss.minScore !== null
      ? { mode: "min_score", value: cfg.cvss.minScore, version: cfg.cvss.version }
      : { mode: "severity", severities: cfg.cvss.severityFilter, version: cfg.cvss.version },
    total_findings: unique.length,
  },
  vulnerabilities: unique.map((f) => ({
    package_name: f.package_name,
    package_version: f.package_version,
    cvss_score: f.cvss_score,
    cvss_severity: f.cvss_severity,
    cvss_vector: f.cvss_vector ?? null,
    vuln_type: f.vuln_type,
    date_published: f.date_published,
    vuln_id: f.vuln_id,
    source: f.source,
    summary: f.summary ?? null,
    patched_version: f.patched_version ?? null,
  })),
};

// ── Write output ──────────────────────────────────────────────────────────────
const outPath = resolve(__dirname, "..", cfg.output.file);
mkdirSync(dirname(outPath), { recursive: true });

const json = cfg.output.pretty_print
  ? JSON.stringify(output, null, 2)
  : JSON.stringify(output);

writeFileSync(outPath, json, "utf8");

console.log(`\n📄  Results written to: ${outPath}`);
console.log("\nDone.\n");
