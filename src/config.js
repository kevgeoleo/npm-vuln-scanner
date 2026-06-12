// src/config.js
// Loads, validates, and normalises config.json into a clean runtime object.

import { readFileSync } from "fs";
import { resolve } from "path";

const DATE_RE = /^(\d{2})-(\d{2})-(\d{4})$/;

function parseDDMMYYYY(str) {
  const m = DATE_RE.exec(str);
  if (!m) throw new Error(`Invalid date format "${str}" — expected DD-MM-YYYY`);
  const [, dd, mm, yyyy] = m;
  const d = new Date(`${yyyy}-${mm}-${dd}T00:00:00Z`);
  if (isNaN(d.getTime())) throw new Error(`Invalid date value "${str}"`);
  return d;
}

export function loadConfig(configPath = "config.json") {
  const raw = JSON.parse(readFileSync(resolve(configPath), "utf8"));

  // ── Time window ──────────────────────────────────────────────────────────
  const tw = raw.time_window ?? {};
  let fromDate, toDate;

  const hasLastHours =
    tw.last_hours !== undefined && tw.last_hours !== null;
  const hasRange =
    tw.date_range &&
    tw.date_range.from !== null &&
    tw.date_range.to !== null;

  if (hasLastHours && hasRange) {
    throw new Error(
      'config.json: specify either "last_hours" OR "date_range", not both.'
    );
  }

  if (hasRange) {
    fromDate = parseDDMMYYYY(tw.date_range.from);
    toDate = parseDDMMYYYY(tw.date_range.to);
    toDate.setUTCHours(23, 59, 59, 999); // inclusive end of day
    if (fromDate > toDate) throw new Error("date_range.from must be before date_range.to");
  } else if (hasLastHours) {
    const hours = Number(tw.last_hours);
    if (!Number.isFinite(hours) || hours <= 0)
      throw new Error('"last_hours" must be a positive number');
    toDate = new Date();
    fromDate = new Date(toDate.getTime() - hours * 60 * 60 * 1000);
  } else {
    throw new Error('config.json: you must specify either "last_hours" or a "date_range".');
  }

  // ── Databases ────────────────────────────────────────────────────────────
  const db = raw.databases ?? {};
  const databases = {
    github_advisory: db.github_advisory ?? true,
    nvd: db.nvd ?? false,
    osv: db.osv ?? false,
  };

  if (!Object.values(databases).some(Boolean)) {
    throw new Error("config.json: at least one database must be enabled.");
  }

  // ── CVSS ─────────────────────────────────────────────────────────────────
  const cvssRaw = raw.cvss ?? {};
  const cvssVersion = (cvssRaw.version ?? "any").toLowerCase();
  if (!["v3", "v4", "any"].includes(cvssVersion)) {
    throw new Error('config.json: cvss.version must be "v3", "v4", or "any"');
  }

  const minScore =
    cvssRaw.min_score !== undefined && cvssRaw.min_score !== null
      ? Number(cvssRaw.min_score)
      : null;

  if (minScore !== null && (minScore < 0 || minScore > 10)) {
    throw new Error("config.json: cvss.min_score must be between 0.0 and 10.0");
  }

  const VALID_SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);
  const severityFilter =
    minScore === null
      ? (cvssRaw.severity_filter ?? ["CRITICAL", "HIGH"]).map((s) =>
          s.toUpperCase()
        )
      : null;

  if (severityFilter) {
    for (const s of severityFilter) {
      if (!VALID_SEVERITIES.has(s)) {
        throw new Error(
          `config.json: unknown severity "${s}". Valid values: CRITICAL, HIGH, MEDIUM, LOW`
        );
      }
    }
  }

  // ── Output ───────────────────────────────────────────────────────────────
  const output = {
    file: raw.output?.file ?? "output/vulnerabilities.json",
    pretty_print: raw.output?.pretty_print ?? true,
  };

  return {
    fromDate,
    toDate,
    databases,
    cvss: { version: cvssVersion, minScore, severityFilter },
    output,
  };
}
