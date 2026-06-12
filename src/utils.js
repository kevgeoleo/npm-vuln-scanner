// src/utils.js
// Shared helpers: CVSS score → severity, deduplication, output normalisation.

/**
 * Convert a numeric CVSS score to a severity label.
 * Follows the standard NVD/FIRST mapping.
 */
export function scoreToSeverity(score) {
  if (score === null || score === undefined) return "UNKNOWN";
  const n = Number(score);
  if (n >= 9.0) return "CRITICAL";
  if (n >= 7.0) return "HIGH";
  if (n >= 4.0) return "MEDIUM";
  if (n > 0) return "LOW";
  return "NONE";
}

/**
 * Returns true when a finding passes the CVSS filter from config.
 *
 * @param {object} finding  - normalised finding (must have cvss_score & cvss_severity)
 * @param {object} cvssConf - { version, minScore, severityFilter }
 */
export function passesFilter(finding, cvssConf) {
  const { minScore, severityFilter } = cvssConf;

  if (minScore !== null) {
    // Numeric threshold mode
    const score = finding.cvss_score;
    if (score === null || score === undefined) return false;
    return Number(score) >= minScore;
  }

  // Severity list mode
  if (severityFilter && severityFilter.length > 0) {
    const sev = (finding.cvss_severity ?? "UNKNOWN").toUpperCase();
    return severityFilter.includes(sev);
  }

  return true; // no filter configured
}

/**
 * Deduplicates findings across sources.
 * Key: package_name + package_version + vuln_id (advisory / CVE id).
 */
export function deduplicateFindings(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    const key = `${f.package_name}|${f.package_version}|${f.vuln_id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Formats a Date to an ISO-8601 string (UTC).
 */
export function toISO(date) {
  return date instanceof Date ? date.toISOString() : date;
}
