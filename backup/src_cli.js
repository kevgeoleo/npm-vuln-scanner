// src/cli.js
// Parses CLI flags from process.argv and returns a sparse overrides object.
// Only flags that are explicitly provided are included — others stay as-is from config.json.
//
// Usage examples:
//   node src/index.js --hours 5
//   node src/index.js --from 01-06-2025 --to 10-06-2025
//   node src/index.js --sources github,osv
//   node src/index.js --severity CRITICAL,HIGH,MEDIUM
//   node src/index.js --min-score 7.5
//   node src/index.js --cvss-version v3
//   node src/index.js --output results/out.json
//   node src/index.js --hours 24 --sources github,nvd --severity CRITICAL

const HELP = `
npm-vuln-scanner — CLI flags (all optional; override config.json when provided)

Time window (pick one):
  --hours  <n>              Last N hours from now           e.g. --hours 5
  --from   <DD-MM-YYYY>     Start of date range             e.g. --from 01-06-2025
  --to     <DD-MM-YYYY>     End of date range               e.g. --to 10-06-2025
             (--from and --to must be used together)

Sources:
  --sources <list>          Comma-separated source names    e.g. --sources github,osv,nvd
                            Valid: github  nvd  osv

CVSS filtering (pick one):
  --severity <list>         Comma-separated severity labels e.g. --severity CRITICAL,HIGH
                            Valid: CRITICAL  HIGH  MEDIUM  LOW
  --min-score <0.0-10.0>    Minimum numeric CVSS score      e.g. --min-score 7.5
  --cvss-version <ver>      Preferred CVSS version          e.g. --cvss-version v3
                            Valid: v3  v4  any

Output:
  --output <path>           Output file path                e.g. --output results/scan.json
  --no-pretty               Write compact (non-pretty) JSON

Other:
  --config <path>           Path to config.json             e.g. --config ./my-config.json
  --help                    Show this help message
`.trim();

const SOURCE_ALIASES = {
  github: "github_advisory",
  github_advisory: "github_advisory",
  nvd: "nvd",
  osv: "osv",
};

const VALID_SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);
const DATE_RE = /^\d{2}-\d{2}-\d{4}$/;

function die(msg) {
  console.error(`❌  CLI error: ${msg}`);
  console.error(`    Run with --help for usage.\n`);
  process.exit(1);
}

/**
 * Parse process.argv[2..] into a flat token list, then build an overrides object.
 *
 * Returns:
 * {
 *   configPath?:  string,
 *   hours?:       number,
 *   from?:        string,   // DD-MM-YYYY
 *   to?:          string,   // DD-MM-YYYY
 *   sources?:     { github_advisory: bool, nvd: bool, osv: bool },
 *   severity?:    string[],
 *   minScore?:    number,
 *   cvssVersion?: string,
 *   outputFile?:  string,
 *   noPretty?:    true,
 * }
 */
export function parseCLI(argv = process.argv.slice(2)) {
  if (argv.includes("--help") || argv.includes("-h")) {
    console.log(HELP);
    process.exit(0);
  }

  const overrides = {};
  let i = 0;

  function next(flag) {
    if (i >= argv.length || argv[i].startsWith("-")) {
      die(`--${flag} requires a value`);
    }
    return argv[i++];
  }

  while (i < argv.length) {
    const token = argv[i++];

    switch (token) {
      // ── Config path ────────────────────────────────────────────────────
      case "--config":
        overrides.configPath = next("config");
        break;

      // ── Time window ────────────────────────────────────────────────────
      case "--hours": {
        const raw = next("hours");
        const n = Number(raw);
        if (!Number.isFinite(n) || n <= 0) die(`--hours must be a positive number, got "${raw}"`);
        overrides.hours = n;
        break;
      }

      case "--from": {
        const raw = next("from");
        if (!DATE_RE.test(raw)) die(`--from expects DD-MM-YYYY, got "${raw}"`);
        overrides.from = raw;
        break;
      }

      case "--to": {
        const raw = next("to");
        if (!DATE_RE.test(raw)) die(`--to expects DD-MM-YYYY, got "${raw}"`);
        overrides.to = raw;
        break;
      }

      // ── Sources ────────────────────────────────────────────────────────
      case "--sources": {
        const raw = next("sources");
        const names = raw.split(",").map((s) => s.trim().toLowerCase());
        const resolved = { github_advisory: false, nvd: false, osv: false };
        for (const name of names) {
          const canonical = SOURCE_ALIASES[name];
          if (!canonical) die(`Unknown source "${name}". Valid: github, nvd, osv`);
          resolved[canonical] = true;
        }
        overrides.sources = resolved;
        break;
      }

      // ── CVSS ───────────────────────────────────────────────────────────
      case "--severity": {
        const raw = next("severity");
        const sevs = raw.split(",").map((s) => s.trim().toUpperCase());
        for (const s of sevs) {
          if (!VALID_SEVERITIES.has(s))
            die(`Unknown severity "${s}". Valid: CRITICAL, HIGH, MEDIUM, LOW`);
        }
        overrides.severity = sevs;
        break;
      }

      case "--min-score": {
        const raw = next("min-score");
        const n = Number(raw);
        if (!Number.isFinite(n) || n < 0 || n > 10)
          die(`--min-score must be 0.0–10.0, got "${raw}"`);
        overrides.minScore = n;
        break;
      }

      case "--cvss-version": {
        const raw = next("cvss-version").toLowerCase();
        if (!["v3", "v4", "any"].includes(raw))
          die(`--cvss-version must be v3, v4, or any — got "${raw}"`);
        overrides.cvssVersion = raw;
        break;
      }

      // ── Output ─────────────────────────────────────────────────────────
      case "--output":
        overrides.outputFile = next("output");
        break;

      case "--no-pretty":
        overrides.noPretty = true;
        break;

      default:
        die(`Unknown flag "${token}"`);
    }
  }

  // ── Cross-flag validation ──────────────────────────────────────────────
  if (overrides.hours !== undefined && (overrides.from || overrides.to)) {
    die("Use either --hours OR --from/--to, not both.");
  }

  if (
    (overrides.from !== undefined) !== (overrides.to !== undefined)
  ) {
    die("--from and --to must be used together.");
  }

  if (overrides.severity && overrides.minScore !== undefined) {
    die("Use either --severity OR --min-score, not both.");
  }

  return overrides;
}

/**
 * Apply CLI overrides on top of a loaded config object (mutates and returns it).
 * Only fields present in `overrides` are changed.
 */
export function applyOverrides(cfg, overrides) {
  // ── Time window ──────────────────────────────────────────────────────
  if (overrides.hours !== undefined) {
    cfg.toDate = new Date();
    cfg.fromDate = new Date(cfg.toDate.getTime() - overrides.hours * 60 * 60 * 1000);
  } else if (overrides.from && overrides.to) {
    cfg.fromDate = parseDate(overrides.from);
    cfg.toDate   = parseDate(overrides.to);
    cfg.toDate.setUTCHours(23, 59, 59, 999);
    if (cfg.fromDate > cfg.toDate) die("--from must be before --to");
  }

  // ── Sources ──────────────────────────────────────────────────────────
  if (overrides.sources) {
    cfg.databases = overrides.sources;
  }

  // ── CVSS ─────────────────────────────────────────────────────────────
  if (overrides.cvssVersion) {
    cfg.cvss.version = overrides.cvssVersion;
  }

  if (overrides.minScore !== undefined) {
    cfg.cvss.minScore      = overrides.minScore;
    cfg.cvss.severityFilter = null;
  } else if (overrides.severity) {
    cfg.cvss.severityFilter = overrides.severity;
    cfg.cvss.minScore       = null;
  }

  // ── Output ───────────────────────────────────────────────────────────
  if (overrides.outputFile) {
    cfg.output.file = overrides.outputFile;
  }
  if (overrides.noPretty) {
    cfg.output.pretty_print = false;
  }

  return cfg;
}

// ── Internal helpers ──────────────────────────────────────────────────────────
function parseDate(str) {
  const [dd, mm, yyyy] = str.split("-");
  const d = new Date(`${yyyy}-${mm}-${dd}T00:00:00Z`);
  if (isNaN(d.getTime())) die(`Invalid date value "${str}"`);
  return d;
}
