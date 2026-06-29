# npm-vuln-scanner

A CLI tool that queries multiple vulnerability databases for **npm package vulnerabilities** within a configurable time window, filters by CVSS score or severity, and writes the results to a structured JSON file.

Settings can be defined in `config.json` and selectively overridden per-run via CLI flags.

---

## Supported Sources

| Source                 | Key required?             | Notes                                                           |
| ---------------------- | ------------------------- | --------------------------------------------------------------- |
| **GitHub Advisory DB** | Optional (`GITHUB_TOKEN`) | Default source. Token raises rate limit from 60 to 5,000 req/hr |
| **NVD (NIST)**         | Optional (`NVD_API_KEY`)  | Keyword-searches CVEs for `npm`. Without key: 5 req/30 s        |
| **OSV (osv.dev)**      | None                      | Open, no auth needed                                            |

---

## Requirements

`node v24+`

## Installation

```bash
npm install
npm link  #optional - enables user to directly call CLI tool using nvs command
```

## Test

```bash
npm test
```

---

## API Keys

Add keys to **`.env`**:

```dotenv
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

- **GitHub token**: https://github.com/settings/tokens (no scopes needed for public advisory data)
- **NVD API key**: https://nvd.nist.gov/developers/request-an-api-key

---

## Configuration

All persistent settings live in **`config.json`**. Any of them can be overridden for a single run using CLI flags — see the [CLI Flags](#cli-flags) section below.

### Time window

Use **one** of the two modes:

```jsonc
// Mode A — last N hours (here: last 24 h)
"time_window": {
  "last_hours": 24  // default - null
}

// Mode B — explicit date range (inclusive)
"time_window": {
  "date_range": {
    "from": "01-01-2025",   // DD-MM-YYYY
    "to":   "31-01-2025"    // default - null
  }
}
```

### Databases

```jsonc
"databases": {
  "github_advisory": true,   // always a good default
  "nvd": false,              // set true if you have NVD_API_KEY
  "osv": false               // free, no key needed
}
```

### CVSS filtering

```jsonc
// Option A — numeric threshold (overrides severity_filter)
"cvss": {
  "version": "any",    // "v3" | "v4" | "any"
  "min_score": 7.0     // include scores >= 7.0
}

// Option B — named severities (used when min_score is null)
"cvss": {
  "version": "any",
  "min_score": null,
  "severity_filter": ["CRITICAL", "HIGH"]
}
```

### Output

```jsonc
"output": {
  "file": "output/vulnerabilities.json",
  "pretty_print": true
}
```

---

## Usage

### Run with config.json defaults

```bash
node src/index.js
# or
npm run scan -- <options>
# or
nvs <options> # if you have run npm link to make nvs globally available
```

### Run with CLI overrides

Any flag you pass overrides the matching value in `config.json` for that run only. Flags you don't pass fall back to the config file.

```bash
# Last 5 hours instead of whatever config.json says
node src/index.js --hours 5

# Explicit date range
node src/index.js --from 01-06-2025 --to 10-06-2025

# Query github and osv, regardless of config
node src/index.js --sources github,osv

# Only critical vulns
node src/index.js --severity CRITICAL

# Numeric score threshold + specific CVSS version
node src/index.js --min-score 7.5 --cvss-version v3

# Write to a different output file
node src/index.js --output results/daily.json

# Combine freely — unspecified options still come from config.json
node src/index.js --hours 24 --sources github,osv --severity CRITICAL,HIGH

# Use a different config file entirely
node src/index.js --config ./configs/weekly.json
```

---

## CLI Flags

All flags are optional. When provided they override `config.json`; when omitted the config value is used. The console output marks overridden settings with `(CLI)` so you can see at a glance what came from where.

### Time window — pick one

| Flag                  | Value                                       | Example             |
| --------------------- | ------------------------------------------- | ------------------- |
| `--hours <n>`         | Last N hours from now                       | `--hours 5`         |
| `--from <DD-MM-YYYY>` | Start of date range                         | `--from 01-06-2025` |
| `--to <DD-MM-YYYY>`   | End of date range (must pair with `--from`) | `--to 10-06-2025`   |

### Sources

| Flag               | Value                                   | Example                |
| ------------------ | --------------------------------------- | ---------------------- |
| `--sources <list>` | Comma-separated: `github`, `nvd`, `osv` | `--sources github,osv` |

`github` is an alias for `github_advisory`.

### CVSS filtering — pick one of `--severity` / `--min-score`

| Flag                   | Value                               | Example                    |
| ---------------------- | ----------------------------------- | -------------------------- |
| `--severity <list>`    | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | `--severity CRITICAL,HIGH` |
| `--min-score <n>`      | Numeric score 0.0 – 10.0              | `--min-score 7.5`          |
| `--cvss-version <ver>` | `v3`, `v4`, or `any`                | `--cvss-version v3`        |

### Output

| Flag              | Description                   | Example                      |
| ----------------- | ----------------------------- | ---------------------------- |
| `--output <path>` | Override output file path     | `--output results/scan.json` |
| `--no-pretty`     | Write compact (minified) JSON |                              |

### Other

| Flag              | Description                   |
| ----------------- | ----------------------------- |
| `--config <path>` | Load a different config file  |
| `--help`          | Print flag reference and exit |

---

## Output Format

`output/vulnerabilities.json`:

```jsonc
{
  "meta": {
    "generated_at": "2025-06-12T10:00:00.000Z",
    "time_window": {
      "from": "2025-06-11T10:00:00.000Z",
      "to": "2025-06-12T10:00:00.000Z",
    },
    "sources_queried": ["github_advisory"],
    "cvss_filter": {
      "mode": "severity",
      "severities": ["CRITICAL", "HIGH"],
      "version": "any",
    },
    "total_findings": 12,
  },
  "vulnerabilities": [
    {
      "package_name": "lodash",
      "package_version": "< 4.17.21",
      "cvss_score": 9.8,
      "cvss_severity": "CRITICAL",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "vuln_type": "CWE-1321",
      "date_published": "2021-02-15T00:00:00Z",
      "vuln_id": "GHSA-35jh-r3h4-6jhm",
      "source": "github_advisory",
      "summary": "Prototype Pollution in lodash",
      "patched_version": "4.17.21",
    },
  ],
}
```

---

## Project Structure

```
npm-vuln-scanner/
├── .env                   # API keys (not committed)
├── .gitignore
├── config.json            # Persistent settings — edit this
├── package.json
├── README.md
├── output/
│   └── vulnerabilities.json   (auto-created on first run)
└── src/
    ├── index.js           # Entry point / orchestrator
    ├── config.js          # config.json loader & validator
    ├── cli.js             # CLI flag parser & override applier
    ├── utils.js           # CVSS helpers, dedup, filters
    └── sources/
        ├── github.js      # GitHub Advisory DB (GraphQL)
        ├── nvd.js         # NIST NVD REST API v2
        └── osv.js         # OSV (osv.dev) REST API
```
