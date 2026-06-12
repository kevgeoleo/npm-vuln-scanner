# npm-vuln-scanner

A CLI tool that queries multiple vulnerability databases for **npm package vulnerabilities** within a configurable time window, filters by CVSS score or severity, and writes the results to a structured JSON file.

---

## Supported Sources

| Source | Key required? | Notes |
|--------|--------------|-------|
| **GitHub Advisory DB** | Optional (`GITHUB_TOKEN`) | Default source. Token raises rate limit from 60 to 5 000 req/hr |
| **NVD (NIST)** | Optional (`NVD_API_KEY`) | Keyword-searches CVEs for `npm`. Without key: 5 req/30 s |
| **OSV (osv.dev)** | None | Open, no auth needed |

---

## Installation

```bash
npm install
```

---

## Configuration

All settings live in **`config.json`** — no CLI flags needed.

### Time window

Use **one** of the two modes:

```jsonc
// Mode A — last N hours (here: last 24 h)
"time_window": {
  "last_hours": 24
}

// Mode B — explicit date range (inclusive)
"time_window": {
  "date_range": {
    "from": "01-01-2025",   // DD-MM-YYYY
    "to":   "31-01-2025"
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

## API Keys

Add keys to **`.env`** (never commit this file):

```dotenv
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

- **GitHub token**: https://github.com/settings/tokens (no scopes needed for public advisory data)
- **NVD API key**: https://nvd.nist.gov/developers/request-an-api-key

---

## Usage

```bash
node src/index.js
# or
npm run scan
```

---

## Output Format

`output/vulnerabilities.json`:

```jsonc
{
  "meta": {
    "generated_at": "2025-06-12T10:00:00.000Z",
    "time_window": {
      "from": "2025-06-11T10:00:00.000Z",
      "to":   "2025-06-12T10:00:00.000Z"
    },
    "sources_queried": ["github_advisory"],
    "cvss_filter": { "mode": "severity", "severities": ["CRITICAL","HIGH"], "version": "any" },
    "total_findings": 12
  },
  "vulnerabilities": [
    {
      "package_name":    "lodash",
      "package_version": "< 4.17.21",
      "cvss_score":      9.8,
      "cvss_severity":   "CRITICAL",
      "cvss_vector":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "vuln_type":       "CWE-1321",
      "date_published":  "2021-02-15T00:00:00Z",
      "vuln_id":         "GHSA-35jh-r3h4-6jhm",
      "source":          "github_advisory",
      "summary":         "Prototype Pollution in lodash",
      "patched_version": "4.17.21"
    }
  ]
}
```

---

## Project Structure

```
npm-vuln-scanner/
├── .env                   # API keys (not committed)
├── .gitignore
├── config.json            # All settings — edit this
├── package.json
├── README.md
├── output/
│   └── vulnerabilities.json   (auto-created on first run)
└── src/
    ├── index.js           # Entry point / orchestrator
    ├── config.js          # Config loader & validator
    ├── utils.js           # CVSS helpers, dedup, filters
    └── sources/
        ├── github.js      # GitHub Advisory DB (GraphQL)
        ├── nvd.js         # NIST NVD REST API v2
        └── osv.js         # OSV (osv.dev) REST API
```
