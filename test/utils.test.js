import {
  scoreToSeverity,
  passesFilter,
  deduplicateFindings,
} from "../src/utils.js";

import { describe, it, expect } from "vitest";

describe("scoreToSeverity", () => {
  it("maps scores correctly", () => {
    expect(scoreToSeverity(9.8)).toBe("CRITICAL");
    expect(scoreToSeverity(7.5)).toBe("HIGH");
    expect(scoreToSeverity(5.0)).toBe("MEDIUM");
    expect(scoreToSeverity(2.0)).toBe("LOW");
    expect(scoreToSeverity(0)).toBe("NONE");
  });
});

describe("passesFilter", () => {
  it("passes severity filter", () => {
    const finding = {
      cvss_severity: "HIGH",
    };

    expect(
      passesFilter(finding, {
        minScore: null,
        severityFilter: ["HIGH"],
      })
    ).toBe(true);
  });

  it("fails severity filter", () => {
    const finding = {
      cvss_severity: "LOW",
    };

    expect(
      passesFilter(finding, {
        minScore: null,
        severityFilter: ["HIGH"],
      })
    ).toBe(false);
  });

  it("passes min score filter", () => {
    const finding = {
      cvss_score: 8.5,
    };

    expect(
      passesFilter(finding, {
        minScore: 7,
        severityFilter: null,
      })
    ).toBe(true);
  });

  it("fails min score filter", () => {
    const finding = {
      cvss_score: 5,
    };

    expect(
      passesFilter(finding, {
        minScore: 7,
        severityFilter: null,
      })
    ).toBe(false);
  });
});

describe("deduplicateFindings", () => {
  it("removes duplicates", () => {
    const findings = [
      {
        package_name: "lodash",
        package_version: "1.0.0",
        vuln_id: "CVE-123",
      },
      {
        package_name: "lodash",
        package_version: "1.0.0",
        vuln_id: "CVE-123",
      },
    ];

    expect(deduplicateFindings(findings)).toHaveLength(1);
  });

  it("keeps unique findings", () => {
    const findings = [
      {
        package_name: "lodash",
        package_version: "1.0.0",
        vuln_id: "CVE-123",
      },
      {
        package_name: "express",
        package_version: "4.0.0",
        vuln_id: "CVE-999",
      },
    ];

    expect(deduplicateFindings(findings)).toHaveLength(2);
  });
});