import { describe, it, expect } from "vitest";
import { applyOverrides } from "../src/cli.js";

function createConfig() {
  return {
    fromDate: null,
    toDate: null,
    databases: {
      github_advisory: true,
      nvd: false,
      osv: false,
    },
    cvss: {
      version: "any",
      minScore: null,
      severityFilter: ["HIGH"],
    },
    output: {
      file: "output.json",
      pretty_print: true,
    },
  };
}

describe("applyOverrides", () => {
  it("overrides sources", () => {
    const cfg = createConfig();

    applyOverrides(cfg, {
      sources: {
        github_advisory: false,
        nvd: true,
        osv: true,
      },
    });

    expect(cfg.databases.nvd).toBe(true);
    expect(cfg.databases.osv).toBe(true);
  });

  it("overrides severity", () => {
    const cfg = createConfig();

    applyOverrides(cfg, {
      severity: ["CRITICAL"],
    });

    expect(cfg.cvss.severityFilter).toEqual([
      "CRITICAL",
    ]);

    expect(cfg.cvss.minScore).toBeNull();
  });

  it("overrides min score", () => {
    const cfg = createConfig();

    applyOverrides(cfg, {
      minScore: 8,
    });

    expect(cfg.cvss.minScore).toBe(8);
    expect(cfg.cvss.severityFilter).toBeNull();
  });

  it("overrides output file", () => {
    const cfg = createConfig();

    applyOverrides(cfg, {
      outputFile: "results/test.json",
    });

    expect(cfg.output.file).toBe(
      "results/test.json"
    );
  });

  it("disables pretty print", () => {
    const cfg = createConfig();

    applyOverrides(cfg, {
      noPretty: true,
    });

    expect(
      cfg.output.pretty_print
    ).toBe(false);
  });
});