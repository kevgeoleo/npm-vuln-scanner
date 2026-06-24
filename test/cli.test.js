import { describe, it, expect } from "vitest";
import { parseCLI } from "../src/cli.js";

describe("parseCLI valid arguments", () => {
  it("parses hours", () => {
    expect(
      parseCLI(["--hours", "5"])
    ).toEqual({
      hours: 5,
    });
  });

  it("parses date range", () => {
    expect(
      parseCLI([
        "--from",
        "01-06-2025",
        "--to",
        "10-06-2025",
      ])
    ).toEqual({
      from: "01-06-2025",
      to: "10-06-2025",
    });
  });

  it("parses sources", () => {
    expect(
      parseCLI([
        "--sources",
        "github,osv",
      ])
    ).toEqual({
      sources: {
        github_advisory: true,
        nvd: false,
        osv: true,
      },
    });
  });

  it("parses severity", () => {
    expect(
      parseCLI([
        "--severity",
        "CRITICAL,HIGH",
      ])
    ).toEqual({
      severity: ["CRITICAL", "HIGH"],
    });
  });

  it("parses min score", () => {
    expect(
      parseCLI([
        "--min-score",
        "7.5",
      ])
    ).toEqual({
      minScore: 7.5,
    });
  });
});

describe("parseCLI validation", () => {
  it("fails on missing hours value", () => {
    expect(() =>
      parseCLI(["--hours"])
    ).toThrow();
  });

  it("fails on invalid source", () => {
    expect(() =>
      parseCLI([
        "--sources",
        "github,bad",
      ])
    ).toThrow();
  });

  it("fails on invalid severity", () => {
    expect(() =>
      parseCLI([
        "--severity",
        "CRITICAL,BAD",
      ])
    ).toThrow();
  });

  it("fails on invalid score", () => {
    expect(() =>
      parseCLI([
        "--min-score",
        "11",
      ])
    ).toThrow();
  });

  it("fails on invalid cvss version", () => {
    expect(() =>
      parseCLI([
        "--cvss-version",
        "v2",
      ])
    ).toThrow();
  });

  it("fails when mixing hours and date range", () => {
    expect(() =>
      parseCLI([
        "--hours",
        "5",
        "--from",
        "01-06-2025",
        "--to",
        "02-06-2025",
      ])
    ).toThrow();
  });

  it("fails when from is missing to", () => {
    expect(() =>
      parseCLI([
        "--from",
        "01-06-2025",
      ])
    ).toThrow();
  });

  it("fails when severity and min score are both used", () => {
    expect(() =>
      parseCLI([
        "--severity",
        "HIGH",
        "--min-score",
        "8",
      ])
    ).toThrow();
  });
});