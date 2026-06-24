import { describe, it, expect } from "vitest";
import { loadConfig } from "../src/config.js";


describe("config loader", () => {

  it("loads last_hours configuration", () => {

    const cfg = loadConfig(
      "./test/configs/valid-last-hours.json"
    );

    expect(cfg.fromDate)
      .toBeInstanceOf(Date);

    expect(cfg.toDate)
      .toBeInstanceOf(Date);


    expect(cfg.databases.github_advisory)
      .toBe(true);


    expect(cfg.cvss.version)
      .toBe("any");


    expect(cfg.cvss.severityFilter)
      .toEqual([
        "CRITICAL",
        "HIGH"
      ]);
  });



  it("loads date range configuration", () => {

    const cfg = loadConfig(
      "./test/configs/valid-date-range.json"
    );


    expect(cfg.fromDate.toISOString())
      .toContain(
        "2025-06-01"
      );


    expect(cfg.toDate.toISOString())
      .toContain(
        "2025-06-10"
      );


    expect(cfg.databases.nvd)
      .toBe(true);


    expect(cfg.output.pretty_print)
      .toBe(false);

  });



  it("rejects both time modes", () => {

    expect(() =>
      loadConfig(
        "./test/configs/invalid-both-time.json"
      )
    )
    .toThrow();

  });



  it("rejects missing time configuration", () => {

    expect(() =>
      loadConfig(
        "./test/configs/invalid-no-time.json"
      )
    )
    .toThrow();

  });



  it("rejects when no database enabled", () => {

    expect(() =>
      loadConfig(
        "./test/configs/invalid-db.json"
      )
    )
    .toThrow();

  });



  it("rejects invalid CVSS version", () => {

    expect(() =>
      loadConfig(
        "./test/configs/invalid-cvss.json"
      )
    )
    .toThrow();

  });



  it("rejects invalid severity", () => {

    expect(() =>
      loadConfig(
        "./test/configs/invalid-severity.json"
      )
    )
    .toThrow();

  });

});