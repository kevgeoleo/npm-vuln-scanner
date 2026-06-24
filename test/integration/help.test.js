import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";

describe("CLI help", () => {
  it("shows help", () => {
    const result = spawnSync(
      "node",
      ["src/index.js", "--help"],
      {
        encoding: "utf8",
      }
    );

    expect(result.status).toBe(0);

    expect(result.stdout).toContain(
      "npm-vuln-scanner"
    );

    expect(result.stdout).toContain(
      "--hours"
    );
  });
});