import { describe, expect, it } from "vitest";

import type { Incident } from "../../analysis/types.js";
import { formatIncidentRowText } from "./summary.js";

function incident(overrides: Partial<Incident> = {}): Incident {
  return {
    id: "sqli:203.0.113.10",
    category: "sqli",
    kind: "compromise",
    severity: "critical",
    score: 100,
    title: "SQL injection",
    description: "payload",
    evidence: [{ key: "ip", value: "203.0.113.10" }],
    samples: [],
    ...overrides
  };
}

describe("formatIncidentRowText", () => {
  it("strips ANSI, OSC, and control characters from title and IP", () => {
    const row = formatIncidentRowText(
      incident({
        title: "\u001B[31mSQL\u001B[0m injection",
        evidence: [
          {
            key: "ip",
            value: "\u001B]8;;https://evil.test\u0007203.0.113.10\u001B]8;;\u0007\u0007"
          }
        ]
      }),
      false
    );

    expect(row).not.toMatch(/\u001B/);
    expect(row).not.toMatch(/\u0007/);
    expect(row).toContain("SQL injection");
    expect(row).toContain("203.0.113.10");
  });
});
