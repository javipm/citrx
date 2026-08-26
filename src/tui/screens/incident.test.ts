import { describe, expect, it } from "vitest";

import { chunkEvidence } from "./incident.js";

describe("chunkEvidence", () => {
  it("strips ANSI, OSC, and control characters from evidence pairs", () => {
    const lines = chunkEvidence(
      [
        { key: "ip", value: "\u001B[31m203.0.113.10\u001B[0m" },
        {
          key: "path",
          value: "\u001B]8;;https://evil.test\u0007/search\u001B]8;;\u0007\u0007"
        }
      ],
      80
    );

    const text = lines.join(" ");
    expect(text).not.toMatch(/\u001B/);
    expect(text).not.toMatch(/\u0007/);
    expect(text).toContain("ip=203.0.113.10");
    expect(text).toContain("path=/search");
  });
});
