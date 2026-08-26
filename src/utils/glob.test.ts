import { describe, expect, it } from "vitest";

import { matchesGlob } from "./glob.js";

describe("matchesGlob", () => {
  it("matches a basename *.log pattern in any directory", () => {
    expect(matchesGlob("/tmp/logs/access.log", "*.log")).toBe(true);
    expect(matchesGlob("/tmp/logs/access.txt", "*.log")).toBe(false);
  });

  it("matches **/*.gz across directories", () => {
    expect(matchesGlob("/var/log/nginx/access.log.gz", "**/*.gz")).toBe(true);
    expect(matchesGlob("/var/log/nginx/access.log", "**/*.gz")).toBe(false);
  });

  it("matches a path suffix such as logs/*.log", () => {
    expect(matchesGlob("/abs/site/logs/access.log", "logs/*.log")).toBe(true);
    expect(matchesGlob("/abs/site/other/access.log", "logs/*.log")).toBe(false);
  });

  it("supports ? as a single non-slash character", () => {
    expect(matchesGlob("access.log", "access.lo?")).toBe(true);
    expect(matchesGlob("access/loX", "access.lo?")).toBe(false);
  });
});
