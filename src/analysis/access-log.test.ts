import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { analyzeAccessLogs } from "./access-log.js";

describe("access log analysis incident matches", () => {
  it("links known AI crawler incidents to matching access lines", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const logFile = join(directory, "access.log");

    await writeFile(
      logFile,
      [
        '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /robots.txt HTTP/1.1" 200 12 "-" "Claude-SearchBot/1.0"',
        '203.0.113.10 - - [25/May/2026:03:12:50 +0200] "GET /product HTTP/1.1" 200 120 "-" "Claude-SearchBot/1.0"',
        '203.0.113.11 - - [25/May/2026:03:12:51 +0200] "GET /human HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
      ].join("\n")
    );

    const report = await analyzeAccessLogs([logFile], {
      top: 5,
      format: "auto"
    });

    const incident = report.incidents.find(
      (item) => item.id === "ai_scraper_known:Claude-SearchBot"
    );
    const matches = report.incidentMatches.find(
      (item) => item.incidentId === "ai_scraper_known:Claude-SearchBot"
    );

    expect(incident).toEqual(expect.objectContaining({ severity: "info" }));
    expect(matches).toEqual(
      expect.objectContaining({
        totalMatches: 2,
        lines: [
          expect.objectContaining({ path: "/robots.txt" }),
          expect.objectContaining({ path: "/product" })
        ]
      })
    );
  });
});
