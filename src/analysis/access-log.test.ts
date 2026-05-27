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
        rowNumbers: [0, 1],
        lines: [
          expect.objectContaining({ row: 0, path: "/robots.txt" }),
          expect.objectContaining({ row: 1, path: "/product" })
        ]
      })
    );
  });

  it("links saturation AI crawler incidents only to materially served lines", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const logFile = join(directory, "access.log");
    const lines: string[] = [];

    for (let minute = 0; minute < 3; minute += 1) {
      for (let index = 0; index < 120; index += 1) {
        lines.push(
          `203.0.113.10 - - [25/May/2026:03:${String(12 + minute).padStart(2, "0")}:00 +0200] "GET /served-${minute}-${index} HTTP/1.1" 200 120 "-" "GPTBot/1.0"`
        );
      }
    }

    for (let index = 0; index < 20; index += 1) {
      lines.push(
        `203.0.113.10 - - [25/May/2026:03:20:00 +0200] "GET /blocked-${index} HTTP/1.1" 403 12 "-" "GPTBot/1.0"`
      );
    }

    await writeFile(logFile, lines.join("\n"));

    const report = await analyzeAccessLogs([logFile], {
      top: 5,
      format: "auto"
    });

    const incident = report.incidents.find((item) => item.id === "ai_scraper_known:GPTBot");
    const matches = report.incidentMatches.find(
      (item) => item.incidentId === "ai_scraper_known:GPTBot"
    );

    expect(incident).toEqual(expect.objectContaining({ kind: "saturation" }));
    expect(matches).toEqual(
      expect.objectContaining({
        totalMatches: 360
      })
    );
    expect(matches?.lines.every((line) => line.status === 200)).toBe(true);
  });

  it("builds exact top user-agent and query parameter lists", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const logFile = join(directory, "access.log");

    await writeFile(
      logFile,
      [
        '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /search?q=camper&token=secret HTTP/1.1" 200 12 "-" "Mozilla/5.0"',
        '203.0.113.11 - - [25/May/2026:03:12:50 +0200] "GET /search?q=camper HTTP/1.1" 200 120 "-" "Mozilla/5.0"',
        '203.0.113.12 - - [25/May/2026:03:12:51 +0200] "GET /search?page=2 HTTP/1.1" 200 100 "-" "curl/8.0"'
      ].join("\n")
    );

    const report = await analyzeAccessLogs([logFile], {
      top: 5,
      format: "auto"
    });

    expect(report.topUserAgents).toContainEqual({ value: "Mozilla/5.0", count: 2 });
    expect(report.topParams).toEqual([
      { value: "q", count: 2 },
      { value: "page", count: 1 },
      { value: "token", count: 1 }
    ]);
    expect(report.topParamValues).toContainEqual({ value: "token=<redacted>", count: 1 });
    expect(report.topParamValues).toContainEqual({ value: "q=camper", count: 2 });
  });
});
