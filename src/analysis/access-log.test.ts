import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { analyzeAccessLogs, insertTopItem } from "./access-log.js";
import type { TopItem } from "./types.js";

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

  it("keeps all matching row numbers even when drill-down lines are sampled", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const logFile = join(directory, "access.log");
    const lines = Array.from(
      { length: 250 },
      (_, index) =>
        `203.0.113.10 - - [25/May/2026:03:${String(10 + Math.floor(index / 60)).padStart(2, "0")}:${String(index % 60).padStart(2, "0")} +0200] "GET /search?q=${index}%20UNION%20SELECT%20password HTTP/1.1" 200 120 "-" "Mozilla/5.0"`
    );

    await writeFile(logFile, lines.join("\n"));

    const report = await analyzeAccessLogs([logFile], {
      top: 5,
      format: "auto"
    });

    const matches = report.incidentMatches.find((item) => item.incidentId === "sqli:203.0.113.10");

    expect(matches).toEqual(
      expect.objectContaining({
        totalMatches: 250,
        rowNumbers: Array.from({ length: 250 }, (_, index) => index)
      })
    );
    expect(matches?.lines).toHaveLength(200);
  });

  it("normalizes stream-kind rowNumbers to monotonic ascending (rule incidents)", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const logFile = join(directory, "access.log");
    const lines = Array.from(
      { length: 10 },
      (_, i) =>
        `203.0.113.10 - - [25/May/2026:03:12:${String(i).padStart(2, "0")} +0200] "GET /search?q=${i}%20UNION%20SELECT%20password HTTP/1.1" 200 120 "-" "Mozilla/5.0"`
    );
    await writeFile(logFile, lines.join("\n"));
    const report = await analyzeAccessLogs([logFile], { top: 5, format: "auto" });
    const matches = report.incidentMatches.find((m) => m.incidentId === "sqli:203.0.113.10");
    expect(matches).toBeDefined();
    const rows = matches!.rowNumbers;
    for (let i = 1; i < rows.length; i++) {
      expect(rows[i]).toBeGreaterThanOrEqual(rows[i - 1]);
    }
  });

  it("normalizes alias-kind rowNumbers to monotonic ascending (aggregate path incidents)", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const logFile = join(directory, "access.log");
    const lines: string[] = [];
    for (let i = 0; i < 60; i++) {
      lines.push(
        `203.0.113.${i % 20} - - [25/May/2026:03:12:${String(i % 60).padStart(2, "0")} +0200] "GET /checkout HTTP/1.1" 200 1200 "-" "Mozilla/5.0"`
      );
    }
    await writeFile(logFile, lines.join("\n"));
    const report = await analyzeAccessLogs([logFile], { top: 5, format: "auto" });
    const saturationMatch = report.incidentMatches.find(
      (m) => m.incidentId.startsWith("path_saturation:") || m.incidentId.startsWith("single_path_")
    );
    // Any aggregate incident that aliases pathMatches.rowNumbers must be monotonic
    for (const m of report.incidentMatches) {
      const rows = m.rowNumbers;
      for (let i = 1; i < rows.length; i++) {
        expect(rows[i]).toBeGreaterThanOrEqual(rows[i - 1]);
      }
    }
    void saturationMatch;
  });

  it("normalizes grouped-kind rowNumbers to monotonic ascending (behavior incidents)", async () => {
    // GPTBot hits two interleaved paths → path-grouped rowNumbers would NOT be
    // monotonic without normalization: path A rows [0,2,4], path B rows [1,3,5]
    // → raw grouped = [0,2,4,1,3,5], normalized = [0,1,2,3,4,5]
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const logFile = join(directory, "access.log");
    const lines: string[] = [];
    for (let i = 0; i < 6; i++) {
      const path = i % 2 === 0 ? "/page-a" : "/page-b";
      lines.push(
        `203.0.113.10 - - [25/May/2026:03:12:${String(i).padStart(2, "0")} +0200] "GET ${path} HTTP/1.1" 200 200 "-" "GPTBot/1.0"`
      );
    }
    await writeFile(logFile, lines.join("\n"));
    const report = await analyzeAccessLogs([logFile], { top: 5, format: "auto" });
    const match = report.incidentMatches.find((m) => m.incidentId === "ai_scraper_known:GPTBot");
    expect(match).toBeDefined();
    const rows = match!.rowNumbers;
    for (let i = 1; i < rows.length; i++) {
      expect(rows[i]).toBeGreaterThanOrEqual(rows[i - 1]);
    }
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

describe("insertTopItem", () => {
  function fullTop(limit: number): TopItem[] {
    const top: TopItem[] = [];
    for (let i = 0; i < limit; i++) {
      insertTopItem(top, { value: `v${i}`, count: limit - i }, limit);
    }
    return top;
  }

  it("does not mutate a full top list when the item is not better than the last entry", () => {
    const top = fullTop(3);
    const snapshot = [...top];

    insertTopItem(top, { value: "zzz", count: 1 }, 3);

    expect(top).toEqual(snapshot);
  });

  it("displaces the last entry and pops when the item is better", () => {
    const top = fullTop(3);

    insertTopItem(top, { value: "new", count: 10 }, 3);

    expect(top).toEqual([
      { value: "new", count: 10 },
      { value: "v0", count: 3 },
      { value: "v1", count: 2 }
    ]);
    expect(top).toHaveLength(3);
  });

  it("resolves count ties by value ascending at the boundary", () => {
    // Full list with the last entry count=1, value="b". A new item with the
    // same count but a smaller value should displace it (tie-break: value asc).
    const top: TopItem[] = [
      { value: "a", count: 2 },
      { value: "b", count: 1 }
    ];

    insertTopItem(top, { value: "aa", count: 1 }, 2);

    expect(top).toEqual([
      { value: "a", count: 2 },
      { value: "aa", count: 1 }
    ]);
  });

  it("does not displace when the tie-break value is not smaller", () => {
    const top: TopItem[] = [
      { value: "a", count: 2 },
      { value: "b", count: 1 }
    ];

    insertTopItem(top, { value: "zz", count: 1 }, 2);

    expect(top).toEqual([
      { value: "a", count: 2 },
      { value: "b", count: 1 }
    ]);
  });
});
