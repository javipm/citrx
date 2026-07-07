import { describe, expect, it } from "vitest";

import type { AnalyzeReport } from "../analysis/types.js";
import { renderTerminalReport } from "./terminal.js";

/**
 * Minimal synthetic AnalyzeReport builder shared (by copy-paste) with
 * markdown.test.ts and html.test.ts. All data is synthetic/fixture-only.
 */
function buildReport(overrides: Partial<AnalyzeReport> = {}): AnalyzeReport {
  return {
    app: "citrx",
    phase: 1,
    status: "ok",
    generatedAt: "2026-05-25T03:12:49.000Z",
    inputs: ["access.log"],
    inputFormats: [
      {
        file: "access.log",
        format: "apache_combined",
        sampledLines: 10,
        parsedSampleLines: 10,
        sampleParseRatio: 1
      }
    ],
    summary: {
      files: 1,
      totalLines: 10,
      parsedLines: 10,
      filteredLines: 0,
      invalidLines: 0,
      totalBytes: 4096
    },
    topIps: [{ value: "203.0.113.10", count: 5 }],
    topPaths: [{ value: "/login", count: 3 }],
    topMethods: [{ value: "GET", count: 8 }],
    topStatuses: [{ value: "200", count: 8 }],
    topUserAgents: [{ value: "Mozilla/5.0", count: 4 }],
    topParams: [{ value: "q", count: 2 }],
    topParamValues: [{ value: "test", count: 1 }],
    accessLog: {
      totalLines: 10,
      indexedLines: 10
    },
    timeStats: {
      firstSeen: "2026-05-25T03:00:00.000Z",
      lastSeen: "2026-05-25T03:12:49.000Z",
      peakGlobalRps: 12,
      peakGlobalRpsAt: "2026-05-25T03:05:00.000Z",
      globalRpsP95: 6,
      invalidTimestampLines: 0,
      outOfOrderTimestamps: 0,
      droppedIpCount: 0,
      droppedSubnetCount: 0
    },
    ipBehaviorStats: [],
    aiBotStats: [],
    incidents: [],
    incidentMatches: [],
    ...overrides
  };
}

describe("renderTerminalReport", () => {
  it("renders top-value sections", () => {
    const report = renderTerminalReport(buildReport(), { color: false });

    expect(report).toContain("Top IPs");
    expect(report).toContain("Top user agents");
    expect(report).toContain("203.0.113.10");
    expect(report).toContain("Mozilla/5.0");
  });

  it("truncates long user agent values for display only (aggregation stays untruncated upstream)", () => {
    const longUa = `Mozilla/5.0 (${"X".repeat(80)}) AppleWebKit/537.36`;
    const report = renderTerminalReport(
      buildReport({
        topUserAgents: [{ value: longUa, count: 1 }]
      }),
      { color: false }
    );

    expect(report).not.toContain(longUa);
    expect(report).toContain("…");
  });

  it("does not truncate long path values (only user agents are display-truncated today)", () => {
    const longPath = `/${"a".repeat(100)}`;
    const report = renderTerminalReport(
      buildReport({
        topPaths: [{ value: longPath, count: 1 }]
      }),
      { color: false }
    );

    expect(report).toContain(longPath);
  });
});
