import { describe, expect, it } from "vitest";

import type { AnalyzeReport } from "../analysis/types.js";
import { renderMarkdownReport } from "./markdown.js";

/**
 * Minimal synthetic AnalyzeReport builder shared (by copy-paste) between
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
    aiBotStats: [
      {
        botName: "GPTBot",
        requests: 5,
        ipCount: 1,
        pathCount: 2,
        requestedRobotsTxt: true,
        firstSeen: "2026-05-25T03:00:00.000Z",
        lastSeen: "2026-05-25T03:10:00.000Z"
      }
    ],
    incidents: [
      {
        id: "incident-1",
        category: "sqli",
        kind: "compromise",
        severity: "critical",
        score: 100,
        title: "SQL injection attempt",
        description: "Detected a SQL injection payload in the request target.",
        evidence: [{ key: "payload", value: "' OR 1=1--" }],
        samples: ['203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /?id=1 OR 1=1-- HTTP/1.1" 200 100'],
        successful: true
      }
    ],
    incidentMatches: [],
    ...overrides
  };
}

describe("renderMarkdownReport", () => {
  it("includes the expected top-level headings and sections", () => {
    const markdown = renderMarkdownReport(buildReport());

    expect(markdown).toContain("# citrx access log analysis");
    expect(markdown).toContain("## Summary");
    expect(markdown).toContain("## Inputs");
    expect(markdown).toContain("## Top IPs");
    expect(markdown).toContain("## Top Paths");
    expect(markdown).toContain("## Top User Agents");
    expect(markdown).toContain("## Top Query Params");
    expect(markdown).toContain("## Top Query Param Values");
    expect(markdown).toContain("## Methods");
    expect(markdown).toContain("## Statuses");
    expect(markdown).toContain("## Known AI Bots");
    expect(markdown).toContain("## Incidents");
  });

  it("ends with a trailing newline", () => {
    const markdown = renderMarkdownReport(buildReport());
    expect(markdown.endsWith("\n")).toBe(true);
  });

  it("renders report data values in the corresponding sections", () => {
    const markdown = renderMarkdownReport(buildReport());

    expect(markdown).toContain("203.0.113.10");
    expect(markdown).toContain("/login");
    expect(markdown).toContain("GPTBot");
    expect(markdown).toContain("SQL injection attempt");
    expect(markdown).toContain("Generated: 2026-05-25T03:12:49.000Z");
  });

  it("escapes pipe characters and collapses newlines in table cells", () => {
    const report = buildReport({
      topPaths: [{ value: "/a|b\nc", count: 1 }]
    });

    const markdown = renderMarkdownReport(report);
    expect(markdown).toContain("/a\\|b c");
    expect(markdown).not.toContain("/a|b\nc");
  });

  it("renders placeholder rows when top lists and incidents are empty", () => {
    const report = buildReport({
      topIps: [],
      topPaths: [],
      topMethods: [],
      topStatuses: [],
      topUserAgents: [],
      topParams: [],
      topParamValues: [],
      aiBotStats: [],
      incidents: []
    });

    const markdown = renderMarkdownReport(report);
    expect(markdown).toContain("| 0 | none |");
    expect(markdown).toContain("| none | 0 | 0 | 0 | no |");
    expect(markdown).toContain("| info | 0 | none | No incidents detected |  |");
  });

  it("includes up to 3 sample rows per incident", () => {
    const report = buildReport({
      incidents: [
        {
          id: "incident-2",
          category: "recon",
          kind: "noise",
          severity: "low",
          score: 10,
          title: "Scanner probe",
          description: "Scanner probing for sensitive files.",
          evidence: [],
          samples: ["sample-1", "sample-2", "sample-3", "sample-4"]
        }
      ]
    });

    const markdown = renderMarkdownReport(report);
    expect(markdown).toContain("`sample-1`");
    expect(markdown).toContain("`sample-2`");
    expect(markdown).toContain("`sample-3`");
    expect(markdown).not.toContain("`sample-4`");
  });

  it("does not escape markdown/HTML content beyond pipe/newline handling (contract check)", () => {
    const report = buildReport({
      topUserAgents: [{ value: "<script>alert(1)</script> & co", count: 1 }]
    });

    const markdown = renderMarkdownReport(report);
    // Markdown renderer only escapes "|" and "\n"; raw HTML-ish text passes through as-is.
    expect(markdown).toContain("<script>alert(1)</script> & co");
  });

  it("truncates long user agent values for display only (aggregation stays untruncated upstream)", () => {
    const longUa = `Mozilla/5.0 (${"X".repeat(80)}) AppleWebKit/537.36`;
    const report = buildReport({
      topUserAgents: [{ value: longUa, count: 1 }]
    });

    const markdown = renderMarkdownReport(report);
    expect(markdown).not.toContain(longUa);
    expect(markdown).toContain("…");
  });
});
