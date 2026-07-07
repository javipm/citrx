import { describe, expect, it } from "vitest";

import type { AnalyzeReport } from "../analysis/types.js";
import { renderHtmlReport } from "./html.js";

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

describe("renderHtmlReport", () => {
  it("returns a full self-contained HTML document", () => {
    const html = renderHtmlReport(buildReport());

    expect(html).toContain("<!doctype html>");
    expect(html).toContain("<html");
    expect(html).toContain("</html>");
    expect(html).toContain("<style>");
  });

  it("includes the expected sections/headings", () => {
    const html = renderHtmlReport(buildReport());

    expect(html).toContain("<h1>citrx access log analysis</h1>");
    expect(html).toContain("<h2>Inputs</h2>");
    expect(html).toContain("<h2>Top IPs</h2>");
    expect(html).toContain("<h2>Top Paths</h2>");
    expect(html).toContain("<h2>Top User Agents</h2>");
    expect(html).toContain("<h2>Top Query Params</h2>");
    expect(html).toContain("<h2>Top Query Param Values</h2>");
    expect(html).toContain("<h2>Methods</h2>");
    expect(html).toContain("<h2>Statuses</h2>");
    expect(html).toContain("<h2>Known AI Bots</h2>");
    expect(html).toContain("<h2>Incidents</h2>");
  });

  it("renders report data values in the document", () => {
    const html = renderHtmlReport(buildReport());

    expect(html).toContain("203.0.113.10");
    expect(html).toContain("/login");
    expect(html).toContain("GPTBot");
    expect(html).toContain("SQL injection attempt");
  });

  it("omits the Known AI Bots section entirely when there are no bot stats", () => {
    const html = renderHtmlReport(buildReport({ aiBotStats: [] }));
    expect(html).not.toContain("<h2>Known AI Bots</h2>");
  });

  it("renders a no-incidents message when incidents is empty", () => {
    const html = renderHtmlReport(buildReport({ incidents: [] }));
    expect(html).toContain("<p>No incidents detected.</p>");
  });

  it("escapes a script tag and ampersand injected via a top path value", () => {
    const html = renderHtmlReport(
      buildReport({
        topPaths: [{ value: "<script>alert(1)</script>&x=1", count: 1 }]
      })
    );

    expect(html).not.toContain("<script>alert(1)</script>&x=1");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;&amp;x=1");
  });

  it("escapes a script tag and ampersand injected via a user-agent value", () => {
    const html = renderHtmlReport(
      buildReport({
        topUserAgents: [{ value: '<script>alert(1)</script> & "quoted"', count: 1 }]
      })
    );

    expect(html).not.toContain('<script>alert(1)</script> & "quoted"');
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;quoted&quot;");
  });

  it("truncates long user agent values for display only (aggregation stays untruncated upstream)", () => {
    const longUa = `Mozilla/5.0 (${"X".repeat(80)}) AppleWebKit/537.36`;
    const html = renderHtmlReport(
      buildReport({
        topUserAgents: [{ value: longUa, count: 1 }]
      })
    );

    expect(html).not.toContain(longUa);
    expect(html).toContain("…");
  });

  it("escapes injected content in incident title, category and evidence", () => {
    const html = renderHtmlReport(
      buildReport({
        incidents: [
          {
            id: "incident-xss",
            category: '<script>alert("cat")</script>',
            kind: "compromise",
            severity: "critical",
            score: 100,
            title: "<script>alert(1)</script>",
            description: "desc",
            evidence: [{ key: "payload", value: "<img src=x onerror=alert(1)>" }],
            samples: ["<script>alert(2)</script>"]
          }
        ]
      })
    );

    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).not.toContain('<script>alert("cat")</script>');
    expect(html).not.toContain("<script>alert(2)</script>");
    expect(html).not.toContain("<img src=x onerror=alert(1)>");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("does not reference any external network resources", () => {
    const html = renderHtmlReport(buildReport());

    // No external stylesheets, scripts, or images: everything is inlined.
    expect(html).not.toMatch(/<link\b/i);
    expect(html).not.toMatch(/<script\s+src=/i);
    expect(html).not.toMatch(/\bsrc="https?:\/\//i);
    expect(html).not.toMatch(/\bhref="https?:\/\//i);
    // The report itself embeds no http(s) URLs unless they come from report data.
    expect(html).not.toContain("http://");
    expect(html).not.toContain("https://");
  });
});
