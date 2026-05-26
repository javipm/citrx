import { describe, expect, it } from "vitest";

import type { AnalyzeReport, Incident } from "../analysis/types.js";
import {
  OpenAiIncidentQuestionClient,
  buildAiContext,
  parseMaxChars,
  parseMaxLines
} from "./incident-question.js";

const incident: Incident = {
  id: "sqli:/search",
  category: "sql_injection",
  severity: "critical",
  score: 95,
  title: "SQL injection payload",
  description: "Request target contains SQL injection indicators.",
  evidence: [{ key: "path", value: "/search" }],
  samples: ["/search?q=union"]
};

const report: AnalyzeReport = {
  app: "citrx",
  phase: 1,
  status: "ok",
  generatedAt: "2026-05-25T00:00:00.000Z",
  inputs: ["/tmp/access.log"],
  inputFormats: [],
  summary: {
    files: 1,
    totalLines: 2,
    parsedLines: 2,
    filteredLines: 0,
    invalidLines: 0,
    totalBytes: 20
  },
  topIps: [{ value: "203.0.113.10", count: 2 }],
  topPaths: [{ value: "/search", count: 2 }],
  topMethods: [{ value: "GET", count: 2 }],
  topStatuses: [{ value: "200", count: 2 }],
  accessLog: {
    totalLines: 2,
    indexedLines: 0
  },
  timeStats: {
    firstSeen: "2026-05-25T00:00:00.000Z",
    lastSeen: "2026-05-25T00:00:01.000Z",
    peakGlobalRps: 2,
    peakGlobalRpsAt: "2026-05-25T00:00:00.000Z",
    globalRpsP95: 2,
    invalidTimestampLines: 0,
    outOfOrderTimestamps: 0,
    droppedIpCount: 0,
    droppedSubnetCount: 0
  },
  ipBehaviorStats: [],
  aiBotStats: [],
  incidents: [incident],
  incidentMatches: []
};

describe("OpenAI incident questions", () => {
  it("requires OPENAI_API_KEY", async () => {
    const client = new OpenAiIncidentQuestionClient(async () => ({
      output_text: "unused"
    }));

    await expect(
      client.ask({
        report,
        incident,
        lines: [],
        question: "What happened?",
        env: {}
      })
    ).rejects.toThrow("OPENAI_API_KEY is required");
  });

  it("limits lines sent to OpenAI and returns renderable text", async () => {
    let payload = "";
    const client = new OpenAiIncidentQuestionClient(async (body) => {
      payload = body.input;
      return {
        output_text: "Likely SQLi scan. Consider blocking the payload pattern."
      };
    });

    const result = await client.ask({
      report,
      incident,
      lines: [
        {
          source: "/tmp/access.log",
          lineNumber: 1,
          raw: "line 1",
          ip: "203.0.113.10",
          timestamp: "25/May/2026:03:12:49 +0200",
          method: "GET",
          path: "/search",
          target: "/search?q=union",
          status: 200,
          bytes: 10,
          userAgent: "Mozilla/5.0"
        },
        {
          source: "/tmp/access.log",
          lineNumber: 2,
          raw: "line 2",
          ip: "203.0.113.11",
          timestamp: "25/May/2026:03:12:50 +0200",
          method: "GET",
          path: "/search",
          target: "/search?q=union",
          status: 200,
          bytes: 10,
          userAgent: "Mozilla/5.0"
        }
      ],
      question: "What WAF rule should I use?",
      env: {
        OPENAI_API_KEY: "test-key",
        CITRX_AI_MAX_LINES: "1",
        CITRX_OPENAI_MODEL: "gpt-5.4-mini"
      }
    });

    expect(result).toEqual({
      answer: "Likely SQLi scan. Consider blocking the payload pattern.",
      model: "gpt-5.4-mini",
      sentLines: 1,
      sentChars: expect.any(Number)
    });
    expect(JSON.parse(payload)).toMatchObject({
      question: "What WAF rule should I use?",
      lines: [expect.stringContaining("1|")]
    });
    expect(payload).not.toContain("raw");
  });

  it("defaults invalid max lines to 200", () => {
    expect(parseMaxLines("-1")).toBe(200);
    expect(parseMaxLines("nope")).toBe(200);
    expect(parseMaxLines("25")).toBe(25);
  });

  it("builds compact summary context without raw log lines", () => {
    const context = buildAiContext(
      {
        report,
        lines: [],
        question: "What should I check?",
        env: {},
        scope: "summary"
      },
      200,
      60000
    );
    const payload = JSON.parse(context.payload);

    expect(payload).toMatchObject({
      scope: "summary",
      question: "What should I check?",
      top: {
        ips: ["203.0.113.10:2"]
      }
    });
    expect(context.sentLines).toBe(0);
  });

  it("deduplicates user agents and honors max char budget", () => {
    const context = buildAiContext(
      {
        report,
        incident,
        lines: Array.from({ length: 10 }, (_, index) => ({
          source: "/tmp/access.log",
          lineNumber: index + 1,
          raw: `raw line ${index + 1}`,
          ip: "203.0.113.10",
          timestamp: "25/May/2026:03:12:49 +0200",
          method: "GET",
          path: "/search",
          target: `/search?q=${index}`,
          status: 200,
          bytes: 10,
          userAgent: "Mozilla/5.0 Very Long Shared UA"
        })),
        question: "What WAF rule should I use?",
        env: {},
        scope: "incident"
      },
      10,
      1200
    );
    const payload = JSON.parse(context.payload);

    expect(context.payload.length).toBeLessThanOrEqual(1200);
    expect(payload.userAgents).toEqual({ ua1: "Mozilla/5.0 Very Long Shared UA" });
    expect(payload.lines.every((line: string) => line.endsWith("|ua1"))).toBe(true);
    expect(context.payload).not.toContain("raw line");
  });

  it("defaults invalid max chars to 60000", () => {
    expect(parseMaxChars("999")).toBe(60000);
    expect(parseMaxChars("nope")).toBe(60000);
    expect(parseMaxChars("5000")).toBe(5000);
  });
});
