import { describe, expect, it } from "vitest";

import type { AnalyzeReport, IncidentLogLine } from "../../analysis/types.js";
import { incidentInsights, nextTopPanel, reportInsights, selectedTopValue, topItemFilter } from "./tops.js";
import { createAccessLogLineFilter } from "../filter.js";

function line(status: number, overrides: Partial<IncidentLogLine> = {}): IncidentLogLine {
  return {
    row: 0,
    source: "access.log",
    lineNumber: 1,
    raw: "",
    ip: "203.0.113.10",
    timestamp: "2026-06-02T00:00:00.000Z",
    method: "GET",
    path: "/",
    target: "/",
    status,
    bytes: 100,
    userAgent: "Mozilla/5.0",
    ...overrides
  };
}

describe("top values screen helpers", () => {
  it("counts HTTP statuses for incident insights", () => {
    expect(incidentInsights([line(200), line(403), line(403)]).statuses).toEqual([
      { value: "403", count: 2 },
      { value: "200", count: 1 }
    ]);
  });

  it("includes global HTTP statuses in report insights", () => {
    const report = {
      topIps: [],
      topPaths: [],
      topUserAgents: [],
      topStatuses: [{ value: "500", count: 3 }],
      topParams: [],
      topParamValues: []
    } as AnalyzeReport;

    expect(reportInsights(report).statuses).toEqual([{ value: "500", count: 3 }]);
  });

  it("builds status filters from status top values", () => {
    expect(topItemFilter("statuses", "404")).toBe('status="404"');
  });

  it("cycles through the status panel", () => {
    expect(nextTopPanel("userAgents")).toBe("statuses");
    expect(nextTopPanel("statuses")).toBe("params");
  });

  describe("selecting a top value builds a filter that matches the originating line", () => {
    it("matches a long, unrecognized user agent (regression: value must not be truncated)", () => {
      const longUa =
        "SomeCustomClient/1.0 (https://example.invalid/client-info; contact=ops@example.invalid) extra-suffix-past-forty-two-chars";
      const target = line(200, { userAgent: longUa });
      const other = line(200, { userAgent: "Mozilla/5.0" });
      const insights = incidentInsights([target, target, other]);

      const topItem = selectedTopValue(insights, "userAgents", 0);
      expect(topItem?.value).toBe(longUa);
      expect(topItem?.value.length).toBeGreaterThan(42);

      const filterExpr = topItemFilter("userAgents", topItem?.value ?? "");
      const matches = createAccessLogLineFilter(filterExpr);

      expect(matches(target)).toBe(true);
      expect(matches(other)).toBe(false);
    });

    it("matches a long path", () => {
      const longPath = "/wp-content/uploads/2024/01/some-very-long-file-name-that-exceeds-forty-two-characters.jpg";
      const target = line(200, { path: longPath, target: longPath });
      const other = line(200, { path: "/", target: "/" });
      const insights = incidentInsights([target, target, other]);

      const topItem = selectedTopValue(insights, "paths", 0);
      expect(topItem?.value).toBe(longPath);

      const filterExpr = topItemFilter("paths", topItem?.value ?? "");
      const matches = createAccessLogLineFilter(filterExpr);

      expect(matches(target)).toBe(true);
      expect(matches(other)).toBe(false);
    });

    it("matches a long query param value", () => {
      const longValue = "select-1-from-information_schema_tables-union-select-2-3-4-5-extra-padding-past-forty-two";
      const target = line(200, {
        target: `/search?q=${longValue}`,
        path: "/search"
      });
      const other = line(200, { target: "/search?q=camper", path: "/search" });
      const insights = incidentInsights([target, target, other]);

      const topItem = selectedTopValue(insights, "paramValues", 0);
      expect(topItem?.value).toBe(`q=${longValue}`);

      const filterExpr = topItemFilter("paramValues", topItem?.value ?? "");
      const matches = createAccessLogLineFilter(filterExpr);

      expect(matches(target)).toBe(true);
      expect(matches(other)).toBe(false);
    });
  });
});
