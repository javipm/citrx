import { describe, expect, it } from "vitest";

import type { AnalyzeReport, IncidentLogLine } from "../../analysis/types.js";
import { incidentInsights, nextTopPanel, reportInsights, topItemFilter } from "./tops.js";

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
});
