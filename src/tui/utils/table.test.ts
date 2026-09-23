import { describe, expect, it } from "vitest";
import type { IncidentLogLine } from "../../analysis/types.js";
import { createAccessLogLineFilter } from "../filter.js";
import { accessTableColumns, accessTableHeader, accessTableRow } from "./table.js";

describe("access log URL column", () => {
  const line: IncidentLogLine = {
    row: 0,
    source: "access.log",
    lineNumber: 1,
    raw: "",
    ip: "192.0.2.1",
    timestamp: "2026-01-01T00:00:00.000Z",
    method: "GET",
    path: "/catalog",
    target: "/catalog?SubmitCurrency=1&token=[REDACTED]",
    status: 200,
    bytes: 123,
    userAgent: "test"
  };

  it("shows the query parameter that matches the filter, preserving redaction", () => {
    const columns = accessTableColumns(180);
    expect(createAccessLogLineFilter("param:SubmitCurrency")(line)).toBe(true);
    expect(accessTableHeader(columns)).toContain("url");
    expect(accessTableRow(line, false, columns)).toContain(line.target);
  });

  it("keeps long request URLs within the table width and marks truncation", () => {
    const columns = accessTableColumns(100);
    const row = accessTableRow(line, false, columns);
    expect(row.length).toBe(accessTableHeader(columns).length);
    expect(row).toContain("/catalog?Sub...");
  });
});
