import { describe, expect, it } from "vitest";

import type { IncidentLogLine } from "../analysis/types.js";
import { compareLine, timestampSortValue } from "./line-compare.js";

function line(row: number, timestamp: string): IncidentLogLine {
  return {
    row,
    source: "access.log",
    lineNumber: row + 1,
    raw: "",
    ip: "203.0.113.10",
    timestamp,
    method: "GET",
    path: "/",
    target: "/",
    status: 200,
    bytes: 1,
    userAgent: "UA"
  };
}

describe("compareLine timestamp", () => {
  it("orders by epoch, with timezone offsets, then row ascending", () => {
    const laterUtc = line(0, "25/May/2026:04:00:00 +0000");
    const earlierOffset = line(1, "25/May/2026:03:00:00 +0200");
    const invalid = line(2, "not-a-date");

    expect(compareLine(earlierOffset, laterUtc, "timestamp", "asc")).toBeLessThan(0);
    expect(compareLine(laterUtc, earlierOffset, "timestamp", "desc")).toBeLessThan(0);
    expect(compareLine(invalid, laterUtc, "timestamp", "asc")).toBeGreaterThan(0);
    expect(compareLine(invalid, laterUtc, "timestamp", "desc")).toBeGreaterThan(0);
    expect(timestampSortValue("not-a-date")).toBe(Number.POSITIVE_INFINITY);

    const a = line(5, "25/May/2026:04:00:00 +0000");
    const b = line(1, "25/May/2026:04:00:00 +0000");
    expect(compareLine(a, b, "timestamp", "asc")).toBeGreaterThan(0);
  });
});
