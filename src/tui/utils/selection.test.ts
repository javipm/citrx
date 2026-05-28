import { describe, expect, it } from "vitest";
import { addLinesToSelectionWithCap } from "./selection.js";
import type { IncidentLogLine } from "../../analysis/types.js";
import { lineKey } from "./table.js";

function line(row: number): IncidentLogLine {
  return {
    row,
    source: "access.log",
    lineNumber: row + 1,
    raw: `${row}`,
    ip: "198.51.100.10",
    timestamp: "2026-01-01T00:00:00.000Z",
    method: "GET",
    path: "/",
    target: "/",
    status: 200,
    bytes: 123,
    userAgent: "test"
  };
}

describe("addLinesToSelectionWithCap", () => {
  it("adds lines to an empty selection", () => {
    const lines = [line(1), line(2), line(3)];
    const { selection, capHit } = addLinesToSelectionWithCap(new Map(), lines, 10);
    expect(selection.size).toBe(3);
    expect(capHit).toBe(false);
    expect(selection.has(lineKey(line(1)))).toBe(true);
  });

  it("stops adding when cap is reached", () => {
    const lines = [line(1), line(2), line(3)];
    const { selection, capHit } = addLinesToSelectionWithCap(new Map(), lines, 2);
    expect(selection.size).toBe(2);
    expect(capHit).toBe(true);
  });

  it("does not add duplicates", () => {
    const l1 = line(1);
    const existing = new Map([[lineKey(l1), l1]]);
    const { selection, capHit } = addLinesToSelectionWithCap(existing, [l1, line(2)], 10);
    expect(selection.size).toBe(2);
    expect(capHit).toBe(false);
  });

  it("does not mutate the original selection", () => {
    const original = new Map();
    const { selection } = addLinesToSelectionWithCap(original, [line(1)], 10);
    expect(original.size).toBe(0);
    expect(selection.size).toBe(1);
  });

  it("reports capHit when existing selection already at cap", () => {
    const l1 = line(1);
    const existing = new Map([[lineKey(l1), l1]]);
    const { selection, capHit } = addLinesToSelectionWithCap(existing, [line(2)], 1);
    expect(selection.size).toBe(1);
    expect(capHit).toBe(true);
  });
});
