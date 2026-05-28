import type { IncidentLogLine } from "../analysis/types.js";

export type LineCompareKey = "timestamp" | "ip" | "status" | "method" | "path" | "bytes";

export function compareSortableValue(
  a: string | number,
  b: string | number,
  direction: "asc" | "desc"
): number {
  const multiplier = direction === "asc" ? 1 : -1;
  if (typeof a === "number" && typeof b === "number") {
    return (a - b) * multiplier;
  }
  return String(a).localeCompare(String(b)) * multiplier;
}

// Stable tie-break by row number, always row-ascending (stream order).
export function compareRow(a: number, b: number): number {
  return a - b;
}

export function compareLine(
  a: IncidentLogLine,
  b: IncidentLogLine,
  sortKey: LineCompareKey,
  direction: "asc" | "desc"
): number {
  let primary: number;
  if (sortKey === "bytes") {
    primary = compareSortableValue(a.bytes ?? 0, b.bytes ?? 0, direction);
  } else if (sortKey === "status") {
    primary = compareSortableValue(a.status, b.status, direction);
  } else {
    primary = compareSortableValue(String(a[sortKey]), String(b[sortKey]), direction);
  }
  return primary || compareRow(a.row, b.row);
}
