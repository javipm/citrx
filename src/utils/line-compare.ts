import type { IncidentLogLine } from "../analysis/types.js";
import { accessLogTimestampToEpochSeconds } from "../analysis/timestamp.js";

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

/** Epoch seconds for chronological sort. Invalid timestamps sort as +Infinity. */
export function timestampSortValue(timestamp: string): number {
  return accessLogTimestampToEpochSeconds(timestamp) ?? Number.POSITIVE_INFINITY;
}

export function isInvalidTimestampValue(value: number): boolean {
  return !Number.isFinite(value);
}

/** Invalid timestamps always sort last, for both asc and desc. */
export function compareTimestampValues(a: number, b: number, direction: "asc" | "desc"): number {
  const aInvalid = isInvalidTimestampValue(a);
  const bInvalid = isInvalidTimestampValue(b);
  if (aInvalid && bInvalid) {
    return 0;
  }
  if (aInvalid) {
    return 1;
  }
  if (bInvalid) {
    return -1;
  }
  return compareSortableValue(a, b, direction);
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
  } else if (sortKey === "timestamp") {
    primary = compareTimestampValues(
      timestampSortValue(a.timestamp),
      timestampSortValue(b.timestamp),
      direction
    );
  } else {
    primary = compareSortableValue(String(a[sortKey]), String(b[sortKey]), direction);
  }
  return primary || compareRow(a.row, b.row);
}
