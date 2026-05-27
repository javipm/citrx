import type { IncidentLogLine } from "../../analysis/types.js";
import { userAgentLabel } from "../../analysis/query-params.js";
import type { AccessTableColumns, SortKey, SortDirection } from "../types.js";
import { compactDateTime, fitText } from "./format.js";

export function accessTableColumns(columns: number): AccessTableColumns {
  const tableWidth = Math.max(60, columns - 14);
  const fixed = {
    sel: 3,
    line: 6,
    time: 15,
    ip: 15,
    method: 4,
    status: 3,
    bytes: 7
  };
  const fixedTotal =
    fixed.sel + fixed.line + fixed.time + fixed.ip + fixed.method + fixed.status + fixed.bytes;
  const spaces = 8;
  const variableTotal = Math.max(16, tableWidth - fixedTotal - spaces);
  const ua = Math.min(36, Math.max(10, Math.floor(variableTotal * 0.35)));
  const path = Math.max(6, variableTotal - ua);

  return {
    ...fixed,
    path,
    ua
  };
}

export function accessTableHeader(columns: AccessTableColumns): string {
  return tableCells([
    ["sel", columns.sel],
    ["line", columns.line, "right"],
    ["time", columns.time],
    ["ip", columns.ip],
    ["meth", columns.method],
    ["st", columns.status, "right"],
    ["bytes", columns.bytes, "right"],
    ["path", columns.path],
    ["ua", columns.ua]
  ]);
}

export function accessTableRow(
  line: IncidentLogLine,
  selected: boolean,
  columns: AccessTableColumns
): string {
  return tableCells([
    [selected ? "*" : "", columns.sel],
    [String(line.lineNumber), columns.line, "right"],
    [compactDateTime(line.timestamp), columns.time],
    [line.ip, columns.ip],
    [line.method, columns.method],
    [String(line.status), columns.status, "right"],
    [String(line.bytes ?? "-"), columns.bytes, "right"],
    [line.path, columns.path],
    [userAgentLabel(line.userAgent), columns.ua]
  ]);
}

export function tableCells(cells: Array<[string, number] | [string, number, "right"]>): string {
  return cells.map(([value, width, align]) => padCell(value, width, align)).join(" ");
}

export function padCell(value: string, width: number, align?: "right"): string {
  const text = fitText(value, width);
  return align === "right" ? text.padStart(width) : text.padEnd(width);
}

export function compareLine(
  a: IncidentLogLine,
  b: IncidentLogLine,
  sortKey: SortKey,
  direction: SortDirection
): number {
  const multiplier = direction === "asc" ? 1 : -1;

  if (sortKey === "bytes") {
    return ((a.bytes ?? 0) - (b.bytes ?? 0)) * multiplier;
  }

  if (sortKey === "status") {
    return (a.status - b.status) * multiplier;
  }

  return String(a[sortKey]).localeCompare(String(b[sortKey])) * multiplier;
}

export function sortLabel(sortKey: SortKey): string {
  switch (sortKey) {
    case "timestamp":
      return "time";
    case "ip":
      return "ip";
    case "status":
      return "status";
    case "method":
      return "method";
    case "path":
      return "path";
    case "bytes":
      return "bytes";
  }
}

export function lineKey(line: IncidentLogLine): string {
  return `${line.source}:${line.lineNumber}`;
}

export function toggleSelection(current: Set<string>, line: IncidentLogLine): Set<string> {
  const next = new Set(current);
  const key = lineKey(line);

  if (next.has(key)) {
    next.delete(key);
  } else {
    next.add(key);
  }

  return next;
}
