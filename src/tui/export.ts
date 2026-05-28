import type { Incident, IncidentLogLine } from "../analysis/types.js";
import type { ExportFormat } from "./types.js";

const DELIMITED_COLUMNS: Array<{
  key: string;
  value: (line: IncidentLogLine) => string | number | null;
}> = [
  { key: "row", value: (line) => line.row },
  { key: "source", value: (line) => line.source },
  { key: "lineNumber", value: (line) => line.lineNumber },
  { key: "timestamp", value: (line) => line.timestamp },
  { key: "ip", value: (line) => line.ip },
  { key: "method", value: (line) => line.method },
  { key: "target", value: (line) => line.target },
  { key: "path", value: (line) => line.path },
  { key: "status", value: (line) => line.status },
  { key: "bytes", value: (line) => line.bytes },
  { key: "userAgent", value: (line) => line.userAgent },
  { key: "raw", value: (line) => line.raw }
];

export function serializeExport(
  incident: Incident | undefined,
  lines: IncidentLogLine[],
  format: ExportFormat
): string {
  if (format === "json") {
    return `${JSON.stringify({ incident, lines }, null, 2)}\n`;
  }

  const separator = format === "csv" ? "," : "\t";
  const rows = [
    DELIMITED_COLUMNS.map((column) => escapeDelimitedCell(column.key, separator)).join(separator),
    ...lines.map((line) =>
      DELIMITED_COLUMNS.map((column) => escapeDelimitedCell(column.value(line), separator)).join(
        separator
      )
    )
  ];

  return `${rows.join("\n")}\n`;
}

function escapeDelimitedCell(value: string | number | null, separator: string): string {
  const text = value === null ? "" : String(value);

  if (
    text.includes('"') ||
    text.includes("\n") ||
    text.includes("\r") ||
    text.includes(separator)
  ) {
    return `"${text.replaceAll('"', '""')}"`;
  }

  return text;
}
