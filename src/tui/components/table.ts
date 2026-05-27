import React from "react";
import { Box, Text } from "ink";
import type { IncidentLogLine } from "../../analysis/types.js";
import type { SortKey, SortDirection } from "../types.js";
import { fitText } from "../utils/format.js";
import { accessTableColumns, accessTableHeader, accessTableRow, lineKey } from "../utils/table.js";

export function LineTable({
  lines,
  pageLines,
  pageStart,
  lineIndex,
  filter,
  sortKey,
  sortDirection,
  selectedLineKeys,
  columns,
  totalLines,
  active = true,
  label = "Accesses",
  emptyMessage = "No related lines for this incident"
}: {
  lines: IncidentLogLine[];
  pageLines: IncidentLogLine[];
  pageStart: number;
  lineIndex: number;
  filter: string;
  sortKey: SortKey;
  sortDirection: SortDirection;
  selectedLineKeys: Set<string>;
  columns: number;
  totalLines?: number;
  active?: boolean;
  label?: string;
  emptyMessage?: string;
}): React.ReactElement {
  const tableColumns = accessTableColumns(columns);
  const lineCount = totalLines ?? lines.length;
  const visibleStart = pageLines.length > 0 ? pageStart + 1 : 0;
  const visibleEnd = pageStart + pageLines.length;
  const filterLabel = filter ? ` | filter: ${filter}` : " | filter: none";

  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "single", paddingX: 1, flexGrow: 1 },
    React.createElement(
      Box,
      { flexShrink: 0 },
      React.createElement(
        Text,
        { bold: true, color: active ? "cyan" : undefined, wrap: "truncate" },
        fitText(
          `${label}${active ? " *" : ""}: ${lineCount} | showing: ${visibleStart}-${visibleEnd} | sort: ${sortKey} ${sortDirection}${filterLabel}`,
          columns - 10
        )
      )
    ),
    React.createElement(
      Box,
      { flexShrink: 0 },
      React.createElement(
        Text,
        { color: "gray", wrap: "truncate" },
        accessTableHeader(tableColumns)
      )
    ),
    ...(pageLines.length > 0
      ? pageLines.map((line, offset) => {
          const absoluteIndex = pageStart + offset;
          const rowActive = active && absoluteIndex === lineIndex;
          const selected = selectedLineKeys.has(lineKey(line));
          return React.createElement(
            Text,
            {
              key: lineKey(line),
              color: rowActive ? "black" : undefined,
              backgroundColor: rowActive ? "white" : undefined,
              wrap: "truncate"
            },
            accessTableRow(line, selected, tableColumns)
          );
        })
      : [React.createElement(Text, { key: "empty", color: "yellow" }, emptyMessage)])
  );
}
