import React from "react";
import { Box, Text } from "ink";
import type { IncidentLogLine } from "../../analysis/types.js";
import type { SortKey, SortDirection } from "../types.js";
import { fitText } from "../utils/format.js";
import { accessTableColumns, accessTableHeader, accessTableRow, lineKey } from "../utils/table.js";
import { useSpinner } from "../hooks/useSpinner.js";

export function LineTable({
  pageLines,
  pageStart,
  lineIndex,
  filter,
  sortKey,
  sortDirection,
  selectedLineKeys,
  columns,
  totalLines = 0,
  active = true,
  label = "Accesses",
  emptyMessage = "No related lines for this incident",
  loading = false,
  loadingMessage = "Loading..."
}: {
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
  loading?: boolean;
  loadingMessage?: string;
}): React.ReactElement {
  const spinner = useSpinner(loading);
  const tableColumns = accessTableColumns(columns);
  const lineCount = totalLines;
  const loadingLabel = loading ? `${spinner} ${loadingMessage}` : "";
  const visibleStart = pageLines.length > 0 ? pageStart + 1 : 0;
  const visibleEnd = pageStart + pageLines.length;
  const filterLabel = filter ? ` | filter: ${filter}` : " | filter: none";
  const baseHeader = `${label}${active ? " *" : ""}: ${lineCount} | showing: ${visibleStart}-${visibleEnd} | sort: ${sortKey} ${sortDirection}${filterLabel}`;
  const maxWidth = columns - 10;
  const fittedBase = fitText(baseHeader + (loadingLabel ? " | " : ""), maxWidth);
  const remainingWidth = Math.max(0, maxWidth - fittedBase.length);
  const fittedLoading = loadingLabel ? fitText(loadingLabel, remainingWidth) : "";

  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "single", paddingX: 1, flexGrow: 1 },
    React.createElement(
      Box,
      { flexShrink: 0 },
      React.createElement(
        Text,
        { bold: true, color: active ? "cyan" : undefined, wrap: "truncate" },
        fittedBase
      ),
      fittedLoading
        ? React.createElement(
            Text,
            { bold: true, color: "yellow", wrap: "truncate" },
            fittedLoading
          )
        : null
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
    ...tableRows({
      loading,
      loadingMessage,
      spinner,
      pageLines,
      pageStart,
      lineIndex,
      active,
      selectedLineKeys,
      tableColumns,
      emptyMessage
    })
  );
}

function tableRows({
  loading,
  loadingMessage,
  spinner,
  pageLines,
  pageStart,
  lineIndex,
  active,
  selectedLineKeys,
  tableColumns,
  emptyMessage
}: {
  loading: boolean;
  loadingMessage: string;
  spinner: string;
  pageLines: IncidentLogLine[];
  pageStart: number;
  lineIndex: number;
  active: boolean;
  selectedLineKeys: Set<string>;
  tableColumns: ReturnType<typeof accessTableColumns>;
  emptyMessage: string;
}): React.ReactElement[] {
  if (loading && pageLines.length === 0) {
    return [
      React.createElement(
        Text,
        { key: "loading", color: "yellow", bold: true },
        `${spinner} ${loadingMessage}`
      )
    ];
  }

  if (pageLines.length === 0) {
    return [React.createElement(Text, { key: "empty", color: "yellow" }, emptyMessage)];
  }

  return pageLines.map((line, offset) => {
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
  });
}
