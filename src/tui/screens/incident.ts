import React from "react";
import { Box, Text } from "ink";
import type { AnalyzeReport, Incident, IncidentLogLine } from "../../analysis/types.js";
import type { SortKey, SortDirection } from "../types.js";
import { severityColor } from "../utils/colors.js";
import { fitText } from "../utils/format.js";
import { LineTable } from "../components/table.js";

export function IncidentScreen({
  report,
  incident,
  lines,
  pageLines,
  pageStart,
  lineIndex,
  filter,
  sortKey,
  sortDirection,
  selectedLineKeys,
  columns
}: {
  report: AnalyzeReport;
  incident: Incident | undefined;
  lines: IncidentLogLine[];
  pageLines: IncidentLogLine[];
  pageStart: number;
  lineIndex: number;
  filter: string;
  sortKey: SortKey;
  sortDirection: SortDirection;
  selectedLineKeys: Set<string>;
  columns: number;
}): React.ReactElement {
  const matchSet = report.incidentMatches.find((item) => item.incidentId === incident?.id);

  if (!incident) {
    return React.createElement(Text, null, "No incident selected");
  }

  const headerWidth = Math.max(40, columns - 10);

  return React.createElement(
    Box,
    { flexDirection: "column", flexGrow: 1 },
    React.createElement(
      Box,
      { flexDirection: "column", borderStyle: "single", paddingX: 1 },
      React.createElement(
        Text,
        { bold: true, color: severityColor(incident.severity), wrap: "truncate" },
        fitText(
          `[${incident.kind.toUpperCase()}] ${incident.severity.toUpperCase()} ${incident.score}${incident.successful ? " !SUCCESS" : ""} | ${incident.title}`,
          headerWidth
        )
      ),
      React.createElement(
        Text,
        { wrap: "truncate" },
        fitText(`${incident.id} | ${incident.category} | ${incident.kind}`, headerWidth)
      ),
      React.createElement(
        Text,
        { color: "gray", wrap: "truncate" },
        fitText(
          incident.evidence.map((item) => `${item.key}=${item.value}`).join(" | "),
          headerWidth
        )
      ),
      React.createElement(
        Text,
        { color: "gray", wrap: "truncate" },
        fitText(`matches=${matchSet?.totalMatches ?? 0} related requests`, headerWidth)
      )
    ),
    React.createElement(LineTable, {
      lines,
      pageLines,
      pageStart,
      lineIndex,
      filter,
      sortKey,
      sortDirection,
      selectedLineKeys,
      columns
    })
  );
}
