import React from "react";
import { Box, Text } from "ink";
import type { AnalyzeReport, Incident, IncidentLogLine } from "../../analysis/types.js";
import type { SummaryFocus, SortKey, SortDirection } from "../types.js";
import { severityColor } from "../utils/colors.js";
import { formatBytes, truncate } from "../utils/format.js";
import { LineTable } from "../components/table.js";

export function SummaryScreen({
  report,
  incidents,
  incidentIndex,
  focus,
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
  loading
}: {
  report: AnalyzeReport;
  incidents: Incident[];
  incidentIndex: number;
  focus: SummaryFocus;
  lines: IncidentLogLine[];
  pageLines: IncidentLogLine[];
  pageStart: number;
  lineIndex: number;
  filter: string;
  sortKey: SortKey;
  sortDirection: SortDirection;
  selectedLineKeys: Set<string>;
  columns: number;
  totalLines: number;
  loading: boolean;
}): React.ReactElement {
  return React.createElement(
    Box,
    { flexDirection: "column", flexGrow: 1 },
    React.createElement(
      Box,
      { flexDirection: "row", gap: 1 },
      React.createElement(SummaryPanel, { report }),
      React.createElement(IncidentList, {
        incidents,
        incidentIndex,
        pageSize: 7,
        focus
      })
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
      columns,
      totalLines,
      active: focus === "accesses",
      label: "Access log",
      emptyMessage: "No indexed access-log lines",
      loading,
      loadingMessage: "Loading access-log results..."
    })
  );
}

function SummaryPanel({ report }: { report: AnalyzeReport }) {
  const formats = [...new Set(report.inputFormats.map((item) => item.format))].join(", ");
  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "single", paddingX: 1, width: 54 },
    React.createElement(Text, { bold: true }, "Analysis"),
    React.createElement(
      Text,
      null,
      `inputs: ${report.inputs.length} | formats: ${formats || "unknown"}`
    ),
    React.createElement(
      Text,
      null,
      `lines: ${report.summary.parsedLines}/${report.summary.totalLines} parsed | invalid: ${report.summary.invalidLines}`
    ),
    React.createElement(Text, null, `bytes served: ${formatBytes(report.summary.totalBytes)}`),
    React.createElement(Text, null, `peak rps: ${report.timeStats.peakGlobalRps}`),
    React.createElement(Text, null, `indexed lines: ${report.accessLog.indexedLines}`),
    React.createElement(Text, { color: "gray" }, "press t for global top values")
  );
}

function IncidentRow({
  incident,
  index,
  incidentIndex,
  active
}: {
  incident: Incident;
  index: number;
  incidentIndex: number;
  active: boolean;
}) {
  const selected = active && index === incidentIndex;
  const successMark = incident.successful ? " 2XX_HIT" : "";
  const ip = incident.evidence.find((item) => item.key === "ip")?.value;
  const ipTag = ip ? ` ${String(ip)}` : "";
  return React.createElement(
    Text,
    {
      key: incident.id,
      color: selected ? "black" : severityColor(incident.severity),
      backgroundColor: selected ? "cyan" : undefined,
      wrap: "truncate"
    },
    `${selected ? ">" : " "} ${incident.severity.padEnd(8)} ${String(incident.score).padStart(3)}${successMark}${ipTag} ${truncate(incident.title, 40)}`
  );
}

function IncidentTabHeader({
  compromiseCount,
  saturationCount,
  noiseCount,
  focus
}: {
  compromiseCount: number;
  saturationCount: number;
  noiseCount: number;
  focus: SummaryFocus;
}) {
  const tab = (label: string, count: number, isActive: boolean, color: string) =>
    React.createElement(Text, { color, bold: true, inverse: isActive }, `[${label} ${count}]`);

  return React.createElement(
    Box,
    { flexShrink: 0 },
    React.createElement(
      Text,
      null,
      tab("SATURATION", saturationCount, focus === "saturation", "yellow"),
      "  ",
      tab("SECURITY", compromiseCount, focus === "compromise", "red"),
      ...(noiseCount > 0 ? ["  ", tab("OTHER", noiseCount, focus === "noise", "gray")] : [])
    )
  );
}

export function IncidentList({
  incidents,
  incidentIndex,
  pageSize,
  focus
}: {
  incidents: Incident[];
  incidentIndex: number;
  pageSize: number;
  focus: SummaryFocus;
}): React.ReactElement {
  const compromise = incidentItemsByKind(incidents, "compromise");
  const saturation = incidentItemsByKind(incidents, "saturation");
  const noise = incidentItemsByKind(incidents, "noise");

  const focusedKind: "compromise" | "saturation" | "noise" | null =
    focus === "accesses" ? null : focus;

  const focusedList =
    focusedKind === "compromise"
      ? compromise
      : focusedKind === "saturation"
        ? saturation
        : focusedKind === "noise"
          ? noise
          : saturation.length > 0
            ? saturation
            : compromise.length > 0
              ? compromise
              : noise;

  const isPanelActive = focus !== "accesses";
  const focusedCursor = focusedList.findIndex((item) => item.index === incidentIndex);
  const localCursor = isPanelActive ? Math.max(0, focusedCursor) : 0;
  const sliceStart = Math.max(
    0,
    Math.min(localCursor - Math.floor(pageSize / 2), Math.max(0, focusedList.length - pageSize))
  );

  const titleColor =
    focusedKind === "compromise"
      ? "red"
      : focusedKind === "saturation"
        ? "yellow"
        : focusedKind === "noise"
          ? "gray"
          : "cyan";
  const titleLabel =
    focusedKind === "compromise"
      ? "Security incidents (attacks)"
      : focusedKind === "saturation"
        ? "Saturation incidents (traffic abuse)"
        : focusedKind === "noise"
          ? "Other (informational)"
          : "Incidents (press Tab to focus)";

  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "single", paddingX: 1, flexGrow: 1 },
    React.createElement(IncidentTabHeader, {
      compromiseCount: compromise.length,
      saturationCount: saturation.length,
      noiseCount: noise.length,
      focus
    }),
    React.createElement(
      Text,
      { bold: true, color: titleColor },
      `${titleLabel}${isPanelActive ? " *" : ""}`
    ),
    ...(focusedList.length > 0
      ? focusedList.slice(sliceStart, sliceStart + pageSize).map((item) =>
          React.createElement(IncidentRow, {
            key: item.incident.id,
            incident: item.incident,
            index: item.index,
            incidentIndex,
            active: isPanelActive
          })
        )
      : [
          React.createElement(
            Text,
            { key: "empty", color: "gray" },
            "  (no incidents in this category)"
          )
        ])
  );
}

function incidentItemsByKind(
  incidents: Incident[],
  kind: Incident["kind"]
): Array<{ incident: Incident; index: number }> {
  return incidents
    .map((incident, index) => ({ incident, index }))
    .filter((item) => item.incident.kind === kind);
}
