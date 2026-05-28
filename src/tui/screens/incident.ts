import React from "react";
import { Box, Text } from "ink";
import type { AnalyzeReport, Incident, IncidentLogLine } from "../../analysis/types.js";
import type { SortKey, SortDirection } from "../types.js";
import { severityColor } from "../utils/colors.js";
import { fitText } from "../utils/format.js";
import { LineTable } from "../components/table.js";

const TIME_KEYS = new Set(["firstSeen", "lastSeen", "windowEnd", "windowApproxSeconds", "windowSeconds"]);

function extractTimeWindow(evidence: Incident["evidence"]): string | null {
  const get = (k: string) => evidence.find((e) => e.key === k)?.value;
  const firstSeen = get("firstSeen");
  const lastSeen = get("lastSeen");
  if (firstSeen || lastSeen) {
    const start = firstSeen ? String(firstSeen) : "?";
    const end = lastSeen ? String(lastSeen) : "?";
    return `Window: ${start}  →  ${end}`;
  }
  const windowEnd = get("windowEnd");
  const durationSecs =
    get("windowApproxSeconds") ?? get("windowSeconds");
  if (windowEnd) {
    if (durationSecs) {
      const endMs = Date.parse(String(windowEnd));
      if (!isNaN(endMs)) {
        const startMs = endMs - Number(durationSecs) * 1000;
        return `Window: ${new Date(startMs).toISOString()}  →  ${windowEnd}`;
      }
    }
    return `Window: ? →  ${windowEnd}`;
  }
  return null;
}

function chunkEvidence(evidence: Incident["evidence"], lineWidth: number): string[] {
  const pairs = evidence
    .filter((e) => !TIME_KEYS.has(e.key))
    .map((e) => `${e.key}=${e.value}`);

  const lines: string[] = [];
  let current = "";
  for (const pair of pairs) {
    const sep = current ? " | " : "";
    if (current && (current + sep + pair).length > lineWidth) {
      lines.push(current);
      current = pair;
    } else {
      current += sep + pair;
    }
  }
  if (current) lines.push(current);
  return lines;
}

export function IncidentScreen({
  report,
  incident,
  incidentTotal,
  pageLines,
  pageStart,
  lineIndex,
  filter,
  sortKey,
  sortDirection,
  selectedLineKeys,
  columns,
  loading,
  loadingMessage = "Loading page…"
}: {
  report: AnalyzeReport;
  incident: Incident | undefined;
  /** Total filtered rows for this incident (from useIncidentQuery). */
  incidentTotal: number;
  pageLines: IncidentLogLine[];
  pageStart: number;
  lineIndex: number;
  filter: string;
  sortKey: SortKey;
  sortDirection: SortDirection;
  selectedLineKeys: Set<string>;
  columns: number;
  loading: boolean;
  loadingMessage?: string;
}): React.ReactElement {
  const matchSet = report.incidentMatches.find((item) => item.incidentId === incident?.id);

  if (!incident) {
    return React.createElement(Text, null, "No incident selected");
  }

  const headerWidth = Math.max(40, columns - 10);
  const timeWindow = extractTimeWindow(incident.evidence);
  const evidenceLines = chunkEvidence(incident.evidence, headerWidth);

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
          `[${incident.kind.toUpperCase()}] ${incident.severity.toUpperCase()} ${incident.score}${incident.successful ? " 2XX_HIT" : ""} | ${incident.title}`,
          headerWidth
        )
      ),
      React.createElement(
        Text,
        { wrap: "truncate" },
        fitText(`${incident.id} | ${incident.category} | ${incident.kind}`, headerWidth)
      ),
      timeWindow
        ? React.createElement(
            Text,
            { color: "cyan", wrap: "truncate" },
            fitText(timeWindow, headerWidth)
          )
        : null,
      ...evidenceLines.map((line, i) =>
        React.createElement(
          Text,
          { key: `ev-${i}`, color: "gray", wrap: "truncate" },
          line
        )
      ),
      React.createElement(
        Text,
        { color: "gray", wrap: "truncate" },
        fitText(`matches=${matchSet?.totalMatches ?? 0} related requests`, headerWidth)
      )
    ),
    React.createElement(LineTable, {
      pageLines,
      pageStart,
      lineIndex,
      filter,
      sortKey,
      sortDirection,
      selectedLineKeys,
      columns,
      totalLines: incidentTotal,
      loading,
      loadingMessage
    })
  );
}
