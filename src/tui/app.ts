import React, { useMemo, useState } from "react";
import { Box, Text, render, useApp, useInput, useWindowSize } from "ink";
import { input } from "@inquirer/prompts";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import type { Readable, Writable } from "node:stream";

import type { AnalyzeReport, Incident, IncidentLogLine, TopItem } from "../analysis/types.js";
import { OpenAiIncidentQuestionClient } from "../ai/incident-question.js";
import type { IncidentQuestionClient } from "../ai/incident-question.js";
import type { CitrxSession } from "../session/types.js";

export interface TuiRuntime {
  env: NodeJS.ProcessEnv;
  stdin: Readable;
  stdout: Writable;
  stderr: Writable;
  aiClient?: IncidentQuestionClient;
}

type Screen = "summary" | "incident";
type SortKey = "timestamp" | "ip" | "status" | "method" | "path" | "bytes";
type SortDirection = "asc" | "desc";

const PAGE_SIZE = 14;

export async function openSessionTui(
  session: CitrxSession,
  runtime: TuiRuntime
): Promise<void> {
  const instance = render(
    React.createElement(CitrxExplorer, {
      session,
      runtime
    }),
    {
      stdin: runtime.stdin as NodeJS.ReadStream,
      stdout: runtime.stdout as NodeJS.WriteStream,
      stderr: runtime.stderr as NodeJS.WriteStream,
      alternateScreen: true
    }
  );

  await instance.waitUntilExit();
}

function CitrxExplorer({
  session,
  runtime
}: {
  session: CitrxSession;
  runtime: TuiRuntime;
}) {
  const { exit } = useApp();
  const { rows, columns } = useWindowSize();
  const [screen, setScreen] = useState<Screen>("summary");
  const [incidentIndex, setIncidentIndex] = useState(0);
  const [lineIndex, setLineIndex] = useState(0);
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [selectedLineKeys, setSelectedLineKeys] = useState<Set<string>>(new Set());
  const [message, setMessage] = useState("Ready");
  const [busy, setBusy] = useState(false);
  const incidents = session.report.incidents;
  const incident = incidents[incidentIndex];
  const allIncidentLines = useMemo(
    () => incidentLines(session.report, incident?.id),
    [session.report, incident?.id]
  );
  const lines = useMemo(
    () => visibleLines(allIncidentLines, filter, sortKey, sortDirection),
    [allIncidentLines, filter, sortKey, sortDirection]
  );
  const selectedLines = useMemo(
    () => lines.filter((line) => selectedLineKeys.has(lineKey(line))),
    [lines, selectedLineKeys]
  );
  const pageStart = Math.max(0, Math.min(lineIndex - Math.floor(PAGE_SIZE / 2), Math.max(0, lines.length - PAGE_SIZE)));
  const pageLines = lines.slice(pageStart, pageStart + PAGE_SIZE);

  useInput((inputValue, key) => {
    if (inputValue === "q" || (screen === "summary" && key.escape)) {
      exit();
      return;
    }

    if ((inputValue === "b" || key.backspace || key.escape) && screen === "incident") {
      setScreen("summary");
      setMessage("Back to summary");
      return;
    }

    if (screen === "summary") {
      if (key.upArrow) {
        setIncidentIndex((value) => Math.max(0, value - 1));
        return;
      }

      if (key.downArrow) {
        setIncidentIndex((value) => Math.min(incidents.length - 1, value + 1));
        return;
      }

      if (key.return && incident) {
        setScreen("incident");
        setLineIndex(0);
        setFilter("");
        setSelectedLineKeys(new Set());
        setMessage(`Opened ${incident.id}`);
        return;
      }

      if (inputValue === "a") {
        void askOpenAi({
          session,
          runtime,
          scope: "summary",
          lines: [],
          setBusy,
          setMessage
        });
      }

      return;
    }

    if (key.upArrow) {
      setLineIndex((value) => Math.max(0, value - 1));
      return;
    }

    if (key.downArrow) {
      setLineIndex((value) => Math.min(lines.length - 1, value + 1));
      return;
    }

    if (inputValue === "s") {
      setSortKey(nextSort(sortKey));
      setLineIndex(0);
      return;
    }

    if (key.tab) {
      setSortDirection((value) => (value === "desc" ? "asc" : "desc"));
      setLineIndex(0);
      return;
    }

    if (inputValue === " ") {
      const line = lines[lineIndex];
      if (line) {
        setSelectedLineKeys((current) => toggleSelection(current, line));
      }
      return;
    }

    if (inputValue === "A") {
      setSelectedLineKeys(new Set(lines.map(lineKey)));
      setMessage(`Selected ${lines.length} visible lines`);
      return;
    }

    if (inputValue === "r") {
      setFilter("");
      setLineIndex(0);
      setSelectedLineKeys(new Set());
      setMessage("Filter and selection reset");
      return;
    }

    if (inputValue === "/") {
      void promptFilter().then((value) => {
        setFilter(value);
        setLineIndex(0);
        setSelectedLineKeys(new Set());
        setMessage(value ? `Filter: ${value}` : "Filter cleared");
      });
      return;
    }

    if (inputValue === "e") {
      const exportable = selectedLines.length > 0 ? selectedLines : lines;
      void exportContext(session.id, incident, exportable).then((file) => {
        setMessage(`Exported ${exportable.length} lines to ${file}`);
      });
      return;
    }

    if (inputValue === "a") {
      void askOpenAi({
        session,
        runtime,
        scope: "incident",
        incident,
        lines: selectedLines.length > 0 ? selectedLines : lines,
        setBusy,
        setMessage
      });
    }
  });

  return React.createElement(
    Box,
    { flexDirection: "column", paddingX: 1, width: columns, height: rows },
    React.createElement(Header, { session }),
    screen === "summary"
      ? React.createElement(SummaryScreen, { report: session.report, incidents, incidentIndex })
      : React.createElement(IncidentScreen, {
          report: session.report,
          incident,
          lines,
          pageLines,
          pageStart,
          lineIndex,
          filter,
          sortKey,
          sortDirection,
          selectedLineKeys
        }),
    React.createElement(Footer, {
      screen,
      busy,
      message,
      selected: selectedLineKeys.size
    })
  );
}

function Header({ session }: { session: CitrxSession }) {
  const report = session.report;
  return React.createElement(
    Text,
    { bold: true, color: "cyan" },
    `citrx ${session.id} | files=${report.summary.files} parsed=${report.summary.parsedLines} incidents=${report.incidents.length}`
  );
}

function SummaryScreen({
  report,
  incidents,
  incidentIndex
}: {
  report: AnalyzeReport;
  incidents: Incident[];
  incidentIndex: number;
}) {
  return React.createElement(
    Box,
    { flexDirection: "column" },
    React.createElement(
      Box,
      { flexDirection: "row", gap: 1 },
      React.createElement(SummaryPanel, { report }),
      React.createElement(WatchlistPanel, { report })
    ),
    React.createElement(IncidentList, { incidents, incidentIndex })
  );
}

function SummaryPanel({ report }: { report: AnalyzeReport }) {
  const formats = [...new Set(report.inputFormats.map((item) => item.format))].join(", ");
  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "single", paddingX: 1, width: 54 },
    React.createElement(Text, { bold: true }, "Analysis"),
    React.createElement(Text, null, `inputs: ${report.inputs.length} | formats: ${formats || "unknown"}`),
    React.createElement(
      Text,
      null,
      `lines: ${report.summary.parsedLines}/${report.summary.totalLines} parsed | invalid: ${report.summary.invalidLines}`
    ),
    React.createElement(Text, null, `bytes: ${formatBytes(report.summary.totalBytes)}`),
    React.createElement(Text, null, `top ips: ${joinTop(report.topIps, 3)}`),
    React.createElement(Text, null, `top paths: ${joinTop(report.topPaths, 2)}`),
    React.createElement(Text, null, `statuses: ${joinTop(report.topStatuses, 4)}`)
  );
}

function WatchlistPanel({ report }: { report: AnalyzeReport }) {
  const items = report.incidents.slice(0, 5);
  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "single", paddingX: 1, flexGrow: 1 },
    React.createElement(Text, { bold: true }, "Watchlist"),
    ...(items.length > 0
      ? items.map((incident) =>
          React.createElement(
            Text,
            { key: incident.id, color: severityColor(incident.severity) },
            `${incident.severity.padEnd(8)} ${incident.score} ${truncate(incident.title, 46)}`
          )
        )
      : [React.createElement(Text, { key: "empty", color: "green" }, "No local incidents detected")])
  );
}

function IncidentList({
  incidents,
  incidentIndex
}: {
  incidents: Incident[];
  incidentIndex: number;
}) {
  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "single", paddingX: 1 },
    React.createElement(Text, { bold: true }, "Incidents"),
    ...(incidents.length > 0
      ? incidents.slice(0, 18).map((incident, index) =>
          React.createElement(
            Text,
            {
              key: incident.id,
              color: index === incidentIndex ? "black" : severityColor(incident.severity),
              backgroundColor: index === incidentIndex ? "cyan" : undefined
            },
            `${index === incidentIndex ? ">" : " "} ${incident.severity.padEnd(8)} ${String(incident.score).padStart(3)} ${truncate(incident.id, 38)} ${truncate(incident.title, 48)}`
          )
        )
      : [React.createElement(Text, { key: "empty" }, "No incidents found")])
  );
}

function IncidentScreen({
  report,
  incident,
  lines,
  pageLines,
  pageStart,
  lineIndex,
  filter,
  sortKey,
  sortDirection,
  selectedLineKeys
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
}) {
  const matchSet = report.incidentMatches.find((item) => item.incidentId === incident?.id);

  if (!incident) {
    return React.createElement(Text, null, "No incident selected");
  }

  return React.createElement(
    Box,
    { flexDirection: "column" },
    React.createElement(
      Box,
      { flexDirection: "column", borderStyle: "single", paddingX: 1 },
      React.createElement(Text, { bold: true, color: severityColor(incident.severity) }, incident.title),
      React.createElement(Text, null, `${incident.id} | ${incident.category} | ${incident.severity} | score=${incident.score}`),
      React.createElement(Text, null, incident.description),
      React.createElement(Text, { color: "gray" }, incident.evidence.map((item) => `${item.key}=${item.value}`).join(" | ")),
      React.createElement(
        Text,
        { color: matchSet?.truncated ? "yellow" : "gray" },
        `matches=${matchSet?.totalMatches ?? 0} stored=${matchSet?.storedLines ?? 0}${matchSet?.truncated ? " truncated: increase --incident-lines for more rows" : ""}`
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
      selectedLineKeys
    })
  );
}

function LineTable({
  lines,
  pageLines,
  pageStart,
  lineIndex,
  filter,
  sortKey,
  sortDirection,
  selectedLineKeys
}: {
  lines: IncidentLogLine[];
  pageLines: IncidentLogLine[];
  pageStart: number;
  lineIndex: number;
  filter: string;
  sortKey: SortKey;
  sortDirection: SortDirection;
  selectedLineKeys: Set<string>;
}) {
  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "single", paddingX: 1 },
    React.createElement(
      Text,
      { bold: true },
      `Accesses ${lines.length} | sort=${sortKey}:${sortDirection}${filter ? ` | filter=${filter}` : ""}`
    ),
    React.createElement(Text, { color: "gray" }, "sel line   time     ip              mth status bytes    path"),
    ...(pageLines.length > 0
      ? pageLines.map((line, offset) => {
          const absoluteIndex = pageStart + offset;
          const active = absoluteIndex === lineIndex;
          const selected = selectedLineKeys.has(lineKey(line));
          return React.createElement(
            Text,
            {
              key: lineKey(line),
              color: active ? "black" : undefined,
              backgroundColor: active ? "white" : undefined
            },
            `${selected ? "*" : " "} ${String(line.lineNumber).padStart(6)} ${compactTime(line.timestamp).padEnd(8)} ${truncate(line.ip, 15).padEnd(15)} ${line.method.padEnd(6)} ${String(line.status).padEnd(6)} ${String(line.bytes ?? "-").padEnd(8)} ${truncate(line.path, 64)}`
          );
        })
      : [React.createElement(Text, { key: "empty", color: "yellow" }, "No stored lines for this incident")])
  );
}

function Footer({
  screen,
  busy,
  message,
  selected
}: {
  screen: Screen;
  busy: boolean;
  message: string;
  selected: number;
}) {
  const shortcuts =
    screen === "summary"
      ? "↑/↓ incidents | Enter detail | a ask global | q quit"
      : "↑/↓ rows | Space select | A select visible | / filter | s sort | Tab dir | a ask | e export | b back | q quit";
  return React.createElement(
    Text,
    { color: busy ? "yellow" : "cyan" },
    `${busy ? "Asking OpenAI..." : message}${selected ? ` | selected=${selected}` : ""} | ${shortcuts}`
  );
}

function incidentLines(report: AnalyzeReport, incidentId: string | undefined): IncidentLogLine[] {
  return report.incidentMatches.find((item) => item.incidentId === incidentId)?.lines ?? [];
}

function visibleLines(
  lines: IncidentLogLine[],
  filter: string,
  sortKey: SortKey,
  sortDirection: SortDirection
): IncidentLogLine[] {
  const needle = filter.toLowerCase();
  return lines
    .filter((line) => (needle ? searchableLine(line).includes(needle) : true))
    .sort((a, b) => compareLine(a, b, sortKey, sortDirection));
}

function compareLine(
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

function searchableLine(line: IncidentLogLine): string {
  return [
    line.ip,
    line.timestamp,
    line.method,
    line.path,
    line.target,
    line.status,
    line.bytes,
    line.userAgent,
    line.raw
  ]
    .join(" ")
    .toLowerCase();
}

function nextSort(sortKey: SortKey): SortKey {
  const keys: SortKey[] = ["timestamp", "ip", "status", "method", "path", "bytes"];
  return keys[(keys.indexOf(sortKey) + 1) % keys.length] ?? "timestamp";
}

async function promptFilter(): Promise<string> {
  return input({ message: "Filter lines" });
}

async function exportContext(
  sessionId: string,
  incident: Incident | undefined,
  lines: IncidentLogLine[]
): Promise<string> {
  const safeSessionId = sanitizeFilePart(sessionId);
  const safeIncidentId = sanitizeFilePart(incident?.id ?? "summary");
  const file = path.join(process.cwd(), `citrx-${safeSessionId}-${safeIncidentId}.json`);
  await writeFile(file, `${JSON.stringify({ incident, lines }, null, 2)}\n`, "utf8");
  return file;
}

async function askOpenAi({
  session,
  runtime,
  scope,
  incident,
  lines,
  setBusy,
  setMessage
}: {
  session: CitrxSession;
  runtime: TuiRuntime;
  scope: "summary" | "incident";
  incident?: Incident;
  lines: IncidentLogLine[];
  setBusy: (value: boolean) => void;
  setMessage: (value: string) => void;
}): Promise<void> {
  const question = await input({ message: scope === "summary" ? "Ask OpenAI about the analysis" : "Ask OpenAI about this incident" });
  if (!question.trim()) {
    return;
  }

  setBusy(true);
  try {
    const client = runtime.aiClient ?? new OpenAiIncidentQuestionClient();
    const result = await client.ask({
      report: session.report,
      incident,
      lines,
      question,
      env: runtime.env,
      scope
    });
    setMessage(`OpenAI (${result.model}, ${result.sentLines} lines, ${result.sentChars} chars): ${truncate(result.answer, 220)}`);
  } catch (error) {
    setMessage(error instanceof Error ? error.message : String(error));
  } finally {
    setBusy(false);
  }
}

function toggleSelection(current: Set<string>, line: IncidentLogLine): Set<string> {
  const next = new Set(current);
  const key = lineKey(line);

  if (next.has(key)) {
    next.delete(key);
  } else {
    next.add(key);
  }

  return next;
}

function lineKey(line: IncidentLogLine): string {
  return `${line.source}:${line.lineNumber}`;
}

function compactTime(timestamp: string): string {
  const match = timestamp.match(/:(\d{2}:\d{2}:\d{2})/);
  return match?.[1] ?? timestamp.slice(0, 8);
}

function joinTop(items: TopItem[], limit: number): string {
  return items
    .slice(0, limit)
    .map((item) => `${item.value} (${item.count})`)
    .join(", ");
}

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }

  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KiB`;
  }

  if (value < 1024 * 1024 * 1024) {
    return `${(value / 1024 / 1024).toFixed(1)} MiB`;
  }

  return `${(value / 1024 / 1024 / 1024).toFixed(1)} GiB`;
}

function sanitizeFilePart(value: string): string {
  return value.replace(/[^a-zA-Z0-9_.-]+/g, "_").replace(/^_+|_+$/g, "") || "unknown";
}

function severityColor(severity: Incident["severity"]): string {
  switch (severity) {
    case "critical":
      return "red";
    case "high":
      return "magenta";
    case "medium":
      return "yellow";
    case "low":
      return "cyan";
    case "info":
      return "gray";
  }
}

function truncate(value: string, length: number): string {
  return value.length <= length ? value : `${value.slice(0, length - 1)}…`;
}
