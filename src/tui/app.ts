import React, { useMemo, useState } from "react";
import { Box, Text, render, useApp, useInput, useWindowSize } from "ink";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import type { Readable, Writable } from "node:stream";

import type { AnalyzeReport, Incident, IncidentLogLine, TopItem } from "../analysis/types.js";
import { OpenAiIncidentQuestionClient } from "../ai/incident-question.js";
import type { IncidentQuestionClient } from "../ai/incident-question.js";
import type { CitrxSession } from "../session/types.js";
import { createAccessLogLineFilter, validateAccessLogFilter } from "./filter.js";

export interface TuiRuntime {
  env: NodeJS.ProcessEnv;
  stdin: Readable;
  stdout: Writable;
  stderr: Writable;
  aiClient?: IncidentQuestionClient;
}

type Screen = "summary" | "incident" | "tops";
type SortKey = "timestamp" | "ip" | "status" | "method" | "path" | "bytes";
type SortDirection = "asc" | "desc";
type PromptState =
  | { kind: "filter"; value: string }
  | {
      kind: "ai";
      value: string;
      scope: "summary" | "incident";
      incident?: Incident;
      lines: IncidentLogLine[];
    };

interface IncidentInsights {
  ips: TopItem[];
  userAgents: TopItem[];
  params: TopItem[];
  paramValues: TopItem[];
}

interface AccessTableColumns {
  sel: number;
  line: number;
  time: number;
  ip: number;
  method: number;
  status: number;
  bytes: number;
  path: number;
  ua: number;
}

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
  const [detailLine, setDetailLine] = useState<IncidentLogLine | undefined>();
  const [detailScroll, setDetailScroll] = useState(0);
  const [prompt, setPrompt] = useState<PromptState | undefined>();
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
  const pageSize = screen === "incident" ? Math.max(8, rows - 10) : Math.max(6, rows - 14);
  const detailRows = Math.max(6, rows - 6);
  const detailWidth = Math.max(40, columns - 10);
  const detailLines = useMemo(
    () => (detailLine ? requestDetailLines(detailLine, detailWidth) : []),
    [detailLine, detailWidth]
  );
  const visibleDetailLines = detailLines.slice(detailScroll, detailScroll + detailRows);
  const pageStart = Math.max(
    0,
    Math.min(lineIndex - Math.floor(pageSize / 2), Math.max(0, lines.length - pageSize))
  );
  const pageLines = lines.slice(pageStart, pageStart + pageSize);

  useInput((inputValue, key) => {
    if (prompt) {
      handlePromptInput({
        inputValue,
        key,
        prompt,
        setPrompt,
        setFilter,
        setLineIndex,
        setSelectedLineKeys,
        setMessage,
        submitAi: (question, state) => {
          void submitOpenAi({
            session,
            runtime,
            scope: state.scope,
            incident: state.incident,
            lines: state.lines,
            question,
            setBusy,
            setMessage
          });
        }
      });
      return;
    }

    if (detailLine) {
      if (inputValue === "q") {
        exit();
        return;
      }

      if (inputValue === "d" || inputValue === "b" || key.escape || key.backspace) {
        setDetailLine(undefined);
        setDetailScroll(0);
        setMessage("Back to incident");
        return;
      }

      if (key.upArrow) {
        setDetailScroll((value) => Math.max(0, value - 1));
        return;
      }

      if (key.downArrow) {
        setDetailScroll((value) => Math.min(Math.max(0, detailLines.length - detailRows), value + 1));
      }
      return;
    }

    if (inputValue === "q" || (screen === "summary" && key.escape)) {
      exit();
      return;
    }

    if ((inputValue === "b" || key.backspace || key.escape) && screen === "tops") {
      setScreen("incident");
      setMessage("Back to incident");
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
        setDetailLine(undefined);
        setMessage(`Opened ${incident.id}`);
        return;
      }

      if (inputValue === "a") {
        setPrompt({
          kind: "ai",
          value: "",
          scope: "summary",
          lines: []
        });
      }

      return;
    }

    if (screen === "tops") {
      if (inputValue === "t") {
        setScreen("incident");
        setMessage("Back to incident");
        return;
      }

      if (inputValue === "a") {
        setPrompt({
          kind: "ai",
          value: "",
          scope: "incident",
          incident,
          lines: selectedLines.length > 0 ? selectedLines : lines
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

    if (inputValue === "d") {
      const line = lines[lineIndex];
      if (line) {
        setDetailLine(line);
        setDetailScroll(0);
      }
      return;
    }

    if (inputValue === "t") {
      setScreen("tops");
      setMessage(`Top values for ${incident?.id ?? "incident"}`);
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

    if (inputValue === "/" || inputValue === "f" || inputValue === "F") {
      setPrompt({ kind: "filter", value: filter });
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
      setPrompt({
        kind: "ai",
        value: "",
        scope: "incident",
        incident,
        lines: selectedLines.length > 0 ? selectedLines : lines
      });
    }
  });

  return React.createElement(
    Box,
    { flexDirection: "column", paddingX: 1, width: columns, height: rows },
    React.createElement(Header, { session, columns }),
    React.createElement(
      Box,
      { flexDirection: "column", flexGrow: 1 },
      detailLine
        ? React.createElement(RequestDetailScreen, {
            line: detailLine,
            visibleLines: visibleDetailLines,
            scroll: detailScroll,
            totalLines: detailLines.length
          })
        : screen === "summary"
          ? React.createElement(SummaryScreen, { report: session.report, incidents, incidentIndex, pageSize })
          : screen === "tops"
            ? React.createElement(TopValuesScreen, {
                report: session.report,
                incident,
                columns
              })
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
              selectedLineKeys,
              columns
            })
    ),
    prompt ? React.createElement(PromptBar, { prompt }) : null,
    React.createElement(Footer, {
      screen,
      detailOpen: Boolean(detailLine),
      busy,
      message,
      selected: selectedLineKeys.size,
      columns
    })
  );
}

function Header({ session, columns }: { session: CitrxSession; columns: number }) {
  const report = session.report;
  return React.createElement(
    Text,
    { bold: true, color: "cyan", wrap: "truncate" },
    fitText(
      `citrx ${session.id} | files=${report.summary.files} parsed=${report.summary.parsedLines} incidents=${report.incidents.length}`,
      columns - 2
    )
  );
}

function SummaryScreen({
  report,
  incidents,
  incidentIndex,
  pageSize
}: {
  report: AnalyzeReport;
  incidents: Incident[];
  incidentIndex: number;
  pageSize: number;
}) {
  return React.createElement(
    Box,
    { flexDirection: "column", flexGrow: 1 },
    React.createElement(
      Box,
      { flexDirection: "row", gap: 1 },
      React.createElement(SummaryPanel, { report }),
      React.createElement(WatchlistPanel, { report })
    ),
    React.createElement(IncidentList, { incidents, incidentIndex, pageSize })
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
  incidentIndex,
  pageSize
}: {
  incidents: Incident[];
  incidentIndex: number;
  pageSize: number;
}) {
  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "single", paddingX: 1, flexGrow: 1 },
    React.createElement(Text, { bold: true }, "Incidents"),
    ...(incidents.length > 0
      ? incidents.slice(0, pageSize).map((incident, index) =>
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
}) {
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
        fitText(`${incident.severity.toUpperCase()} ${incident.score} | ${incident.title}`, headerWidth)
      ),
      React.createElement(Text, { wrap: "truncate" }, fitText(`${incident.id} | ${incident.category}`, headerWidth)),
      React.createElement(Text, { color: "gray", wrap: "truncate" }, fitText(incident.evidence.map((item) => `${item.key}=${item.value}`).join(" | "), headerWidth)),
      React.createElement(
        Text,
        { color: matchSet?.truncated ? "yellow" : "gray", wrap: "truncate" },
        fitText(
          `matches=${matchSet?.totalMatches ?? 0} stored=${matchSet?.storedLines ?? 0}${matchSet?.truncated ? " truncated: increase --incident-lines for more rows" : ""}`,
          headerWidth
        )
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

function TopValuesScreen({
  report,
  incident,
  columns
}: {
  report: AnalyzeReport;
  incident: Incident | undefined;
  columns: number;
}) {
  const matchSet = report.incidentMatches.find((item) => item.incidentId === incident?.id);
  const insights = incidentInsights(matchSet?.lines ?? []);
  const panelWidth = Math.max(30, Math.floor((columns - 7) / 2));
  const headerWidth = Math.max(40, columns - 10);

  if (!incident) {
    return React.createElement(Text, null, "No incident selected");
  }

  return React.createElement(
    Box,
    { flexDirection: "column", flexGrow: 1 },
    React.createElement(
      Box,
      { flexDirection: "column", borderStyle: "single", paddingX: 1 },
      React.createElement(
        Text,
        { bold: true, color: severityColor(incident.severity), wrap: "truncate" },
        fitText(`Top values for ${incident.id}`, headerWidth)
      ),
      React.createElement(
        Text,
        { color: matchSet?.truncated ? "yellow" : "gray", wrap: "truncate" },
        fitText(
          `computed from ${matchSet?.storedLines ?? 0}/${matchSet?.totalMatches ?? 0} stored matching requests${matchSet?.truncated ? " (sample truncated)" : ""}`,
          headerWidth
        )
      )
    ),
    React.createElement(
      Box,
      { flexDirection: "column", flexGrow: 1 },
      React.createElement(
        Box,
        { flexDirection: "row", gap: 1, flexGrow: 1 },
        React.createElement(TopListPanel, {
          title: "Top IPs",
          items: insights.ips,
          width: panelWidth
        }),
        React.createElement(TopListPanel, {
          title: "Top user agents",
          items: insights.userAgents,
          width: panelWidth
        })
      ),
      React.createElement(
        Box,
        { flexDirection: "row", gap: 1, flexGrow: 1 },
        React.createElement(TopListPanel, {
          title: "Top query params",
          items: insights.params,
          width: panelWidth
        }),
        React.createElement(TopListPanel, {
          title: "Top query param values",
          items: insights.paramValues,
          width: panelWidth
        })
      )
    )
  );
}

function TopListPanel({
  title,
  items,
  width
}: {
  title: string;
  items: TopItem[];
  width: number;
}) {
  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "single", paddingX: 1, width },
    React.createElement(Text, { bold: true, wrap: "truncate" }, fitText(title, width - 2)),
    ...(items.length > 0
      ? items.map((item) =>
          React.createElement(
            Text,
            { key: item.value, wrap: "truncate" },
            fitText(`${String(item.count).padStart(5)}  ${item.value}`, width - 2)
          )
        )
      : [React.createElement(Text, { key: "empty", color: "gray" }, "none")])
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
  selectedLineKeys,
  columns
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
}) {
  const tableColumns = accessTableColumns(columns);

  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "single", paddingX: 1, flexGrow: 1 },
    React.createElement(
      Text,
      { bold: true, wrap: "truncate" },
      `Accesses ${lines.length} | sort=${sortKey}:${sortDirection}${filter ? ` | filter=${filter}` : ""}`
    ),
    React.createElement(
      Text,
      { color: "gray", wrap: "truncate" },
      accessTableHeader(tableColumns)
    ),
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
              backgroundColor: active ? "white" : undefined,
              wrap: "truncate"
            },
            accessTableRow(line, selected, tableColumns)
          );
        })
      : [React.createElement(Text, { key: "empty", color: "yellow" }, "No stored lines for this incident")])
  );
}

function RequestDetailScreen({
  line,
  visibleLines,
  scroll,
  totalLines
}: {
  line: IncidentLogLine;
  visibleLines: string[];
  scroll: number;
  totalLines: number;
}) {
  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "double", paddingX: 1, flexGrow: 1 },
    React.createElement(
      Text,
      { bold: true, color: "cyan", wrap: "truncate" },
      `Request detail | line=${line.lineNumber} | ${scroll + 1}-${Math.min(scroll + visibleLines.length, totalLines)}/${totalLines}`
    ),
    ...visibleLines.map((value, index) =>
      React.createElement(Text, { key: `${scroll + index}:${value}`, color: value.startsWith("raw") || value.startsWith("        ") ? "gray" : undefined, wrap: "truncate" }, value)
    )
  );
}

function PromptBar({ prompt }: { prompt: PromptState }) {
  const label =
    prompt.kind === "filter"
      ? "Filter"
      : prompt.scope === "summary"
        ? "Ask OpenAI about analysis"
        : "Ask OpenAI about incident";

  return React.createElement(
    Box,
    { borderStyle: "single", paddingX: 1 },
    React.createElement(Text, { color: "cyan", wrap: "truncate" }, `${label}: `),
    React.createElement(Text, { wrap: "truncate" }, prompt.value),
    React.createElement(Text, { inverse: true }, " ")
  );
}

function Footer({
  screen,
  detailOpen,
  busy,
  message,
  selected,
  columns
}: {
  screen: Screen;
  detailOpen: boolean;
  busy: boolean;
  message: string;
  selected: number;
  columns: number;
}) {
  const shortcuts = detailOpen
    ? "↑/↓ scroll | d/b/Esc close | q quit"
    : screen === "summary"
      ? "↑/↓ incidents | Enter detail | a ask global | q quit"
      : screen === "tops"
        ? "t/b/Esc back | a ask about incident | q quit"
        : "↑/↓ rows | d detail | t tops | Space select | A select visible | f filter | s sort | Tab dir | a ask | e export | b back | q quit";
  const status = `${busy ? "Asking OpenAI..." : message}${selected ? ` | selected=${selected}` : ""}`;

  return React.createElement(
    Box,
    { flexDirection: "column" },
    React.createElement(Text, { color: busy ? "yellow" : "cyan", wrap: "truncate" }, fitText(status, columns - 2)),
    React.createElement(Text, { color: "cyan", wrap: "truncate" }, fitText(shortcuts, columns - 2))
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
  const lineMatches = createAccessLogLineFilter(filter);
  return lines
    .filter((line) => lineMatches(line))
    .sort((a, b) => compareLine(a, b, sortKey, sortDirection));
}

function incidentInsights(lines: IncidentLogLine[]): IncidentInsights {
  const ips = new Map<string, number>();
  const userAgents = new Map<string, number>();
  const params = new Map<string, number>();
  const paramValues = new Map<string, number>();

  for (const line of lines) {
    incrementMap(ips, line.ip);
    incrementMap(userAgents, userAgentLabel(line.userAgent));

    for (const param of requestParamNames(line.target)) {
      incrementMap(params, param);
    }

    for (const paramValue of requestParamValues(line.target)) {
      incrementMap(paramValues, paramValue);
    }
  }

  return {
    ips: topMapItems(ips, 10),
    userAgents: topMapItems(userAgents, 10),
    params: topMapItems(params, 10),
    paramValues: topMapItems(paramValues, 10)
  };
}

function requestParamNames(target: string): string[] {
  try {
    const url = new URL(target, "http://citrx.local");
    return [...new Set([...url.searchParams.keys()])];
  } catch {
    const queryStart = target.indexOf("?");

    if (queryStart === -1) {
      return [];
    }

    return [
      ...new Set(
        target
          .slice(queryStart + 1)
          .split("&")
          .map((part) => part.split("=")[0]?.trim())
          .filter((part): part is string => Boolean(part))
      )
    ];
  }
}

function requestParamValues(target: string): string[] {
  try {
    const url = new URL(target, "http://citrx.local");
    return uniqueParamValues([...url.searchParams.entries()]);
  } catch {
    const queryStart = target.indexOf("?");

    if (queryStart === -1) {
      return [];
    }

    return uniqueParamValues(
      target
        .slice(queryStart + 1)
        .split("&")
        .map(parseQueryPart)
    );
  }
}

function parseQueryPart(part: string): [string, string] {
  const separator = part.indexOf("=");

  if (separator === -1) {
    return [safeDecode(part), ""];
  }

  return [safeDecode(part.slice(0, separator)), safeDecode(part.slice(separator + 1))];
}

function uniqueParamValues(entries: Array<[string, string]>): string[] {
  return [
    ...new Set(
      entries
        .map(([name, value]) => paramValueLabel(name.trim(), value.trim()))
        .filter((part): part is string => Boolean(part))
    )
  ];
}

function paramValueLabel(name: string, value: string): string | undefined {
  if (!name) {
    return undefined;
  }

  if (isSensitiveParamName(name)) {
    return `${name}=<redacted>`;
  }

  return `${name}=${value || "<empty>"}`;
}

function isSensitiveParamName(name: string): boolean {
  return /pass(word)?|token|secret|key|auth|session|sid|jwt|credential/i.test(name);
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

function incrementMap(map: Map<string, number>, key: string): void {
  if (!key || key === "-") {
    return;
  }

  map.set(key, (map.get(key) ?? 0) + 1);
}

function topMapItems(map: Map<string, number>, limit: number): TopItem[] {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([value, count]) => ({ value, count }));
}

function accessTableColumns(columns: number): AccessTableColumns {
  const tableWidth = Math.max(60, columns - 14);
  const fixed = {
    sel: 1,
    line: 6,
    time: 8,
    ip: 15,
    method: 4,
    status: 3,
    bytes: 7
  };
  const fixedTotal =
    fixed.sel +
    fixed.line +
    fixed.time +
    fixed.ip +
    fixed.method +
    fixed.status +
    fixed.bytes;
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

function accessTableHeader(columns: AccessTableColumns): string {
  return tableCells(
    [
      ["s", columns.sel],
      ["line", columns.line, "right"],
      ["time", columns.time],
      ["ip", columns.ip],
      ["meth", columns.method],
      ["st", columns.status, "right"],
      ["bytes", columns.bytes, "right"],
      ["path", columns.path],
      ["ua", columns.ua]
    ]
  );
}

function accessTableRow(
  line: IncidentLogLine,
  selected: boolean,
  columns: AccessTableColumns
): string {
  return tableCells(
    [
      [selected ? "*" : " ", columns.sel],
      [String(line.lineNumber), columns.line, "right"],
      [compactTime(line.timestamp), columns.time],
      [line.ip, columns.ip],
      [line.method, columns.method],
      [String(line.status), columns.status, "right"],
      [String(line.bytes ?? "-"), columns.bytes, "right"],
      [line.path, columns.path],
      [userAgentLabel(line.userAgent), columns.ua]
    ]
  );
}

function tableCells(cells: Array<[string, number] | [string, number, "right"]>): string {
  return cells
    .map(([value, width, align]) => padCell(value, width, align))
    .join(" ");
}

function padCell(value: string, width: number, align?: "right"): string {
  const text = fitText(value, width);
  return align === "right" ? text.padStart(width) : text.padEnd(width);
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

function nextSort(sortKey: SortKey): SortKey {
  const keys: SortKey[] = ["timestamp", "ip", "status", "method", "path", "bytes"];
  return keys[(keys.indexOf(sortKey) + 1) % keys.length] ?? "timestamp";
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

function handlePromptInput({
  inputValue,
  key,
  prompt,
  setPrompt,
  setFilter,
  setLineIndex,
  setSelectedLineKeys,
  setMessage,
  submitAi
}: {
  inputValue: string;
  key: {
    return?: boolean;
    escape?: boolean;
    backspace?: boolean;
    delete?: boolean;
    ctrl?: boolean;
  };
  prompt: PromptState;
  setPrompt: (value: PromptState | undefined) => void;
  setFilter: (value: string) => void;
  setLineIndex: (value: number) => void;
  setSelectedLineKeys: (value: Set<string>) => void;
  setMessage: (value: string) => void;
  submitAi: (question: string, state: Extract<PromptState, { kind: "ai" }>) => void;
}): void {
  if (key.escape) {
    setPrompt(undefined);
    setMessage("Prompt cancelled");
    return;
  }

  if (key.return) {
    const value = prompt.value.trim();

    if (prompt.kind === "filter") {
      const validation = validateAccessLogFilter(value);

      if (!validation.ok) {
        setMessage(`Invalid filter: ${validation.error}`);
        setPrompt(prompt);
        return;
      }

      setPrompt(undefined);
      setFilter(value);
      setLineIndex(0);
      setSelectedLineKeys(new Set());
      setMessage(value ? `Filter: ${value}` : "Filter cleared");
      return;
    }

    setPrompt(undefined);

    if (value) {
      submitAi(value, prompt);
    }
    return;
  }

  if (key.backspace || key.delete) {
    setPrompt({ ...prompt, value: prompt.value.slice(0, -1) });
    return;
  }

  if (key.ctrl || !isPrintableInput(inputValue)) {
    return;
  }

  setPrompt({ ...prompt, value: `${prompt.value}${inputValue}` });
}

async function submitOpenAi({
  session,
  runtime,
  scope,
  incident,
  lines,
  question,
  setBusy,
  setMessage
}: {
  session: CitrxSession;
  runtime: TuiRuntime;
  scope: "summary" | "incident";
  incident?: Incident;
  lines: IncidentLogLine[];
  question: string;
  setBusy: (value: boolean) => void;
  setMessage: (value: string) => void;
}): Promise<void> {
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

function isPrintableInput(inputValue: string): boolean {
  return inputValue.length > 0 && !inputValue.startsWith("\u001B");
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

function requestDetailLines(line: IncidentLogLine, width: number): string[] {
  return [
    ...wrapDetailField("source", line.source, width),
    ...wrapDetailField("time", line.timestamp, width),
    ...wrapDetailField("ip", line.ip, width),
    ...wrapDetailField("method", `${line.method} | status=${line.status} | bytes=${line.bytes ?? "-"}`, width),
    ...wrapDetailField("path", line.path, width),
    ...wrapDetailField("target", line.target, width),
    ...wrapDetailField("ua", line.userAgent ?? "-", width),
    ...wrapDetailField("raw", line.raw, width)
  ];
}

function wrapDetailField(label: string, value: string, width: number): string[] {
  const labelWidth = 8;
  const contentWidth = Math.max(20, width - labelWidth - 1);
  const chunks = wrapHard(value, contentWidth);

  return chunks.map((chunk, index) =>
    `${index === 0 ? label.padEnd(labelWidth) : " ".repeat(labelWidth)} ${chunk}`
  );
}

function wrapHard(value: string, width: number): string[] {
  const chunks: string[] = [];
  let remaining = value || "-";

  while (remaining.length > width) {
    chunks.push(remaining.slice(0, width));
    remaining = remaining.slice(width);
  }

  chunks.push(remaining);
  return chunks;
}

function compactTime(timestamp: string): string {
  const match = timestamp.match(/:(\d{2}:\d{2}:\d{2})/);
  return match?.[1] ?? timestamp.slice(0, 8);
}

function userAgentLabel(userAgent: string | null): string {
  if (!userAgent || userAgent === "-") {
    return "-";
  }

  const normalized = userAgent.replace(/\s+/g, " ").trim();
  const bot = normalized.match(
    /(Googlebot\/[^\s;)]+|Claude-SearchBot\/[^\s;)]+|MJ12bot\/[^\s;)]+|bingbot\/[^\s;)]+|AhrefsBot\/[^\s;)]+|SemrushBot\/[^\s;)]+)/i
  );

  if (bot) {
    return bot[1] ?? normalized;
  }

  const browser =
    normalized.match(/(?:Chrome|Firefox|Version|OPR|Edg)\/[^\s;)]+/)?.[0] ??
    normalized.match(/Safari\/[^\s;)]+/)?.[0] ??
    "UA";
  const os =
    normalized.match(/Android [^;)]+/)?.[0] ??
    normalized.match(/Windows NT [^;)]+/)?.[0] ??
    normalized.match(/Mac OS X [^;)]+/)?.[0] ??
    normalized.match(/Linux [^;)]+/)?.[0];

  return os ? `${browser} ${os}` : browser;
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

function fitText(value: string, width: number): string {
  if (width <= 0) {
    return "";
  }

  const text = value.replace(/\s+/g, " ").trim();

  if (text.length <= width) {
    return text;
  }

  if (width <= 3) {
    return text.slice(0, width);
  }

  return `${text.slice(0, width - 3)}...`;
}
