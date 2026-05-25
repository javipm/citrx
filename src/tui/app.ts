import React, { useMemo, useState } from "react";
import { Box, Text, render, useApp, useInput } from "ink";
import { input } from "@inquirer/prompts";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import type { Readable, Writable } from "node:stream";

import type { Incident, IncidentLogLine } from "../analysis/types.js";
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

type SortKey = "timestamp" | "ip" | "status" | "method" | "path" | "bytes";

export async function openSessionTui(
  session: CitrxSession,
  runtime: TuiRuntime
): Promise<void> {
  const instance = render(
    React.createElement(IncidentExplorer, {
      session,
      runtime
    }),
    {
      stdin: runtime.stdin as NodeJS.ReadStream,
      stdout: runtime.stdout as NodeJS.WriteStream,
      stderr: runtime.stderr as NodeJS.WriteStream
    }
  );

  await instance.waitUntilExit();
}

function IncidentExplorer({
  session,
  runtime
}: {
  session: CitrxSession;
  runtime: TuiRuntime;
}) {
  const { exit } = useApp();
  const [incidentIndex, setIncidentIndex] = useState(0);
  const [lineIndex, setLineIndex] = useState(0);
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [message, setMessage] = useState("Ready");
  const [busy, setBusy] = useState(false);
  const incidents = session.report.incidents;
  const incident = incidents[incidentIndex];
  const lines = useMemo(
    () => visibleLines(session, incident?.id, filter, sortKey),
    [session, incident?.id, filter, sortKey]
  );

  useInput((inputValue, key) => {
    if (key.escape || inputValue === "q") {
      exit();
      return;
    }

    if (key.upArrow) {
      setIncidentIndex((value) => Math.max(0, value - 1));
      setLineIndex(0);
      return;
    }

    if (key.downArrow) {
      setIncidentIndex((value) => Math.min(incidents.length - 1, value + 1));
      setLineIndex(0);
      return;
    }

    if (inputValue === "j") {
      setLineIndex((value) => Math.min(lines.length - 1, value + 1));
      return;
    }

    if (inputValue === "k") {
      setLineIndex((value) => Math.max(0, value - 1));
      return;
    }

    if (inputValue === "s") {
      setSortKey(nextSort(sortKey));
      return;
    }

    if (inputValue === "r") {
      setFilter("");
      setLineIndex(0);
      setMessage("Filter reset");
      return;
    }

    if (inputValue === "/") {
      void promptFilter().then((value) => {
        setFilter(value);
        setLineIndex(0);
        setMessage(value ? `Filter: ${value}` : "Filter cleared");
      });
      return;
    }

    if (inputValue === "e") {
      void exportLines(session.id, incident, lines).then((file) => {
        setMessage(`Exported ${lines.length} lines to ${file}`);
      });
      return;
    }

    if (inputValue === "a") {
      void askOpenAi(session, runtime, incident, lines, setBusy, setMessage);
    }
  });

  if (!incident) {
    return React.createElement(Text, null, "No incidents found. Press q to exit.");
  }

  return React.createElement(
    Box,
    { flexDirection: "column", paddingX: 1 },
    React.createElement(Header, { session }),
    React.createElement(
      Box,
      { flexDirection: "row", gap: 1 },
      React.createElement(IncidentList, { incidents, incidentIndex }),
      React.createElement(
        Box,
        { flexDirection: "column", flexGrow: 1 },
        React.createElement(IncidentDetails, { incident }),
        React.createElement(LineTable, { lines, lineIndex, sortKey, filter })
      )
    ),
    React.createElement(
      Text,
      { color: busy ? "yellow" : "cyan" },
      `${busy ? "Asking OpenAI..." : message} | ↑/↓ incidents · j/k lines · / filter · s sort · a ask · e export · r reset · q quit`
    )
  );
}

function Header({ session }: { session: CitrxSession }) {
  return React.createElement(
    Text,
    { bold: true },
    `citrx session ${session.id} · incidents=${session.report.incidents.length} · parsed=${session.report.summary.parsedLines}`
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
    { flexDirection: "column", width: 38, borderStyle: "single", paddingX: 1 },
    React.createElement(Text, { bold: true }, "Incidents"),
    ...incidents.slice(0, 20).map((incident, index) =>
      React.createElement(
        Text,
        {
          key: incident.id,
          color: index === incidentIndex ? "black" : severityColor(incident.severity),
          backgroundColor: index === incidentIndex ? "cyan" : undefined
        },
        `${incident.severity.padEnd(8)} ${incident.score} ${truncate(incident.title, 20)}`
      )
    )
  );
}

function IncidentDetails({ incident }: { incident: Incident }) {
  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "single", paddingX: 1 },
    React.createElement(Text, { bold: true }, incident.title),
    React.createElement(Text, null, `${incident.category} · ${incident.severity} · score ${incident.score}`),
    React.createElement(Text, null, incident.description),
    React.createElement(
      Text,
      { color: "gray" },
      incident.evidence.map((item) => `${item.key}=${item.value}`).join(" · ")
    )
  );
}

function LineTable({
  lines,
  lineIndex,
  sortKey,
  filter
}: {
  lines: IncidentLogLine[];
  lineIndex: number;
  sortKey: SortKey;
  filter: string;
}) {
  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "single", paddingX: 1, minHeight: 12 },
    React.createElement(
      Text,
      { bold: true },
      `Lines (${lines.length}) · sort=${sortKey}${filter ? ` · filter=${filter}` : ""}`
    ),
    ...lines.slice(0, 12).map((line, index) =>
      React.createElement(
        Text,
        {
          key: `${line.source}:${line.lineNumber}`,
          color: index === lineIndex ? "black" : undefined,
          backgroundColor: index === lineIndex ? "white" : undefined
        },
        `${String(line.lineNumber).padStart(6)} ${line.status} ${line.method.padEnd(6)} ${truncate(line.ip, 20)} ${truncate(line.path, 46)}`
      )
    )
  );
}

function visibleLines(
  session: CitrxSession,
  incidentId: string | undefined,
  filter: string,
  sortKey: SortKey
): IncidentLogLine[] {
  const matchSet = session.report.incidentMatches.find((item) => item.incidentId === incidentId);
  const needle = filter.toLowerCase();
  const lines = (matchSet?.lines ?? []).filter((line) =>
    needle ? JSON.stringify(line).toLowerCase().includes(needle) : true
  );

  return lines.sort((a, b) => compareLine(a, b, sortKey));
}

function compareLine(a: IncidentLogLine, b: IncidentLogLine, sortKey: SortKey): number {
  if (sortKey === "bytes") {
    return (b.bytes ?? 0) - (a.bytes ?? 0);
  }

  if (sortKey === "status") {
    return b.status - a.status;
  }

  return String(b[sortKey]).localeCompare(String(a[sortKey]));
}

function nextSort(sortKey: SortKey): SortKey {
  const keys: SortKey[] = ["timestamp", "ip", "status", "method", "path", "bytes"];
  return keys[(keys.indexOf(sortKey) + 1) % keys.length] ?? "timestamp";
}

async function promptFilter(): Promise<string> {
  return input({ message: "Filter lines" });
}

async function exportLines(
  sessionId: string,
  incident: Incident | undefined,
  lines: IncidentLogLine[]
): Promise<string> {
  const safeSessionId = sanitizeFilePart(sessionId);
  const safeIncidentId = sanitizeFilePart(incident?.id ?? "incident");
  const file = path.join(process.cwd(), `citrx-${safeSessionId}-${safeIncidentId}.json`);
  await writeFile(file, `${JSON.stringify({ incident, lines }, null, 2)}\n`, "utf8");
  return file;
}

function sanitizeFilePart(value: string): string {
  return value.replace(/[^a-zA-Z0-9_.-]+/g, "_").replace(/^_+|_+$/g, "") || "unknown";
}

async function askOpenAi(
  session: CitrxSession,
  runtime: TuiRuntime,
  incident: Incident | undefined,
  lines: IncidentLogLine[],
  setBusy: (value: boolean) => void,
  setMessage: (value: string) => void
): Promise<void> {
  if (!incident) {
    return;
  }

  const question = await input({ message: "Ask OpenAI" });
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
      env: runtime.env
    });
    setMessage(`OpenAI (${result.model}, ${result.sentLines} lines): ${truncate(result.answer, 180)}`);
  } catch (error) {
    setMessage(error instanceof Error ? error.message : String(error));
  } finally {
    setBusy(false);
  }
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
