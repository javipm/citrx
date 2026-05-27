import React, { useEffect, useMemo, useState } from "react";
import { Box, Text, render, useApp, useInput, useWindowSize } from "ink";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import type { Readable, Writable } from "node:stream";

import type { AnalyzeReport, Incident, IncidentLogLine, TopItem } from "../analysis/types.js";
import { requestParamNames, requestParamValueLabels, userAgentLabel } from "../analysis/query-params.js";
import { OpenAiIncidentQuestionClient } from "../ai/incident-question.js";
import type { IncidentQuestionClient } from "../ai/incident-question.js";
import {
  passThroughFilter,
  readAccessLogIndexCachedPage,
  readAccessLogIndexRows,
  AccessLogIndexQueryCache
} from "../run/access-index.js";
import type { CitrxRun } from "../run/types.js";
import { createAccessLogLineFilter, validateAccessLogFilter } from "./filter.js";

export interface TuiRuntime {
  env: NodeJS.ProcessEnv;
  stdin: Readable;
  stdout: Writable;
  stderr: Writable;
  aiClient?: IncidentQuestionClient;
}

type Screen = "summary" | "incident" | "tops";
type SummaryFocus = "accesses" | "compromise" | "saturation" | "noise";

function isIncidentFocus(focus: SummaryFocus): focus is "compromise" | "saturation" | "noise" {
  return focus !== "accesses";
}

function kindRange(
  incidents: Incident[],
  kind: "compromise" | "saturation" | "noise"
): { start: number; end: number } {
  let start = -1;
  let end = -1;
  for (let index = 0; index < incidents.length; index += 1) {
    if (incidents[index]!.kind === kind) {
      if (start === -1) start = index;
      end = index + 1;
    }
  }
  return { start, end };
}

function availableFocuses(incidents: Incident[]): SummaryFocus[] {
  const order: SummaryFocus[] = ["accesses"];
  if (incidents.some((i) => i.kind === "saturation")) order.push("saturation");
  if (incidents.some((i) => i.kind === "compromise")) order.push("compromise");
  if (incidents.some((i) => i.kind === "noise")) order.push("noise");
  return order;
}
type TopScope = "summary" | "incident";
type TopPanelKey = "ips" | "paths" | "userAgents" | "params" | "paramValues";
type SortKey = "timestamp" | "ip" | "status" | "method" | "path" | "bytes";
type SortDirection = "asc" | "desc";
type SortMenuFocus = "key" | "direction" | "apply";
interface PromptInputState {
  value: string;
  cursor: number;
}

interface OpenAiAnswerState {
  title: string;
  meta: string;
  answer: string;
}

interface RenderLine {
  text: string;
  color?: "cyan" | "gray" | "yellow" | "green";
  bold?: boolean;
}

type PromptState =
  | ({ kind: "filter" } & PromptInputState)
  | {
      kind: "ai";
      scope: "summary" | "incident";
      incident?: Incident;
      lines: IncidentLogLine[];
      extraContext?: string;
    } & PromptInputState;

interface IncidentInsights {
  ips: TopItem[];
  paths: TopItem[];
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

const TOP_PANEL_KEYS: TopPanelKey[] = ["ips", "paths", "userAgents", "params", "paramValues"];
const SORT_KEYS: SortKey[] = ["timestamp", "ip", "status", "method", "path", "bytes"];
const SPINNER_FRAMES = ["-", "\\", "|", "/"];

export async function openRunTui(
  run: CitrxRun,
  runtime: TuiRuntime
): Promise<void> {
  const instance = render(
    React.createElement(CitrxExplorer, {
      run,
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
  run,
  runtime
}: {
  run: CitrxRun;
  runtime: TuiRuntime;
}) {
  const { exit } = useApp();
  const { rows, columns } = useWindowSize();
  const [screen, setScreen] = useState<Screen>("summary");
  // Default focus is the saturation panel — that's the most-used view.
  const [summaryFocus, setSummaryFocus] = useState<SummaryFocus>("saturation");
  const [topScope, setTopScope] = useState<TopScope>("summary");
  const [topFocus, setTopFocus] = useState<TopPanelKey>("ips");
  const [topIndexes, setTopIndexes] = useState<Record<TopPanelKey, number>>({
    ips: 0,
    paths: 0,
    userAgents: 0,
    params: 0,
    paramValues: 0
  });
  const [incidentIndex, setIncidentIndex] = useState(() => {
    // Align cursor with the default-focused saturation panel so arrow keys land there.
    const satStart = run.report.incidents.findIndex((i) => i.kind === "saturation");
    return satStart >= 0 ? satStart : 0;
  });
  const [lineIndex, setLineIndex] = useState(0);
  const [summaryLineIndex, setSummaryLineIndex] = useState(0);
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [selectedLineKeys, setSelectedLineKeys] = useState<Set<string>>(new Set());
  const [detailLine, setDetailLine] = useState<IncidentLogLine | undefined>();
  const [detailScroll, setDetailScroll] = useState(0);
  const [openAiAnswer, setOpenAiAnswer] = useState<OpenAiAnswerState | undefined>();
  const [openAiAnswerScroll, setOpenAiAnswerScroll] = useState(0);
  const [prompt, setPrompt] = useState<PromptState | undefined>();
  const [sortMenu, setSortMenu] = useState<{
    sortKey: SortKey;
    sortDirection: SortDirection;
    focus: SortMenuFocus;
  }>();
  const [message, setMessage] = useState("Ready");
  const [busy, setBusy] = useState(false);
  const [indexLoading, setIndexLoading] = useState(false);
  const [globalTotal, setGlobalTotal] = useState(run.report.accessLog.indexedLines);
  const [summaryPageLines, setSummaryPageLines] = useState<IncidentLogLine[]>([]);
  const accessQueryCache = useMemo(() => new AccessLogIndexQueryCache(), [run.accessIndex]);
  const incidents = run.report.incidents;
  const incident = incidents[incidentIndex];
  const allIncidentLines = useMemo(
    () => incidentLines(run.report, incident?.id),
    [run.report, incident?.id]
  );
  const lines = useMemo(
    () => visibleLines(allIncidentLines, filter, sortKey, sortDirection),
    [allIncidentLines, filter, sortKey, sortDirection]
  );
  const selectedLines = useMemo(
    () => lines.filter((line) => selectedLineKeys.has(lineKey(line))),
    [lines, selectedLineKeys]
  );
  const selectedGlobalLines = useMemo(
    () => summaryPageLines.filter((line) => selectedLineKeys.has(lineKey(line))),
    [summaryPageLines, selectedLineKeys]
  );
  const controlRows = prompt ? 3 : 0;
  const pageSize = screen === "incident" ? Math.max(4, rows - 13 - controlRows) : Math.max(4, rows - 16 - controlRows);
  const summaryPageSize = Math.max(4, rows - 15 - controlRows);
  const detailRows = Math.max(4, rows - 6 - controlRows);
  const detailWidth = Math.max(40, columns - 10);
  const detailLines = useMemo(
    () => (detailLine ? requestDetailLines(detailLine, detailWidth) : []),
    [detailLine, detailWidth]
  );
  const visibleDetailLines = detailLines.slice(detailScroll, detailScroll + detailRows);
  const answerRows = Math.max(4, rows - 7 - controlRows);
  const answerWidth = Math.max(40, columns - 10);
  const openAiAnswerLines = useMemo(
    () => (openAiAnswer ? renderMarkdownAnswer(openAiAnswer.answer, answerWidth) : []),
    [openAiAnswer, answerWidth]
  );
  const visibleOpenAiAnswerLines = openAiAnswerLines.slice(
    openAiAnswerScroll,
    openAiAnswerScroll + answerRows
  );
  const pageStart = Math.max(
    0,
    Math.min(lineIndex - Math.floor(pageSize / 2), Math.max(0, lines.length - pageSize))
  );
  const pageLines = lines.slice(pageStart, pageStart + pageSize);
  const summaryPageStart = Math.max(
    0,
    Math.min(summaryLineIndex - Math.floor(summaryPageSize / 2), Math.max(0, globalTotal - summaryPageSize))
  );

  useEffect(() => {
    let cancelled = false;
    const filterFn = filter ? createAccessLogLineFilter(filter) : passThroughFilter;
    const cacheKey = accessQueryKey(filter, sortKey, sortDirection);
    const needsIndexBuild = !accessQueryCache.has(cacheKey) && (filter || sortKey !== "timestamp");

    if (needsIndexBuild) {
      setIndexLoading(true);
      setMessage("Building filter cache...");
    } else {
      setIndexLoading(false);
    }

    void readAccessLogIndexCachedPage(run.accessIndex, accessQueryCache, cacheKey, {
      filter: filterFn,
      sortKey,
      sortDirection,
      start: summaryPageStart,
      limit: summaryPageSize
    })
      .then((page) => {
        if (cancelled) {
          return;
        }

        setGlobalTotal(page.total);
        setSummaryPageLines(page.lines);
        if (needsIndexBuild) {
          setIndexLoading(false);
        }
        setMessage(filter || sortKey !== "timestamp" ? "Filter cache ready" : "Ready");

        setSummaryLineIndex((value) => Math.min(Math.max(0, page.total - 1), value));
      })
      .catch((error) => {
        if (!cancelled) {
          if (needsIndexBuild) {
            setIndexLoading(false);
          }
          setMessage(error instanceof Error ? error.message : String(error));
        }
      });

    return () => {
      cancelled = true;
    };
  }, [accessQueryCache, filter, run.accessIndex, sortDirection, sortKey, summaryPageSize, summaryPageStart]);

  useInput((inputValue, key) => {
    if (sortMenu) {
      handleSortMenuInput({
        inputValue,
        key,
        sortMenu,
        setSortMenu,
        applySort: (nextSortKey, nextSortDirection) => {
          setSortMenu(undefined);
          setSortKey(nextSortKey);
          setSortDirection(nextSortDirection);
          if (screen === "summary") {
            setSummaryLineIndex(0);
          } else {
            setLineIndex(0);
          }
          setSelectedLineKeys(new Set());
          setMessage(`Sort: ${sortLabel(nextSortKey)} ${nextSortDirection}`);
        },
        setMessage
      });
      return;
    }

    if (prompt) {
      handlePromptInput({
        inputValue,
        key,
        prompt,
        setPrompt,
        setFilter,
        setLineIndex: screen === "summary" ? setSummaryLineIndex : setLineIndex,
        setSelectedLineKeys,
        setMessage,
        submitAi: (question, state) => {
          void submitOpenAi({
            run,
            runtime,
            scope: state.scope,
            incident: state.incident,
            lines: state.lines,
            question: state.extraContext
              ? `${question}\n\nContexto TUI:\n${state.extraContext}`
              : question,
            setBusy,
            setMessage,
            setOpenAiAnswer,
            setOpenAiAnswerScroll
          });
        }
      });
      return;
    }

    if (openAiAnswer) {
      if (inputValue === "q") {
        exit();
        return;
      }

      if (inputValue === "b" || key.escape || key.backspace) {
        setOpenAiAnswer(undefined);
        setOpenAiAnswerScroll(0);
        setMessage("Back to analysis");
        return;
      }

      if (key.upArrow) {
        setOpenAiAnswerScroll((value) => Math.max(0, value - 1));
        return;
      }

      if (key.downArrow) {
        setOpenAiAnswerScroll((value) =>
          Math.min(Math.max(0, openAiAnswerLines.length - answerRows), value + 1)
        );
        return;
      }

      if (isPageUp(inputValue, key)) {
        setOpenAiAnswerScroll((value) => Math.max(0, value - answerRows));
        return;
      }

      if (isPageDown(inputValue, key)) {
        setOpenAiAnswerScroll((value) =>
          Math.min(Math.max(0, openAiAnswerLines.length - answerRows), value + answerRows)
        );
        return;
      }

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
        setMessage(screen === "summary" ? "Back to summary" : "Back to incident");
        return;
      }

      if (key.upArrow) {
        setDetailScroll((value) => Math.max(0, value - 1));
        return;
      }

      if (key.downArrow) {
        setDetailScroll((value) => Math.min(Math.max(0, detailLines.length - detailRows), value + 1));
        return;
      }

      if (isPageUp(inputValue, key)) {
        setDetailScroll((value) => Math.max(0, value - detailRows));
        return;
      }

      if (isPageDown(inputValue, key)) {
        setDetailScroll((value) => Math.min(Math.max(0, detailLines.length - detailRows), value + detailRows));
        return;
      }
      return;
    }

    if (inputValue === "q" || (screen === "summary" && key.escape)) {
      exit();
      return;
    }

    if ((inputValue === "b" || key.backspace || key.escape) && screen === "tops") {
      setScreen(topScope === "summary" ? "summary" : "incident");
      setMessage(topScope === "summary" ? "Back to summary" : "Back to incident");
      return;
    }

    if ((inputValue === "b" || key.backspace || key.escape) && screen === "incident") {
      setScreen("summary");
      setMessage("Back to summary");
      return;
    }

    if (screen === "summary") {
      const incidentBounds = isIncidentFocus(summaryFocus)
        ? kindRange(incidents, summaryFocus)
        : { start: -1, end: -1 };

      if (key.upArrow) {
        if (isIncidentFocus(summaryFocus) && incidentBounds.start >= 0) {
          setIncidentIndex((value) => Math.max(incidentBounds.start, value - 1));
        } else {
          setSummaryLineIndex((value) => Math.max(0, value - 1));
        }
        return;
      }

      if (key.downArrow) {
        if (isIncidentFocus(summaryFocus) && incidentBounds.start >= 0) {
          setIncidentIndex((value) => Math.min(incidentBounds.end - 1, value + 1));
        } else {
          setSummaryLineIndex((value) => Math.min(Math.max(0, globalTotal - 1), value + 1));
        }
        return;
      }

      if (isPageUp(inputValue, key)) {
        if (isIncidentFocus(summaryFocus) && incidentBounds.start >= 0) {
          setIncidentIndex((value) => Math.max(incidentBounds.start, value - 7));
        } else {
          setSummaryLineIndex((value) => Math.max(0, value - summaryPageSize));
        }
        return;
      }

      if (isPageDown(inputValue, key)) {
        if (isIncidentFocus(summaryFocus) && incidentBounds.start >= 0) {
          setIncidentIndex((value) => Math.min(incidentBounds.end - 1, value + 7));
        } else {
          setSummaryLineIndex((value) => Math.min(Math.max(0, globalTotal - 1), value + summaryPageSize));
        }
        return;
      }

      if (key.tab) {
        const order = availableFocuses(incidents);
        const idx = order.indexOf(summaryFocus);
        const next = order[(idx === -1 ? 0 : idx + 1) % order.length]!;
        setSummaryFocus(next);
        if (isIncidentFocus(next)) {
          const range = kindRange(incidents, next);
          if (range.start >= 0) {
            setIncidentIndex(range.start);
          }
        }
        return;
      }

      if (key.return && isIncidentFocus(summaryFocus) && incident) {
        setScreen("incident");
        setLineIndex(0);
        setFilter("");
        setSelectedLineKeys(new Set());
        setDetailLine(undefined);
        setMessage(`Opened ${incident.id}`);
        return;
      }

      if ((inputValue === "d" || key.return) && summaryFocus === "accesses") {
        const line = summaryPageLines[summaryLineIndex - summaryPageStart];
        if (line) {
          setDetailLine(line);
          setDetailScroll(0);
        }
        return;
      }

      if (inputValue === "s") {
        setSortMenu({ sortKey, sortDirection, focus: "key" });
        setMessage("Choose sort field and direction");
        return;
      }

      if (inputValue === "S") {
        setSortMenu({ sortKey, sortDirection, focus: "key" });
        setMessage("Choose sort field and direction");
        return;
      }

      if (inputValue === " ") {
        const line = summaryPageLines[summaryLineIndex - summaryPageStart];
        if (line) {
          setSelectedLineKeys((current) => toggleSelection(current, line));
        }
        return;
      }

      if (inputValue === "A") {
        setSelectedLineKeys(new Set(summaryPageLines.map(lineKey)));
        setMessage(`Selected ${summaryPageLines.length} visible lines`);
        return;
      }

      if (inputValue === "r") {
        setFilter("");
        setSummaryLineIndex(0);
        setSelectedLineKeys(new Set());
        setMessage("Filter and selection reset");
        return;
      }

      if (inputValue === "/" || inputValue === "f" || inputValue === "F") {
        setPrompt({ kind: "filter", value: filter, cursor: filter.length });
        return;
      }

      if (inputValue === "t") {
        setTopScope("summary");
        setScreen("tops");
        setMessage("Global top values");
        return;
      }

      if (inputValue === "a") {
        setPrompt({
          kind: "ai",
          value: "",
          cursor: 0,
          scope: "summary",
          lines: selectedGlobalLines.length > 0 ? selectedGlobalLines : summaryPageLines
        });
        return;
      }

      if (inputValue === "e") {
        const exportable = selectedGlobalLines.length > 0 ? selectedGlobalLines : summaryPageLines;
        void exportContext(run.id, undefined, exportable).then((file) => {
          setMessage(`Exported ${exportable.length} lines to ${file}`);
        });
        return;
      }

      return;
    }

    if (screen === "tops") {
      if (key.tab) {
        setTopFocus((value) => nextTopPanel(value));
        return;
      }

      if (key.upArrow) {
        setTopIndexes((value) => ({
          ...value,
          [topFocus]: Math.max(0, value[topFocus] - 1)
        }));
        return;
      }

      if (key.downArrow) {
        setTopIndexes((value) => ({
          ...value,
          [topFocus]: Math.min(9, value[topFocus] + 1)
        }));
        return;
      }

      if (inputValue === "t") {
        setScreen(topScope === "summary" ? "summary" : "incident");
        setMessage(topScope === "summary" ? "Back to summary" : "Back to incident");
        return;
      }

      if (inputValue === "a") {
        const topContext = currentTopContext(run.report, topScope, incident, filter, topFocus, topIndexes);
        setPrompt({
          kind: "ai",
          value: "",
          cursor: 0,
          scope: topScope === "summary" ? "summary" : "incident",
          incident: topScope === "summary" ? undefined : incident,
          lines: [],
          extraContext: topContext
        });
      }

      return;
    }

    if (key.upArrow) {
      setLineIndex((value) => Math.max(0, value - 1));
      return;
    }

    if (key.downArrow) {
      setLineIndex((value) => Math.min(Math.max(0, lines.length - 1), value + 1));
      return;
    }

    if (isPageUp(inputValue, key)) {
      setLineIndex((value) => Math.max(0, value - pageSize));
      return;
    }

    if (isPageDown(inputValue, key)) {
      setLineIndex((value) => Math.min(Math.max(0, lines.length - 1), value + pageSize));
      return;
    }

    if (inputValue === "s") {
      setSortMenu({ sortKey, sortDirection, focus: "key" });
      setMessage("Choose sort field and direction");
      return;
    }

    if (key.tab) {
      return;
    }

    if (inputValue === "S") {
      setSortMenu({ sortKey, sortDirection, focus: "key" });
      setMessage("Choose sort field and direction");
      return;
    }

    if (inputValue === " ") {
      const line = lines[lineIndex];
      if (line) {
        setSelectedLineKeys((current) => toggleSelection(current, line));
      }
      return;
    }

    if (inputValue === "d" || key.return) {
      const line = lines[lineIndex];
      if (line) {
        setDetailLine(line);
        setDetailScroll(0);
      }
      return;
    }

    if (inputValue === "t") {
      setTopScope("incident");
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
      setPrompt({ kind: "filter", value: filter, cursor: filter.length });
      return;
    }

    if (inputValue === "e") {
      const exportable = selectedLines.length > 0 ? selectedLines : lines;
      void exportContext(run.id, incident, exportable).then((file) => {
        setMessage(`Exported ${exportable.length} lines to ${file}`);
      });
      return;
    }

    if (inputValue === "a") {
      setPrompt({
        kind: "ai",
        value: "",
        cursor: 0,
        scope: "incident",
        incident,
        lines: selectedLines.length > 0 ? selectedLines : lines
      });
    }
  });

  return React.createElement(
    Box,
    { flexDirection: "column", paddingX: 1, width: columns, height: rows },
    React.createElement(Header, { run, columns }),
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
        : openAiAnswer
          ? React.createElement(OpenAiAnswerScreen, {
              answer: openAiAnswer,
              visibleLines: visibleOpenAiAnswerLines,
              scroll: openAiAnswerScroll,
              totalLines: openAiAnswerLines.length
            })
        : screen === "summary"
          ? React.createElement(SummaryScreen, {
              report: run.report,
              incidents,
              incidentIndex,
              focus: summaryFocus,
              lines: [],
              totalLines: globalTotal,
              pageLines: summaryPageLines,
              pageStart: summaryPageStart,
              lineIndex: summaryLineIndex,
              filter,
              sortKey,
              sortDirection,
              selectedLineKeys,
              columns
            })
          : screen === "tops"
            ? React.createElement(TopValuesScreen, {
                run,
                accessQueryCache,
                report: run.report,
                incident: topScope === "summary" ? undefined : incident,
                scope: topScope,
                filter,
                focus: topFocus,
                selectedIndexes: topIndexes,
                onApplyFilter: (nextFilter) => {
                  setIndexLoading(true);
                  setFilter(nextFilter);
                  setSelectedLineKeys(new Set());
                  setLineIndex(0);
                  setSummaryLineIndex(0);
                  setSummaryFocus("accesses");
                  setScreen(topScope === "summary" ? "summary" : "incident");
                  setMessage(`Filter applied: ${nextFilter}`);
                },
                columns
              })
          : React.createElement(IncidentScreen, {
              report: run.report,
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
    sortMenu ? React.createElement(SortMenuOverlay, { sortMenu, columns, rows }) : null,
    prompt ? React.createElement(PromptBar, { prompt, columns }) : null,
    React.createElement(Footer, {
      screen,
      summaryFocus,
      detailOpen: Boolean(detailLine),
      answerOpen: Boolean(openAiAnswer),
      busy,
      loading: indexLoading,
      message,
      selected: selectedLineKeys.size,
      columns
    })
  );
}

function Header({ run, columns }: { run: CitrxRun; columns: number }) {
  const report = run.report;
  return React.createElement(
    Text,
    { bold: true, color: "cyan", wrap: "truncate" },
    fitText(
      `citrx ${run.id} | files=${report.summary.files} parsed=${report.summary.parsedLines} incidents=${report.incidents.length}`,
      columns - 2
    )
  );
}

function SummaryScreen({
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
  totalLines
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
}) {
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
      emptyMessage: "No indexed access-log lines"
    })
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
  const successMark = incident.successful ? " !SUCCESS" : "";
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
  // Wrap in a Box so this row is guaranteed to occupy its own line in the
  // parent column layout — two adjacent <Text> siblings can render on the same
  // physical line in Ink under wide terminals.
  const tab = (label: string, count: number, isActive: boolean, color: string) =>
    React.createElement(
      Text,
      { color, bold: true, inverse: isActive },
      `[${label} ${count}]`
    );

  return React.createElement(
    Box,
    { flexShrink: 0 },
    React.createElement(
      Text,
      null,
      tab("SATURATION", saturationCount, focus === "saturation", "yellow"),
      "  ",
      tab("SECURITY", compromiseCount, focus === "compromise", "red"),
      ...(noiseCount > 0
        ? ["  ", tab("OTHER", noiseCount, focus === "noise", "gray")]
        : [])
    )
  );
}

function IncidentList({
  incidents,
  incidentIndex,
  pageSize,
  focus
}: {
  incidents: Incident[];
  incidentIndex: number;
  pageSize: number;
  focus: SummaryFocus;
}) {
  const compromise = incidents.filter((i) => i.kind === "compromise");
  const saturation = incidents.filter((i) => i.kind === "saturation");
  const noise = incidents.filter((i) => i.kind === "noise");

  const focusedKind: "compromise" | "saturation" | "noise" | null =
    focus === "accesses" ? null : focus;

  // Which list to display + its flat-array start offset for cursor mapping.
  const focusedList =
    focusedKind === "compromise"
      ? { items: compromise, start: 0 }
      : focusedKind === "saturation"
      ? { items: saturation, start: compromise.length }
      : focusedKind === "noise"
      ? { items: noise, start: compromise.length + saturation.length }
      : { items: compromise, start: 0 };

  const isPanelActive = focus !== "accesses";
  const localCursor = isPanelActive
    ? Math.max(0, incidentIndex - focusedList.start)
    : 0;
  const sliceStart = Math.max(
    0,
    Math.min(
      localCursor - Math.floor(pageSize / 2),
      Math.max(0, focusedList.items.length - pageSize)
    )
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
    ...(focusedList.items.length > 0
      ? focusedList.items.slice(sliceStart, sliceStart + pageSize).map((incident, offset) =>
          React.createElement(IncidentRow, {
            key: incident.id,
            incident,
            index: focusedList.start + sliceStart + offset,
            incidentIndex,
            active: isPanelActive
          })
        )
      : [React.createElement(Text, { key: "empty", color: "gray" }, "  (no incidents in this category)")])
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
        fitText(`[${incident.kind.toUpperCase()}] ${incident.severity.toUpperCase()} ${incident.score}${incident.successful ? " !SUCCESS" : ""} | ${incident.title}`, headerWidth)
      ),
      React.createElement(Text, { wrap: "truncate" }, fitText(`${incident.id} | ${incident.category} | ${incident.kind}`, headerWidth)),
      React.createElement(Text, { color: "gray", wrap: "truncate" }, fitText(incident.evidence.map((item) => `${item.key}=${item.value}`).join(" | "), headerWidth)),
      React.createElement(
        Text,
        { color: "gray", wrap: "truncate" },
        fitText(
          `matches=${matchSet?.totalMatches ?? 0} related requests`,
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
  run,
  accessQueryCache,
  report,
  incident,
  scope,
  filter,
  focus,
  selectedIndexes,
  onApplyFilter,
  columns
}: {
  run: CitrxRun;
  accessQueryCache: AccessLogIndexQueryCache;
  report: AnalyzeReport;
  incident: Incident | undefined;
  scope: TopScope;
  filter: string;
  focus: TopPanelKey;
  selectedIndexes: Record<TopPanelKey, number>;
  onApplyFilter: (filter: string) => void;
  columns: number;
}) {
  const matchSet = report.incidentMatches.find((item) => item.incidentId === incident?.id);
  const incidentTopValues = useMemo(
    () => incidentInsights(filteredTopLines(matchSet?.lines ?? [], filter)),
    [filter, matchSet]
  );
  const [summaryTopValues, setSummaryTopValues] = useState<{
    insights: IncidentInsights;
    count: number;
  }>();
  const [loading, setLoading] = useState(false);
  const panelWidth = Math.max(30, Math.floor((columns - 7) / 2));
  const headerWidth = Math.max(40, columns - 10);

  useEffect(() => {
    if (scope !== "summary") {
      setLoading(false);
      return;
    }

    let cancelled = false;
    const needsSummaryBuild = Boolean(filter);

    if (needsSummaryBuild) {
      setLoading(true);
      setSummaryTopValues(undefined);
    }

    void incidentInsightsFromAccessIndex(run, accessQueryCache, filter).then((value) => {
      if (!cancelled) {
        setSummaryTopValues(value);
        setLoading(false);
      }
    }).catch(() => {
      if (!cancelled) {
        setSummaryTopValues(undefined);
        setLoading(false);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [accessQueryCache, filter, run, scope]);

  const insights = scope === "summary"
    ? filter
      ? summaryTopValues?.insights ?? emptyIncidentInsights()
      : reportInsights(report)
    : incidentTopValues;
  const sourceCount = scope === "summary"
    ? filter
      ? summaryTopValues?.count ?? 0
      : report.accessLog.totalLines
    : matchSet?.totalMatches ?? 0;
  const selectedTopItem = selectedTopValue(insights, focus, selectedIndexes[focus]);

  useInput((_inputValue, key) => {
    if (!key.return || !selectedTopItem) {
      return;
    }

    onApplyFilter(topItemFilter(focus, selectedTopItem.value));
  });

  if (scope === "incident" && !incident) {
    return React.createElement(Text, null, "No incident selected");
  }

  const title = scope === "summary" ? "Global top values" : `Top values for ${incident?.id ?? "incident"}`;
  const subtitle = scope === "summary"
    ? `${loading ? "computing..." : "computed"} from ${sourceCount}/${report.accessLog.totalLines} parsed access-log rows${filter ? ` | filter=${filter}` : ""}`
    : `computed from ${sourceCount} related requests${filter ? ` | filter=${filter}` : ""}`;

  return React.createElement(
    Box,
    { flexDirection: "column", flexGrow: 1 },
    React.createElement(
      Box,
      { flexDirection: "column", borderStyle: "single", paddingX: 1 },
      React.createElement(
        Text,
        { bold: true, color: scope === "summary" ? "cyan" : severityColor(incident?.severity ?? "info"), wrap: "truncate" },
        fitText(title, headerWidth)
      ),
      React.createElement(
        Text,
        { color: "gray", wrap: "truncate" },
        fitText(subtitle, headerWidth)
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
          panelKey: "ips",
          items: insights.ips,
          width: panelWidth,
          active: focus === "ips",
          selectedIndex: selectedIndexes.ips,
          loading
        }),
        React.createElement(TopListPanel, {
          title: "Top paths",
          panelKey: "paths",
          items: insights.paths,
          width: panelWidth,
          active: focus === "paths",
          selectedIndex: selectedIndexes.paths,
          loading
        })
      ),
      React.createElement(
        Box,
        { flexDirection: "row", gap: 1, flexGrow: 1 },
        React.createElement(TopListPanel, {
          title: "Top user agents",
          panelKey: "userAgents",
          items: insights.userAgents,
          width: panelWidth,
          active: focus === "userAgents",
          selectedIndex: selectedIndexes.userAgents,
          loading
        }),
        React.createElement(TopListPanel, {
          title: "Top query params",
          panelKey: "params",
          items: insights.params,
          width: panelWidth,
          active: focus === "params",
          selectedIndex: selectedIndexes.params,
          loading
        })
      ),
      React.createElement(
        Box,
        { flexDirection: "row", flexGrow: 1 },
        React.createElement(TopListPanel, {
          title: "Top query param values",
          panelKey: "paramValues",
          items: insights.paramValues,
          width: panelWidth,
          active: focus === "paramValues",
          selectedIndex: selectedIndexes.paramValues,
          loading
        })
      )
    )
  );
}

function TopListPanel({
  title,
  panelKey,
  items,
  width,
  active,
  selectedIndex,
  loading = false
}: {
  title: string;
  panelKey: TopPanelKey;
  items: TopItem[];
  width: number;
  active: boolean;
  selectedIndex: number;
  loading?: boolean;
}) {
  const safeSelectedIndex = Math.max(0, Math.min(selectedIndex, Math.max(0, items.length - 1)));

  return React.createElement(
    Box,
    {
      flexDirection: "column",
      borderStyle: "single",
      borderColor: active ? "cyan" : undefined,
      paddingX: 1,
      width
    },
    React.createElement(
      Text,
      { bold: true, color: active ? "cyan" : undefined, wrap: "truncate" },
      fitText(`${active ? "> " : "  "}${title}`, width - 2)
    ),
    ...(loading
      ? [React.createElement(Text, { key: "loading", color: "yellow" }, fitText("computing...", width - 2))]
      : items.length > 0
      ? items.map((item, index) =>
          React.createElement(
            Text,
            {
              key: `${panelKey}:${item.value}`,
              color: active && index === safeSelectedIndex ? "black" : undefined,
              backgroundColor: active && index === safeSelectedIndex ? "white" : undefined,
              wrap: "truncate"
            },
            fitText(`${String(item.count).padStart(5)}  ${item.value}`, width - 2)
          )
        )
      : [React.createElement(Text, { key: "empty", color: "gray" }, "none")])
  );
}

function selectedTopValue(
  insights: IncidentInsights,
  panel: TopPanelKey,
  selectedIndex: number
): TopItem | undefined {
  const items = insights[panel];
  return items[Math.max(0, Math.min(selectedIndex, Math.max(0, items.length - 1)))];
}

function topItemFilter(panel: TopPanelKey, value: string): string {
  switch (panel) {
    case "ips":
      return `ip=${filterValue(value)}`;
    case "paths":
      return `path=${filterValue(value)}`;
    case "userAgents":
      return `ua:${filterValue(value)}`;
    case "params":
      return `param=${filterValue(value)}`;
    case "paramValues":
      return `param:${filterValue(value)}`;
  }
}

function filterValue(value: string): string {
  return `"${value.replace(/["\\]/g, (char) => `\\${char}`)}"`;
}

function currentTopContext(
  report: AnalyzeReport,
  scope: TopScope,
  incident: Incident | undefined,
  filter: string,
  focus: TopPanelKey,
  selectedIndexes: Record<TopPanelKey, number>
): string {
  const matchSet = report.incidentMatches.find((item) => item.incidentId === incident?.id);
  const insights = scope === "summary"
    ? {
        ips: report.topIps,
        paths: report.topPaths,
        userAgents: report.topUserAgents,
        params: report.topParams,
        paramValues: report.topParamValues
      }
    : incidentInsights(filteredTopLines(matchSet?.lines ?? [], filter));
  const selected = selectedTopValue(insights, focus, selectedIndexes[focus]);
  const lines = [
    `scope=${scope}`,
    filter ? `filter=${filter}` : undefined,
    incident ? `incident=${incident.id}` : undefined,
    selected ? `selectedPanel=${focus} selected=${selected.value} count=${selected.count}` : `selectedPanel=${focus}`,
    `topIps=${topItemsForContext(insights.ips)}`,
    `topPaths=${topItemsForContext(insights.paths)}`,
    `topUserAgents=${topItemsForContext(insights.userAgents)}`,
    `topParams=${topItemsForContext(insights.params)}`,
    `topParamValues=${topItemsForContext(insights.paramValues)}`
  ].filter((line): line is string => Boolean(line));

  return lines.join("\n");
}

function topItemsForContext(items: TopItem[]): string {
  return items
    .slice(0, 10)
    .map((item) => `${item.value}:${item.count}`)
    .join(" | ") || "none";
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
}) {
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

function OpenAiAnswerScreen({
  answer,
  visibleLines,
  scroll,
  totalLines
}: {
  answer: OpenAiAnswerState;
  visibleLines: RenderLine[];
  scroll: number;
  totalLines: number;
}) {
  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "double", paddingX: 1, flexGrow: 1 },
    React.createElement(
      Text,
      { bold: true, color: "cyan", wrap: "truncate" },
      `${answer.title} | ${scroll + 1}-${Math.min(scroll + visibleLines.length, totalLines)}/${totalLines}`
    ),
    React.createElement(Text, { color: "gray", wrap: "truncate" }, answer.meta),
    ...visibleLines.map((value, index) =>
      React.createElement(
        Text,
        {
          key: `${scroll + index}:${value.text}`,
          color: value.color,
          bold: value.bold,
          wrap: "truncate"
        },
        value.text
      )
    )
  );
}

function PromptBar({ prompt, columns }: { prompt: PromptState; columns: number }) {
  const label =
    prompt.kind === "filter"
      ? "Filter"
      : prompt.scope === "summary"
        ? "Ask OpenAI about analysis"
        : "Ask OpenAI about incident";
  const display = promptDisplay(prompt, columns - label.length - 8);

  return React.createElement(
    Box,
    { borderStyle: "single", paddingX: 1 },
    React.createElement(Text, { color: "cyan", wrap: "truncate" }, `${label}: `),
    React.createElement(Text, { wrap: "truncate" }, display.beforeCursor),
    React.createElement(Text, { inverse: true }, display.cursorValue),
    React.createElement(Text, { wrap: "truncate" }, display.afterCursor)
  );
}

function SortMenuOverlay({
  sortMenu,
  columns,
  rows
}: {
  sortMenu: {
    sortKey: SortKey;
    sortDirection: SortDirection;
    focus: SortMenuFocus;
  };
  columns: number;
  rows: number;
}) {
  const width = Math.min(62, Math.max(42, columns - 6));
  const innerWidth = width - 6;
  const fieldWidth = Math.floor((width - 10) * 0.58);
  const directionWidth = Math.floor((width - 10) * 0.3);
  const top = Math.max(1, Math.floor((rows - 13) / 2));
  const left = Math.max(0, Math.floor((columns - width) / 2));
  const blankLine = " ".repeat(innerWidth);

  return React.createElement(
    Box,
    {
      position: "absolute",
      top,
      left,
      width,
      flexDirection: "column",
      borderStyle: "double",
      borderColor: "cyan",
      backgroundColor: "black",
      paddingX: 2,
      paddingY: 1
    },
    React.createElement(
      Text,
      { bold: true, color: "cyan", backgroundColor: "black", wrap: "truncate" },
      fitText("Sort log", innerWidth).padEnd(innerWidth)
    ),
    React.createElement(Text, { backgroundColor: "black" }, blankLine),
    React.createElement(
      Box,
      { flexDirection: "row", gap: 4, backgroundColor: "black" },
      React.createElement(
        Box,
        { flexDirection: "column", width: fieldWidth, backgroundColor: "black" },
        React.createElement(
          Text,
          { bold: true, color: sortMenu.focus === "key" ? "cyan" : "gray", backgroundColor: "black" },
          "Field".padEnd(fieldWidth)
        ),
        ...SORT_KEYS.map((key) => {
          const active = sortMenu.sortKey === key;
          const focused = sortMenu.focus === "key" && active;
          return React.createElement(
            Text,
            {
              key,
              bold: active,
              color: focused ? "black" : active ? "yellow" : undefined,
              backgroundColor: focused ? "yellow" : "black",
              wrap: "truncate"
            },
            fitText(`${active ? ">" : " "} ${sortLabel(key)}`, fieldWidth).padEnd(fieldWidth)
          );
        })
      ),
      React.createElement(
        Box,
        { flexDirection: "column", width: directionWidth, backgroundColor: "black" },
        React.createElement(
          Text,
          { bold: true, color: sortMenu.focus === "direction" ? "cyan" : "gray", backgroundColor: "black" },
          "Direction".padEnd(directionWidth)
        ),
        ...(["desc", "asc"] as const).map((direction) => {
          const active = sortMenu.sortDirection === direction;
          const focused = sortMenu.focus === "direction" && active;
          return React.createElement(
            Text,
            {
              key: direction,
              bold: active,
              color: focused ? "black" : active ? "yellow" : undefined,
              backgroundColor: focused ? "yellow" : "black"
            },
            `${active ? ">" : " "} ${direction}`.padEnd(directionWidth)
          );
        })
      )
    ),
    React.createElement(Text, { backgroundColor: "black" }, blankLine),
    React.createElement(
      Box,
      { justifyContent: "center", backgroundColor: "black" },
      React.createElement(
        Text,
        {
          bold: true,
          color: sortMenu.focus === "apply" ? "black" : "yellow",
          backgroundColor: sortMenu.focus === "apply" ? "yellow" : "black"
        },
        "  Filter  "
      )
    ),
    React.createElement(
      Text,
      { color: "gray", backgroundColor: "black", wrap: "truncate" },
      fitText("Arrows move | Space select | Enter apply | Esc cancel", innerWidth).padEnd(innerWidth)
    )
  );
}

function Footer({
  screen,
  summaryFocus,
  detailOpen,
  answerOpen,
  busy,
  loading,
  message,
  selected,
  columns
}: {
  screen: Screen;
  summaryFocus: SummaryFocus;
  detailOpen: boolean;
  answerOpen: boolean;
  busy: boolean;
  loading: boolean;
  message: string;
  selected: number;
  columns: number;
}) {
  const spinner = useSpinner(loading || busy);
  const shortcuts = answerOpen
    ? "↑/↓ PgUp/PgDn scroll | b/Esc close answer | q quit"
    : detailOpen
    ? "↑/↓ PgUp/PgDn scroll | d/b/Esc close | q quit"
    : screen === "summary"
      ? `Tab focus(${summaryFocus}) | ↑/↓ PgUp/PgDn navigate panel | Enter/d open | f filter | s sort menu | t tops | a ask | e export | q quit`
      : screen === "tops"
        ? "Tab panel | ↑/↓ row | Enter filter by value | a ask about tops | t/b/Esc back | q quit"
        : "↑/↓ PgUp/PgDn rows | Enter/d detail | t tops | Space select | A select visible | f filter | s sort menu | a ask | e export | b back | q quit";
  const prefix = loading || busy ? `${spinner} ` : "";
  const status = `${prefix}${busy ? "Asking OpenAI..." : message}${selected ? ` | selected=${selected}` : ""}`;

  return React.createElement(
    Box,
    { flexDirection: "column" },
    React.createElement(Text, { color: busy || loading ? "yellow" : "cyan", wrap: "truncate" }, fitText(status, columns - 2)),
    React.createElement(Text, { color: "cyan", wrap: "truncate" }, fitText(shortcuts, columns - 2))
  );
}

function useSpinner(active: boolean): string {
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    if (!active) {
      setFrame(0);
      return;
    }

    const timer = setInterval(() => {
      setFrame((value) => (value + 1) % SPINNER_FRAMES.length);
    }, 120);

    return () => {
      clearInterval(timer);
    };
  }, [active]);

  return SPINNER_FRAMES[frame] ?? "-";
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
  const paths = new Map<string, number>();
  const userAgents = new Map<string, number>();
  const params = new Map<string, number>();
  const paramValues = new Map<string, number>();

  for (const line of lines) {
    addInsightLine({ ips, paths, userAgents, params, paramValues }, line);
  }

  return topInsightMaps({ ips, paths, userAgents, params, paramValues });
}

async function incidentInsightsFromAccessIndex(
  run: CitrxRun,
  accessQueryCache: AccessLogIndexQueryCache,
  filter: string
): Promise<{
  insights: IncidentInsights;
  count: number;
}> {
  if (!filter) {
    return {
      insights: reportInsights(run.report),
      count: run.report.accessLog.totalLines
    };
  }

  const maps = {
    ips: new Map<string, number>(),
    paths: new Map<string, number>(),
    userAgents: new Map<string, number>(),
    params: new Map<string, number>(),
    paramValues: new Map<string, number>()
  };
  const query = await accessQueryCache.getOrBuild(run.accessIndex, accessQueryKey(filter, "timestamp", "desc"), {
    filter: createAccessLogLineFilter(filter),
    sortKey: "timestamp",
    sortDirection: "desc"
  });

  for (const line of readAccessLogIndexRows(run.accessIndex, query.rows)) {
    addInsightLine(maps, line);
  }

  return {
    insights: topInsightMaps(maps),
    count: query.total
  };
}

function filteredTopLines(lines: IncidentLogLine[], filter: string): IncidentLogLine[] {
  if (!filter) {
    return lines;
  }

  const matches = createAccessLogLineFilter(filter);
  return lines.filter((line) => matches(line));
}

function emptyIncidentInsights(): IncidentInsights {
  return {
    ips: [],
    paths: [],
    userAgents: [],
    params: [],
    paramValues: []
  };
}

function addInsightLine(
  maps: {
    ips: Map<string, number>;
    paths: Map<string, number>;
    userAgents: Map<string, number>;
    params: Map<string, number>;
    paramValues: Map<string, number>;
  },
  line: IncidentLogLine
): void {
  incrementMap(maps.ips, line.ip);
  incrementMap(maps.paths, line.path);
  incrementMap(maps.userAgents, userAgentLabel(line.userAgent));

  for (const param of requestParamNames(line.target)) {
    incrementMap(maps.params, param);
  }

  for (const paramValue of requestParamValueLabels(line.target)) {
    incrementMap(maps.paramValues, paramValue);
  }
}

function topInsightMaps(maps: {
  ips: Map<string, number>;
  paths: Map<string, number>;
  userAgents: Map<string, number>;
  params: Map<string, number>;
  paramValues: Map<string, number>;
}): IncidentInsights {
  return {
    ips: topMapItems(maps.ips, 10),
    paths: topMapItems(maps.paths, 10),
    userAgents: topMapItems(maps.userAgents, 10),
    params: topMapItems(maps.params, 10),
    paramValues: topMapItems(maps.paramValues, 10)
  };
}

function reportInsights(report: AnalyzeReport): IncidentInsights {
  return {
    ips: report.topIps.slice(0, 10),
    paths: report.topPaths.slice(0, 10),
    userAgents: report.topUserAgents.slice(0, 10),
    params: report.topParams.slice(0, 10),
    paramValues: report.topParamValues.slice(0, 10)
  };
}

function accessQueryKey(filter: string, sortKey: SortKey, sortDirection: SortDirection): string {
  return `${sortKey}:${sortDirection}:${filter}`;
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
    sel: 3,
    line: 6,
    time: 15,
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
      ["sel", columns.sel],
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
      [selected ? "*" : "", columns.sel],
      [String(line.lineNumber), columns.line, "right"],
      [compactDateTime(line.timestamp), columns.time],
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

function sortLabel(sortKey: SortKey): string {
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

async function exportContext(
  runId: string,
  incident: Incident | undefined,
  lines: IncidentLogLine[]
): Promise<string> {
  const safeRunId = sanitizeFilePart(runId);
  const safeIncidentId = sanitizeFilePart(incident?.id ?? "summary");
  const file = path.join(process.cwd(), `citrx-${safeRunId}-${safeIncidentId}.json`);
  await writeFile(file, `${JSON.stringify({ incident, lines }, null, 2)}\n`, "utf8");
  return file;
}

function handleSortMenuInput({
  inputValue,
  key,
  sortMenu,
  setSortMenu,
  applySort,
  setMessage
}: {
  inputValue: string;
  key: {
    return?: boolean;
    escape?: boolean;
    backspace?: boolean;
    tab?: boolean;
    upArrow?: boolean;
    downArrow?: boolean;
    leftArrow?: boolean;
    rightArrow?: boolean;
  };
  sortMenu: {
    sortKey: SortKey;
    sortDirection: SortDirection;
    focus: SortMenuFocus;
  };
  setSortMenu: (value: typeof sortMenu | undefined) => void;
  applySort: (sortKey: SortKey, sortDirection: SortDirection) => void;
  setMessage: (value: string) => void;
}): void {
  if (key.escape || key.backspace) {
    setSortMenu(undefined);
    setMessage("Sort cancelled");
    return;
  }

  if (key.return) {
    applySort(sortMenu.sortKey, sortMenu.sortDirection);
    return;
  }

  if (inputValue === " ") {
    if (sortMenu.focus === "apply") {
      applySort(sortMenu.sortKey, sortMenu.sortDirection);
      return;
    }

    setSortMenu({
      ...sortMenu,
      focus: sortMenu.focus === "key" ? "direction" : "apply"
    });
    return;
  }

  if (key.tab) {
    setSortMenu({
      ...sortMenu,
      focus: sortMenu.focus === "key" ? "direction" : sortMenu.focus === "direction" ? "apply" : "key"
    });
    return;
  }

  if (key.leftArrow || key.rightArrow) {
    if (sortMenu.focus === "apply") {
      setSortMenu({
        ...sortMenu,
        focus: key.leftArrow ? "key" : "direction"
      });
      return;
    }

    if (sortMenu.focus === "key") {
      setSortMenu({
        ...sortMenu,
        focus: "direction"
      });
      return;
    }

    setSortMenu({
      ...sortMenu,
      focus: "key"
    });
    return;
  }

  if (key.upArrow || key.downArrow) {
    const step = key.upArrow ? -1 : 1;

    if (sortMenu.focus === "apply") {
      setSortMenu({
        ...sortMenu,
        focus: step < 0 ? "key" : "apply"
      });
      return;
    }

    if (sortMenu.focus === "key") {
      const currentIndex = SORT_KEYS.indexOf(sortMenu.sortKey);

      if (step > 0 && currentIndex === SORT_KEYS.length - 1) {
        setSortMenu({
          ...sortMenu,
          focus: "apply"
        });
        return;
      }

      if (step < 0 && currentIndex === 0) {
        return;
      }

      setSortMenu({
        ...sortMenu,
        sortKey: SORT_KEYS[currentIndex + step] ?? sortMenu.sortKey
      });
      return;
    }

    if (step > 0 && sortMenu.sortDirection === "asc") {
      setSortMenu({
        ...sortMenu,
        focus: "apply"
      });
      return;
    }

    if (step < 0 && sortMenu.sortDirection === "desc") {
      return;
    }

    setSortMenu({
      ...sortMenu,
      sortDirection: sortMenu.sortDirection === "desc" ? "asc" : "desc"
    });
    return;
  }

  if (inputValue === "S") {
    setSortMenu({
      ...sortMenu,
      focus: "direction"
    });
  }
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
    leftArrow?: boolean;
    rightArrow?: boolean;
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

  if (key.leftArrow) {
    setPrompt({ ...prompt, cursor: Math.max(0, prompt.cursor - 1) });
    return;
  }

  if (key.rightArrow) {
    setPrompt({ ...prompt, cursor: Math.min(prompt.value.length, prompt.cursor + 1) });
    return;
  }

  if (key.backspace) {
    if (prompt.cursor === 0) {
      return;
    }

    setPrompt({
      ...prompt,
      value: `${prompt.value.slice(0, prompt.cursor - 1)}${prompt.value.slice(prompt.cursor)}`,
      cursor: prompt.cursor - 1
    });
    return;
  }

  if (key.delete) {
    if (prompt.cursor >= prompt.value.length) {
      return;
    }

    setPrompt({
      ...prompt,
      value: `${prompt.value.slice(0, prompt.cursor)}${prompt.value.slice(prompt.cursor + 1)}`
    });
    return;
  }

  if (key.ctrl || !isPrintableInput(inputValue)) {
    return;
  }

  setPrompt({
    ...prompt,
    value: `${prompt.value.slice(0, prompt.cursor)}${inputValue}${prompt.value.slice(prompt.cursor)}`,
    cursor: prompt.cursor + inputValue.length
  });
}

function promptDisplay(
  prompt: PromptInputState,
  width: number
): { beforeCursor: string; cursorValue: string; afterCursor: string } {
  const safeCursor = Math.max(0, Math.min(prompt.cursor, prompt.value.length));
  const available = Math.max(8, width);

  if (prompt.value.length < available) {
    return {
      beforeCursor: prompt.value.slice(0, safeCursor),
      cursorValue: prompt.value[safeCursor] ?? " ",
      afterCursor: prompt.value.slice(safeCursor + 1)
    };
  }

  const hasCursorChar = safeCursor < prompt.value.length;
  const textSlots = available - 1;
  let start = Math.max(0, safeCursor - Math.floor(textSlots / 2));

  if (safeCursor === prompt.value.length) {
    start = Math.max(0, prompt.value.length - textSlots);
  }

  let end = Math.min(prompt.value.length, start + textSlots);

  if (safeCursor >= end) {
    end = Math.min(prompt.value.length, safeCursor + (hasCursorChar ? 1 : 0));
    start = Math.max(0, end - textSlots);
  }

  const prefix = start > 0 ? "..." : "";
  const suffix = end < prompt.value.length ? "..." : "";
  const visibleBefore = prompt.value.slice(start, safeCursor);
  const visibleAfter = hasCursorChar
    ? prompt.value.slice(safeCursor + 1, end)
    : prompt.value.slice(safeCursor, end);

  return {
    beforeCursor: `${prefix}${visibleBefore}`,
    cursorValue: prompt.value[safeCursor] ?? " ",
    afterCursor: `${visibleAfter}${suffix}`
  };
}

async function submitOpenAi({
  run,
  runtime,
  scope,
  incident,
  lines,
  question,
  setBusy,
  setMessage,
  setOpenAiAnswer,
  setOpenAiAnswerScroll
}: {
  run: CitrxRun;
  runtime: TuiRuntime;
  scope: "summary" | "incident";
  incident?: Incident;
  lines: IncidentLogLine[];
  question: string;
  setBusy: (value: boolean) => void;
  setMessage: (value: string) => void;
  setOpenAiAnswer: (value: OpenAiAnswerState | undefined) => void;
  setOpenAiAnswerScroll: (value: number) => void;
}): Promise<void> {
  setBusy(true);
  try {
    const client = runtime.aiClient ?? new OpenAiIncidentQuestionClient();
    const result = await client.ask({
      report: run.report,
      incident,
      lines,
      question,
      env: runtime.env,
      scope
    });
    setOpenAiAnswer({
      title: scope === "summary" ? "OpenAI analysis" : `OpenAI incident analysis`,
      meta: `${result.model} | sent ${result.sentLines} lines | ${result.sentChars} chars`,
      answer: result.answer
    });
    setOpenAiAnswerScroll(0);
    setMessage("OpenAI answer ready");
  } catch (error) {
    setMessage(error instanceof Error ? error.message : String(error));
  } finally {
    setBusy(false);
  }
}

function isPrintableInput(inputValue: string): boolean {
  return inputValue.length > 0 && !inputValue.startsWith("\u001B");
}

function isPageUp(
  inputValue: string,
  key: { pageUp?: boolean }
): boolean {
  return Boolean(key.pageUp) || inputValue === "\u001B[5~";
}

function isPageDown(
  inputValue: string,
  key: { pageDown?: boolean }
): boolean {
  return Boolean(key.pageDown) || inputValue === "\u001B[6~";
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

function renderMarkdownAnswer(value: string, width: number): RenderLine[] {
  const contentWidth = Math.max(20, width);
  const lines = value.replace(/\r\n/g, "\n").split("\n");
  const rendered: RenderLine[] = [];
  let inCodeBlock = false;

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed.startsWith("```")) {
      inCodeBlock = !inCodeBlock;
      rendered.push({ text: inCodeBlock ? "  ┌─ code" : "  └─", color: "gray" });
      continue;
    }

    if (line.trim().length === 0) {
      rendered.push({ text: "" });
      continue;
    }

    if (inCodeBlock) {
      for (const chunk of wrapHard(line, Math.max(20, contentWidth - 6))) {
        rendered.push({ text: `  │ ${stripMarkdownInline(chunk)}`, color: "green" });
      }
      continue;
    }

    const heading = line.match(/^(#{1,4})\s+(.+)$/);
    if (heading) {
      if (rendered.length > 0 && rendered[rendered.length - 1]?.text !== "") {
        rendered.push({ text: "" });
      }
      rendered.push({
        text: `▶ ${fitText(stripMarkdownInline(heading[2] ?? ""), contentWidth - 2)}`,
        color: "cyan",
        bold: true
      });
      continue;
    }

    const bullet = line.match(/^(\s*)[-*]\s+(.+)$/);
    if (bullet) {
      const indent = " ".repeat(Math.min(6, Math.floor((bullet[1]?.length ?? 0) / 2) * 2));
      const prefix = `${indent}• `;
      for (const [index, chunk] of wrapWords(stripMarkdownInline(bullet[2] ?? ""), Math.max(20, contentWidth - prefix.length)).entries()) {
        rendered.push({
          text: `${index === 0 ? prefix : " ".repeat(prefix.length)}${chunk}`,
          color: index === 0 ? undefined : "gray"
        });
      }
      continue;
    }

    const ordered = line.match(/^(\s*)(\d+)\.\s+(.+)$/);
    if (ordered) {
      const indent = " ".repeat(Math.min(6, Math.floor((ordered[1]?.length ?? 0) / 2) * 2));
      const prefix = `${indent}${ordered[2]}. `;
      for (const [index, chunk] of wrapWords(stripMarkdownInline(ordered[3] ?? ""), Math.max(20, contentWidth - prefix.length)).entries()) {
        rendered.push({
          text: `${index === 0 ? prefix : " ".repeat(prefix.length)}${chunk}`,
          color: index === 0 ? undefined : "gray"
        });
      }
      continue;
    }

    for (const chunk of wrapWords(stripMarkdownInline(line), contentWidth)) {
      rendered.push({ text: chunk });
    }
  }

  return rendered.length > 0 ? rendered : [{ text: "No answer returned." }];
}

function stripMarkdownInline(value: string): string {
  return value
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/__([^_]+)__/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[([^\]]+)]\([^)]+\)/g, "$1");
}

function wrapWords(value: string, width: number): string[] {
  if (value.length <= width) {
    return [value];
  }

  const chunks: string[] = [];
  let current = "";

  for (const word of value.split(/\s+/)) {
    if (word.length > width) {
      if (current) {
        chunks.push(current);
        current = "";
      }
      chunks.push(...wrapHard(word, width));
      continue;
    }

    const next = current ? `${current} ${word}` : word;
    if (next.length > width) {
      chunks.push(current);
      current = word;
    } else {
      current = next;
    }
  }

  if (current) {
    chunks.push(current);
  }

  return chunks.length > 0 ? chunks : [value];
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

function compactDateTime(timestamp: string): string {
  // Apache: "15/Jan/2024:14:30:00 +0000" → "15/Jan 14:30:00"
  const apache = timestamp.match(/^(\d{2}\/\w{3})\/\d{4}:(\d{2}:\d{2}:\d{2})/);
  if (apache) return `${apache[1]} ${apache[2]}`;
  // ISO: "2024-01-15T14:30:00..." → "01-15 14:30:00"
  const iso = timestamp.match(/^\d{4}-(\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/);
  if (iso) return `${iso[1]} ${iso[2]}`;
  return timestamp.slice(0, 15);
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

function nextTopPanel(value: TopPanelKey): TopPanelKey {
  const index = TOP_PANEL_KEYS.indexOf(value);
  return TOP_PANEL_KEYS[(index + 1) % TOP_PANEL_KEYS.length] ?? "ips";
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
