import React, { useMemo, useState } from "react";
import { Box, Text, render, useApp, useInput, useWindowSize } from "ink";

import { writeFile } from "node:fs/promises";
import path from "node:path";

import type { Incident, IncidentLogLine } from "../analysis/types.js";
import {
  AccessLogIndexQueryCache,
  passThroughFilter,
  readAccessLogIndexCachedPage
} from "../run/access-index.js";
import type { CitrxRun } from "../run/types.js";

// Types
export type { TuiRuntime } from "./types.js";
import type { TuiRuntime } from "./types.js";

// Utils
import { fitText, sanitizeFilePart } from "./utils/format.js";
import { sortLabel } from "./utils/table.js";
import { serializeExport } from "./export.js";

// Hooks
import { useNavigationState } from "./hooks/useNavigationState.js";
import { useContentState } from "./hooks/useContentState.js";
import { useFilterSortState } from "./hooks/useFilterSortState.js";
import { usePageLayout } from "./hooks/usePageLayout.js";
import { useVisibleLines } from "./hooks/useVisibleLines.js";
import { useAccessLogQuery } from "./hooks/useAccessLogQuery.js";
import { handleSortMenuInput } from "./hooks/useSortMenuInput.js";
import { handleExportMenuInput } from "./hooks/useExportMenuInput.js";
import { handlePromptInput } from "./hooks/usePromptInput.js";
import { submitOpenAi } from "./hooks/useSubmitOpenAi.js";
import { handleDetailViewInput } from "./hooks/useDetailViewInput.js";
import { handleOpenAiAnswerInput } from "./hooks/useOpenAiAnswerInput.js";
import { handleSummaryScreenInput } from "./hooks/useSummaryScreenInput.js";
import { handleIncidentScreenInput } from "./hooks/useIncidentScreenInput.js";
import { handleTopsScreenInput } from "./hooks/useTopsScreenInput.js";
import { accessQueryKey } from "./hooks/useAccessLogQuery.js";
import { createAccessLogLineFilter } from "./filter.js";

// Components
import {
  PromptBar,
  SortMenuOverlay,
  ExportMenuOverlay,
  ExportNoticeBar,
  QuitConfirmBar,
  Footer
} from "./components/overlays.js";
import { HelpOverlay } from "./components/helpOverlay.js";

// Screens
import { SummaryScreen } from "./screens/summary.js";
import { IncidentScreen } from "./screens/incident.js";
import { RequestDetailScreen, OpenAiAnswerScreen } from "./screens/detail.js";
import { TopValuesScreen } from "./screens/tops.js";
import type { ExportFormat, HelpOverlayState, HelpContext } from "./types.js";

/**
 * Launch the interactive TUI for a completed citrx run.
 *
 * Renders the {@link CitrxExplorer} React/Ink application into the provided
 * runtime streams and blocks until the user confirms quit (q / Escape, then y / Enter).
 *
 * @param run     The completed `CitrxRun` whose report and logs to explore.
 * @param runtime I/O streams and optional OpenAI client for AI features.
 */
export async function openRunTui(run: CitrxRun, runtime: TuiRuntime): Promise<void> {
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

/**
 * Serialize an incident and its associated log lines to a JSON file in cwd.
 *
 * Output filename: `citrx-<runId>-<incidentId>.json`
 * (or `citrx-<runId>-summary.json` when `incident` is undefined).
 *
 * @param runId    Identifier of the active run; used in the filename.
 * @param incident The incident to export, or `undefined` for a summary export.
 * @param lines    Log lines to include alongside the incident data.
 * @returns        Absolute path of the written file.
 */
async function exportContext(
  runId: string,
  incident: Incident | undefined,
  lines: IncidentLogLine[],
  format: ExportFormat
): Promise<string> {
  const safeRunId = sanitizeFilePart(runId);
  const safeIncidentId = sanitizeFilePart(incident?.id ?? "summary");
  const file = path.join(process.cwd(), `citrx-${safeRunId}-${safeIncidentId}.${format}`);
  await writeFile(file, serializeExport(incident, lines, format), "utf8");
  return file;
}

async function exportAccessLogContext({
  run,
  accessQueryCache,
  filter,
  sortKey,
  sortDirection,
  total,
  format
}: {
  run: CitrxRun;
  accessQueryCache: AccessLogIndexQueryCache;
  filter: string;
  sortKey: "timestamp" | "ip" | "status" | "method" | "path" | "bytes";
  sortDirection: "asc" | "desc";
  total: number;
  format: ExportFormat;
}): Promise<{ file: string; lines: number }> {
  const page = await readAccessLogIndexCachedPage(
    run.accessIndex,
    accessQueryCache,
    accessQueryKey(filter, sortKey, sortDirection),
    {
      filter: filter ? createAccessLogLineFilter(filter) : passThroughFilter,
      sortKey,
      sortDirection,
      start: 0,
      limit: total
    }
  );
  const file = await exportContext(run.id, undefined, page.lines, format);
  return { file, lines: page.lines.length };
}

/**
 * Top status bar showing run ID, file count, parsed line count, and incident count.
 */
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

/**
 * Main TUI orchestrator component.
 *
 * Composes all navigation, content, filter/sort, and layout hooks, then routes
 * keyboard input to the active screen handler (summary, incident, tops, detail,
 * or AI answer). Renders the appropriate screen together with overlay bars
 * (sort menu, prompt, export notice, footer).
 *
 * @param run     The completed `CitrxRun` whose report and logs are displayed.
 * @param runtime I/O streams and optional OpenAI client forwarded to AI hooks.
 */
function CitrxExplorer({ run, runtime }: { run: CitrxRun; runtime: TuiRuntime }) {
  const { exit } = useApp();
  const { rows, columns } = useWindowSize();
  const [quitConfirm, setQuitConfirm] = useState(false);
  const [helpOverlay, setHelpOverlay] = useState<HelpOverlayState | null>(null);

  const {
    screen,
    setScreen,
    summaryFocus,
    setSummaryFocus,
    topScope,
    setTopScope,
    topFocus,
    setTopFocus,
    topIndexes,
    setTopIndexes,
    incidentIndex,
    setIncidentIndex
  } = useNavigationState(run);

  const {
    lineIndex,
    setLineIndex,
    summaryLineIndex,
    setSummaryLineIndex,
    detailLine,
    setDetailLine,
    detailScroll,
    setDetailScroll,
    openAiAnswer,
    setOpenAiAnswer,
    openAiAnswerScroll,
    setOpenAiAnswerScroll
  } = useContentState();

  const {
    filter,
    setFilter,
    sortKey,
    setSortKey,
    sortDirection,
    setSortDirection,
    selectedLineKeys,
    setSelectedLineKeys,
    prompt,
    setPrompt,
    sortMenu,
    setSortMenu,
    exportMenu,
    setExportMenu,
    exportNotice,
    setExportNotice,
    message,
    setMessage,
    busy,
    setBusy,
    exportLoading,
    setExportLoading,
    indexLoading,
    setIndexLoading
  } = useFilterSortState();

  const accessQueryCache = useMemo(() => new AccessLogIndexQueryCache(), [run.accessIndex]);
  const incidents = run.report.incidents;
  const incident = incidents[incidentIndex];

  const { pageSize, summaryPageSize, detailRows, detailWidth, answerRows, answerWidth } =
    usePageLayout({ screen, rows, columns, prompt, exportNotice });

  const {
    globalTotal,
    summaryPageLines,
    summaryPageStart: computedSummaryPageStart
  } = useAccessLogQuery({
    run,
    accessQueryCache,
    filter,
    sortKey,
    sortDirection,
    summaryPageSize,
    summaryLineIndex,
    setIndexLoading,
    setMessage,
    setSummaryLineIndex
  });

  const {
    lines,
    selectedLines,
    selectedGlobalLines,
    pageStart,
    pageLines,
    incidentLinesLoading,
    detailLines,
    visibleDetailLines,
    openAiAnswerLines,
    visibleOpenAiAnswerLines
  } = useVisibleLines({
    run,
    incidentId: incident?.id,
    filter,
    sortKey,
    sortDirection,
    lineIndex,
    summaryPageLines,
    summaryPageStart: computedSummaryPageStart,
    pageSize,
    detailLine,
    detailWidth,
    detailScroll,
    detailRows,
    openAiAnswer,
    answerWidth,
    openAiAnswerScroll,
    answerRows,
    selectedLineKeys
  });

  const requestExit = () => {
    setQuitConfirm(true);
    setMessage("Exit citrx? Press y/Enter to quit, Esc/n to stay");
  };

  const applyExport = (format: ExportFormat) => {
    setExportMenu(undefined);
    setExportLoading(true);
    setMessage(`Exporting ${format.toUpperCase()}...`);

    if (screen === "summary") {
      if (selectedGlobalLines.length > 0) {
        const exportable = selectedGlobalLines;
        setTimeout(() => {
          void exportContext(run.id, undefined, exportable, format)
            .then((file) => {
              setExportNotice({ file, lines: exportable.length, format });
              setMessage(`Export OK: ${exportable.length} rows saved`);
            })
            .catch((error) => {
              setMessage(
                `Export failed: ${error instanceof Error ? error.message : String(error)}`
              );
            })
            .finally(() => {
              setExportLoading(false);
            });
        }, 0);
        return;
      }

      setTimeout(() => {
        void exportAccessLogContext({
          run,
          accessQueryCache,
          filter,
          sortKey,
          sortDirection,
          total: globalTotal,
          format
        })
          .then(({ file, lines }) => {
            setExportNotice({ file, lines, format });
            setMessage(`Export OK: ${lines} rows saved`);
          })
          .catch((error) => {
            setMessage(`Export failed: ${error instanceof Error ? error.message : String(error)}`);
          })
          .finally(() => {
            setExportLoading(false);
          });
      }, 0);
      return;
    }

    const exportable = selectedLines.length > 0 ? selectedLines : lines;
    setTimeout(() => {
      void exportContext(run.id, incident, exportable, format)
        .then((file) => {
          setExportNotice({ file, lines: exportable.length, format });
          setMessage(`Export OK: ${exportable.length} rows saved`);
        })
        .catch((error) => {
          setMessage(`Export failed: ${error instanceof Error ? error.message : String(error)}`);
        })
        .finally(() => {
          setExportLoading(false);
        });
    }, 0);
  };

  useInput((inputValue, key) => {
    if (quitConfirm) {
      if (inputValue === "y" || inputValue === "Y" || key.return) {
        exit();
        return;
      }

      if (inputValue === "n" || inputValue === "N" || inputValue === "b" || key.escape) {
        setQuitConfirm(false);
        setMessage("Exit cancelled");
        return;
      }

      setMessage("Exit citrx? Press y/Enter to quit, Esc/n to stay");
      return;
    }

    if (helpOverlay) {
      if (inputValue === "h" || inputValue === "H" || key.escape) {
        setHelpOverlay(null);
        setMessage("Help closed");
        return;
      }

      if (key.tab || key.rightArrow || key.leftArrow) {
        setHelpOverlay({
          ...helpOverlay,
          tab: helpOverlay.tab === "keys" ? "filters" : "keys",
          scroll: 0
        });
        return;
      }

      if (key.downArrow) {
        setHelpOverlay({ ...helpOverlay, scroll: helpOverlay.scroll + 1 });
        return;
      }

      if (key.upArrow) {
        setHelpOverlay({ ...helpOverlay, scroll: Math.max(0, helpOverlay.scroll - 1) });
        return;
      }

      if (key.pageDown) {
        setHelpOverlay({ ...helpOverlay, scroll: helpOverlay.scroll + 8 });
        return;
      }

      if (key.pageUp) {
        setHelpOverlay({ ...helpOverlay, scroll: Math.max(0, helpOverlay.scroll - 8) });
        return;
      }

      return;
    }

    if (!prompt && (inputValue === "h" || inputValue === "H")) {
      const context: HelpContext = detailLine
        ? "detail"
        : openAiAnswer
          ? "answer"
          : exportMenu
            ? "exportMenu"
            : sortMenu
              ? "sortMenu"
              : (screen as HelpContext);
      setHelpOverlay({ context, tab: "keys", scroll: 0 });
      setMessage("Help: Tab switch tab | Esc/h close");
      return;
    }

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

    if (exportMenu) {
      handleExportMenuInput({
        inputValue,
        key,
        exportMenu,
        setExportMenu,
        applyExport,
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
      handleOpenAiAnswerInput({
        inputValue,
        key,
        openAiAnswerLines,
        answerRows,
        exit: requestExit,
        setOpenAiAnswer,
        setOpenAiAnswerScroll,
        setMessage
      });
      return;
    }

    if (detailLine) {
      handleDetailViewInput({
        inputValue,
        key,
        screen,
        detailLines,
        detailRows,
        exit: requestExit,
        setDetailLine,
        setDetailScroll,
        setMessage
      });
      return;
    }

    if (inputValue === "q" || (screen === "summary" && key.escape)) {
      requestExit();
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
      handleSummaryScreenInput({
        inputValue,
        key,
        incidents,
        incident,
        summaryFocus,
        summaryPageLines,
        summaryLineIndex,
        computedSummaryPageStart,
        globalTotal,
        summaryPageSize,
        selectedGlobalLines,
        filter,
        sortKey,
        sortDirection,
        runId: run.id,
        setSummaryFocus,
        setIncidentIndex,
        setSummaryLineIndex,
        setScreen,
        setLineIndex,
        setFilter,
        setSelectedLineKeys,
        setDetailLine,
        setDetailScroll,
        setSortMenu,
        setTopScope,
        setPrompt,
        setExportMenu,
        setMessage
      });
      return;
    }

    if (screen === "tops") {
      handleTopsScreenInput({
        inputValue,
        key,
        run,
        incident,
        topScope,
        topFocus,
        topIndexes,
        filter,
        setTopFocus,
        setTopIndexes,
        setScreen,
        setPrompt,
        setMessage
      });
      return;
    }

    // incident screen (default)
    handleIncidentScreenInput({
      inputValue,
      key,
      incident,
      lines,
      selectedLines,
      lineIndex,
      pageSize,
      filter,
      sortKey,
      sortDirection,
      runId: run.id,
      exportReady: !incidentLinesLoading,
      setLineIndex,
      setFilter,
      setSelectedLineKeys,
      setDetailLine,
      setDetailScroll,
      setSortMenu,
      setTopScope,
      setScreen,
      setPrompt,
      setExportMenu,
      setMessage
    });
  });

  const loading = indexLoading || incidentLinesLoading || exportLoading;

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
                pageStart: computedSummaryPageStart,
                lineIndex: summaryLineIndex,
                filter,
                sortKey,
                sortDirection,
                selectedLineKeys,
                columns,
                loading: indexLoading
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
                  onApplyFilter: (nextFilter: string) => {
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
                  columns,
                  loading: indexLoading || incidentLinesLoading
                })
    ),
    sortMenu ? React.createElement(SortMenuOverlay, { sortMenu, columns, rows }) : null,
    exportMenu ? React.createElement(ExportMenuOverlay, { exportMenu, columns, rows }) : null,
    prompt ? React.createElement(PromptBar, { prompt, columns }) : null,
    exportNotice ? React.createElement(ExportNoticeBar, { notice: exportNotice, columns }) : null,
    quitConfirm ? React.createElement(QuitConfirmBar, { columns }) : null,
    helpOverlay ? React.createElement(HelpOverlay, { state: helpOverlay, columns, rows }) : null,
    React.createElement(Footer, {
      screen,
      summaryFocus,
      detailOpen: Boolean(detailLine),
      answerOpen: Boolean(openAiAnswer),
      busy,
      loading,
      incidentExportReady: !incidentLinesLoading,
      message,
      selected: selectedLineKeys.size,
      columns
    })
  );
}
