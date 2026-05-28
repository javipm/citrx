import React, { useCallback, useMemo, useState } from "react";
import { Box, Text, render, useApp, useInput, useWindowSize } from "ink";

import { createWriteStream } from "node:fs";
import { writeFile, unlink, rename } from "node:fs/promises";
import { finished } from "node:stream/promises";
import path from "node:path";

import type { Incident, IncidentLogLine } from "../analysis/types.js";
import {
  AccessLogIndexQueryCache,
  passThroughFilter,
  readAccessLogIndexCachedPage,
  iterateAccessLogIndexChunks
} from "../run/access-index.js";
import type { CitrxRun } from "../run/types.js";

// Types
export type { TuiRuntime } from "./types.js";
import type { TuiRuntime, ActiveAbortEntry } from "./types.js";

// Utils
import { fitText, sanitizeFilePart } from "./utils/format.js";
import { sortLabel, lineKey } from "./utils/table.js";
import { serializeExport, streamSerializeExport } from "./export.js";
import {
  addLinesToSelectionWithCap,
  INCIDENT_MANUAL_SELECT_LIMIT,
  INCIDENT_SELECT_ALL_LIMIT
} from "./utils/selection.js";

// Hooks
import { useNavigationState } from "./hooks/useNavigationState.js";
import { useContentState } from "./hooks/useContentState.js";
import { useFilterSortState } from "./hooks/useFilterSortState.js";
import { usePageLayout } from "./hooks/usePageLayout.js";
import { useVisibleLines } from "./hooks/useVisibleLines.js";
import { useAccessLogQuery } from "./hooks/useAccessLogQuery.js";
import { useIncidentQuery, IncidentQueryCache } from "./hooks/useIncidentQuery.js";
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
 * Serialize an incident and its associated log lines to a file in cwd.
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
 */
function CitrxExplorer({ run, runtime }: { run: CitrxRun; runtime: TuiRuntime }) {
  const { exit } = useApp();
  const { rows, columns } = useWindowSize();
  const [quitConfirm, setQuitConfirm] = useState(false);
  const [helpOverlay, setHelpOverlay] = useState<HelpOverlayState | null>(null);
  const [activeAbort, setActiveAbort] = useState<ActiveAbortEntry | undefined>(undefined);

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
    selection,
    setSelection,
    selectedLineKeys,
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
  const incidentQueryCache = useMemo(() => new IncidentQueryCache(), [run.accessIndex]);
  const incidents = run.report.incidents;
  const incident = incidents[incidentIndex];

  const incidentMatchSet = useMemo(
    () => run.report.incidentMatches.find((m) => m.incidentId === incident?.id),
    [run.report.incidentMatches, incident?.id]
  );

  const {
    orderedRowNumbers,
    total: incidentTotal,
    building: incidentBuilding
  } = useIncidentQuery({
    matchSet: incidentMatchSet,
    accessIndex: run.accessIndex,
    incidentQueryCache,
    filter,
    sortKey,
    sortDirection,
    setIndexLoading,
    setMessage
  });

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
    pageLines,
    pageLoading,
    pageStart,
    selectedLines,
    selectedLineKeys: derivedSelectedLineKeys,
    selectedGlobalLines,
    detailLines,
    visibleDetailLines,
    openAiAnswerLines,
    visibleOpenAiAnswerLines
  } = useVisibleLines({
    accessIndex: run.accessIndex,
    orderedRowNumbers,
    incidentTotal,
    lineIndex,
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
    selection,
    incidentRowNumbers: incidentMatchSet?.rowNumbers
  });

  // Use the derived set from useVisibleLines (same reference as selectedLineKeys from state)
  void derivedSelectedLineKeys;

  const requestExit = () => {
    setQuitConfirm(true);
    setMessage("Exit citrx? Press y/Enter to quit, Esc/n to stay");
  };

  const handleSelectAll = useCallback(() => {
    if (!orderedRowNumbers || incidentTotal > INCIDENT_SELECT_ALL_LIMIT) {
      // Page-only select
      const { selection: next, capHit } = addLinesToSelectionWithCap(
        selection,
        pageLines,
        INCIDENT_MANUAL_SELECT_LIMIT
      );
      setSelection(() => next);
      setMessage(
        capHit
          ? `Selection cap reached (${INCIDENT_MANUAL_SELECT_LIMIT})`
          : `Selected ${pageLines.length} visible lines`
      );
      return;
    }

    const controller = new AbortController();
    setActiveAbort({ kind: "select-all", controller, label: "Selecting all… Esc to cancel" });
    const total = incidentTotal;

    void (async () => {
      const next = new Map(selection);
      let done = 0;
      let lastMsg = Date.now();
      let capHit = false;
      try {
        for await (const chunk of iterateAccessLogIndexChunks(run.accessIndex, orderedRowNumbers, {
          signal: controller.signal
        })) {
          for (const line of chunk) {
            if (next.size >= INCIDENT_MANUAL_SELECT_LIMIT) {
              capHit = true;
              break;
            }
            next.set(lineKey(line), line);
          }
          done += chunk.length;
          const now = Date.now();
          if (now - lastMsg >= 100) {
            setMessage(`Selecting… ${done.toLocaleString()} / ${total.toLocaleString()}`);
            lastMsg = now;
          }
          if (capHit) break;
          if (controller.signal.aborted) break;
        }
      } catch (err) {
        if (!(err instanceof DOMException && err.name === "AbortError")) {
          setMessage(err instanceof Error ? err.message : String(err));
        }
      } finally {
        setSelection(() => next);
        setActiveAbort(undefined);
        if (!controller.signal.aborted) {
          setMessage(
            capHit
              ? `Selection cap reached (${INCIDENT_MANUAL_SELECT_LIMIT}). Filter to narrow.`
              : `Selected ${next.size.toLocaleString()} rows`
          );
        } else {
          setMessage("Selection cancelled");
        }
      }
    })();
  }, [orderedRowNumbers, incidentTotal, selection, pageLines, run.accessIndex]);

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

    // Incident screen export
    if (selectedLines.length > 0) {
      // Selected rows: in-memory path (fast, bounded)
      const exportable = selectedLines;
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
      return;
    }

    // Full incident: streaming path
    if (!orderedRowNumbers) {
      setMessage("Incident not loaded yet");
      setExportLoading(false);
      return;
    }

    const controller = new AbortController();
    setActiveAbort({ kind: "export", controller, label: "Exporting… Esc to cancel" });
    const safeRunId = sanitizeFilePart(run.id);
    const safeId = sanitizeFilePart(incident?.id ?? "incident");
    const finalPath = path.join(process.cwd(), `citrx-${safeRunId}-${safeId}.${format}`);
    const tmpPath = path.join(
      path.dirname(finalPath),
      `.${path.basename(finalPath)}.tmp-${process.pid}`
    );
    const stream = createWriteStream(tmpPath);
    const sig = controller.signal;

    setTimeout(() => {
      void (async () => {
        try {
          await streamSerializeExport(incident, { run, orderedRowNumbers }, format, stream, {
            signal: sig,
            onProgress: (done, total) => {
              setMessage(
                `Exporting ${format.toUpperCase()}… ${done.toLocaleString()} / ${total.toLocaleString()}`
              );
            }
          });
          stream.end();
          await finished(stream);
          await unlink(finalPath).catch((e: NodeJS.ErrnoException) => {
            if (e.code !== "ENOENT") throw e;
          });
          await rename(tmpPath, finalPath);
          setExportNotice({ file: finalPath, lines: orderedRowNumbers.length, format });
          setMessage(`Export OK: ${orderedRowNumbers.length.toLocaleString()} rows saved`);
        } catch (err) {
          stream.destroy();
          await finished(stream).catch(() => {});
          await unlink(tmpPath).catch(() => {});
          const isAbort = err instanceof DOMException && err.name === "AbortError";
          if (!isAbort) {
            setMessage(`Export failed: ${err instanceof Error ? err.message : String(err)}`);
          } else {
            setMessage("Export cancelled");
          }
        } finally {
          setExportLoading(false);
          setActiveAbort(undefined);
        }
      })();
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
          setSelection(() => new Map());
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
        setSelection: (v) => setSelection(() => v),
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

    // Global Esc: cancel active abort
    if (key.escape && activeAbort) {
      activeAbort.controller.abort();
      setActiveAbort(undefined);
      setMessage("Cancelled");
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
      if (key.escape && incidentBuilding) {
        // Cancel incident build via its own abort (not activeAbort)
        // useIncidentQuery manages its own AbortController internally
      }
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
        setSelection,
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
      total: incidentTotal,
      pageLines,
      pageStart,
      pageLoading,
      selectedLines,
      lineIndex,
      pageSize,
      filter,
      sortKey,
      sortDirection,
      setLineIndex,
      setFilter,
      setSelection,
      setDetailLine,
      setDetailScroll,
      setSortMenu,
      setTopScope,
      setScreen,
      setPrompt,
      setExportMenu,
      setMessage,
      onSelectAll: handleSelectAll
    });
  });

  const loading = indexLoading || exportLoading;

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
                    setSelection(() => new Map());
                    setLineIndex(0);
                    setSummaryLineIndex(0);
                    setSummaryFocus("accesses");
                    setScreen(topScope === "summary" ? "summary" : "incident");
                    setMessage(`Filter applied: ${nextFilter}`);
                  },
                  setActiveAbort,
                  columns
                })
              : React.createElement(IncidentScreen, {
                  report: run.report,
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
                  loading: indexLoading || pageLoading || exportLoading,
                  loadingMessage: exportLoading ? message : "Loading page…"
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
      incidentExportReady: selectedLines.length > 0 || Boolean(orderedRowNumbers),
      message,
      selected: selectedLineKeys.size,
      columns
    })
  );
}
