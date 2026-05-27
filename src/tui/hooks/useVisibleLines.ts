// Derives all visible line sets from raw data, filters, sort, and pagination parameters.
import { useEffect, useMemo, useState } from "react";
import { setImmediate } from "node:timers/promises";
import type { IncidentLogLine } from "../../analysis/types.js";
import { readAccessLogIndexRows } from "../../run/access-index.js";
import type { CitrxRun } from "../../run/types.js";
import type { SortKey, SortDirection, OpenAiAnswerState } from "../types.js";
import { createAccessLogLineFilter } from "../filter.js";
import { renderMarkdownAnswer, requestDetailLines } from "../utils/text.js";
import { lineKey, compareLine } from "../utils/table.js";

const INCIDENT_HYDRATION_BATCH = 2000;

function visibleFilteredLines(
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

/** All inputs consumed by {@link useVisibleLines}. */
interface VisibleLinesOptions {
  /** Active analysis run providing `report.incidentMatches`. */
  run: CitrxRun;
  /** ID of the incident whose log lines are being viewed, or `undefined` on the summary screen. */
  incidentId: string | undefined;
  /** Free-text filter applied to log lines. */
  filter: string;
  /** Column used as primary sort key. */
  sortKey: SortKey;
  /** Ascending or descending sort direction. */
  sortDirection: SortDirection;
  /** Zero-based index of the cursor row within the filtered+sorted `lines` array. */
  lineIndex: number;
  /** Pre-computed page of log lines shown on the summary screen. */
  summaryPageLines: IncidentLogLine[];
  /** Index of the first visible row on the summary page. */
  summaryPageStart: number;
  /** Number of rows visible in the main log-line viewport. */
  pageSize: number;
  /** The log line whose detail panel is currently open, or `undefined` if closed. */
  detailLine: IncidentLogLine | undefined;
  /** Terminal column-width available for the detail panel. */
  detailWidth: number;
  /** Vertical scroll offset inside the detail panel (rows from top). */
  detailScroll: number;
  /** Number of visible rows in the detail panel. */
  detailRows: number;
  /** Current AI answer state, or `undefined` when the panel is closed. */
  openAiAnswer: OpenAiAnswerState | undefined;
  /** Terminal column-width available for the AI answer panel. */
  answerWidth: number;
  /** Vertical scroll offset inside the AI answer panel (rows from top). */
  openAiAnswerScroll: number;
  /** Number of visible rows in the AI answer panel. */
  answerRows: number;
  /** Set of line keys (from `lineKey()`) that the user has selected/checked. */
  selectedLineKeys: Set<string>;
}

/**
 * Derives all visible line slices used by the incident and summary screens.
 *
 * All values are memoized; a slice is only recomputed when its specific
 * dependencies change.
 *
 * @returns An object containing:
 * - `allIncidentLines`       – Raw, unfiltered lines for the current incident.
 * - `lines`                  – Filtered and sorted subset of `allIncidentLines`.
 * - `selectedLines`          – Rows from `lines` whose key is in `selectedLineKeys`.
 * - `selectedGlobalLines`    – Rows from `summaryPageLines` whose key is in `selectedLineKeys`.
 * - `pageStart`              – Index of the first row in the current viewport window.
 * - `pageLines`              – The `pageSize`-sized slice of `lines` for the viewport.
 * - `summaryPageStart`       – Passed through from options (summary screen page offset).
 * - `detailLines`            – Word-wrapped lines for the detail panel.
 * - `visibleDetailLines`     – The visible slice of `detailLines` after `detailScroll`.
 * - `openAiAnswerLines`      – Rendered markdown lines for the AI answer panel.
 * - `visibleOpenAiAnswerLines` – The visible slice of `openAiAnswerLines` after scroll.
 */
export function useVisibleLines({
  run,
  incidentId,
  filter,
  sortKey,
  sortDirection,
  lineIndex,
  summaryPageLines,
  summaryPageStart,
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
}: VisibleLinesOptions) {
  const matchSet = useMemo(
    () => run.report.incidentMatches.find((item) => item.incidentId === incidentId),
    [run.report.incidentMatches, incidentId]
  );
  const [allIncidentLines, setAllIncidentLines] = useState<IncidentLogLine[]>(() =>
    matchSet?.lines ?? []
  );
  const [incidentLinesLoading, setIncidentLinesLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;

    if (!matchSet) {
      setAllIncidentLines([]);
      setIncidentLinesLoading(false);
      return () => {
        cancelled = true;
      };
    }

    setAllIncidentLines(matchSet.lines);

    if (matchSet.rowNumbers.length <= matchSet.lines.length) {
      setIncidentLinesLoading(false);
      return () => {
        cancelled = true;
      };
    }

    setIncidentLinesLoading(true);

    void (async () => {
      const loadedRows = new Set(matchSet.lines.map((line) => line.row));
      let hydrated = matchSet.lines;

      for (let start = 0; start < matchSet.rowNumbers.length; start += INCIDENT_HYDRATION_BATCH) {
        await setImmediate();

        if (cancelled) {
          return;
        }

        const batch = readAccessLogIndexRows(
          run.accessIndex,
          matchSet.rowNumbers.slice(start, start + INCIDENT_HYDRATION_BATCH)
        ).filter((line) => {
          if (loadedRows.has(line.row)) {
            return false;
          }

          loadedRows.add(line.row);
          return true;
        });

        if (batch.length === 0) {
          continue;
        }

        hydrated = [...hydrated, ...batch];

        if (!cancelled) {
          setAllIncidentLines(hydrated);
        }
      }

      if (!cancelled) {
        setIncidentLinesLoading(false);
      }
    })().catch(() => {
      if (!cancelled) {
        setIncidentLinesLoading(false);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [matchSet, run.accessIndex]);

  const lines = useMemo(
    () => visibleFilteredLines(allIncidentLines, filter, sortKey, sortDirection),
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

  const pageStart = useMemo(
    () =>
      Math.max(
        0,
        Math.min(lineIndex - Math.floor(pageSize / 2), Math.max(0, lines.length - pageSize))
      ),
    [lineIndex, pageSize, lines.length]
  );

  const pageLines = useMemo(
    () => lines.slice(pageStart, pageStart + pageSize),
    [lines, pageStart, pageSize]
  );

  const detailLines = useMemo(
    () => (detailLine ? requestDetailLines(detailLine, detailWidth) : []),
    [detailLine, detailWidth]
  );

  const visibleDetailLines = useMemo(
    () => detailLines.slice(detailScroll, detailScroll + detailRows),
    [detailLines, detailScroll, detailRows]
  );

  const openAiAnswerLines = useMemo(
    () => (openAiAnswer ? renderMarkdownAnswer(openAiAnswer.answer, answerWidth) : []),
    [openAiAnswer, answerWidth]
  );

  const visibleOpenAiAnswerLines = useMemo(
    () => openAiAnswerLines.slice(openAiAnswerScroll, openAiAnswerScroll + answerRows),
    [openAiAnswerLines, openAiAnswerScroll, answerRows]
  );

  return {
    allIncidentLines,
    lines,
    selectedLines,
    selectedGlobalLines,
    incidentLinesLoading,
    pageStart,
    pageLines,
    summaryPageStart,
    detailLines,
    visibleDetailLines,
    openAiAnswerLines,
    visibleOpenAiAnswerLines
  };
}
