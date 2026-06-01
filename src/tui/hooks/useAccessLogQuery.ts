// Reads paginated access log index pages reactively, managing loading state and message feedback.
import { useEffect, useState } from "react";
import { setImmediate } from "node:timers/promises";

import type { IncidentLogLine } from "../../analysis/types.js";
import type { AccessLogIndexQueryCache } from "../../run/access-index.js";
import { passThroughFilter, readAccessLogIndexCachedPage } from "../../run/access-index.js";
import type { CitrxRun } from "../../run/types.js";
import { createAccessLogLineFilter } from "../filter.js";
import type { SortKey, SortDirection } from "../types.js";

/**
 * Derives a stable string key for the query cache from the active filter,
 * sort column, and sort direction. Used to detect whether a cached index
 * already exists before issuing an async build.
 */
export function accessQueryKey(
  filter: string,
  sortKey: SortKey,
  sortDirection: SortDirection
): string {
  return `${sortKey}:${sortDirection}:${filter}`;
}

/**
 * Options accepted by {@link useAccessLogQuery}.
 */
interface AccessLogQueryOptions {
  /** Run context providing the access index path and baseline stats. */
  run: CitrxRun;
  /**
   * Mutable cache shared across renders. Keyed by {@link accessQueryKey}.
   * Populated lazily on the first fetch for a given filter/sort combination.
   */
  accessQueryCache: AccessLogIndexQueryCache;
  /** Active filter string; empty string disables filtering. */
  filter: string;
  /** Column used to sort the access log. */
  sortKey: SortKey;
  /** Ascending or descending sort order. */
  sortDirection: SortDirection;
  /** Number of log lines to display per page. */
  summaryPageSize: number;
  /** Current cursor position (absolute line index) within the full result set. */
  summaryLineIndex: number;
  /** Called to surface status/error text in the TUI status bar. */
  setMessage: (value: string) => void;
  /** Functional updater that clamps the cursor to the new total after each fetch. */
  setSummaryLineIndex: (updater: (value: number) => number) => void;
}

/**
 * React hook that reactively fetches one page of the access log index.
 *
 * Behaviour:
 * - Re-runs whenever `filter`, `sortKey`, `sortDirection`, `summaryPageSize`,
 *   or the derived `summaryPageStart` changes.
 * - When the requested `(filter, sortKey, sortDirection)` combination is not
 *   yet in `accessQueryCache`, sets `indexLoading = true` and shows a
 *   "Building filter cache…" message while `readAccessLogIndexCachedPage`
 *   builds and stores the index asynchronously.
 * - Subsequent calls for the same key hit the in-memory cache synchronously
 *   (no loading spinner).
 * - Stale fetches are discarded via a `cancelled` flag set in the effect
 *   cleanup, preventing out-of-order state updates.
 * - On error, clears the loading flag and forwards the error message to the
 *   TUI status bar.
 *
 * @returns `globalTotal` – total lines matching the current filter;
 *          `summaryPageLines` – the fetched page of log lines;
 *          `summaryPageStart` – absolute offset of the first line on the page.
 */
export function useAccessLogQuery({
  run,
  accessQueryCache,
  filter,
  sortKey,
  sortDirection,
  summaryPageSize,
  summaryLineIndex,
  setMessage,
  setSummaryLineIndex
}: AccessLogQueryOptions) {
  const [globalTotal, setGlobalTotal] = useState(run.report.accessLog.indexedLines);
  const [summaryPageLines, setSummaryPageLines] = useState<IncidentLogLine[]>([]);
  const [summaryLoading, setSummaryLoading] = useState(false);

  // Compute the page offset from current index and known total.
  const summaryPageStart = Math.max(
    0,
    Math.min(
      summaryLineIndex - Math.floor(summaryPageSize / 2),
      Math.max(0, globalTotal - summaryPageSize)
    )
  );

  useEffect(() => {
    let cancelled = false;
    const filterFn = filter ? createAccessLogLineFilter(filter) : passThroughFilter;
    const cacheKey = accessQueryKey(filter, sortKey, sortDirection);
    const needsIndexBuild = !accessQueryCache.has(cacheKey) && (filter || sortKey !== "timestamp");

    if (needsIndexBuild) {
      setSummaryLoading(true);
      setMessage(filter ? "Building filter cache..." : "Building sort cache...");
    }

    void (async () => {
      if (needsIndexBuild) {
        await setImmediate();
      }

      return readAccessLogIndexCachedPage(run.accessIndex, accessQueryCache, cacheKey, {
        filter: filterFn,
        sortKey,
        sortDirection,
        start: summaryPageStart,
        limit: summaryPageSize
      });
    })()
      .then((page) => {
        if (cancelled) {
          return;
        }

        setGlobalTotal(page.total);
        setSummaryPageLines(page.lines);
        setSummaryLoading(false);
        setMessage(filter || sortKey !== "timestamp" ? "Filter cache ready" : "Ready");

        setSummaryLineIndex((value) => Math.min(Math.max(0, page.total - 1), value));
      })
      .catch((error) => {
        if (!cancelled) {
          setSummaryLoading(false);
          setMessage(error instanceof Error ? error.message : String(error));
        }
      });

    return () => {
      cancelled = true;
    };
  }, [
    accessQueryCache,
    filter,
    run.accessIndex,
    sortDirection,
    sortKey,
    summaryPageSize,
    summaryPageStart
  ]);

  return { globalTotal, summaryPageLines, summaryPageStart, summaryLoading };
}
