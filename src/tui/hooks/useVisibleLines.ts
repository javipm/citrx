// Derives viewport + detail slices. Incident lines load on demand by bucket.
import { useEffect, useMemo, useRef, useState } from "react";
import type { IncidentLogLine } from "../../analysis/types.js";
import {
  type OrderedRowNumbers,
  type AccessLogIndex,
  arrayOrderedRowNumbers,
  iterateAccessLogIndexChunks
} from "../../run/access-index.js";
import { requestDetailLines } from "../utils/text.js";

const INCIDENT_BUCKET_SIZE = 200;
const INCIDENT_PAGE_CACHE_MAX = 50;

export function binarySearchIncludes(arr: readonly number[], val: number): boolean {
  let lo = 0;
  let hi = arr.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const v = arr[mid]!;
    if (v === val) return true;
    if (v < val) lo = mid + 1;
    else hi = mid - 1;
  }
  return false;
}

/** All inputs consumed by {@link useVisibleLines}. */
interface VisibleLinesOptions {
  /** Access log index, used by the bucket loader. */
  accessIndex: AccessLogIndex;
  /** Ordered row numbers for the incident (null on summary screen). */
  orderedRowNumbers: OrderedRowNumbers | null;
  /** Total filtered lines for the incident (from useIncidentQuery). */
  incidentTotal: number;
  /** Zero-based cursor index within the filtered+sorted rows. */
  lineIndex: number;
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
  /** Selection map (line key → line) across all screens. */
  selection: Map<string, IncidentLogLine>;
  /** Sorted row numbers of the current incident match set (for cross-screen selection filtering). */
  incidentRowNumbers?: readonly number[];
}

export function useVisibleLines({
  accessIndex,
  orderedRowNumbers,
  incidentTotal,
  lineIndex,
  summaryPageStart,
  pageSize,
  detailLine,
  detailWidth,
  detailScroll,
  detailRows,
  selection,
  incidentRowNumbers
}: VisibleLinesOptions) {
  // ── Bucket cache (incident path) ─────────────────────────────────────────
  const bucketCacheRef = useRef<Map<number, IncidentLogLine[]>>(new Map());
  const inFlightRef = useRef<Map<number, Promise<IncidentLogLine[]>>>(new Map());
  const cacheOrderRef = useRef<number[]>([]); // LRU order (front=oldest)
  const prevOrderedRef = useRef<OrderedRowNumbers | null>(null);
  const cancelledRef = useRef(false);
  const lastGoodViewportRef = useRef<{
    pageLines: IncidentLogLine[];
    pageStart: number;
    lineIndex: number;
  } | null>(null);

  // Reset bucket cache when orderedRowNumbers reference changes (new build or new incident)
  if (prevOrderedRef.current !== orderedRowNumbers) {
    prevOrderedRef.current = orderedRowNumbers;
    bucketCacheRef.current = new Map();
    inFlightRef.current = new Map();
    cacheOrderRef.current = [];
    lastGoodViewportRef.current = null;
  }

  // ── Page geometry ─────────────────────────────────────────────────────────
  const pageStart = useMemo(
    () =>
      Math.max(
        0,
        Math.min(lineIndex - Math.floor(pageSize / 2), Math.max(0, incidentTotal - pageSize))
      ),
    [lineIndex, pageSize, incidentTotal]
  );

  const firstBucket = Math.floor(pageStart / INCIDENT_BUCKET_SIZE);
  const lastBucket = Math.floor(
    Math.max(0, Math.min(pageStart + pageSize - 1, incidentTotal - 1)) / INCIDENT_BUCKET_SIZE
  );

  const requiredBucketsKey = useMemo(() => {
    if (!orderedRowNumbers || incidentTotal === 0) return "";
    const bs: number[] = [];
    for (let b = firstBucket; b <= lastBucket; b++) bs.push(b);
    return bs.join(",");
  }, [firstBucket, lastBucket, orderedRowNumbers, incidentTotal]);

  // ── Bucket loader effect ───────────────────────────────────────────────────
  const [pageVersion, setPageVersion] = useState(0);

  useEffect(() => {
    if (!orderedRowNumbers || requiredBucketsKey === "") return;

    cancelledRef.current = false;
    const neededBuckets = requiredBucketsKey.split(",").map(Number);

    for (const b of neededBuckets) {
      if (bucketCacheRef.current.has(b) || inFlightRef.current.has(b)) continue;

      const start = b * INCIDENT_BUCKET_SIZE;
      const end = Math.min(start + INCIDENT_BUCKET_SIZE, orderedRowNumbers.length);
      const sliceRows: number[] = [];
      for (let i = start; i < end; i++) {
        sliceRows.push(orderedRowNumbers.rowAt(i));
      }

      const promise = (async (): Promise<IncidentLogLine[]> => {
        const lines: IncidentLogLine[] = [];
        for await (const chunk of iterateAccessLogIndexChunks(
          accessIndex,
          arrayOrderedRowNumbers(sliceRows)
        )) {
          lines.push(...chunk);
        }
        return lines;
      })();

      inFlightRef.current.set(b, promise);

      promise
        .then((lines) => {
          if (cancelledRef.current) return;
          inFlightRef.current.delete(b);

          // LRU eviction: skip pinned (in-flight) entries
          while (cacheOrderRef.current.length >= INCIDENT_PAGE_CACHE_MAX) {
            const oldest = cacheOrderRef.current[0];
            if (oldest === undefined) break;
            if (inFlightRef.current.has(oldest)) break; // pinned
            cacheOrderRef.current.shift();
            bucketCacheRef.current.delete(oldest);
          }
          bucketCacheRef.current.set(b, lines);
          cacheOrderRef.current.push(b);
          setPageVersion((v) => v + 1);
        })
        .catch(() => {
          if (!cancelledRef.current) inFlightRef.current.delete(b);
        });
    }

    return () => {
      cancelledRef.current = true;
    };
  }, [requiredBucketsKey, orderedRowNumbers, accessIndex]);

  // ── Viewport derivation ────────────────────────────────────────────────────
  const { pageLines, pageLoading } = useMemo(() => {
    void pageVersion; // trigger re-memo when a bucket loads

    if (!orderedRowNumbers || incidentTotal === 0) {
      return { pageLines: [] as IncidentLogLine[], pageLoading: false };
    }

    const neededBuckets: number[] = requiredBucketsKey
      ? requiredBucketsKey.split(",").map(Number)
      : [];
    const allLoaded =
      neededBuckets.length > 0 && neededBuckets.every((b) => bucketCacheRef.current.has(b));

    if (allLoaded) {
      const allLines: IncidentLogLine[] = [];
      for (const b of neededBuckets) {
        allLines.push(...(bucketCacheRef.current.get(b) ?? []));
      }
      const startInFirst = pageStart - firstBucket * INCIDENT_BUCKET_SIZE;
      const slice = allLines.slice(startInFirst, startInFirst + pageSize);
      lastGoodViewportRef.current = { pageLines: slice, pageStart, lineIndex };
      return { pageLines: slice, pageLoading: false };
    }

    if (lastGoodViewportRef.current) {
      return { pageLines: lastGoodViewportRef.current.pageLines, pageLoading: true };
    }
    return { pageLines: [] as IncidentLogLine[], pageLoading: true };
  }, [pageVersion, orderedRowNumbers, incidentTotal, requiredBucketsKey, pageStart, pageSize]);

  // ── Selection ──────────────────────────────────────────────────────────────
  const selectedLineKeys = useMemo(() => new Set(selection.keys()), [selection]);

  // All selected lines across any screen
  const selectedGlobalLines = useMemo(() => Array.from(selection.values()), [selection]);

  // Selected lines scoped to the current incident (binary search for membership)
  const selectedLines = useMemo(
    () =>
      incidentRowNumbers
        ? selectedGlobalLines.filter((l) => binarySearchIncludes(incidentRowNumbers, l.row))
        : [],
    [selectedGlobalLines, incidentRowNumbers]
  );

  // ── Detail panel ──────────────────────────────────────────────────────────
  const detailLines = useMemo(
    () => (detailLine ? requestDetailLines(detailLine, detailWidth) : []),
    [detailLine, detailWidth]
  );

  const visibleDetailLines = useMemo(
    () => detailLines.slice(detailScroll, detailScroll + detailRows),
    [detailLines, detailScroll, detailRows]
  );

  return {
    pageLines,
    pageLoading,
    pageStart,
    selectedLines,
    selectedLineKeys,
    selectedGlobalLines,
    summaryPageStart,
    detailLines,
    visibleDetailLines
  };
}
