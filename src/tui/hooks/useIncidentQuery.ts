// On-demand incident query: default fast path via virtual accessor, build path
// via background scan+sort. Mirrors useAccessLogQuery but scoped to one incident.
import { useEffect, useMemo, useRef, useState } from "react";
import { setImmediate } from "node:timers/promises";
import type { IncidentMatchSet } from "../../analysis/types.js";
import {
  type OrderedRowNumbers,
  type AccessLogIndex,
  arrayOrderedRowNumbers,
  iterateAccessLogIndexChunks,
  sortInChunks
} from "../../run/access-index.js";
import { compareSortableValue, compareRow } from "../../utils/line-compare.js";
import { createAccessLogLineFilter } from "../filter.js";
import type { SortKey, SortDirection } from "../types.js";

const INCIDENT_QUERY_CACHE_MAX = 32;
const INCIDENT_PROGRESS_THROTTLE_MS = 100;

export function incidentQueryKey(
  incidentId: string,
  filter: string,
  sortKey: SortKey,
  sortDir: SortDirection
): string {
  return `${incidentId}:${sortKey}:${sortDir}:${filter}`;
}

type QueryResult = { orderedRowNumbers: OrderedRowNumbers; total: number };

interface CacheEntry {
  promise: Promise<QueryResult>;
  controller?: AbortController;
  resolved: boolean;
}

export class IncidentQueryCache {
  private readonly entries = new Map<string, CacheEntry>();
  private readonly order: string[] = [];

  get(key: string): CacheEntry | undefined {
    const entry = this.entries.get(key);
    if (entry) {
      const idx = this.order.indexOf(key);
      if (idx !== -1) this.order.splice(idx, 1);
      this.order.push(key);
    }
    return entry;
  }

  set(key: string, entry: CacheEntry): void {
    const existing = this.entries.get(key);
    if (existing) {
      this.entries.set(key, entry);
      const idx = this.order.indexOf(key);
      if (idx !== -1) this.order.splice(idx, 1);
      this.order.push(key);
      return;
    }
    // Evict oldest resolved entry when over cap
    while (this.order.length >= INCIDENT_QUERY_CACHE_MAX) {
      const oldest = this.order[0];
      if (!oldest) break;
      const old = this.entries.get(oldest);
      if (old && !old.resolved) break; // pinned (in-flight)
      this.order.shift();
      this.entries.delete(oldest);
    }
    this.entries.set(key, entry);
    this.order.push(key);
  }

  delete(key: string): void {
    this.entries.delete(key);
    const idx = this.order.indexOf(key);
    if (idx !== -1) this.order.splice(idx, 1);
  }

  clearByIncidentId(incidentId: string): void {
    const prefix = `${incidentId}:`;
    for (const [key, entry] of this.entries) {
      if (key.startsWith(prefix)) {
        entry.controller?.abort();
        this.entries.delete(key);
      }
    }
    const toRemove = this.order.filter((k) => k.startsWith(prefix));
    for (const k of toRemove) {
      const idx = this.order.indexOf(k);
      if (idx !== -1) this.order.splice(idx, 1);
    }
  }
}

function virtualOrderedRowNumbers(
  rowNumbers: readonly number[],
  sortDir: SortDirection
): OrderedRowNumbers {
  return {
    get length() {
      return rowNumbers.length;
    },
    rowAt(i: number): number {
      if (i < 0 || i >= rowNumbers.length) {
        throw new RangeError(`index ${i} out of range [0, ${rowNumbers.length})`);
      }
      if (sortDir === "asc") return rowNumbers[i]!;
      return rowNumbers[rowNumbers.length - 1 - i]!;
    }
  };
}

function sortableValueForKey(
  line: { timestamp: string; ip: string; status: number; method: string; path: string; bytes: number | null },
  sortKey: SortKey
): string | number {
  if (sortKey === "bytes") return line.bytes ?? 0;
  if (sortKey === "status") return line.status;
  return String((line as Record<string, unknown>)[sortKey]);
}

async function buildIncidentSubset(
  matchSet: IncidentMatchSet,
  accessIndex: AccessLogIndex,
  filter: string,
  sortKey: SortKey,
  sortDir: SortDirection,
  signal: AbortSignal,
  onProgress?: (done: number, total: number) => void
): Promise<QueryResult> {
  const filterFn = filter ? createAccessLogLineFilter(filter) : null;
  const source = arrayOrderedRowNumbers(matchSet.rowNumbers);
  const total = matchSet.rowNumbers.length;

  let done = 0;
  let lastProgress = 0;

  // Filter-only with timestamp sort: collect matching rows then optionally reverse
  if (!filter && sortKey === "timestamp") {
    // No build needed — default fast path handles this
    throw new Error("default fast path should be used");
  }

  if (sortKey === "timestamp") {
    // Filter only, no sort change — collect matching row numbers in stream order
    const rows: number[] = [];
    for await (const chunk of iterateAccessLogIndexChunks(accessIndex, source, {
      signal
    })) {
      for (const line of chunk) {
        if (!filterFn || filterFn(line)) {
          rows.push(line.row);
        }
      }
      done += chunk.length;
      const now = Date.now();
      if (onProgress && now - lastProgress >= INCIDENT_PROGRESS_THROTTLE_MS) {
        onProgress(done, total);
        lastProgress = now;
      }
    }
    onProgress?.(done, total);
    if (sortDir === "desc") rows.reverse();
    return { orderedRowNumbers: arrayOrderedRowNumbers(rows), total: rows.length };
  }

  // Non-timestamp sort: collect { row, value } tuples then sort
  const tuples: { row: number; value: string | number }[] = [];
  for await (const chunk of iterateAccessLogIndexChunks(accessIndex, source, { signal })) {
    for (const line of chunk) {
      if (!filterFn || filterFn(line)) {
        tuples.push({ row: line.row, value: sortableValueForKey(line, sortKey) });
      }
    }
    done += chunk.length;
    const now = Date.now();
    if (onProgress && now - lastProgress >= INCIDENT_PROGRESS_THROTTLE_MS) {
      onProgress(done, total);
      lastProgress = now;
    }
  }

  if (signal.aborted) {
    throw new DOMException("buildIncidentSubset aborted", "AbortError");
  }

  const sorted = await sortInChunks(
    tuples,
    (a, b) => compareSortableValue(a.value, b.value, sortDir) || compareRow(a.row, b.row),
    { signal }
  );
  onProgress?.(total, total);

  return {
    orderedRowNumbers: arrayOrderedRowNumbers(sorted.map((t) => t.row)),
    total: sorted.length
  };
}

interface IncidentQueryOptions {
  matchSet: IncidentMatchSet | undefined;
  accessIndex: AccessLogIndex;
  incidentQueryCache: IncidentQueryCache;
  filter: string;
  sortKey: SortKey;
  sortDirection: SortDirection;
  setIndexLoading: (v: boolean) => void;
  setMessage: (v: string) => void;
}

export function useIncidentQuery({
  matchSet,
  accessIndex,
  incidentQueryCache,
  filter,
  sortKey,
  sortDirection,
  setIndexLoading,
  setMessage
}: IncidentQueryOptions) {
  // Default fast path (no filter + timestamp sort): virtual accessor, no build
  const defaultResult = useMemo<QueryResult | null>(() => {
    if (!matchSet) return null;
    return {
      orderedRowNumbers: virtualOrderedRowNumbers(matchSet.rowNumbers, sortDirection),
      total: matchSet.rowNumbers.length
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [matchSet, sortDirection]);

  // Seed the cache with the default fast-path entry on matchSet/sortDirection change
  useEffect(() => {
    if (!matchSet || !defaultResult) return;
    const defaultKey = incidentQueryKey(matchSet.incidentId, "", "timestamp", sortDirection);
    if (!incidentQueryCache.get(defaultKey)) {
      incidentQueryCache.set(defaultKey, {
        promise: Promise.resolve(defaultResult),
        resolved: true
      });
    }
  }, [matchSet, sortDirection, defaultResult, incidentQueryCache]);

  const lastResolvedRef = useRef<QueryResult | null>(null);
  if (lastResolvedRef.current === null && defaultResult !== null) {
    lastResolvedRef.current = defaultResult;
  }

  const [result, setResult] = useState<QueryResult | null>(defaultResult);
  const [building, setBuilding] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const isDefaultPath =
    !filter && sortKey === "timestamp" && matchSet !== undefined && matchSet !== null;

  useEffect(() => {
    if (!matchSet) {
      setResult(null);
      setBuilding(false);
      return;
    }

    if (isDefaultPath) {
      setResult(defaultResult);
      setBuilding(false);
      setIndexLoading(false);
      return;
    }

    const key = incidentQueryKey(matchSet.incidentId, filter, sortKey, sortDirection);
    const cached = incidentQueryCache.get(key);

    if (cached) {
      void cached.promise.then((r) => {
        lastResolvedRef.current = r;
        setResult(r);
        setBuilding(false);
        setIndexLoading(false);
      });
      return;
    }

    // Start a new build
    const controller = new AbortController();
    abortRef.current = controller;
    setBuilding(true);
    setIndexLoading(true);
    setMessage(filter ? "Building incident filter cache…" : "Building incident sort cache…");

    let lastProgressMs = 0;
    const onProgress = (done: number, total: number) => {
      const now = Date.now();
      if (now - lastProgressMs >= INCIDENT_PROGRESS_THROTTLE_MS) {
        setMessage(
          `${filter ? "Filtering" : "Sorting"} incident… ${done.toLocaleString()} / ${total.toLocaleString()}`
        );
        lastProgressMs = now;
      }
    };

    const buildPromise = buildIncidentSubset(
      matchSet,
      accessIndex,
      filter,
      sortKey,
      sortDirection,
      controller.signal,
      onProgress
    );

    const entry: CacheEntry = { promise: buildPromise, controller, resolved: false };
    incidentQueryCache.set(key, entry);

    buildPromise
      .then((r) => {
        entry.resolved = true;
        lastResolvedRef.current = r;
        setResult(r);
        setBuilding(false);
        setIndexLoading(false);
        setMessage("Incident filter cache ready");
      })
      .catch((err: unknown) => {
        incidentQueryCache.delete(key);
        setBuilding(false);
        setIndexLoading(false);
        const isAbort =
          err instanceof DOMException && err.name === "AbortError";
        if (!isAbort) {
          setMessage(err instanceof Error ? err.message : String(err));
        } else {
          setMessage("Showing previous result (filter cache cancelled)");
          // Keep showing the last resolved result
          if (lastResolvedRef.current) {
            setResult(lastResolvedRef.current);
          }
        }
      });

    return () => {
      controller.abort();
      abortRef.current = null;
    };
  }, [matchSet, filter, sortKey, sortDirection, isDefaultPath]);

  const abort = () => {
    abortRef.current?.abort();
  };

  const finalResult = result ?? defaultResult;

  return {
    orderedRowNumbers: finalResult?.orderedRowNumbers ?? null,
    total: finalResult?.total ?? (matchSet?.rowNumbers.length ?? 0),
    building,
    abort
  };
}
