// On-demand incident query: default fast path via virtual accessor, build path
// via background scan+sort. Mirrors useAccessLogQuery but scoped to one incident.
import { useEffect, useRef, useState, type Dispatch, type SetStateAction } from "react";
import type { IncidentMatchSet } from "../../analysis/types.js";
import {
  type AccessLogIndex,
  type OrderedRowNumbers,
  arrayOrderedRowNumbers,
  iterateAccessLogIndexChunks,
  sortInChunks
} from "../../run/access-index.js";
import {
  compareSortableValue,
  compareRow,
  compareTimestampValues,
  timestampSortValue
} from "../../utils/line-compare.js";
import { createAccessLogLineFilter } from "../filter.js";
import type { ActiveAbortEntry, SortKey, SortDirection } from "../types.js";

const INCIDENT_QUERY_CACHE_MAX = 32;
const INCIDENT_QUERY_CACHE_MAX_ROWS = 2_000_000;
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
  rowCount?: number;
}

export class IncidentQueryCache {
  private readonly entries = new Map<string, CacheEntry>();
  private readonly order: string[] = [];
  private totalRows = 0;

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
    this.evictIfNeeded();
    entry.rowCount ??= 0;
    this.entries.set(key, entry);
    this.order.push(key);
  }

  delete(key: string): void {
    const existing = this.entries.get(key);
    if (existing?.resolved) {
      this.totalRows = Math.max(0, this.totalRows - (existing.rowCount ?? 0));
    }
    this.entries.delete(key);
    const idx = this.order.indexOf(key);
    if (idx !== -1) this.order.splice(idx, 1);
  }

  markResolved(key: string, rowCount: number): void {
    const entry = this.entries.get(key);
    if (!entry || entry.resolved) {
      return;
    }
    entry.resolved = true;
    entry.rowCount = rowCount;
    this.totalRows += rowCount;
    this.evictIfNeeded();
  }

  private evictIfNeeded(): void {
    while (
      (this.order.length >= INCIDENT_QUERY_CACHE_MAX ||
        this.totalRows > INCIDENT_QUERY_CACHE_MAX_ROWS) &&
      this.order.length > 0
    ) {
      const resolvedKey = this.order.find((key) => this.entries.get(key)?.resolved);
      if (!resolvedKey) {
        break;
      }
      this.delete(resolvedKey);
    }
  }

  clearByIncidentId(incidentId: string): void {
    const prefix = `${incidentId}:`;
    const keys = [...this.entries.keys()].filter((key) => key.startsWith(prefix));
    for (const key of keys) {
      this.entries.get(key)?.controller?.abort();
      this.delete(key);
    }
  }
}

function sortableValueForKey(
  line: {
    timestamp: string;
    ip: string;
    status: number;
    method: string;
    path: string;
    bytes: number | null;
  },
  sortKey: SortKey
): string | number {
  if (sortKey === "bytes") return line.bytes ?? 0;
  if (sortKey === "status") return line.status;
  if (sortKey === "timestamp") return timestampSortValue(line.timestamp);
  return String((line as Record<string, unknown>)[sortKey]);
}

export async function buildIncidentSubset(
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
    (a, b) =>
      (sortKey === "timestamp"
        ? compareTimestampValues(Number(a.value), Number(b.value), sortDir)
        : compareSortableValue(a.value, b.value, sortDir)) || compareRow(a.row, b.row),
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
  setActiveAbort?: Dispatch<SetStateAction<ActiveAbortEntry | undefined>>;
}

export function useIncidentQuery({
  matchSet,
  accessIndex,
  incidentQueryCache,
  filter,
  sortKey,
  sortDirection,
  setIndexLoading,
  setMessage,
  setActiveAbort
}: IncidentQueryOptions) {
  const lastResolvedRef = useRef<{ incidentId: string; result: QueryResult } | null>(null);
  const [result, setResult] = useState<QueryResult | null>(null);
  const [building, setBuilding] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!matchSet) {
      setResult(null);
      setBuilding(false);
      lastResolvedRef.current = null;
      return;
    }

    let cancelled = false;
    const incidentId = matchSet.incidentId;
    const key = incidentQueryKey(incidentId, filter, sortKey, sortDirection);
    const cached = incidentQueryCache.get(key);

    const applyResult = (r: QueryResult) => {
      if (cancelled) {
        return;
      }
      lastResolvedRef.current = { incidentId, result: r };
      setResult(r);
      setBuilding(false);
      setIndexLoading(false);
    };

    if (cached) {
      void cached.promise.then(applyResult).catch((err: unknown) => {
        if (cancelled) {
          return;
        }
        setBuilding(false);
        setIndexLoading(false);
        const isAbort = err instanceof DOMException && err.name === "AbortError";
        if (!isAbort) {
          setMessage(err instanceof Error ? err.message : String(err));
        }
      });
      return () => {
        cancelled = true;
      };
    }

    const controller = new AbortController();
    abortRef.current = controller;
    setBuilding(true);
    setIndexLoading(true);
    setMessage(filter ? "Building incident filter cache…" : "Building incident sort cache…");
    setActiveAbort?.({
      kind: "incident-query",
      controller,
      label: "Building incident query… Esc to cancel"
    });

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
        if (cancelled || controller.signal.aborted) {
          return;
        }
        incidentQueryCache.markResolved(key, r.total);
        applyResult(r);
        setActiveAbort?.((prev) => (prev?.controller === controller ? undefined : prev));
        setMessage("Incident filter cache ready");
      })
      .catch((err: unknown) => {
        if (cancelled) {
          return;
        }
        incidentQueryCache.delete(key);
        setBuilding(false);
        setIndexLoading(false);
        setActiveAbort?.((prev) => (prev?.controller === controller ? undefined : prev));
        const isAbort = err instanceof DOMException && err.name === "AbortError";
        if (!isAbort) {
          setMessage(err instanceof Error ? err.message : String(err));
          return;
        }
        setMessage("Query cancelled");
        if (lastResolvedRef.current?.incidentId === incidentId) {
          setResult(lastResolvedRef.current.result);
        }
      });

    return () => {
      cancelled = true;
      controller.abort();
      abortRef.current = null;
      setActiveAbort?.((prev) => (prev?.controller === controller ? undefined : prev));
    };
  }, [matchSet, filter, sortKey, sortDirection, accessIndex, incidentQueryCache]);

  const abort = () => {
    abortRef.current?.abort();
  };

  return {
    orderedRowNumbers: result?.orderedRowNumbers ?? null,
    total: result?.total ?? matchSet?.rowNumbers.length ?? 0,
    building,
    abort
  };
}
