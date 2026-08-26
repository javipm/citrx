import { randomUUID } from "node:crypto";
import { closeSync, createReadStream, openSync, readSync, statSync, writeSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { setImmediate } from "node:timers/promises";

import type { IncidentLogLine } from "../analysis/types.js";
import {
  type LineCompareKey,
  compareSortableValue as compareSortableValueFromUtil,
  compareRow as compareRowFromUtil,
  compareTimestampValues,
  timestampSortValue
} from "../utils/line-compare.js";

export type { LineCompareKey };
export { compareSortableValueFromUtil as compareSortableValue, compareRowFromUtil as compareRow };

const INDEX_SCAN_YIELD_INTERVAL = 5000;
const SORT_CHUNK_SIZE = 10000;
const ITERATE_CHUNK_SIZE = 2000;

/**
 * Read-only ordered sequence of row numbers backed by either a real array or
 * a virtual accessor (e.g. reverse iteration over matchSet.rowNumbers without
 * copying). `rowAt(i)` must throw `RangeError` for i < 0 or i >= length.
 * Row numbers are guaranteed numerically ascending (stream order) after
 * analysis finalization; the virtual reverse accessor produces desc order.
 */
export interface OrderedRowNumbers {
  readonly length: number;
  rowAt(index: number): number;
}

/**
 * Wraps a `number[]` as an `OrderedRowNumbers`. Throws `RangeError` for
 * out-of-range indices so callers catch bugs rather than silently reading
 * undefined.
 */
/** Virtual 0..length-1 or reverse sequence without allocating the array. */
export function sequentialOrderedRowNumbers(
  length: number,
  direction: "asc" | "desc" = "asc"
): OrderedRowNumbers {
  return {
    get length() {
      return length;
    },
    rowAt(i: number): number {
      if (i < 0 || i >= length) {
        throw new RangeError(`sequentialOrderedRowNumbers: index ${i} out of range [0, ${length})`);
      }
      return direction === "asc" ? i : length - 1 - i;
    }
  };
}

/** Virtual 0..length-1 sequence without allocating the array. */
export function rangeOrderedRowNumbers(length: number): OrderedRowNumbers {
  return {
    get length() {
      return length;
    },
    rowAt(i: number): number {
      if (i < 0 || i >= length) {
        throw new RangeError(`rangeOrderedRowNumbers: index ${i} out of range [0, ${length})`);
      }
      return i;
    }
  };
}

export function arrayOrderedRowNumbers(arr: readonly number[]): OrderedRowNumbers {
  return {
    get length() {
      return arr.length;
    },
    rowAt(i: number): number {
      if (i < 0 || i >= arr.length) {
        throw new RangeError(`arrayOrderedRowNumbers: index ${i} out of range [0, ${arr.length})`);
      }
      return arr[i]!;
    }
  };
}

// Compile-time check: AccessLogIndexPageOptions["sortKey"] must satisfy LineCompareKey.
// If access-index.ts adds a sort key not in LineCompareKey, this line fails typecheck.
const _checkSortKey: LineCompareKey = "timestamp" as AccessLogIndexPageOptions["sortKey"];
void _checkSortKey;

/**
 * Metadata for an indexed access log stored on disk.
 * Describes the dual-file layout (rows.jsonl + offsets.u64) used for random access.
 */
export interface AccessLogIndex {
  /** Unique identifier for this index instance. */
  id: string;
  /** Absolute path to the directory containing the index files. */
  directory: string;
  /** Absolute path to the JSONL file storing serialised log line rows. */
  rowsPath: string;
  /** Absolute path to the binary u64 array storing per-row byte offsets. */
  offsetsPath: string;
  /** Total number of rows written to the index. */
  totalRows: number;
  /** True when valid timestamps were non-decreasing in stream order. */
  timestampsMonotonic: boolean;
  /** Rows whose timestamp could not be parsed. */
  invalidTimestampCount: number;
}

/**
 * Write-once contract for appending log lines to an `AccessLogIndex`.
 * Implementations buffer writes internally and flush on `close()`.
 */
export interface AccessLogIndexWriter {
  /** The index metadata being written to. */
  readonly index: AccessLogIndex;
  /**
   * Append a single parsed log line to the index.
   * @param line - The incident log line to write.
   * @returns The zero-based row number assigned to the written line.
   */
  write(line: IncidentLogLine): number;
  /** Flush buffered rows so the index can be read before `close()`. */
  flush(): void;
  /**
   * Flush any buffered data and close the underlying file descriptors.
   * Subsequent calls are no-ops.
   */
  close(): void;
}

/**
 * Pagination, sort, and filter parameters for reading a page of log lines.
 */
export interface AccessLogIndexPageOptions {
  /**
   * Predicate applied to each line before sorting.
   * Use `passThroughFilter` to skip filtering.
   */
  filter: (line: IncidentLogLine) => boolean;
  /** Field to sort results by. Timestamp sorts use a fast sequential path. */
  sortKey: keyof Pick<IncidentLogLine, "timestamp" | "ip" | "status" | "method" | "path" | "bytes">;
  /** Sort order: ascending or descending. */
  sortDirection: "asc" | "desc";
  /** Zero-based index of the first row to return (within the filtered set). */
  start: number;
  /** Maximum number of rows to return. */
  limit: number;
}

/**
 * Result of a paginated read from an `AccessLogIndex`.
 */
export interface AccessLogIndexPage {
  /** Total number of rows matching the applied filter (before pagination). */
  total: number;
  /** The slice of log lines for the requested page. */
  lines: IncidentLogLine[];
}

/**
 * Result of a full scan over an `AccessLogIndex` with filter and sort applied.
 * Stores row numbers rather than full lines to enable cheap random-access reads later.
 */
export interface AccessLogIndexQuery {
  /** Total number of rows matching the filter. */
  total: number;
  /** Ordered list of zero-based row numbers after filtering and sorting. */
  rows: number[];
}

/**
 * Memoizes `AccessLogIndexQuery` results keyed by an arbitrary string.
 * Prevents redundant full-scan operations when the same filter+sort combination
 * is requested multiple times (e.g. across paginated requests for the same view).
 * Failed promises are evicted so the next caller triggers a fresh build.
 */
const QUERY_CACHE_MAX_KEYS = 32;
const QUERY_CACHE_MAX_ROWS = 2_000_000;

interface QueryCacheEntry {
  promise: Promise<AccessLogIndexQuery>;
  controller?: AbortController;
  resolved: boolean;
  rowCount: number;
}

export class AccessLogIndexQueryCache {
  private readonly entries = new Map<string, QueryCacheEntry>();
  private readonly order: string[] = [];
  private totalRows = 0;

  has(key: string): boolean {
    return this.entries.has(key);
  }

  getOrBuild(
    index: AccessLogIndex,
    key: string,
    options: Pick<AccessLogIndexPageOptions, "filter" | "sortKey" | "sortDirection">,
    signal?: AbortSignal
  ): Promise<AccessLogIndexQuery> {
    const cached = this.entries.get(key);

    if (cached) {
      const idx = this.order.indexOf(key);
      if (idx !== -1) {
        this.order.splice(idx, 1);
        this.order.push(key);
      }
      return abortablePromise(cached.promise, signal);
    }

    const controller = new AbortController();
    const onAbort = () => controller.abort();
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) {
      controller.abort();
    }

    const next = buildAccessLogIndexQuery(index, options, controller.signal)
      .then((query) => {
        const entry = this.entries.get(key);
        if (entry) {
          entry.resolved = true;
          entry.rowCount = query.rows.length;
          this.totalRows += query.rows.length;
          this.evictIfNeeded();
        }
        return query;
      })
      .catch((error) => {
        this.delete(key);
        throw error;
      })
      .finally(() => {
        signal?.removeEventListener("abort", onAbort);
      });

    this.entries.set(key, {
      promise: next,
      controller,
      resolved: false,
      rowCount: 0
    });
    this.order.push(key);
    this.evictIfNeeded();
    return next;
  }

  abort(key: string): void {
    this.entries.get(key)?.controller?.abort();
  }

  delete(key: string): void {
    const entry = this.entries.get(key);
    if (entry?.resolved) {
      this.totalRows = Math.max(0, this.totalRows - entry.rowCount);
    }
    this.entries.delete(key);
    const idx = this.order.indexOf(key);
    if (idx !== -1) {
      this.order.splice(idx, 1);
    }
  }

  private evictIfNeeded(): void {
    while (
      (this.order.length > QUERY_CACHE_MAX_KEYS || this.totalRows > QUERY_CACHE_MAX_ROWS) &&
      this.order.length > 0
    ) {
      const resolvedKey = this.order.find((key) => this.entries.get(key)?.resolved);
      if (!resolvedKey) {
        break;
      }
      this.delete(resolvedKey);
    }
  }
}

export function canUseMonotonicTimestampFastPath(
  index: AccessLogIndex,
  options: Pick<AccessLogIndexPageOptions, "filter" | "sortKey">
): boolean {
  return (
    options.sortKey === "timestamp" &&
    options.filter === passThroughFilter &&
    index.timestampsMonotonic &&
    index.invalidTimestampCount === 0
  );
}

/**
 * Create a new `AccessLogIndexWriter` backed by a fresh index directory.
 * Creates `<directory>/access-index/` if it does not exist, then opens
 * `rows.jsonl` and `offsets.u64` for writing.
 * @param directory - Parent directory in which to create the `access-index` subdirectory.
 * @returns A writer ready to accept `write()` calls.
 */
export async function createAccessLogIndexWriter(directory: string): Promise<AccessLogIndexWriter> {
  const indexDirectory = path.join(directory, "access-index");
  await mkdir(indexDirectory, { recursive: true });

  return new SyncAccessLogIndexWriter({
    id: randomUUID(),
    directory: indexDirectory,
    rowsPath: path.join(indexDirectory, "rows.jsonl"),
    offsetsPath: path.join(indexDirectory, "offsets.u64"),
    totalRows: 0,
    timestampsMonotonic: true,
    invalidTimestampCount: 0
  });
}

/**
 * Read one page of log lines from an index, applying filter and sort.
 * Uses a fast sequential path when sorting by `timestamp`; falls back to a
 * full in-memory scan + sort for all other sort keys.
 * @param index - The index to read from.
 * @param options - Pagination, filter, and sort parameters.
 * @returns A page containing the matching lines and the unsliced total count.
 */
export async function readAccessLogIndexPage(
  index: AccessLogIndex,
  options: AccessLogIndexPageOptions,
  signal?: AbortSignal
): Promise<AccessLogIndexPage> {
  if (canUseMonotonicTimestampFastPath(index, options)) {
    return readSequentialPage(index, options.start, options.limit, options.sortDirection);
  }

  const query = await buildAccessLogIndexQuery(index, options, signal);
  return {
    total: query.total,
    lines: readAccessLogIndexRows(
      index,
      query.rows.slice(options.start, options.start + options.limit)
    )
  };
}

/**
 * Read one page of log lines using a query cache to avoid redundant full scans.
 * Bypasses the cache and uses the sequential path when sorting by `timestamp`
 * with no filter. For all other combinations, delegates to `cache.getOrBuild`.
 * @param index - The index to read from.
 * @param cache - Shared cache instance; keyed by `key`.
 * @param key - Unique string identifying the filter+sort combination for caching.
 * @param options - Pagination, filter, and sort parameters.
 * @returns A page containing the matching lines and the unsliced total count.
 */
export async function readAccessLogIndexCachedPage(
  index: AccessLogIndex,
  cache: AccessLogIndexQueryCache,
  key: string,
  options: AccessLogIndexPageOptions,
  signal?: AbortSignal
): Promise<AccessLogIndexPage> {
  if (canUseMonotonicTimestampFastPath(index, options)) {
    return readSequentialPage(index, options.start, options.limit, options.sortDirection);
  }

  const query = await cache.getOrBuild(index, key, options, signal);
  return {
    total: query.total,
    lines: readAccessLogIndexRows(
      index,
      query.rows.slice(options.start, options.start + options.limit)
    )
  };
}

/**
 * No-op filter predicate that accepts every log line.
 * Pass this as `options.filter` to skip filtering entirely.
 * @returns Always `true`.
 */
export function passThroughFilter(): boolean {
  return true;
}

/**
 * Async generator that yields every log line in an index in insertion order.
 * Streams `rows.jsonl` line-by-line; memory usage is O(1) relative to index size.
 * @param index - The index whose rows to read.
 * @yields Each parsed `IncidentLogLine` in sequence.
 */
export async function* readAccessLogIndexLines(
  index: AccessLogIndex
): AsyncIterable<IncidentLogLine> {
  const reader = createInterface({
    input: createReadStream(index.rowsPath, { encoding: "utf8" }),
    crlfDelay: Infinity
  });

  for await (const line of reader) {
    if (line.length > 0) {
      yield JSON.parse(line) as IncidentLogLine;
    }
  }
}

/**
 * Synchronously read a specific set of rows by number using the offset index.
 * Opens both index files once, seeks to each row via its u64 offset, and closes
 * the descriptors in a `finally` block. Out-of-range row numbers are silently skipped.
 * @param index - The index to read from.
 * @param rowNumbers - Zero-based row numbers to fetch, in the desired output order.
 * @returns Parsed log lines in the same order as `rowNumbers`.
 */
export function readAccessLogIndexRows(
  index: AccessLogIndex,
  rowNumbers: number[]
): IncidentLogLine[] {
  if (rowNumbers.length === 0) {
    return [];
  }

  const lines: IncidentLogLine[] = [];
  const fileHandles = openIndexFiles(index);

  try {
    for (const rowNumber of rowNumbers) {
      if (rowNumber >= 0 && rowNumber < index.totalRows) {
        lines.push(readAccessLogIndexRowFromOpenFiles(index, rowNumber, fileHandles));
      }
    }
  } finally {
    closeIndexFiles(fileHandles);
  }

  return lines;
}

/**
 * Async generator that reads `rowNumbers` in fixed-size chunks, yielding one
 * chunk of `IncidentLogLine[]` per iteration. Opens index files once and closes
 * them in `finally`, so callers never need to manage descriptors.
 *
 * Checks `options.signal` between chunks and throws `AbortError` if aborted.
 * Validates each row number against `index.totalRows`; throws `RangeError` for
 * out-of-range values so bugs surface rather than silently producing empty rows.
 */
export async function* iterateAccessLogIndexChunks(
  index: AccessLogIndex,
  rowNumbers: OrderedRowNumbers,
  options: { chunkSize?: number; signal?: AbortSignal } = {}
): AsyncGenerator<IncidentLogLine[]> {
  const chunkSize = options.chunkSize ?? ITERATE_CHUNK_SIZE;

  if (rowNumbers.length === 0) {
    return;
  }

  const fileHandles = openIndexFiles(index);

  try {
    let chunk: IncidentLogLine[] = [];

    for (let i = 0; i < rowNumbers.length; i++) {
      const row = rowNumbers.rowAt(i);

      if (row < 0 || row >= index.totalRows) {
        throw new RangeError(
          `iterateAccessLogIndexChunks: row ${row} out of range [0, ${index.totalRows})`
        );
      }

      chunk.push(readAccessLogIndexRowFromOpenFiles(index, row, fileHandles));

      if (chunk.length >= chunkSize) {
        yield chunk;
        chunk = [];
        await setImmediate();

        if (options.signal?.aborted) {
          throw new DOMException("iterateAccessLogIndexChunks aborted", "AbortError");
        }
      }
    }

    if (chunk.length > 0) {
      yield chunk;
    }
  } finally {
    closeIndexFiles(fileHandles);
  }
}

/**
 * Perform a full scan of the index, applying filter and sort, and return the
 * resulting ordered row numbers.
 * Uses a fast O(n) path (no sort) when the sort key is `timestamp`, since rows
 * are stored in insertion (timestamp) order. All other sort keys require a
 * comparison sort over the filtered set.
 * @param index - The index to scan.
 * @param options - Filter predicate and sort parameters.
 * @returns Total match count and the ordered list of matching row numbers.
 */
export async function buildAccessLogIndexQuery(
  index: AccessLogIndex,
  options: Pick<AccessLogIndexPageOptions, "filter" | "sortKey" | "sortDirection">,
  signal?: AbortSignal
): Promise<AccessLogIndexQuery> {
  if (
    canUseMonotonicTimestampFastPath(index, { filter: options.filter, sortKey: options.sortKey })
  ) {
    return {
      total: index.totalRows,
      rows: materializeSequentialRows(index.totalRows, options.sortDirection)
    };
  }

  let rows: Array<{ row: number; value: string | number }> = [];
  const fileHandles = openIndexFiles(index);

  try {
    for (let row = 0; row < index.totalRows; row += 1) {
      if (signal?.aborted) {
        throw new DOMException("buildAccessLogIndexQuery aborted", "AbortError");
      }

      const line = readAccessLogIndexRowFromOpenFiles(index, row, fileHandles);

      if (options.filter(line)) {
        rows.push({
          row,
          value: sortableValue(line, options.sortKey)
        });
      }

      if (row > 0 && row % INDEX_SCAN_YIELD_INTERVAL === 0) {
        await setImmediate();
      }
    }
  } finally {
    closeIndexFiles(fileHandles);
  }

  if (signal?.aborted) {
    throw new DOMException("buildAccessLogIndexQuery aborted", "AbortError");
  }

  rows = await sortQueryRows(rows, options.sortKey, options.sortDirection, signal);

  return {
    total: rows.length,
    rows: rows.map((item) => item.row)
  };
}

async function sortQueryRows(
  rows: Array<{ row: number; value: string | number }>,
  sortKey: AccessLogIndexPageOptions["sortKey"],
  sortDirection: "asc" | "desc",
  signal?: AbortSignal
): Promise<Array<{ row: number; value: string | number }>> {
  const compare =
    sortKey === "timestamp"
      ? (a: { row: number; value: string | number }, b: { row: number; value: string | number }) =>
          compareTimestampValues(Number(a.value), Number(b.value), sortDirection) ||
          compareRowFromUtil(a.row, b.row)
      : (a: { row: number; value: string | number }, b: { row: number; value: string | number }) =>
          compareSortableValue(a.value, b.value, sortDirection) || compareRowFromUtil(a.row, b.row);

  return sortInChunks(rows, compare, { signal });
}

function readSequentialPage(
  index: AccessLogIndex,
  start: number,
  limit: number,
  direction: "asc" | "desc"
): AccessLogIndexPage {
  const lines: IncidentLogLine[] = [];
  const safeStart = Math.max(0, Math.min(start, index.totalRows));
  const safeLimit = Math.max(0, limit);
  const fileHandles = openIndexFiles(index);

  try {
    for (let offset = 0; offset < safeLimit; offset += 1) {
      const rowNumber =
        direction === "asc" ? safeStart + offset : index.totalRows - 1 - safeStart - offset;
      if (rowNumber < 0 || rowNumber >= index.totalRows) {
        break;
      }
      lines.push(readAccessLogIndexRowFromOpenFiles(index, rowNumber, fileHandles));
    }
  } finally {
    closeIndexFiles(fileHandles);
  }

  return { total: index.totalRows, lines };
}

function materializeSequentialRows(totalRows: number, direction: "asc" | "desc"): number[] {
  const rows: number[] = [];
  if (direction === "asc") {
    for (let row = 0; row < totalRows; row += 1) {
      rows.push(row);
    }
    return rows;
  }
  for (let row = totalRows - 1; row >= 0; row -= 1) {
    rows.push(row);
  }
  return rows;
}

export async function abortablePromise<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) {
    return promise;
  }
  if (signal.aborted) {
    throw new DOMException("aborted", "AbortError");
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      reject(new DOMException("aborted", "AbortError"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      }
    );
  });
}

export async function sortInChunks<T>(
  items: T[],
  compare: (a: T, b: T) => number,
  options?: { signal?: AbortSignal }
): Promise<T[]> {
  if (items.length <= SORT_CHUNK_SIZE) {
    items.sort(compare);
    return items;
  }

  let chunks: T[][] = [];

  for (let start = 0; start < items.length; start += SORT_CHUNK_SIZE) {
    if (options?.signal?.aborted) {
      throw new DOMException("sortInChunks aborted", "AbortError");
    }
    chunks.push(items.slice(start, start + SORT_CHUNK_SIZE).sort(compare));
    await setImmediate();
  }

  while (chunks.length > 1) {
    if (options?.signal?.aborted) {
      throw new DOMException("sortInChunks aborted", "AbortError");
    }
    const merged: T[][] = [];

    for (let index = 0; index < chunks.length; index += 2) {
      const left = chunks[index]!;
      const right = chunks[index + 1];
      merged.push(right ? mergeSorted(left, right, compare) : left);
      await setImmediate();
    }

    chunks = merged;
  }

  return chunks[0] ?? [];
}

function mergeSorted<T>(left: T[], right: T[], compare: (a: T, b: T) => number): T[] {
  const merged: T[] = [];
  let leftIndex = 0;
  let rightIndex = 0;

  while (leftIndex < left.length && rightIndex < right.length) {
    if (compare(left[leftIndex]!, right[rightIndex]!) <= 0) {
      merged.push(left[leftIndex]!);
      leftIndex += 1;
    } else {
      merged.push(right[rightIndex]!);
      rightIndex += 1;
    }
  }

  if (leftIndex < left.length) {
    merged.push(...left.slice(leftIndex));
  }

  if (rightIndex < right.length) {
    merged.push(...right.slice(rightIndex));
  }

  return merged;
}

function openIndexFiles(index: AccessLogIndex): {
  offsetsFd: number;
  rowsFd: number;
  rowsSize: number;
} {
  const offsetsFd = openSync(index.offsetsPath, "r");
  const rowsFd = openSync(index.rowsPath, "r");
  return {
    offsetsFd,
    rowsFd,
    rowsSize: statSync(index.rowsPath).size
  };
}

function closeIndexFiles(fileHandles: { offsetsFd: number; rowsFd: number }): void {
  closeSync(fileHandles.offsetsFd);
  closeSync(fileHandles.rowsFd);
}

function readAccessLogIndexRowFromOpenFiles(
  index: AccessLogIndex,
  rowNumber: number,
  fileHandles: { offsetsFd: number; rowsFd: number; rowsSize: number }
): IncidentLogLine {
  const start = readOffset(fileHandles.offsetsFd, rowNumber);
  const end =
    rowNumber + 1 < index.totalRows
      ? readOffset(fileHandles.offsetsFd, rowNumber + 1)
      : fileHandles.rowsSize;
  const length = end - start;
  const buffer = Buffer.allocUnsafe(length);
  readSync(fileHandles.rowsFd, buffer, 0, length, start);
  return JSON.parse(buffer.toString("utf8").trimEnd()) as IncidentLogLine;
}

function readOffset(fd: number, rowNumber: number): number {
  const buffer = Buffer.allocUnsafe(8);
  readSync(fd, buffer, 0, 8, rowNumber * 8);
  return Number(buffer.readBigUInt64LE(0));
}

function sortableValue(
  line: IncidentLogLine,
  sortKey: AccessLogIndexPageOptions["sortKey"]
): string | number {
  if (sortKey === "bytes") {
    return line.bytes ?? 0;
  }

  if (sortKey === "status") {
    return line.status;
  }

  if (sortKey === "timestamp") {
    return timestampSortValue(line.timestamp);
  }

  return String(line[sortKey]);
}

function compareSortableValue(
  a: string | number,
  b: string | number,
  direction: "asc" | "desc"
): number {
  return compareSortableValueFromUtil(a, b, direction);
}

class SyncAccessLogIndexWriter implements AccessLogIndexWriter {
  readonly index: AccessLogIndex;
  private readonly rowsFd: number;
  private readonly offsetsFd: number;
  private readonly rowsBuffer: Buffer[] = [];
  private readonly offsetsBuffer: Buffer[] = [];
  private bufferedBytes = 0;
  private byteOffset = 0;
  private closed = false;
  private lastEpoch: number | null = null;

  constructor(index: AccessLogIndex) {
    this.index = index;
    this.rowsFd = openSync(index.rowsPath, "w");
    this.offsetsFd = openSync(index.offsetsPath, "w");
  }

  write(line: IncidentLogLine): number {
    if (this.closed) {
      throw new Error("Cannot write to closed access-log index.");
    }

    const epoch = timestampSortValue(line.timestamp);
    if (!Number.isFinite(epoch)) {
      this.index.invalidTimestampCount += 1;
    } else {
      if (this.lastEpoch !== null && epoch < this.lastEpoch) {
        this.index.timestampsMonotonic = false;
      }
      this.lastEpoch = epoch;
    }

    const rowNumber = this.index.totalRows;
    const row = Buffer.from(`${JSON.stringify({ ...line, row: rowNumber })}\n`, "utf8");
    const offset = Buffer.allocUnsafe(8);
    offset.writeBigUInt64LE(BigInt(this.byteOffset), 0);
    this.offsetsBuffer.push(offset);
    this.rowsBuffer.push(row);
    this.bufferedBytes += offset.length + row.length;
    this.byteOffset += row.length;
    this.index.totalRows += 1;

    if (this.bufferedBytes >= 1024 * 1024) {
      this.flush();
    }

    return rowNumber;
  }

  flush(): void {
    if (this.closed || this.bufferedBytes === 0) {
      return;
    }

    writeSync(this.offsetsFd, Buffer.concat(this.offsetsBuffer));
    writeSync(this.rowsFd, Buffer.concat(this.rowsBuffer));
    this.offsetsBuffer.length = 0;
    this.rowsBuffer.length = 0;
    this.bufferedBytes = 0;
  }

  close(): void {
    if (this.closed) {
      return;
    }

    this.flush();
    closeSync(this.rowsFd);
    closeSync(this.offsetsFd);
    this.closed = true;
  }
}
