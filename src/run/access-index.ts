import { randomUUID } from "node:crypto";
import { closeSync, createReadStream, openSync, readSync, statSync, writeSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { createInterface } from "node:readline/promises";

import type { IncidentLogLine } from "../analysis/types.js";

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
export class AccessLogIndexQueryCache {
  private readonly entries = new Map<string, Promise<AccessLogIndexQuery>>();

  /**
   * Returns `true` if a cached (or in-flight) query exists for `key`.
   * @param key - The cache key to check.
   */
  has(key: string): boolean {
    return this.entries.has(key);
  }

  /**
   * Returns the cached query for `key`, or builds and caches a new one.
   * @param index - The index to scan if no cached result exists.
   * @param key - Unique string identifying the filter+sort combination.
   * @param options - Filter and sort parameters forwarded to `buildAccessLogIndexQuery`.
   * @returns A promise resolving to the filtered and sorted query result.
   */
  getOrBuild(
    index: AccessLogIndex,
    key: string,
    options: Pick<AccessLogIndexPageOptions, "filter" | "sortKey" | "sortDirection">
  ): Promise<AccessLogIndexQuery> {
    const cached = this.entries.get(key);

    if (cached) {
      return cached;
    }

    const next = buildAccessLogIndexQuery(index, options).catch((error) => {
      this.entries.delete(key);
      throw error;
    });
    this.entries.set(key, next);
    return next;
  }
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
    totalRows: 0
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
  options: AccessLogIndexPageOptions
): Promise<AccessLogIndexPage> {
  if (options.sortKey === "timestamp") {
    return options.filter === passThroughFilter
      ? readSequentialPage(index, options.start, options.limit, options.sortDirection)
      : readFilteredSequentialPage(index, options);
  }

  const lines: IncidentLogLine[] = [];

  for await (const line of readAccessLogIndexLines(index)) {
    if (options.filter(line)) {
      lines.push(line);
    }
  }

  lines.sort((a, b) => compareLine(a, b, options.sortKey, options.sortDirection));

  return {
    total: lines.length,
    lines: lines.slice(options.start, options.start + options.limit)
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
  options: AccessLogIndexPageOptions
): Promise<AccessLogIndexPage> {
  if (options.filter === passThroughFilter && options.sortKey === "timestamp") {
    return readSequentialPage(index, options.start, options.limit, options.sortDirection);
  }

  const query = await cache.getOrBuild(index, key, options);
  return {
    total: query.total,
    lines: readAccessLogIndexRows(index, query.rows.slice(options.start, options.start + options.limit))
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
export async function* readAccessLogIndexLines(index: AccessLogIndex): AsyncIterable<IncidentLogLine> {
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
export function readAccessLogIndexRows(index: AccessLogIndex, rowNumbers: number[]): IncidentLogLine[] {
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
  options: Pick<AccessLogIndexPageOptions, "filter" | "sortKey" | "sortDirection">
): Promise<AccessLogIndexQuery> {
  if (options.filter === passThroughFilter && options.sortKey === "timestamp") {
    return {
      total: index.totalRows,
      rows: sequentialRows(index.totalRows, options.sortDirection)
    };
  }

  const rows: Array<{ row: number; value: string | number }> = [];
  const fileHandles = openIndexFiles(index);

  try {
    for (let row = 0; row < index.totalRows; row += 1) {
      const line = readAccessLogIndexRowFromOpenFiles(index, row, fileHandles);

      if (options.filter(line)) {
        rows.push({
          row,
          value: sortableValue(line, options.sortKey)
        });
      }
    }
  } finally {
    closeIndexFiles(fileHandles);
  }

  if (options.sortKey === "timestamp") {
    if (options.sortDirection === "desc") {
      rows.reverse();
    }
  } else {
    rows.sort((a, b) => compareSortableValue(a.value, b.value, options.sortDirection));
  }

  return {
    total: rows.length,
    rows: rows.map((item) => item.row)
  };
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
      const rowNumber = direction === "asc"
        ? safeStart + offset
        : index.totalRows - 1 - safeStart - offset;

      if (rowNumber < 0 || rowNumber >= index.totalRows) {
        break;
      }

      lines.push(readAccessLogIndexRowFromOpenFiles(index, rowNumber, fileHandles));
    }
  } finally {
    closeIndexFiles(fileHandles);
  }

  return {
    total: index.totalRows,
    lines
  };
}

function readFilteredSequentialPage(
  index: AccessLogIndex,
  options: AccessLogIndexPageOptions
): AccessLogIndexPage {
  const lines: IncidentLogLine[] = [];
  const safeStart = Math.max(0, options.start);
  const safeLimit = Math.max(0, options.limit);
  const fileHandles = openIndexFiles(index);
  let total = 0;

  try {
    for (let offset = 0; offset < index.totalRows; offset += 1) {
      const rowNumber = options.sortDirection === "asc"
        ? offset
        : index.totalRows - 1 - offset;
      const line = readAccessLogIndexRowFromOpenFiles(index, rowNumber, fileHandles);

      if (!options.filter(line)) {
        continue;
      }

      if (total >= safeStart && lines.length < safeLimit) {
        lines.push(line);
      }

      total += 1;
    }
  } finally {
    closeIndexFiles(fileHandles);
  }

  return {
    total,
    lines
  };
}

function openIndexFiles(index: AccessLogIndex): { offsetsFd: number; rowsFd: number; rowsSize: number } {
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
  const end = rowNumber + 1 < index.totalRows
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

function compareLine(
  a: IncidentLogLine,
  b: IncidentLogLine,
  sortKey: AccessLogIndexPageOptions["sortKey"],
  direction: "asc" | "desc"
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

function sequentialRows(totalRows: number, direction: "asc" | "desc"): number[] {
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

  return String(line[sortKey]);
}

function compareSortableValue(
  a: string | number,
  b: string | number,
  direction: "asc" | "desc"
): number {
  const multiplier = direction === "asc" ? 1 : -1;

  if (typeof a === "number" && typeof b === "number") {
    return (a - b) * multiplier;
  }

  return String(a).localeCompare(String(b)) * multiplier;
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

  constructor(index: AccessLogIndex) {
    this.index = index;
    this.rowsFd = openSync(index.rowsPath, "w");
    this.offsetsFd = openSync(index.offsetsPath, "w");
  }

  write(line: IncidentLogLine): number {
    if (this.closed) {
      throw new Error("Cannot write to closed access-log index.");
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

  close(): void {
    if (this.closed) {
      return;
    }

    this.flush();
    closeSync(this.rowsFd);
    closeSync(this.offsetsFd);
    this.closed = true;
  }

  private flush(): void {
    if (this.bufferedBytes === 0) {
      return;
    }

    writeSync(this.offsetsFd, Buffer.concat(this.offsetsBuffer));
    writeSync(this.rowsFd, Buffer.concat(this.rowsBuffer));
    this.offsetsBuffer.length = 0;
    this.rowsBuffer.length = 0;
    this.bufferedBytes = 0;
  }
}
