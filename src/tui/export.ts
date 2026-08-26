import { randomBytes } from "node:crypto";
import { createWriteStream } from "node:fs";
import { rename, unlink } from "node:fs/promises";
import path from "node:path";
import { setTimeout as setTimeoutPromise } from "node:timers/promises";
import { Writable } from "node:stream";
import { finished } from "node:stream/promises";
import type { Incident, IncidentLogLine } from "../analysis/types.js";
import { iterateAccessLogIndexChunks, type OrderedRowNumbers } from "../run/access-index.js";
import type { CitrxRun } from "../run/types.js";
import { sanitizeText } from "../utils/sanitize.js";
import type { ExportFormat } from "./types.js";

const DELIMITED_COLUMNS: Array<{
  key: string;
  value: (line: IncidentLogLine) => string | number | null;
}> = [
  { key: "row", value: (line) => line.row },
  { key: "source", value: (line) => line.source },
  { key: "lineNumber", value: (line) => line.lineNumber },
  { key: "timestamp", value: (line) => line.timestamp },
  { key: "ip", value: (line) => line.ip },
  { key: "method", value: (line) => line.method },
  { key: "target", value: (line) => line.target },
  { key: "path", value: (line) => line.path },
  { key: "status", value: (line) => line.status },
  { key: "bytes", value: (line) => line.bytes },
  { key: "userAgent", value: (line) => line.userAgent },
  { key: "raw", value: (line) => line.raw }
];

export function serializeExport(
  incident: Incident | undefined,
  lines: IncidentLogLine[],
  format: ExportFormat
): string {
  if (format === "json") {
    return `${JSON.stringify({ incident, lines }, null, 2)}\n`;
  }

  const separator = format === "csv" ? "," : "\t";
  const sink = format === "csv" ? "csv" : "tsv";
  const rows = [
    DELIMITED_COLUMNS.map((column) => escapeDelimitedCell(column.key, separator, sink)).join(
      separator
    ),
    ...lines.map((line) =>
      DELIMITED_COLUMNS.map((column) =>
        escapeDelimitedCell(column.value(line), separator, sink)
      ).join(separator)
    )
  ];

  return `${rows.join("\n")}\n`;
}

function escapeDelimitedCell(
  value: string | number | null,
  separator: string,
  sink: "csv" | "tsv"
): string {
  const text = value === null ? "" : sanitizeText(String(value), sink);

  if (
    text.includes('"') ||
    text.includes("\n") ||
    text.includes("\r") ||
    text.includes(separator)
  ) {
    return `"${text.replaceAll('"', '""')}"`;
  }

  return text;
}

const STREAM_PROGRESS_THROTTLE_MS = 50;

async function writeWithBackpressure(
  stream: Writable,
  signal: AbortSignal | undefined,
  chunk: string
): Promise<void> {
  if (signal?.aborted) throw new DOMException("aborted", "AbortError");
  const ok = stream.write(chunk);
  if (!ok) {
    await new Promise<void>((resolve, reject) => {
      const onDrain = () => {
        cleanup();
        resolve();
      };
      const onError = (err: Error) => {
        cleanup();
        reject(err);
      };
      const cleanup = () => {
        stream.off("drain", onDrain);
        stream.off("error", onError);
      };
      stream.once("drain", onDrain);
      stream.once("error", onError);
    });
  }
}

export async function streamSerializeExport(
  incident: Incident | undefined,
  source: { run: CitrxRun; orderedRowNumbers: OrderedRowNumbers },
  format: ExportFormat,
  writer: Writable,
  options: {
    signal?: AbortSignal;
    onProgress?: (done: number, total: number) => void;
  } = {}
): Promise<void> {
  const { signal, onProgress } = options;
  const total = source.orderedRowNumbers.length;
  let done = 0;
  let lastProgress = 0; // 0 ensures first chunk always emits a progress update

  if (format === "json") {
    const incidentJson = incident ? JSON.stringify(incident) : undefined;
    const header = incidentJson ? `{"incident":${incidentJson},"lines":[` : `{"lines":[`;
    await writeWithBackpressure(writer, signal, header);
    let first = true;
    for await (const chunk of iterateAccessLogIndexChunks(
      source.run.accessIndex,
      source.orderedRowNumbers,
      { signal }
    )) {
      for (const line of chunk) {
        const sep = first ? "" : ",";
        await writeWithBackpressure(writer, signal, `${sep}${JSON.stringify(line)}`);
        first = false;
      }
      done += chunk.length;
      const now = Date.now();
      if (onProgress && now - lastProgress >= STREAM_PROGRESS_THROTTLE_MS) {
        onProgress(done, total);
        lastProgress = now;
        await setTimeoutPromise(0); // yield so UI can repaint the progress message
      }
    }
    await writeWithBackpressure(writer, signal, "]}");
  } else {
    const separator = format === "csv" ? "," : "\t";
    const sink = format === "csv" ? "csv" : "tsv";
    const headerRow =
      DELIMITED_COLUMNS.map((c) => escapeDelimitedCell(c.key, separator, sink)).join(separator) +
      "\n";
    await writeWithBackpressure(writer, signal, headerRow);
    for await (const chunk of iterateAccessLogIndexChunks(
      source.run.accessIndex,
      source.orderedRowNumbers,
      { signal }
    )) {
      let rows = "";
      for (const line of chunk) {
        rows +=
          DELIMITED_COLUMNS.map((c) => escapeDelimitedCell(c.value(line), separator, sink)).join(
            separator
          ) + "\n";
      }
      await writeWithBackpressure(writer, signal, rows);
      done += chunk.length;
      const now = Date.now();
      if (onProgress && now - lastProgress >= STREAM_PROGRESS_THROTTLE_MS) {
        onProgress(done, total);
        lastProgress = now;
        await setTimeoutPromise(0); // yield so UI can repaint the progress message
      }
    }
  }
  onProgress?.(total, total);
}

export function uniqueExportTmpPath(finalPath: string): string {
  const id = randomBytes(8).toString("hex");
  return path.join(
    path.dirname(finalPath),
    `.${path.basename(finalPath)}.tmp-${process.pid}-${id}`
  );
}

export async function replaceFileAtomically(
  tmpPath: string,
  finalPath: string,
  io: { rename: typeof rename; unlink: typeof unlink } = { rename, unlink }
): Promise<void> {
  try {
    await io.rename(tmpPath, finalPath);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "EEXIST" && code !== "EPERM" && code !== "EACCES") {
      throw error;
    }

    const backup = `${finalPath}.bak-${process.pid}-${randomBytes(4).toString("hex")}`;
    await io.rename(finalPath, backup);
    try {
      await io.rename(tmpPath, finalPath);
    } catch (inner) {
      await io.rename(backup, finalPath).catch(() => undefined);
      throw inner;
    }
    await io.unlink(backup).catch(() => undefined);
  }
}

export async function streamExportToFile(
  incident: Incident | undefined,
  source: { run: CitrxRun; orderedRowNumbers: OrderedRowNumbers },
  format: ExportFormat,
  finalPath: string,
  options: {
    signal?: AbortSignal;
    onProgress?: (done: number, total: number) => void;
  } = {}
): Promise<void> {
  const tmpPath = uniqueExportTmpPath(finalPath);
  const stream = createWriteStream(tmpPath);
  const streamFailed = new Promise<never>((_, reject) => {
    stream.once("error", reject);
  });
  try {
    await Promise.race([
      (async () => {
        await streamSerializeExport(incident, source, format, stream, options);
        stream.end();
        await finished(stream);
      })(),
      streamFailed
    ]);
    await replaceFileAtomically(tmpPath, finalPath);
  } catch (error) {
    stream.destroy();
    await finished(stream).catch(() => undefined);
    await unlink(tmpPath).catch(() => undefined);
    throw error;
  }
}
