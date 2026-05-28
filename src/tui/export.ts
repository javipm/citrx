import { setTimeout as setTimeoutPromise } from "node:timers/promises";
import { Writable } from "node:stream";
import type { Incident, IncidentLogLine } from "../analysis/types.js";
import { iterateAccessLogIndexChunks, type OrderedRowNumbers } from "../run/access-index.js";
import type { CitrxRun } from "../run/types.js";
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
  const rows = [
    DELIMITED_COLUMNS.map((column) => escapeDelimitedCell(column.key, separator)).join(separator),
    ...lines.map((line) =>
      DELIMITED_COLUMNS.map((column) => escapeDelimitedCell(column.value(line), separator)).join(
        separator
      )
    )
  ];

  return `${rows.join("\n")}\n`;
}

function escapeDelimitedCell(value: string | number | null, separator: string): string {
  const text = value === null ? "" : String(value);

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
    const headerRow =
      DELIMITED_COLUMNS.map((c) => escapeDelimitedCell(c.key, separator)).join(separator) + "\n";
    await writeWithBackpressure(writer, signal, headerRow);
    for await (const chunk of iterateAccessLogIndexChunks(
      source.run.accessIndex,
      source.orderedRowNumbers,
      { signal }
    )) {
      let rows = "";
      for (const line of chunk) {
        rows +=
          DELIMITED_COLUMNS.map((c) => escapeDelimitedCell(c.value(line), separator)).join(
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
