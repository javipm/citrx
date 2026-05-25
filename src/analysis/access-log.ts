import { createReadStream } from "node:fs";
import { open } from "node:fs/promises";
import { createInterface } from "node:readline/promises";

import {
  detectParser,
  loadCustomParsers,
  resolveParser,
  validateParserOnSample
} from "../parser/access-log.js";
import type { AccessLogParser, FormatChoice } from "../parser/access-log.js";
import type { AnalyzeInputSource, AnalyzeReport, TopItem } from "./types.js";

interface AnalyzeOptions {
  top: number;
  format: FormatChoice;
  formatConfig?: string;
  since?: Date;
  until?: Date;
}

interface SourceParserSelection {
  label: string;
  parser: AccessLogParser;
  sampledLines: number;
  parsedLines: number;
  parseRatio: number;
  sampleLines?: string[];
  remainingLines?: AsyncIterable<string>;
}

interface Counters {
  files: number;
  totalLines: number;
  parsedLines: number;
  filteredLines: number;
  invalidLines: number;
  totalBytes: number;
  ips: Map<string, number>;
  paths: Map<string, number>;
  methods: Map<string, number>;
  statuses: Map<string, number>;
}

const SAMPLE_BYTES = 64 * 1024;
const MIN_SAMPLE_LINES = 1;
const MIN_PARSE_RATIO = 0.8;
const MAX_SAMPLE_LINES = 200;

export async function analyzeAccessLogs(
  files: string[],
  options: AnalyzeOptions
): Promise<AnalyzeReport> {
  return analyzeAccessLogSources(
    files.map((file) => ({ kind: "file", path: file })),
    options
  );
}

export async function analyzeAccessLogSources(
  sources: AnalyzeInputSource[],
  options: AnalyzeOptions
): Promise<AnalyzeReport> {
  if (sources.length === 0) {
    throw new Error("No input sources found.");
  }

  const customParsers = await loadCustomParsers(options.formatConfig);
  const counters: Counters = {
    files: sources.length,
    totalLines: 0,
    parsedLines: 0,
    filteredLines: 0,
    invalidLines: 0,
    totalBytes: 0,
    ips: new Map(),
    paths: new Map(),
    methods: new Map(),
    statuses: new Map()
  };
  const inputFormats: AnalyzeReport["inputFormats"] = [];

  for (const source of sources) {
    const selection =
      source.kind === "file"
        ? await selectParserForFile(source.path, options.format, customParsers)
        : await selectParserForStream(source, options.format, customParsers);

    if (
      selection.sampledLines < MIN_SAMPLE_LINES ||
      selection.parseRatio < MIN_PARSE_RATIO
    ) {
      throw new Error(
        `Input does not look like an Apache/Nginx access log: ${selection.label} ` +
          `(${selection.parsedLines}/${selection.sampledLines} sampled lines parsed). ` +
          "If this is a custom access-log format, pass --format custom:<name> " +
          "and --format-config <path>."
      );
    }

    inputFormats.push({
      file: selection.label,
      format: selection.parser.id,
      sampledLines: selection.sampledLines,
      parsedSampleLines: selection.parsedLines,
      sampleParseRatio: selection.parseRatio
    });

    if (source.kind === "file") {
      await analyzeFile(source.path, selection.parser, counters, options);
    } else {
      await analyzeLines(
        selection.remainingLines ?? emptyAsyncIterable(),
        selection.parser,
        counters,
        options,
        selection.sampleLines ?? []
      );
    }
  }

  return {
    app: "citrx",
    phase: 1,
    status: "ok",
    generatedAt: new Date().toISOString(),
    inputs: sources.map((source) => (source.kind === "file" ? source.path : source.label)),
    inputFormats,
    summary: {
      files: counters.files,
      totalLines: counters.totalLines,
      parsedLines: counters.parsedLines,
      filteredLines: counters.filteredLines,
      invalidLines: counters.invalidLines,
      totalBytes: counters.totalBytes
    },
    topIps: topItems(counters.ips, options.top),
    topPaths: topItems(counters.paths, options.top),
    topMethods: topItems(counters.methods, options.top),
    topStatuses: topItems(counters.statuses, options.top)
  };
}

async function selectParserForFile(
  file: string,
  format: FormatChoice,
  customParsers: AccessLogParser[]
): Promise<SourceParserSelection> {
  const sampleLines = await readSampleLines(file);
  const detection = detectOrValidate(format, customParsers, sampleLines);

  return {
    label: file,
    parser: detection?.parser ?? fallbackParser(),
    sampledLines: detection?.sampledLines ?? sampleLines.length,
    parsedLines: detection?.parsedLines ?? 0,
    parseRatio: detection?.parseRatio ?? 0
  };
}

async function selectParserForStream(
  source: Extract<AnalyzeInputSource, { kind: "stream" }>,
  format: FormatChoice,
  customParsers: AccessLogParser[]
): Promise<SourceParserSelection> {
  const iterator = createInterface({
    input: source.stream,
    crlfDelay: Infinity
  })[Symbol.asyncIterator]();
  const sampleLines: string[] = [];

  while (sampleLines.length < MAX_SAMPLE_LINES) {
    const next = await iterator.next();

    if (next.done) {
      break;
    }

    if (next.value.length > 0) {
      sampleLines.push(next.value);
    }
  }

  const detection = detectOrValidate(format, customParsers, sampleLines);

  return {
    label: source.label,
    parser: detection?.parser ?? fallbackParser(),
    sampledLines: detection?.sampledLines ?? sampleLines.length,
    parsedLines: detection?.parsedLines ?? 0,
    parseRatio: detection?.parseRatio ?? 0,
    sampleLines,
    remainingLines: iteratorToAsyncIterable(iterator)
  };
}

function detectOrValidate(
  format: FormatChoice,
  customParsers: AccessLogParser[],
  sampleLines: string[]
): ReturnType<typeof detectParser> {
  const explicitParser = resolveParser(format, customParsers);

  if (format !== "auto" && !explicitParser) {
    throw new Error(
      `Unknown access-log format: ${format}. ` +
        "Use one of auto, apache_common, apache_combined, nginx_combined, " +
        "or provide --format-config for custom:<name>."
    );
  }

  return explicitParser
    ? validateParserOnSample(explicitParser, sampleLines)
    : detectParser(sampleLines, customParsers);
}

async function readSampleLines(file: string): Promise<string[]> {
  const handle = await open(file, "r");

  try {
    const buffer = Buffer.alloc(SAMPLE_BYTES);
    const { bytesRead } = await handle.read(buffer, 0, SAMPLE_BYTES, 0);

    if (bytesRead === 0) {
      return [];
    }

    const sampleBuffer = buffer.subarray(0, bytesRead);

    if (sampleBuffer.includes(0)) {
      return [];
    }

    const text = sampleBuffer.toString("utf8");
    const lines = text
      .split(/\r?\n/)
      .slice(0, MAX_SAMPLE_LINES)
      .filter((line) => line.trim().length > 0);

    return bytesRead === SAMPLE_BYTES ? lines.slice(0, -1) : lines;
  } finally {
    await handle.close();
  }
}

async function analyzeFile(
  file: string,
  parser: AccessLogParser,
  counters: Counters,
  options: AnalyzeOptions
): Promise<void> {
  const stream = createReadStream(file, {
    encoding: "utf8",
    highWaterMark: 64 * 1024
  });
  const lines = createInterface({
    input: stream,
    crlfDelay: Infinity
  });

  await analyzeLines(lines, parser, counters, options);
}

async function analyzeLines(
  lines: AsyncIterable<string>,
  parser: AccessLogParser,
  counters: Counters,
  options: AnalyzeOptions,
  prefixLines: string[] = []
): Promise<void> {
  for (const line of prefixLines) {
    analyzeLine(line, parser, counters, options);
  }

  for await (const line of lines) {
    analyzeLine(line, parser, counters, options);
  }
}

function analyzeLine(
  line: string,
  parser: AccessLogParser,
  counters: Counters,
  options: AnalyzeOptions
): void {
  if (line.length === 0) {
    return;
  }

  counters.totalLines += 1;

  const entry = parser.parse(line);

  if (!entry) {
    counters.invalidLines += 1;
    return;
  }

  if (!isInsideDateRange(entry.timestamp, options)) {
    counters.filteredLines += 1;
    return;
  }

  counters.parsedLines += 1;
  counters.totalBytes += entry.bytes ?? 0;
  increment(counters.ips, entry.ip);
  increment(counters.paths, entry.path);
  increment(counters.methods, entry.method);
  increment(counters.statuses, String(entry.status));
}

function fallbackParser(): AccessLogParser {
  return {
    id: "apache_combined",
    label: "Apache combined",
    parse: () => null
  };
}

function increment(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1);
}

function topItems(map: Map<string, number>, limit: number): TopItem[] {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([value, count]) => ({ value, count }));
}

async function* iteratorToAsyncIterable(
  iterator: AsyncIterator<string>
): AsyncIterable<string> {
  while (true) {
    const next = await iterator.next();

    if (next.done) {
      break;
    }

    yield next.value;
  }
}

async function* emptyAsyncIterable(): AsyncIterable<string> {
  // Empty by design.
}

function isInsideDateRange(timestamp: string, options: AnalyzeOptions): boolean {
  if (!options.since && !options.until) {
    return true;
  }

  const date = parseAccessLogTimestamp(timestamp);

  if (!date) {
    return true;
  }

  if (options.since && date < options.since) {
    return false;
  }

  if (options.until && date > options.until) {
    return false;
  }

  return true;
}

function parseAccessLogTimestamp(timestamp: string): Date | null {
  const match =
    /^(?<day>\d{2})\/(?<month>[A-Za-z]{3})\/(?<year>\d{4}):(?<time>\d{2}:\d{2}:\d{2}) (?<offset>[+-]\d{4})$/.exec(
      timestamp
    );

  if (!match?.groups) {
    const fallback = new Date(timestamp);
    return Number.isNaN(fallback.getTime()) ? null : fallback;
  }

  const month = monthNumber(match.groups.month);

  if (month === null) {
    return null;
  }

  const offset = match.groups.offset;
  const iso = `${match.groups.year}-${month}-${match.groups.day}T${match.groups.time}${offset.slice(0, 3)}:${offset.slice(3)}`;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date;
}

function monthNumber(month: string): string | null {
  const months = new Map([
    ["Jan", "01"],
    ["Feb", "02"],
    ["Mar", "03"],
    ["Apr", "04"],
    ["May", "05"],
    ["Jun", "06"],
    ["Jul", "07"],
    ["Aug", "08"],
    ["Sep", "09"],
    ["Oct", "10"],
    ["Nov", "11"],
    ["Dec", "12"]
  ]);

  return months.get(month) ?? null;
}
