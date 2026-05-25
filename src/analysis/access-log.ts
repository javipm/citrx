import { createReadStream } from "node:fs";
import { open } from "node:fs/promises";
import { createInterface } from "node:readline/promises";

import {
  detectParser,
  loadCustomParsers,
  resolveParser,
  validateParserOnSample
} from "../parser/access-log.js";
import type {
  AccessLogParser,
  FormatChoice
} from "../parser/access-log.js";
import type { AnalyzeReport, TopItem } from "./types.js";

interface AnalyzeOptions {
  top: number;
  format: FormatChoice;
  formatConfig?: string;
}

interface FileParserSelection {
  file: string;
  parser: AccessLogParser;
  sampledLines: number;
  parsedLines: number;
  parseRatio: number;
}

interface Counters {
  files: number;
  totalLines: number;
  parsedLines: number;
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
  if (files.length === 0) {
    throw new Error("No input files found.");
  }

  const customParsers = await loadCustomParsers(options.formatConfig);
  const counters: Counters = {
    files: files.length,
    totalLines: 0,
    parsedLines: 0,
    invalidLines: 0,
    totalBytes: 0,
    ips: new Map(),
    paths: new Map(),
    methods: new Map(),
    statuses: new Map()
  };
  const inputFormats: AnalyzeReport["inputFormats"] = [];

  for (const file of files) {
    const selection = await selectParserForFile(
      file,
      options.format,
      customParsers
    );

    if (
      selection.sampledLines < MIN_SAMPLE_LINES ||
      selection.parseRatio < MIN_PARSE_RATIO
    ) {
      throw new Error(
        `Input does not look like an Apache/Nginx access log: ${file} ` +
          `(${selection.parsedLines}/${selection.sampledLines} sampled lines parsed). ` +
          "If this is a custom access-log format, pass --format custom:<name> " +
          "and --format-config <path>."
      );
    }

    inputFormats.push({
      file,
      format: selection.parser.id,
      sampledLines: selection.sampledLines,
      parsedSampleLines: selection.parsedLines,
      sampleParseRatio: selection.parseRatio
    });

    await analyzeFile(file, selection.parser, counters);
  }

  return {
    app: "citrx",
    phase: 1,
    status: "ok",
    generatedAt: new Date().toISOString(),
    inputs: files,
    inputFormats,
    summary: {
      files: counters.files,
      totalLines: counters.totalLines,
      parsedLines: counters.parsedLines,
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
): Promise<FileParserSelection> {
  const sampleLines = await readSampleLines(file);
  const explicitParser = resolveParser(format, customParsers);

  if (format !== "auto" && !explicitParser) {
    throw new Error(
      `Unknown access-log format: ${format}. ` +
        "Use one of auto, apache_common, apache_combined, nginx_combined, " +
        "or provide --format-config for custom:<name>."
    );
  }

  const detection = explicitParser
    ? validateParserOnSample(explicitParser, sampleLines)
    : detectParser(sampleLines, customParsers);

  if (!detection) {
    return {
      file,
      parser: explicitParser ?? customParsers[0] ?? fallbackParser(),
      sampledLines: sampleLines.length,
      parsedLines: 0,
      parseRatio: 0
    };
  }

  return {
    file,
    parser: detection.parser,
    sampledLines: detection.sampledLines,
    parsedLines: detection.parsedLines,
    parseRatio: detection.parseRatio
  };
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
    const completeLines = bytesRead === SAMPLE_BYTES ? lines.slice(0, -1) : lines;
    return completeLines;
  } finally {
    await handle.close();
  }
}

async function analyzeFile(
  file: string,
  parser: AccessLogParser,
  counters: Counters
): Promise<void> {
  const stream = createReadStream(file, {
    encoding: "utf8",
    highWaterMark: 64 * 1024
  });
  const lines = createInterface({
    input: stream,
    crlfDelay: Infinity
  });

  for await (const line of lines) {
    if (line.length === 0) {
      continue;
    }

    counters.totalLines += 1;

    const entry = parser.parse(line);

    if (!entry) {
      counters.invalidLines += 1;
      continue;
    }

    counters.parsedLines += 1;
    counters.totalBytes += entry.bytes ?? 0;
    increment(counters.ips, entry.ip);
    increment(counters.paths, entry.path);
    increment(counters.methods, entry.method);
    increment(counters.statuses, String(entry.status));
  }
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
