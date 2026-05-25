import { createReadStream } from "node:fs";
import { open } from "node:fs/promises";
import { createInterface } from "node:readline/promises";

import { parseAccessLogLine } from "../parser/access-log.js";
import type { AnalyzeReport, TopItem } from "./types.js";

interface AnalyzeOptions {
  top: number;
}

interface ValidationResult {
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

  for (const file of files) {
    const validation = await validateAccessLogFile(file);

    if (
      validation.sampledLines < MIN_SAMPLE_LINES ||
      validation.parseRatio < MIN_PARSE_RATIO
    ) {
      throw new Error(
        `Input does not look like an Apache/Nginx access log: ${file} ` +
          `(${validation.parsedLines}/${validation.sampledLines} sampled lines parsed).`
      );
    }

    await analyzeFile(file, counters);
  }

  return {
    app: "citrx",
    phase: 1,
    status: "ok",
    generatedAt: new Date().toISOString(),
    inputs: files,
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

async function validateAccessLogFile(file: string): Promise<ValidationResult> {
  const handle = await open(file, "r");

  try {
    const buffer = Buffer.alloc(SAMPLE_BYTES);
    const { bytesRead } = await handle.read(buffer, 0, SAMPLE_BYTES, 0);

    if (bytesRead === 0) {
      return { sampledLines: 0, parsedLines: 0, parseRatio: 0 };
    }

    const sampleBuffer = buffer.subarray(0, bytesRead);

    if (sampleBuffer.includes(0)) {
      return { sampledLines: 0, parsedLines: 0, parseRatio: 0 };
    }

    const text = sampleBuffer.toString("utf8");
    const lines = text
      .split(/\r?\n/)
      .slice(0, MAX_SAMPLE_LINES)
      .filter((line) => line.trim().length > 0);
    const completeLines = bytesRead === SAMPLE_BYTES ? lines.slice(0, -1) : lines;
    const parsedLines = completeLines.filter((line) => parseAccessLogLine(line))
      .length;

    return {
      sampledLines: completeLines.length,
      parsedLines,
      parseRatio:
        completeLines.length === 0 ? 0 : parsedLines / completeLines.length
    };
  } finally {
    await handle.close();
  }
}

async function analyzeFile(file: string, counters: Counters): Promise<void> {
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

    const entry = parseAccessLogLine(line);

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

function increment(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1);
}

function topItems(map: Map<string, number>, limit: number): TopItem[] {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([value, count]) => ({ value, count }));
}
