import { createInterface } from "node:readline/promises";

import { openTextInputStreams } from "../input/compressed.js";
import {
  detectParser,
  loadCustomParsers,
  resolveParser,
  validateParserOnSample
} from "../parser/access-log.js";
import type { AccessLogEntry, AccessLogParser, FormatChoice } from "../parser/access-log.js";
import type { AccessLogIndexWriter } from "../run/access-index.js";
import {
  buildAggregateIncidents,
  detectRequestHits,
  mergeRuleHit,
  redactTarget,
  querySignature
} from "../rules/local.js";
import type { PathStats } from "../rules/local.js";
import type {
  AnalyzeInputSource,
  AnalyzeReport,
  Incident,
  IncidentLogLine,
  IncidentMatchSet,
  TopItem
} from "./types.js";
import { BehaviorTracker } from "./behavior.js";
import { parseAccessLogTimestamp } from "./timestamp.js";

interface AnalyzeOptions {
  top: number;
  format: FormatChoice;
  formatConfig?: string;
  since?: Date;
  until?: Date;
  accessLogWriter?: AccessLogIndexWriter;
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
  pathStats: Map<string, PathStats>;
  ruleIncidents: Map<string, Incident>;
  ruleMatches: Map<string, MutableIncidentMatches>;
  pathMatches: Map<string, MutableIncidentMatches>;
  lineNumbers: Map<string, number>;
  accessLogWriter?: AccessLogIndexWriter;
  behavior: BehaviorTracker;
}

interface MutableIncidentMatches {
  incidentId: string;
  totalMatches: number;
  lines: IncidentLogLine[];
}

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
    files: 0,
    totalLines: 0,
    parsedLines: 0,
    filteredLines: 0,
    invalidLines: 0,
    totalBytes: 0,
    ips: new Map(),
    paths: new Map(),
    methods: new Map(),
    statuses: new Map(),
    pathStats: new Map(),
    ruleIncidents: new Map(),
    ruleMatches: new Map(),
    pathMatches: new Map(),
    lineNumbers: new Map(),
    accessLogWriter: options.accessLogWriter,
    behavior: new BehaviorTracker()
  };
  const inputFormats: AnalyzeReport["inputFormats"] = [];

  for (const source of sources) {
    if (source.kind === "file") {
      for await (const textSource of openTextInputStreams(source.path)) {
        await analyzeTextSource(
          {
            kind: "stream",
            label: textSource.label,
            stream: textSource.stream
          },
          customParsers,
          counters,
          inputFormats,
          options
        );
      }
    } else {
      await analyzeTextSource(source, customParsers, counters, inputFormats, options);
    }
  }

  const behavior = counters.behavior.finalize();

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
    topStatuses: topItems(counters.statuses, options.top),
    accessLog: {
      totalLines: counters.parsedLines,
      indexedLines: counters.accessLogWriter?.index.totalRows ?? 0
    },
    timeStats: behavior.timeStats,
    ipBehaviorStats: behavior.ipBehaviorStats,
    incidents: sortIncidents([
      ...counters.ruleIncidents.values(),
      ...buildAggregateIncidents(counters.pathStats.values()),
      ...behavior.incidents
    ]),
    incidentMatches: incidentMatches(counters)
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

async function analyzeTextSource(
  source: Extract<AnalyzeInputSource, { kind: "stream" }>,
  customParsers: AccessLogParser[],
  counters: Counters,
  inputFormats: AnalyzeReport["inputFormats"],
  options: AnalyzeOptions
): Promise<void> {
  const selection = await selectParserForStream(source, options.format, customParsers);

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

  counters.files += 1;
  inputFormats.push({
    file: selection.label,
    format: selection.parser.id,
    sampledLines: selection.sampledLines,
    parsedSampleLines: selection.parsedLines,
    sampleParseRatio: selection.parseRatio
  });

  await analyzeLines(
    selection.remainingLines ?? emptyAsyncIterable(),
    selection.parser,
    counters,
    options,
    selection.label,
    selection.sampleLines ?? []
  );
}

async function analyzeLines(
  lines: AsyncIterable<string>,
  parser: AccessLogParser,
  counters: Counters,
  options: AnalyzeOptions,
  sourceLabel: string,
  prefixLines: string[] = []
): Promise<void> {
  for (const line of prefixLines) {
    analyzeLine(line, parser, counters, options, sourceLabel);
  }

  for await (const line of lines) {
    analyzeLine(line, parser, counters, options, sourceLabel);
  }
}

function analyzeLine(
  line: string,
  parser: AccessLogParser,
  counters: Counters,
  options: AnalyzeOptions,
  sourceLabel: string
): void {
  if (line.length === 0) {
    return;
  }

  counters.totalLines += 1;
  const lineNumber = incrementLineNumber(counters.lineNumbers, sourceLabel);

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
  const storedLine = {
    source: sourceLabel,
    lineNumber,
    raw: redactRawLine(line),
    ip: entry.ip,
    timestamp: entry.timestamp,
    method: entry.method,
    path: entry.path,
    target: redactTarget(entry.target),
    status: entry.status,
    bytes: entry.bytes,
    userAgent: entry.userAgent
  };

  counters.accessLogWriter?.write(storedLine);
  counters.behavior.observe(entry);
  increment(counters.ips, entry.ip);
  increment(counters.paths, entry.path);
  increment(counters.methods, entry.method);
  increment(counters.statuses, String(entry.status));
  updatePathStats(counters.pathStats, entry);
  addIncidentLine(counters.pathMatches, entry.path, storedLine);

  for (const hit of detectRequestHits(entry)) {
    const incidentId = mergeRuleHit(counters.ruleIncidents, hit, entry);
    addIncidentLine(counters.ruleMatches, incidentId, storedLine);
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

function incidentMatches(counters: Counters): IncidentMatchSet[] {
  const aggregateIncidents = buildAggregateIncidents(counters.pathStats.values());
  const matches = new Map<string, MutableIncidentMatches>();

  for (const [incidentId, matchSet] of counters.ruleMatches) {
    matches.set(incidentId, matchSet);
  }

  for (const incident of aggregateIncidents) {
    const path = String(
      incident.evidence.find((item) => item.key === "path")?.value ?? ""
    );
    const pathMatches = counters.pathMatches.get(path);

    if (pathMatches) {
      matches.set(incident.id, {
        incidentId: incident.id,
        totalMatches: pathMatches.totalMatches,
        lines: pathMatches.lines
      });
    }
  }

  return [...matches.values()]
    .sort((a, b) => a.incidentId.localeCompare(b.incidentId))
    .map((matchSet) => ({
      incidentId: matchSet.incidentId,
      totalMatches: matchSet.totalMatches,
      lines: matchSet.lines
    }));
}

function addIncidentLine(
  matches: Map<string, MutableIncidentMatches>,
  incidentId: string,
  line: IncidentLogLine
): void {
  const current = matches.get(incidentId) ?? {
    incidentId,
    totalMatches: 0,
    lines: []
  };

  current.totalMatches += 1;
  current.lines.push(line);

  matches.set(incidentId, current);
}

function incrementLineNumber(map: Map<string, number>, sourceLabel: string): number {
  const next = (map.get(sourceLabel) ?? 0) + 1;
  map.set(sourceLabel, next);
  return next;
}

function redactRawLine(line: string): string {
  return line.replace(
    /(token|_token|sid|session|password|passwd|key|secret|jwt|auth|authorization)=([^&\s"]+)/gi,
    "$1=[REDACTED]"
  );
}

function updatePathStats(
  statsByPath: Map<string, PathStats>,
  entry: AccessLogEntry
): void {
  let stats = statsByPath.get(entry.path);

  if (!stats) {
    stats = {
      path: entry.path,
      count: 0,
      bytes: 0,
      ipCounts: new Map(),
      queryVariants: new Set(),
      postCount: 0
    };
    statsByPath.set(entry.path, stats);
  }

  stats.count += 1;
  stats.bytes += entry.bytes ?? 0;
  stats.ipCounts.set(entry.ip, (stats.ipCounts.get(entry.ip) ?? 0) + 1);

  const signature = querySignature(entry.target);
  if (signature) {
    stats.queryVariants.add(signature);
  }

  if (entry.method === "POST") {
    stats.postCount += 1;
  }
}

function sortIncidents(incidents: Incident[]): Incident[] {
  const severityWeight: Record<Incident["severity"], number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1
  };

  return incidents.sort(
    (a, b) =>
      severityWeight[b.severity] - severityWeight[a.severity] ||
      b.score - a.score ||
      a.id.localeCompare(b.id)
  );
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
