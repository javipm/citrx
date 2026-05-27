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
import { AI_BOT_PATTERNS } from "../rules/data/ai-bots.js";
import { FINGERPRINT_PATHS } from "../rules/data/scanner-fingerprint-paths.js";
import { SCANNER_UA_PATTERNS } from "../rules/data/scanner-uas.js";
import {
  buildAggregateIncidents,
  detectRequestHits,
  mergeRuleHit,
  pruneNoise,
  redactTarget,
  querySignature
} from "../rules/local.js";
import type { PathStats } from "../rules/local.js";
import { applyScoringMultipliers } from "../rules/scoring.js";
import type {
  AnalyzeInputSource,
  AnalyzeReport,
  Incident,
  IncidentLogLine,
  IncidentMatchSet,
  TopItem
} from "./types.js";
import { BehaviorTracker, extractSubnetPrefix } from "./behavior.js";
import { requestParamNames, requestParamValueLabels, userAgentLabel } from "./query-params.js";
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
  userAgents: Map<string, number>;
  params: Map<string, number>;
  paramValues: Map<string, number>;
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
const MAX_INCIDENT_SAMPLE_LINES = 200;

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
    userAgents: new Map(),
    params: new Map(),
    paramValues: new Map(),
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
  // Drop low-signal rule incidents (single 404 probes, isolated rare methods, etc.)
  pruneNoise(counters.ruleIncidents);
  // Compute once — reused for both incidents list and incidentMatches.
  const aggregateIncidents = buildAggregateIncidents(counters.pathStats.values());

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
    topUserAgents: topItems(counters.userAgents, options.top),
    topParams: topItems(counters.params, options.top),
    topParamValues: topItems(counters.paramValues, options.top),
    accessLog: {
      totalLines: counters.parsedLines,
      indexedLines: counters.accessLogWriter?.index.totalRows ?? 0
    },
    timeStats: behavior.timeStats,
    ipBehaviorStats: behavior.ipBehaviorStats,
    aiBotStats: behavior.aiBotStats,
    incidents: sortIncidents(
      applyScoringMultipliers([
        ...counters.ruleIncidents.values(),
        ...aggregateIncidents,
        ...behavior.incidents
      ])
    ),
    incidentMatches: incidentMatches(counters, aggregateIncidents, behavior.incidents)
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
  const storedLine: IncidentLogLine = {
    row: -1,
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

  storedLine.row = counters.accessLogWriter?.write(storedLine) ?? counters.parsedLines - 1;
  counters.behavior.observe(entry);
  increment(counters.ips, entry.ip);
  increment(counters.paths, entry.path);
  increment(counters.methods, entry.method);
  increment(counters.statuses, String(entry.status));
  increment(counters.userAgents, userAgentLabel(entry.userAgent));
  for (const param of requestParamNames(entry.target)) {
    increment(counters.params, param);
  }
  for (const paramValue of requestParamValueLabels(entry.target)) {
    increment(counters.paramValues, paramValue);
  }
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

function incidentMatches(
  counters: Counters,
  aggregateIncidents: Incident[],
  behaviorIncidents: Incident[]
): IncidentMatchSet[] {
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

  for (const incident of behaviorIncidents) {
    const matchSet = behaviorIncidentMatches(incident, counters);

    if (matchSet.totalMatches > 0) {
      matches.set(incident.id, matchSet);
    }
  }

  return [...matches.values()]
    .sort((a, b) => a.incidentId.localeCompare(b.incidentId))
    .map((matchSet) => ({
      incidentId: matchSet.incidentId,
      totalMatches: matchSet.totalMatches,
      rowNumbers: matchSet.lines.map((line) => line.row),
      lines: matchSet.lines
    }));
}

function behaviorIncidentMatches(
  incident: Incident,
  counters: Counters
): MutableIncidentMatches {
  const matchSet: MutableIncidentMatches = {
    incidentId: incident.id,
    totalMatches: 0,
    lines: []
  };
  const predicate = behaviorIncidentPredicate(incident);

  if (!predicate) {
    return matchSet;
  }

  for (const pathMatchSet of counters.pathMatches.values()) {
    for (const line of pathMatchSet.lines) {
      if (predicate(line)) {
        matchSet.totalMatches += 1;
        pushSampleLine(matchSet.lines, line);
      }
    }
  }

  return matchSet;
}

function behaviorIncidentPredicate(
  incident: Incident
): ((line: IncidentLogLine) => boolean) | null {
  if (incident.id.startsWith("ai_scraper_known:")) {
    const botName = String(evidenceValue(incident, "botName") ?? "");
    const pattern = AI_BOT_PATTERNS.find((item) => item.name === botName);
    return pattern
      ? (line) => Boolean(line.userAgent && pattern.regex.test(line.userAgent))
      : null;
  }

  if (incident.id.startsWith("scanner_ua_known:")) {
    const scanner = String(evidenceValue(incident, "scanner") ?? "");
    const ip = String(evidenceValue(incident, "ip") ?? "");
    const pattern = SCANNER_UA_PATTERNS.find((item) => item.name === scanner);
    return pattern
      ? (line) => line.ip === ip && Boolean(line.userAgent && pattern.regex.test(line.userAgent))
      : null;
  }

  if (incident.id.startsWith("scanner_signature_paths:")) {
    const ip = String(evidenceValue(incident, "ip") ?? "");
    return (line) => line.ip === ip && FINGERPRINT_PATHS.has(line.path);
  }

  if (incident.id.startsWith("http_4xx_storm:")) {
    const ip = String(evidenceValue(incident, "ip") ?? "");
    return (line) => line.ip === ip && line.status >= 400 && line.status <= 499;
  }

  if (incident.id.startsWith("http_5xx_storm:")) {
    const ip = String(evidenceValue(incident, "ip") ?? "");
    return (line) => line.ip === ip && line.status >= 500 && line.status <= 599;
  }

  if (incident.id.startsWith("http_head_flood:")) {
    const ip = String(evidenceValue(incident, "ip") ?? "");
    return (line) => line.ip === ip && line.method === "HEAD";
  }

  if (
    incident.id.startsWith("fake_bot_googlebot:") ||
    incident.id.startsWith("fake_bot_bingbot:")
  ) {
    const ip = String(evidenceValue(incident, "ip") ?? "");
    return (line) => line.ip === ip;
  }

  if (incident.id.startsWith("ddos_distributed_subnet:")) {
    const prefix = String(evidenceValue(incident, "prefix") ?? "");
    return (line) => extractSubnetPrefix(line.ip) === prefix;
  }

  if (
    incident.id.startsWith("ddos_rps_burst_single_ip:") ||
    incident.id.startsWith("single_ip_path_explosion:") ||
    incident.id.startsWith("ua_rotation_same_ip:")
  ) {
    const ip = String(evidenceValue(incident, "ip") ?? "");
    return (line) => line.ip === ip;
  }

  return null;
}

function evidenceValue(incident: Incident, key: string): Incident["evidence"][number]["value"] | undefined {
  return incident.evidence.find((item) => item.key === key)?.value;
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
  pushSampleLine(current.lines, line);

  matches.set(incidentId, current);
}

function pushSampleLine(lines: IncidentLogLine[], line: IncidentLogLine): void {
  if (lines.length < MAX_INCIDENT_SAMPLE_LINES) {
    lines.push(line);
  }
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
  const kindWeight: Record<Incident["kind"], number> = {
    compromise: 3,
    saturation: 2,
    noise: 1
  };

  return incidents.sort(
    (a, b) =>
      kindWeight[b.kind] - kindWeight[a.kind] ||
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
