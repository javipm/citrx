import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { setImmediate } from "node:timers/promises";

import { openTextInputStreams } from "../input/compressed.js";
import {
  detectParser,
  loadCustomParsers,
  resolveParser,
  validateParserOnSample
} from "../parser/access-log.js";
import type { AccessLogEntry, AccessLogParser, FormatChoice } from "../parser/access-log.js";
import { createAccessLogIndexWriter, type AccessLogIndexWriter } from "../run/access-index.js";
import { AI_BOT_PATTERNS } from "../rules/data/ai-bots.js";
import { FINGERPRINT_PATHS } from "../rules/data/scanner-fingerprint-paths.js";
import { SCANNER_UA_PATTERNS } from "../rules/data/scanner-uas.js";
import {
  buildAggregateIncidents,
  demoteSoftServedRecon,
  demoteVerifiedCrawlerPayloads,
  detectRequestHits,
  isHighValueSensitivePath,
  mergeRuleHit,
  parseTargetUrl,
  pruneNoise,
  redactTarget,
  querySignature
} from "../rules/local.js";
import type { PathStats } from "../rules/local.js";
import { applyScoringMultipliers } from "../rules/scoring.js";
import { redactSecretPairs } from "../utils/redact.js";
import type {
  AnalyzeInputSource,
  AnalyzeReport,
  Incident,
  IncidentLogLine,
  IncidentMatchSet,
  TopItem
} from "./types.js";
import { BehaviorTracker, extractSubnetPrefix } from "./behavior.js";
import { requestParamLabels, userAgentLabel } from "./query-params.js";
import { accessLogTimestampToEpochSeconds } from "./timestamp.js";
import {
  admitHeavyHitter,
  MAX_AGGREGATION_KEYS,
  MAX_GLOBAL_PATH_IP_ENTRIES,
  MAX_GLOBAL_PATH_VARIANT_ENTRIES,
  MAX_PATH_STATS,
  MAX_PATH_UNIQUE_IPS,
  MAX_QUERY_VARIANTS,
  MIN_PATH_IPS_GUARANTEED,
  MIN_PATH_VARIANTS_GUARANTEED,
  addCappedSet,
  incrementCapped,
  rememberDroppedKey
} from "./capped-counter.js";
import { iterateAccessLogIndexChunks, rangeOrderedRowNumbers } from "../run/access-index.js";

interface AnalyzeOptions {
  top: number;
  format: FormatChoice;
  formatConfig?: string;
  since?: Date;
  until?: Date;
  accessLogWriter?: AccessLogIndexWriter;
  onProgress?: (progress: AnalysisProgress) => void;
}

interface AnalysisProgress {
  phase: "reading" | "finalizing";
  totalLines: number;
  parsedLines: number;
  source: string;
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
  lineNumbers: Map<string, number>;
  accessLogWriter?: AccessLogIndexWriter;
  behavior: BehaviorTracker;
  droppedAggregationKeySet: Set<string>;
  droppedPathSet: Set<string>;
  droppedPathIpSet: Set<string>;
  droppedQueryVariantSet: Set<string>;
  pathIpEntries: number;
  pathVariantEntries: number;
  /** Times a top-N counter had to evict to admit a busier key. */
  aggregationEvictions: number;
  pathStatsEvictions: number;
  /** How often each 2xx body size is served on non-sensitive paths. */
  servedBodySizes: Map<number, number>;
}

interface MutableIncidentMatches {
  incidentId: string;
  totalMatches: number;
  /**
   * Row numbers in numerically ascending (stream) order. Rule matches are
   * built during the parse stream; aggregate and behavior match sets are
   * filled from a single index scan after incidents are known.
   */
  rowNumbers: number[];
  lines: IncidentLogLine[];
}

const MIN_SAMPLE_LINES = 1;
const MIN_PARSE_RATIO = 0.8;
const MAX_SAMPLE_LINES = 200;
const MAX_INCIDENT_SAMPLE_LINES = 200;
const MAX_SERVED_BODY_SIZES = 65_536;
const GENERIC_BODY_MIN_OCCURRENCES = 3;
const PROGRESS_YIELD_INTERVAL = 5000;
const FINALIZATION_YIELD_INTERVAL = 5000;

/**
 * Thrown when one input does not look like an access log. Directory inputs
 * routinely mix access logs with `error_log`, `xferlog`, `.statbuf` and OS
 * junk, so a single unparseable file must not abort the whole run — the loop
 * records it as skipped and only fails when no input validated at all.
 */
export class NotAnAccessLogError extends Error {
  constructor(
    readonly label: string,
    readonly detail: string
  ) {
    super(
      `Input does not look like an Apache/Nginx access log: ${label} ` +
        `(${detail}). ` +
        "If this is a custom access-log format, pass --format custom:<name> " +
        "and --format-config <path>."
    );
    this.name = "NotAnAccessLogError";
  }
}

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

  let ownedIndexDir: string | undefined;
  let writer = options.accessLogWriter;
  if (!writer) {
    ownedIndexDir = await mkdtemp(join(tmpdir(), "citrx-match-index-"));
    writer = await createAccessLogIndexWriter(ownedIndexDir);
  }

  try {
    return await analyzeAccessLogSourcesWithWriter(sources, {
      ...options,
      accessLogWriter: writer
    });
  } finally {
    if (ownedIndexDir) {
      writer.close();
      await rm(ownedIndexDir, { recursive: true, force: true });
    }
  }
}

async function analyzeAccessLogSourcesWithWriter(
  sources: AnalyzeInputSource[],
  options: AnalyzeOptions
): Promise<AnalyzeReport> {
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
    lineNumbers: new Map(),
    accessLogWriter: options.accessLogWriter,
    behavior: new BehaviorTracker(),
    droppedAggregationKeySet: new Set(),
    droppedPathSet: new Set(),
    droppedPathIpSet: new Set(),
    droppedQueryVariantSet: new Set(),
    pathIpEntries: 0,
    pathVariantEntries: 0,
    aggregationEvictions: 0,
    pathStatsEvictions: 0,
    servedBodySizes: new Map()
  };
  const inputFormats: AnalyzeReport["inputFormats"] = [];
  const skippedInputs: AnalyzeReport["skippedInputs"] = [];

  for (const source of sources) {
    if (source.kind === "file") {
      for await (const textSource of openTextInputStreams(source.path)) {
        await analyzeOptionalTextSource(
          {
            kind: "stream",
            label: textSource.label,
            stream: textSource.stream
          },
          customParsers,
          counters,
          inputFormats,
          skippedInputs,
          options
        );
      }
    } else {
      await analyzeOptionalTextSource(
        source,
        customParsers,
        counters,
        inputFormats,
        skippedInputs,
        options
      );
    }
  }

  // Every discovered input failed validation: this is a real configuration
  // error, so surface the first one rather than reporting an empty analysis.
  if (counters.files === 0 && skippedInputs.length > 0) {
    throw new NotAnAccessLogError(skippedInputs[0].file, skippedInputs[0].reason);
  }

  await yieldForFinalization(counters, options);
  const behavior = counters.behavior.finalize();
  await yieldForFinalization(counters, options);
  // Drop low-signal rule incidents (single 404 probes, isolated rare methods, etc.)
  pruneNoise(counters.ruleIncidents);
  // Payloads fetched by real Googlebot/bingbot describe a poisoned URL, not an
  // attacker, so they must not sit at the top of the report as critical hits.
  demoteVerifiedCrawlerPayloads(counters.ruleIncidents);
  // A sensitive path "served" at exactly the size of an ordinary page is the
  // site's generic response, not a disclosure.
  demoteSoftServedRecon(counters.ruleIncidents, counters.servedBodySizes);
  await yieldForFinalization(counters, options);
  // Compute once — reused for both incidents list and incidentMatches.
  const aggregateIncidents = buildAggregateIncidents(counters.pathStats.values());
  await yieldForFinalization(counters, options);
  const topIps = await topItems(counters.ips, options.top, counters, options);
  const topPaths = await topItems(counters.paths, options.top, counters, options);
  const topMethods = await topItems(counters.methods, options.top, counters, options);
  const topStatuses = await topItems(counters.statuses, options.top, counters, options);
  const topUserAgents = await topItems(counters.userAgents, options.top, counters, options);
  const topParams = await topItems(counters.params, options.top, counters, options);
  const topParamValues = await topItems(counters.paramValues, options.top, counters, options);
  const incidents = sortIncidents(
    applyScoringMultipliers([
      ...counters.ruleIncidents.values(),
      ...aggregateIncidents,
      ...behavior.incidents
    ])
  );
  await yieldForFinalization(counters, options);
  const matches = await incidentMatches(counters, aggregateIncidents, behavior.incidents, options);

  return {
    app: "citrx",
    phase: 1,
    status: "ok",
    generatedAt: new Date().toISOString(),
    inputs: sources.map((source) => (source.kind === "file" ? source.path : source.label)),
    inputFormats,
    skippedInputs,
    summary: {
      files: counters.files,
      totalLines: counters.totalLines,
      parsedLines: counters.parsedLines,
      filteredLines: counters.filteredLines,
      invalidLines: counters.invalidLines,
      totalBytes: counters.totalBytes,
      droppedAggregationKeys: counters.aggregationEvictions,
      droppedPathStats: counters.droppedPathSet.size + counters.pathStatsEvictions,
      droppedPathIps: counters.droppedPathIpSet.size,
      droppedQueryVariants: counters.droppedQueryVariantSet.size,
      droppedRpsSeconds: counters.behavior.droppedRpsSeconds
    },
    topIps,
    topPaths,
    topMethods,
    topStatuses,
    topUserAgents,
    topParams,
    topParamValues,
    accessLog: {
      totalLines: counters.parsedLines,
      indexedLines: counters.accessLogWriter?.index.totalRows ?? 0
    },
    timeStats: behavior.timeStats,
    ipBehaviorStats: behavior.ipBehaviorStats,
    aiBotStats: behavior.aiBotStats,
    incidents,
    incidentMatches: matches
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
        "Use one of auto, apache_common, apache_combined, nginx_combined " +
        "(same combined regex as apache_combined), or provide --format-config for custom:<name>."
    );
  }

  return explicitParser
    ? validateParserOnSample(explicitParser, sampleLines)
    : detectParser(sampleLines, customParsers);
}

/**
 * Analyzes one input, recording it as skipped instead of throwing when it does
 * not validate as an access log. The caller fails the run only if nothing
 * validated, so a single explicit non-log input still errors out.
 */
async function analyzeOptionalTextSource(
  source: Extract<AnalyzeInputSource, { kind: "stream" }>,
  customParsers: AccessLogParser[],
  counters: Counters,
  inputFormats: AnalyzeReport["inputFormats"],
  skippedInputs: AnalyzeReport["skippedInputs"],
  options: AnalyzeOptions
): Promise<void> {
  try {
    await analyzeTextSource(source, customParsers, counters, inputFormats, options);
  } catch (error) {
    if (!(error instanceof NotAnAccessLogError)) {
      throw error;
    }
    skippedInputs.push({ file: error.label, reason: error.detail });
  }
}

async function analyzeTextSource(
  source: Extract<AnalyzeInputSource, { kind: "stream" }>,
  customParsers: AccessLogParser[],
  counters: Counters,
  inputFormats: AnalyzeReport["inputFormats"],
  options: AnalyzeOptions
): Promise<void> {
  const selection = await selectParserForStream(source, options.format, customParsers);

  if (selection.sampledLines < MIN_SAMPLE_LINES || selection.parseRatio < MIN_PARSE_RATIO) {
    throw new NotAnAccessLogError(
      selection.label,
      `${selection.parsedLines}/${selection.sampledLines} sampled lines parsed`
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
  let processedSinceYield = 0;

  for (const line of prefixLines) {
    analyzeLine(line, parser, counters, options, sourceLabel);
    processedSinceYield = await yieldForProgress(
      processedSinceYield + 1,
      counters,
      options,
      sourceLabel
    );
  }

  for await (const line of lines) {
    analyzeLine(line, parser, counters, options, sourceLabel);
    processedSinceYield = await yieldForProgress(
      processedSinceYield + 1,
      counters,
      options,
      sourceLabel
    );
  }
}

async function yieldForProgress(
  processedSinceYield: number,
  counters: Counters,
  options: AnalyzeOptions,
  sourceLabel: string
): Promise<number> {
  if (processedSinceYield < PROGRESS_YIELD_INTERVAL) {
    return processedSinceYield;
  }

  options.onProgress?.({
    phase: "reading",
    totalLines: counters.totalLines,
    parsedLines: counters.parsedLines,
    source: sourceLabel
  });
  await setImmediate();

  return 0;
}

async function yieldForFinalization(counters: Counters, options: AnalyzeOptions): Promise<void> {
  options.onProgress?.({
    phase: "finalizing",
    totalLines: counters.totalLines,
    parsedLines: counters.parsedLines,
    source: "all inputs"
  });
  await setImmediate();
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

  const epochSecond = accessLogTimestampToEpochSeconds(entry.timestamp);

  if (!isInsideDateRange(epochSecond, options)) {
    counters.filteredLines += 1;
    return;
  }

  counters.parsedLines += 1;
  counters.totalBytes += entry.bytes ?? 0;
  // Parse the target URL once per request and reuse it for redaction and the
  // query-variant signature, instead of each helper re-parsing independently.
  const targetUrl = parseTargetUrl(entry.target);
  const storedLine: IncidentLogLine = {
    row: -1,
    source: sourceLabel,
    lineNumber,
    raw: redactRawLine(line),
    ip: entry.ip,
    timestamp: entry.timestamp,
    method: entry.method,
    path: entry.path,
    target: redactTarget(entry.target, targetUrl),
    status: entry.status,
    bytes: entry.bytes,
    userAgent: entry.userAgent
  };

  storedLine.row = counters.accessLogWriter?.write(storedLine) ?? counters.parsedLines - 1;
  counters.behavior.observe(entry, epochSecond);
  countOrDrop(counters, counters.ips, entry.ip);
  countOrDrop(counters, counters.paths, entry.path);
  increment(counters.methods, entry.method);
  increment(counters.statuses, String(entry.status));
  countOrDrop(counters, counters.userAgents, userAgentLabel(entry.userAgent));
  const params = requestParamLabels(entry.target);
  for (const param of params.names) {
    countOrDrop(counters, counters.params, param);
  }
  for (const paramValue of params.values) {
    countOrDrop(counters, counters.paramValues, paramValue);
  }
  observeServedBodySize(counters, entry);
  updatePathStats(counters.pathStats, counters, entry, epochSecond, targetUrl);

  for (const hit of detectRequestHits(entry)) {
    const incidentId = mergeRuleHit(counters.ruleIncidents, hit, entry);
    addIncidentLine(counters.ruleMatches, incidentId, storedLine);
  }
}

function fallbackParser(): AccessLogParser {
  return {
    id: "apache_combined",
    label: "Combined (Apache/Nginx)",
    parse: () => null
  };
}

function increment(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1);
}

function countOrDrop(counters: Counters, map: Map<string, number>, key: string): void {
  if (admitHeavyHitter(map, key, MAX_AGGREGATION_KEYS)) {
    counters.aggregationEvictions += 1;
  }
}

async function topItems(
  map: Map<string, number>,
  limit: number,
  counters: Counters,
  options: AnalyzeOptions
): Promise<TopItem[]> {
  if (limit <= 0) {
    return [];
  }

  const top: TopItem[] = [];
  let processed = 0;

  for (const [value, count] of map) {
    insertTopItem(top, { value, count }, limit);
    processed += 1;

    if (processed % FINALIZATION_YIELD_INTERVAL === 0) {
      await yieldForFinalization(counters, options);
    }
  }

  return top;
}

function compareTopItem(a: TopItem, b: TopItem): number {
  if (a.count !== b.count) {
    return b.count - a.count;
  }
  return a.value < b.value ? -1 : a.value > b.value ? 1 : 0;
}

export function insertTopItem(top: TopItem[], item: TopItem, limit: number): void {
  if (top.length === limit) {
    const last = top[top.length - 1];
    if (last !== undefined && compareTopItem(item, last) >= 0) {
      return;
    }
  }

  const insertAt = top.findIndex((current) => compareTopItem(item, current) < 0);

  if (insertAt === -1) {
    if (top.length < limit) {
      top.push(item);
    }
    return;
  }

  top.splice(insertAt, 0, item);

  if (top.length > limit) {
    top.pop();
  }
}

/**
 * Ensures rowNumbers is numerically ascending (stream order). Must be called
 * once per matchSet before finalization. "alias" and "stream" kinds are already
 * monotonic; "grouped" (behavior incidents) may have path-interleaved rows.
 */
function normalizeIncidentRowNumbers(
  matchSet: MutableIncidentMatches,
  kind: "alias" | "grouped" | "stream"
): void {
  if (kind === "grouped") {
    matchSet.rowNumbers.sort((a, b) => a - b);
  } else if (process.env.NODE_ENV !== "production") {
    for (let i = 1; i < matchSet.rowNumbers.length; i++) {
      if (matchSet.rowNumbers[i] < matchSet.rowNumbers[i - 1]) {
        throw new Error(
          `rowNumbers not monotonic at index ${i} (kind=${kind}): ${matchSet.rowNumbers[i - 1]} > ${matchSet.rowNumbers[i]}`
        );
      }
    }
  }
}

async function incidentMatches(
  counters: Counters,
  aggregateIncidents: Incident[],
  behaviorIncidents: Incident[],
  options: AnalyzeOptions
): Promise<IncidentMatchSet[]> {
  const matches = new Map<string, MutableIncidentMatches>();
  let processed = 0;

  for (const [incidentId, matchSet] of counters.ruleMatches) {
    normalizeIncidentRowNumbers(matchSet, "stream");
    matches.set(incidentId, matchSet);
    processed = await yieldAfterFinalizationItems(processed + 1, counters, options);
  }

  const pathIncidents = new Map<string, Incident[]>();
  for (const incident of aggregateIncidents) {
    const path = String(incident.evidence.find((item) => item.key === "path")?.value ?? "");
    const list = pathIncidents.get(path) ?? [];
    list.push(incident);
    pathIncidents.set(path, list);
    matches.set(incident.id, emptyMatchSet(incident.id));
  }

  const behaviorPreds: Array<{
    incident: Incident;
    predicate: (line: IncidentLogLine) => boolean;
  }> = [];
  for (const incident of behaviorIncidents) {
    const predicate = behaviorIncidentPredicate(incident);
    if (!predicate) {
      continue;
    }
    behaviorPreds.push({ incident, predicate });
    matches.set(incident.id, emptyMatchSet(incident.id));
  }

  if (pathIncidents.size > 0 || behaviorPreds.length > 0) {
    const writer = counters.accessLogWriter;
    if (!writer || writer.index.totalRows === 0) {
      throw new Error(
        "Access log index is required to build exact incident match sets. Pass accessLogWriter or use the CLI TUI path."
      );
    }
    writer.flush();
    let scanned = 0;
    for await (const chunk of iterateAccessLogIndexChunks(
      writer.index,
      rangeOrderedRowNumbers(writer.index.totalRows)
    )) {
      for (const line of chunk) {
        const forPath = pathIncidents.get(line.path);
        if (forPath) {
          for (const incident of forPath) {
            appendMatchLine(matches.get(incident.id)!, line);
          }
        }
        for (const { incident, predicate } of behaviorPreds) {
          if (predicate(line)) {
            appendMatchLine(matches.get(incident.id)!, line);
          }
        }
      }
      scanned = await yieldAfterFinalizationItems(scanned + chunk.length, counters, options);
    }
  }

  return [...matches.values()]
    .filter(
      (matchSet) => matchSet.totalMatches > 0 || counters.ruleMatches.has(matchSet.incidentId)
    )
    .sort((a, b) => a.incidentId.localeCompare(b.incidentId))
    .map((matchSet) => ({
      incidentId: matchSet.incidentId,
      totalMatches: matchSet.totalMatches,
      rowNumbers: matchSet.rowNumbers,
      lines: matchSet.lines
    }));
}

function emptyMatchSet(incidentId: string): MutableIncidentMatches {
  return { incidentId, totalMatches: 0, rowNumbers: [], lines: [] };
}

function appendMatchLine(matchSet: MutableIncidentMatches, line: IncidentLogLine): void {
  matchSet.totalMatches += 1;
  matchSet.rowNumbers.push(line.row);
  pushSampleLine(matchSet.lines, line);
}

async function yieldAfterFinalizationItems(
  processed: number,
  counters: Counters,
  options: AnalyzeOptions
): Promise<number> {
  if (processed < FINALIZATION_YIELD_INTERVAL) {
    return processed;
  }

  await yieldForFinalization(counters, options);

  return 0;
}

function behaviorIncidentPredicate(
  incident: Incident
): ((line: IncidentLogLine) => boolean) | null {
  if (incident.id.startsWith("ai_scraper_known:")) {
    const botName = String(evidenceValue(incident, "botName") ?? "");
    const pattern = AI_BOT_PATTERNS.find((item) => item.name === botName);
    return pattern
      ? (line) =>
          Boolean(line.userAgent && pattern.regex.test(line.userAgent)) &&
          (incident.kind !== "saturation" || isMateriallyServed(line.status))
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

function isMateriallyServed(status: number): boolean {
  return (status >= 200 && status < 300) || (status >= 500 && status < 600);
}

function evidenceValue(
  incident: Incident,
  key: string
): Incident["evidence"][number]["value"] | undefined {
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
    rowNumbers: [],
    lines: []
  };

  current.totalMatches += 1;
  current.rowNumbers.push(line.row);
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
  return redactSecretPairs(line);
}

/**
 * Records the body sizes the site serves on ordinary paths. A sensitive path
 * that comes back at one of these sizes is being answered with the generic
 * page, not with its own content.
 */
function observeServedBodySize(counters: Counters, entry: AccessLogEntry): void {
  if (entry.status < 200 || entry.status >= 300) {
    return;
  }

  const bytes = entry.bytes ?? 0;

  if (bytes <= 0 || isHighValueSensitivePath(entry.path)) {
    return;
  }

  const seen = counters.servedBodySizes.get(bytes);

  if (seen !== undefined) {
    counters.servedBodySizes.set(bytes, seen + 1);
    return;
  }

  // Only repeated sizes can ever read as boilerplate, so on pressure drop the
  // long tail of one- and two-off sizes instead of refusing new keys: a first
  // occurrence arriving late would otherwise never get the chance to repeat.
  if (counters.servedBodySizes.size >= MAX_SERVED_BODY_SIZES) {
    pruneRareBodySizes(counters.servedBodySizes);

    if (counters.servedBodySizes.size >= MAX_SERVED_BODY_SIZES) {
      return;
    }
  }

  counters.servedBodySizes.set(bytes, 1);
}

/**
 * Drops the least-requested paths so a busier one can be tracked, and reports
 * the request count the freed slot was worth. Returns null when nothing could
 * be freed, which only happens on an empty map.
 */
function evictLeastSeenPathStats(statsByPath: Map<string, PathStats>): number | null {
  let lowest = Number.POSITIVE_INFINITY;

  for (const stats of statsByPath.values()) {
    if (stats.count < lowest) {
      lowest = stats.count;
    }
  }

  if (!Number.isFinite(lowest)) {
    return null;
  }

  for (const [path, stats] of statsByPath) {
    if (stats.count === lowest) {
      statsByPath.delete(path);
    }
  }

  return statsByPath.size < MAX_PATH_STATS ? lowest : null;
}

function pruneRareBodySizes(sizes: Map<number, number>): void {
  for (const [size, count] of sizes) {
    if (count < GENERIC_BODY_MIN_OCCURRENCES) {
      sizes.delete(size);
    }
  }
}

function updatePathStats(
  statsByPath: Map<string, PathStats>,
  counters: Counters,
  entry: AccessLogEntry,
  epoch: number | null,
  targetUrl?: URL | null
): boolean {
  let stats = statsByPath.get(entry.path);

  if (!stats) {
    let seedCount = 0;

    if (statsByPath.size >= MAX_PATH_STATS) {
      // Same reasoning as the top-N counters: refusing late arrivals hides the
      // busiest paths on a long log. Free a slot by dropping the least-seen
      // paths instead, and keep the new one.
      const floor = evictLeastSeenPathStats(statsByPath);

      if (floor === null) {
        rememberDroppedKey(counters.droppedPathSet, entry.path);
        return false;
      }

      // Seed at the evicted floor so the new path is not itself the minimum on
      // the next sweep — otherwise a genuinely busy path that starts late is
      // evicted again before it can ever climb. The seed inflates `count` by at
      // most that floor, which only ever deflates the ratios computed from it.
      seedCount = floor;
      counters.pathStatsEvictions += 1;
    }

    stats = {
      path: entry.path,
      count: seedCount,
      bytes: 0,
      ipCounts: new Map(),
      queryVariants: new Set(),
      uniqueIpCount: 0,
      queryVariantCount: 0,
      uniqueIpsIsLowerBound: false,
      queryVariantsIsLowerBound: false,
      postCount: 0,
      firstSeen: null,
      lastSeen: null,
      status2xx: 0,
      status3xx: 0,
      status4xx: 0,
      status5xx: 0,
      currentMinute: null,
      currentMinuteRequests: 0,
      currentMinuteServed: 0,
      maxRequestsPerMinute: 0,
      maxServedPerMinute: 0,
      samples: []
    };
    statsByPath.set(entry.path, stats);
  }

  stats.count += 1;
  stats.bytes += entry.bytes ?? 0;
  observePathIp(stats, counters, entry.ip);

  const signature = querySignature(entry.target, targetUrl);
  if (signature) {
    observePathQueryVariant(stats, counters, signature);
  }

  if (entry.method === "POST") {
    stats.postCount += 1;
  }

  // Track first/last seen epoch for rate-per-minute and persistence scoring.
  if (epoch !== null) {
    if (stats.firstSeen === null || epoch < stats.firstSeen) stats.firstSeen = epoch;
    if (stats.lastSeen === null || epoch > stats.lastSeen) stats.lastSeen = epoch;
    updatePathMinuteStats(stats, epoch, entry.status);
  }

  // Status counters for server-distress signal and served-request gating.
  if (entry.status >= 200 && entry.status < 300) {
    stats.status2xx += 1;
  } else if (entry.status >= 300 && entry.status < 400) {
    stats.status3xx += 1;
  } else if (entry.status >= 400 && entry.status < 500) {
    stats.status4xx += 1;
  } else if (entry.status >= 500 && entry.status < 600) {
    stats.status5xx += 1;
  }

  // Collect up to 5 redacted sample targets (query-bearing only) for operator review.
  if (stats.samples.length < 5 && entry.target.includes("?")) {
    const sample = redactTarget(entry.target, targetUrl);
    if (!stats.samples.includes(sample)) {
      stats.samples.push(sample);
    }
  }

  return true;
}

function observePathIp(stats: PathStats, counters: Counters, ip: string): void {
  if (stats.ipCounts.has(ip)) {
    incrementCapped(stats.ipCounts, ip, MAX_PATH_UNIQUE_IPS);
    return;
  }

  const atOwnCap = stats.ipCounts.size >= MAX_PATH_UNIQUE_IPS;
  const atCap =
    atOwnCap ||
    (counters.pathIpEntries >= MAX_GLOBAL_PATH_IP_ENTRIES &&
      stats.ipCounts.size >= MIN_PATH_IPS_GUARANTEED);

  if (atOwnCap) {
    stats.uniqueIpsAtOwnCap = true;
  }

  if (!atCap && incrementCapped(stats.ipCounts, ip, MAX_PATH_UNIQUE_IPS)) {
    counters.pathIpEntries += 1;
    stats.uniqueIpCount = (stats.uniqueIpCount ?? 0) + 1;
    return;
  }

  stats.uniqueIpsIsLowerBound = true;
  const droppedKey = `${stats.path}\0${ip}`;
  if (counters.droppedPathIpSet.has(droppedKey)) {
    return;
  }
  if (rememberDroppedKey(counters.droppedPathIpSet, droppedKey)) {
    stats.uniqueIpCount = (stats.uniqueIpCount ?? 0) + 1;
  }
}

function observePathQueryVariant(stats: PathStats, counters: Counters, signature: string): void {
  if (stats.queryVariants.has(signature)) {
    return;
  }

  const atOwnCap = stats.queryVariants.size >= MAX_QUERY_VARIANTS;
  const atCap =
    atOwnCap ||
    (counters.pathVariantEntries >= MAX_GLOBAL_PATH_VARIANT_ENTRIES &&
      stats.queryVariants.size >= MIN_PATH_VARIANTS_GUARANTEED);

  if (atOwnCap) {
    stats.queryVariantsAtOwnCap = true;
  }

  if (!atCap && addCappedSet(stats.queryVariants, signature, MAX_QUERY_VARIANTS)) {
    counters.pathVariantEntries += 1;
    stats.queryVariantCount = (stats.queryVariantCount ?? 0) + 1;
    return;
  }

  stats.queryVariantsIsLowerBound = true;
  const droppedKey = `${stats.path}\0${signature}`;
  if (counters.droppedQueryVariantSet.has(droppedKey)) {
    return;
  }
  if (rememberDroppedKey(counters.droppedQueryVariantSet, droppedKey)) {
    stats.queryVariantCount = (stats.queryVariantCount ?? 0) + 1;
  }
}

function updatePathMinuteStats(stats: PathStats, epochSecond: number, status: number): void {
  const minute = Math.floor(epochSecond / 60);
  const served = (status >= 200 && status < 300) || (status >= 500 && status < 600);

  if (stats.currentMinute !== minute) {
    stats.currentMinute = minute;
    stats.currentMinuteRequests = 0;
    stats.currentMinuteServed = 0;
  }

  stats.currentMinuteRequests = (stats.currentMinuteRequests ?? 0) + 1;
  stats.maxRequestsPerMinute = Math.max(
    stats.maxRequestsPerMinute ?? 0,
    stats.currentMinuteRequests
  );

  if (served) {
    stats.currentMinuteServed = (stats.currentMinuteServed ?? 0) + 1;
    stats.maxServedPerMinute = Math.max(stats.maxServedPerMinute ?? 0, stats.currentMinuteServed);
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

async function* iteratorToAsyncIterable(iterator: AsyncIterator<string>): AsyncIterable<string> {
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

function isInsideDateRange(epochSecond: number | null, options: AnalyzeOptions): boolean {
  if (!options.since && !options.until) {
    return true;
  }

  if (epochSecond === null) {
    return false;
  }

  const date = new Date(epochSecond * 1000);

  if (options.since && date < options.since) {
    return false;
  }

  if (options.until && date > options.until) {
    return false;
  }

  return true;
}
