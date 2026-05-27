/** A value with an associated occurrence count, used for top-N ranked lists. */
export interface TopItem {
  /** The string value being counted (IP, path, method, etc.). */
  value: string;
  /** Number of times this value was observed. */
  count: number;
}

/** Severity level of a detected incident, from informational to critical. */
export type IncidentSeverity = "info" | "low" | "medium" | "high" | "critical";

/** Compromise: attack attempt or success. Saturation: load/abuse/DoS. Noise: low-signal informational. */
export type IncidentKind = "compromise" | "saturation" | "noise";

/** A single key-value pair attached to an incident as supporting evidence. */
export interface IncidentEvidence {
  /** Name of the evidence attribute (e.g. "payload", "threshold"). */
  key: string;
  /** Observed value for this evidence attribute. */
  value: string | number | boolean;
}

/** A detected security or operational incident derived from log analysis. */
export interface Incident {
  /** Unique identifier for this incident. */
  id: string;
  /** Detector category that raised this incident (e.g. "sqli", "ratelimit"). */
  category: string;
  /** Whether this incident represents a compromise/attack attempt vs. volumetric abuse vs. low-signal noise. */
  kind: IncidentKind;
  /** Assessed severity level of the incident. */
  severity: IncidentSeverity;
  /** Numeric risk score used to rank incidents. */
  score: number;
  /** Short human-readable title for the incident. */
  title: string;
  /** Detailed explanation of why this incident was raised. */
  description: string;
  /** Key-value pairs providing supporting evidence for the detection. */
  evidence: IncidentEvidence[];
  /** Representative raw log line samples that triggered this incident. */
  samples: string[];
  /** True when attack payload received a 2xx response (possible successful exploit). */
  successful?: boolean;
}

/** A parsed access log line linked to a specific incident match. */
export interface IncidentLogLine {
  /** Sequential row index in the merged log stream (0-based). */
  row: number;
  /** File path or stream label this line originated from. */
  source: string;
  /** 1-based line number within the source file. */
  lineNumber: number;
  /** Unparsed original log line text. */
  raw: string;
  /** Client IP address. */
  ip: string;
  /** Request timestamp as parsed from the log (ISO-8601 or original format). */
  timestamp: string;
  /** HTTP method (GET, POST, etc.). */
  method: string;
  /** Request path including query string. */
  path: string;
  /** Full request target as written in the log. */
  target: string;
  /** HTTP response status code. */
  status: number;
  /** Response body size in bytes, or null if not present in the log. */
  bytes: number | null;
  /** User-Agent header value, or null if absent. */
  userAgent: string | null;
}

/** Aggregated set of log lines that matched a single incident detector. */
export interface IncidentMatchSet {
  /** ID of the incident this match set belongs to. */
  incidentId: string;
  /** Exact total number of log lines that matched (may exceed sampled rows). */
  totalMatches: number;
  /** Sample row ordinals for fast incident drill-down; totalMatches remains exact. */
  rowNumbers: number[];
  /** Parsed log line objects for the sampled rows. */
  lines: IncidentLogLine[];
}

/** High-level counts describing the access log index build result. */
export interface AccessLogIndexSummary {
  /** Total raw lines encountered across all input files. */
  totalLines: number;
  /** Lines successfully parsed and stored in the index. */
  indexedLines: number;
}

/** Temporal statistics computed across all parsed log entries. */
export interface TimeStats {
  /** ISO-8601 timestamp of the earliest log entry, or null if unavailable. */
  firstSeen: string | null;
  /** ISO-8601 timestamp of the latest log entry, or null if unavailable. */
  lastSeen: string | null;
  /** Highest requests-per-second observed across the entire log window. */
  peakGlobalRps: number;
  /** ISO-8601 timestamp when peakGlobalRps was reached, or null. */
  peakGlobalRpsAt: string | null;
  /** 95th-percentile requests-per-second across the log window. */
  globalRpsP95: number;
  /** Number of lines whose timestamps could not be parsed. */
  invalidTimestampLines: number;
  /** Number of lines whose timestamp was earlier than the previous line (clock skew / log rotation). */
  outOfOrderTimestamps: number;
  /** Number of individual IPs dropped from per-IP stats due to memory limits. */
  droppedIpCount: number;
  /** Number of subnets dropped from per-subnet stats due to memory limits. */
  droppedSubnetCount: number;
}

/** Per-IP behavioral profile derived from the full log window. */
export interface IpBehaviorStats {
  /** Client IP address this profile describes. */
  ip: string;
  /** Total number of requests made by this IP. */
  totalRequests: number;
  /** ISO-8601 timestamp of this IP's first observed request. */
  firstSeen: string;
  /** ISO-8601 timestamp of this IP's last observed request. */
  lastSeen: string;
  /** Peak requests-per-second recorded for this IP. */
  peakRps: number;
  /** ISO-8601 timestamp when this IP's peakRps was reached. */
  peakRpsAt: string;
  /** Number of distinct paths requested by this IP. */
  pathCount: number;
  /** Number of distinct User-Agent strings seen from this IP. */
  uaCount: number;
  /** Number of 4xx responses received by this IP. */
  status4xxCount: number;
  /** Number of 5xx responses received by this IP. */
  status5xxCount: number;
}

/** Aggregated activity statistics for a known AI crawler bot. */
export interface AiBotStats {
  /** Canonical name of the AI bot (e.g. "GPTBot", "ClaudeBot"). */
  botName: string;
  /** Total requests attributed to this bot. */
  requests: number;
  /** Number of distinct IPs from which this bot was observed. */
  ipCount: number;
  /** Number of distinct paths this bot requested. */
  pathCount: number;
  /** Whether this bot fetched /robots.txt during the log window. */
  requestedRobotsTxt: boolean;
  /** ISO-8601 timestamp of the first request from this bot. */
  firstSeen: string;
  /** ISO-8601 timestamp of the last request from this bot. */
  lastSeen: string;
}

/** Aggregate line and byte counts for the overall analysis run. */
export interface AnalyzeSummary {
  /** Number of input files processed. */
  files: number;
  /** Total raw lines read across all files before any parsing. */
  totalLines: number;
  /** Lines successfully parsed into structured records. */
  parsedLines: number;
  /** Lines excluded by active filters (IP allowlist, time range, etc.). */
  filteredLines: number;
  /** Lines that could not be parsed by any supported format. */
  invalidLines: number;
  /** Total bytes read from all input files. */
  totalBytes: number;
}

/** Auto-detected format information for a single input file. */
export interface InputFormatSummary {
  /** Path to the input file. */
  file: string;
  /** Detected log format name (e.g. "combined", "json"). */
  format: string;
  /** Number of lines used for format detection sampling. */
  sampledLines: number;
  /** Number of sampled lines that parsed successfully. */
  parsedSampleLines: number;
  /** Fraction of sampled lines that parsed (0–1). */
  sampleParseRatio: number;
}

/** Describes where log data should be read from — a file on disk or a live stream. */
export type AnalyzeInputSource =
  | {
      kind: "file";
      path: string;
    }
  | {
      kind: "stream";
      label: string;
      stream: NodeJS.ReadableStream;
    };

/** Full output document produced by a citrx phase-1 analysis run. */
export interface AnalyzeReport {
  /** Application identifier, always "citrx". */
  app: "citrx";
  /** Analysis phase, always 1 for this report type. */
  phase: 1;
  /** Outcome of the analysis run; "ok" means no fatal errors. */
  status: "ok";
  /** ISO-8601 timestamp of when this report was generated. */
  generatedAt: string;
  /** Resolved file paths or stream labels that were analyzed. */
  inputs: string[];
  /** Per-file format detection summaries. */
  inputFormats: InputFormatSummary[];
  /** Aggregate line and byte counts for the run. */
  summary: AnalyzeSummary;
  /** Top client IPs by request volume. */
  topIps: TopItem[];
  /** Top requested paths by hit count. */
  topPaths: TopItem[];
  /** Top HTTP methods by usage. */
  topMethods: TopItem[];
  /** Top HTTP response status codes by frequency. */
  topStatuses: TopItem[];
  /** Top User-Agent strings by frequency. */
  topUserAgents: TopItem[];
  /** Top query parameter names by frequency. */
  topParams: TopItem[];
  /** Top query parameter values by frequency. */
  topParamValues: TopItem[];
  /** Summary of the access log index built during analysis. */
  accessLog: AccessLogIndexSummary;
  /** Temporal statistics across all parsed log entries. */
  timeStats: TimeStats;
  /** Per-IP behavioral profiles for notable IPs. */
  ipBehaviorStats: IpBehaviorStats[];
  /** Activity statistics for detected AI crawler bots. */
  aiBotStats: AiBotStats[];
  /** List of detected incidents ordered by descending score. */
  incidents: Incident[];
  /** Log line match sets keyed to each incident. */
  incidentMatches: IncidentMatchSet[];
}
