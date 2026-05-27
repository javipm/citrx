export interface TopItem {
  value: string;
  count: number;
}

export type IncidentSeverity = "info" | "low" | "medium" | "high" | "critical";

/** Compromise: attack attempt or success. Saturation: load/abuse/DoS. Noise: low-signal informational. */
export type IncidentKind = "compromise" | "saturation" | "noise";

export interface IncidentEvidence {
  key: string;
  value: string | number | boolean;
}

export interface Incident {
  id: string;
  category: string;
  /** Whether this incident represents a compromise/attack attempt vs. volumetric abuse vs. low-signal noise. */
  kind: IncidentKind;
  severity: IncidentSeverity;
  score: number;
  title: string;
  description: string;
  evidence: IncidentEvidence[];
  samples: string[];
  /** True when attack payload received a 2xx response (possible successful exploit). */
  successful?: boolean;
}

export interface IncidentLogLine {
  row: number;
  source: string;
  lineNumber: number;
  raw: string;
  ip: string;
  timestamp: string;
  method: string;
  path: string;
  target: string;
  status: number;
  bytes: number | null;
  userAgent: string | null;
}

export interface IncidentMatchSet {
  incidentId: string;
  totalMatches: number;
  /** Sample row ordinals for fast incident drill-down; totalMatches remains exact. */
  rowNumbers: number[];
  lines: IncidentLogLine[];
}

export interface AccessLogIndexSummary {
  totalLines: number;
  indexedLines: number;
}

export interface TimeStats {
  firstSeen: string | null;
  lastSeen: string | null;
  peakGlobalRps: number;
  peakGlobalRpsAt: string | null;
  globalRpsP95: number;
  invalidTimestampLines: number;
  outOfOrderTimestamps: number;
  droppedIpCount: number;
  droppedSubnetCount: number;
}

export interface IpBehaviorStats {
  ip: string;
  totalRequests: number;
  firstSeen: string;
  lastSeen: string;
  peakRps: number;
  peakRpsAt: string;
  pathCount: number;
  uaCount: number;
  status4xxCount: number;
  status5xxCount: number;
}

export interface AiBotStats {
  botName: string;
  requests: number;
  ipCount: number;
  pathCount: number;
  requestedRobotsTxt: boolean;
  firstSeen: string;
  lastSeen: string;
}

export interface AnalyzeSummary {
  files: number;
  totalLines: number;
  parsedLines: number;
  filteredLines: number;
  invalidLines: number;
  totalBytes: number;
}

export interface InputFormatSummary {
  file: string;
  format: string;
  sampledLines: number;
  parsedSampleLines: number;
  sampleParseRatio: number;
}

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

export interface AnalyzeReport {
  app: "citrx";
  phase: 1;
  status: "ok";
  generatedAt: string;
  inputs: string[];
  inputFormats: InputFormatSummary[];
  summary: AnalyzeSummary;
  topIps: TopItem[];
  topPaths: TopItem[];
  topMethods: TopItem[];
  topStatuses: TopItem[];
  topUserAgents: TopItem[];
  topParams: TopItem[];
  topParamValues: TopItem[];
  accessLog: AccessLogIndexSummary;
  timeStats: TimeStats;
  ipBehaviorStats: IpBehaviorStats[];
  aiBotStats: AiBotStats[];
  incidents: Incident[];
  incidentMatches: IncidentMatchSet[];
}
