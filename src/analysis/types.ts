export interface TopItem {
  value: string;
  count: number;
}

export type IncidentSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface IncidentEvidence {
  key: string;
  value: string | number | boolean;
}

export interface Incident {
  id: string;
  category: string;
  severity: IncidentSeverity;
  score: number;
  title: string;
  description: string;
  evidence: IncidentEvidence[];
  samples: string[];
}

export interface IncidentLogLine {
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
  accessLog: AccessLogIndexSummary;
  timeStats: TimeStats;
  ipBehaviorStats: IpBehaviorStats[];
  aiBotStats: AiBotStats[];
  incidents: Incident[];
  incidentMatches: IncidentMatchSet[];
}
