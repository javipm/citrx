export interface TopItem {
  value: string;
  count: number;
}

export type IncidentSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface IncidentEvidence {
  key: string;
  value: string | number;
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
  storedLines: number;
  truncated: boolean;
  lines: IncidentLogLine[];
}

export interface AccessLogIndexSummary {
  totalLines: number;
  indexedLines: number;
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
  incidents: Incident[];
  incidentMatches: IncidentMatchSet[];
}
