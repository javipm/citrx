export interface TopItem {
  value: string;
  count: number;
}

export interface GeoIpInfo {
  ip: string;
  country: string | null;
  countryCode: string | null;
  asn: string | null;
  org: string | null;
  cached: boolean;
}

export interface GeoSummary {
  provider: string;
  lookedUp: number;
  failed: number;
  topCountries: TopItem[];
  topAsns: TopItem[];
  ips: GeoIpInfo[];
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
  sessionId?: string;
  inputs: string[];
  inputFormats: InputFormatSummary[];
  summary: AnalyzeSummary;
  topIps: TopItem[];
  topPaths: TopItem[];
  topMethods: TopItem[];
  topStatuses: TopItem[];
  incidents: Incident[];
  geo?: GeoSummary;
}
