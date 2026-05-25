export interface TopItem {
  value: string;
  count: number;
}

export interface AnalyzeSummary {
  files: number;
  totalLines: number;
  parsedLines: number;
  invalidLines: number;
  totalBytes: number;
}

export interface AnalyzeReport {
  app: "citrx";
  phase: 1;
  status: "ok";
  generatedAt: string;
  inputs: string[];
  summary: AnalyzeSummary;
  topIps: TopItem[];
  topPaths: TopItem[];
  topMethods: TopItem[];
  topStatuses: TopItem[];
}
