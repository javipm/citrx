export interface TopItem {
  value: string;
  count: number;
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
}
