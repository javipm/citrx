import type { AnalyzeReport } from "../analysis/types.js";

export interface CitrxSession {
  id: string;
  createdAt: string;
  updatedAt: string;
  sourcePaths: string[];
  report: AnalyzeReport;
}

export interface SessionSummary {
  id: string;
  createdAt: string;
  updatedAt: string;
  files: number;
  parsedLines: number;
  invalidLines: number;
  formats: string[];
}
