import type { AnalyzeReport } from "../analysis/types.js";
import type { AccessLogIndex } from "./access-index.js";

export interface CitrxRun {
  id: string;
  createdAt: string;
  sourcePaths: string[];
  tempDir: string;
  report: AnalyzeReport;
  accessIndex: AccessLogIndex;
}
