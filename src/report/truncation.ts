import { DROPPED_KEY_TRACK_LIMIT, MAX_OVERFLOW_RPS_SECONDS } from "../analysis/capped-counter.js";
import type { AnalyzeSummary } from "../analysis/types.js";

export function formatDroppedCount(count: number, trackLimit: number): string {
  return count >= trackLimit ? `>=${trackLimit}` : String(count);
}

export function formatTruncation(summary: AnalyzeSummary): string | null {
  const parts: string[] = [];
  if (summary.droppedAggregationKeys > 0) {
    parts.push(
      `${formatDroppedCount(summary.droppedAggregationKeys, DROPPED_KEY_TRACK_LIMIT)} aggregation keys`
    );
  }
  if (summary.droppedPathStats > 0) {
    parts.push(`${formatDroppedCount(summary.droppedPathStats, DROPPED_KEY_TRACK_LIMIT)} paths`);
  }
  if (summary.droppedPathIps > 0) {
    parts.push(`${formatDroppedCount(summary.droppedPathIps, DROPPED_KEY_TRACK_LIMIT)} path IPs`);
  }
  if (summary.droppedQueryVariants > 0) {
    parts.push(
      `${formatDroppedCount(summary.droppedQueryVariants, DROPPED_KEY_TRACK_LIMIT)} query variants`
    );
  }
  if (summary.droppedRpsSeconds > 0) {
    parts.push(
      `${formatDroppedCount(summary.droppedRpsSeconds, MAX_OVERFLOW_RPS_SECONDS)} RPS seconds`
    );
  }
  return parts.length > 0 ? `Truncated: ${parts.join(", ")}` : null;
}
