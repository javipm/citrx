import { describe, expect, it } from "vitest";

import { DROPPED_KEY_TRACK_LIMIT, MAX_OVERFLOW_RPS_SECONDS } from "../analysis/capped-counter.js";
import type { AnalyzeSummary } from "../analysis/types.js";
import { formatDroppedCount, formatTruncation } from "./truncation.js";

function summary(overrides: Partial<AnalyzeSummary> = {}): AnalyzeSummary {
  return {
    files: 1,
    totalLines: 1,
    parsedLines: 1,
    filteredLines: 0,
    invalidLines: 0,
    totalBytes: 1,
    droppedAggregationKeys: 0,
    droppedPathStats: 0,
    droppedPathIps: 0,
    droppedQueryVariants: 0,
    droppedRpsSeconds: 0,
    ...overrides
  };
}

describe("formatTruncation", () => {
  it("shows exact counts below the fingerprint cap", () => {
    expect(formatTruncation(summary({ droppedAggregationKeys: 12 }))).toBe(
      "Truncated: 12 aggregation keys"
    );
  });

  it("shows a lower-bound marker when the tracking set is full", () => {
    expect(formatDroppedCount(DROPPED_KEY_TRACK_LIMIT, DROPPED_KEY_TRACK_LIMIT)).toBe(
      `>=${DROPPED_KEY_TRACK_LIMIT}`
    );
    expect(formatTruncation(summary({ droppedRpsSeconds: MAX_OVERFLOW_RPS_SECONDS }))).toBe(
      `Truncated: >=${MAX_OVERFLOW_RPS_SECONDS} RPS seconds`
    );
  });
});
