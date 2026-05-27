import { describe, expect, it } from "vitest";

import type { Incident } from "../../analysis/types.js";
import { defaultSummaryFocus, firstIncidentIndexForFocus } from "./useSummaryScreenInput.js";

describe("summary incident focus", () => {
  it("defaults to saturation when saturation incidents exist", () => {
    const incidents = [
      incident("sqli:1", "compromise"),
      incident("abusive_crawl:/hot", "saturation"),
      incident("query_explosion:/hot", "noise")
    ];

    expect(defaultSummaryFocus(incidents)).toBe("saturation");
    expect(firstIncidentIndexForFocus(incidents, defaultSummaryFocus(incidents))).toBe(1);
  });

  it("falls back to accesses when no incidents exist", () => {
    expect(defaultSummaryFocus([])).toBe("accesses");
    expect(firstIncidentIndexForFocus([], "accesses")).toBe(0);
  });
});

function incident(id: string, kind: Incident["kind"]): Incident {
  return {
    id,
    kind,
    category: "test",
    severity: "medium",
    score: 50,
    title: id,
    description: id,
    evidence: [],
    samples: []
  };
}
