import { describe, expect, it } from "vitest";

import type { Incident, IncidentEvidence } from "../analysis/types.js";
import { applyScoringMultipliers, severityFromScore } from "./scoring.js";

function incident(
  id: string,
  score: number,
  evidence: IncidentEvidence[] = [],
  severity: Incident["severity"] = severityFromScore(score)
): Incident {
  return {
    id,
    category: "test",
    severity,
    score,
    title: id,
    description: id,
    evidence,
    samples: []
  };
}

describe("scoring multipliers", () => {
  it("maps severity from score boundaries", () => {
    expect(severityFromScore(24)).toBe("info");
    expect(severityFromScore(25)).toBe("low");
    expect(severityFromScore(49)).toBe("low");
    expect(severityFromScore(50)).toBe("medium");
    expect(severityFromScore(74)).toBe("medium");
    expect(severityFromScore(75)).toBe("high");
    expect(severityFromScore(89)).toBe("high");
    expect(severityFromScore(90)).toBe("critical");
    expect(severityFromScore(100)).toBe("critical");
  });

  it("adds correlation bonus to two incidents with the same IP", () => {
    const scored = applyScoringMultipliers([
      incident("scanner_ua_known:203.0.113.1", 70, [{ key: "ip", value: "203.0.113.1" }]),
      incident("ddos_rps_burst_single_ip:203.0.113.1", 80, [
        { key: "ip", value: "203.0.113.1" }
      ])
    ]);

    expect(scored.map((item) => item.score)).toEqual([80, 90]);
  });

  it("does not add correlation bonus for a single incident with an IP", () => {
    const [scored] = applyScoringMultipliers([
      incident("scanner_ua_known:203.0.113.1", 70, [{ key: "ip", value: "203.0.113.1" }])
    ]);

    expect(scored?.score).toBe(70);
  });

  it("adds correlation bonus once for three incidents with the same IP", () => {
    const scored = applyScoringMultipliers([
      incident("scanner_ua_known:203.0.113.1", 70, [{ key: "ip", value: "203.0.113.1" }]),
      incident("ddos_rps_burst_single_ip:203.0.113.1", 80, [
        { key: "ip", value: "203.0.113.1" }
      ]),
      incident("fake_bot_googlebot:203.0.113.1", 80, [
        { key: "ip", value: "203.0.113.1" }
      ])
    ]);

    expect(scored.map((item) => item.score)).toEqual([80, 90, 90]);
  });

  it("does not correlate different IPs", () => {
    const scored = applyScoringMultipliers([
      incident("scanner_ua_known:203.0.113.1", 70, [{ key: "ip", value: "203.0.113.1" }]),
      incident("scanner_ua_known:203.0.113.2", 70, [{ key: "ip", value: "203.0.113.2" }])
    ]);

    expect(scored.map((item) => item.score)).toEqual([70, 70]);
  });

  it("adds persistence bonus from burst timestamps", () => {
    const [scored] = applyScoringMultipliers([
      incident("ddos_rps_burst_single_ip:203.0.113.1", 60, [
        { key: "burstStart", value: "2026-05-25T00:00:00.000Z" },
        { key: "burstEnd", value: "2026-05-25T00:35:00.000Z" }
      ])
    ]);

    expect(scored).toMatchObject({ score: 75, severity: "high" });
  });

  it("does not add persistence bonus below threshold or without timestamps", () => {
    const scored = applyScoringMultipliers([
      incident("ddos_rps_burst_single_ip:203.0.113.1", 60, [
        { key: "burstStart", value: "2026-05-25T00:00:00.000Z" },
        { key: "burstEnd", value: "2026-05-25T00:20:00.000Z" }
      ]),
      incident("scanner_ua_known:203.0.113.2", 70)
    ]);

    expect(scored.map((item) => item.score)).toEqual([60, 70]);
  });

  it("adds persistence bonus from firstSeen and lastSeen", () => {
    const [scored] = applyScoringMultipliers([
      incident("ai_scraper_known:GPTBot", 25, [
        { key: "firstSeen", value: "2026-05-25T00:00:00.000Z" },
        { key: "lastSeen", value: "2026-05-25T01:00:00.000Z" }
      ])
    ]);

    expect(scored?.score).toBe(40);
  });

  it("penalizes moderate AI bots that requested robots.txt", () => {
    const [scored] = applyScoringMultipliers([
      incident("ai_scraper_known:GPTBot", 25, [
        { key: "requests", value: 300 },
        { key: "requestedRobotsTxt", value: true }
      ])
    ]);

    expect(scored).toMatchObject({ score: 15, severity: "info" });
  });

  it("does not penalize high-volume AI bots or bots that skipped robots.txt", () => {
    const scored = applyScoringMultipliers([
      incident("ai_scraper_known:GPTBot", 80, [
        { key: "requests", value: 6000 },
        { key: "requestedRobotsTxt", value: true }
      ]),
      incident("ai_scraper_known:ClaudeBot", 25, [
        { key: "requests", value: 300 },
        { key: "requestedRobotsTxt", value: false }
      ]),
      incident("scanner_ua_known:203.0.113.1", 70, [
        { key: "requests", value: 300 },
        { key: "requestedRobotsTxt", value: true }
      ])
    ]);

    expect(scored.map((item) => item.score)).toEqual([80, 25, 70]);
  });

  it("caps scores and recalculates severity after multipliers", () => {
    const scored = applyScoringMultipliers([
      incident("scanner_ua_known:203.0.113.1", 95, [
        { key: "ip", value: "203.0.113.1" },
        { key: "burstStart", value: "2026-05-25T00:00:00.000Z" },
        { key: "burstEnd", value: "2026-05-25T01:00:00.000Z" }
      ]),
      incident("fake_bot_googlebot:203.0.113.1", 30, [
        { key: "ip", value: "203.0.113.1" }
      ]),
      incident("ai_scraper_known:GPTBot", 20, [
        { key: "requests", value: 300 },
        { key: "requestedRobotsTxt", value: "true" }
      ])
    ]);

    expect(scored[0]).toMatchObject({ score: 100, severity: "critical" });
    expect(scored[1]).toMatchObject({ score: 40, severity: "low" });
    expect(scored[2]).toMatchObject({ score: 10, severity: "info" });
  });

  it("can correlate local-rule incidents with behavior incidents", () => {
    const scored = applyScoringMultipliers([
      incident("sqli:/login", 95, [{ key: "ip", value: "203.0.113.1" }]),
      incident("ddos_rps_burst_single_ip:203.0.113.1", 95, [
        { key: "ip", value: "203.0.113.1" }
      ]),
      incident("ddos_distributed_subnet:203.0.113.0/24", 90, [
        { key: "prefix", value: "203.0.113.0/24" }
      ])
    ]);

    expect(scored.map((item) => item.score)).toEqual([100, 100, 90]);
  });
});
