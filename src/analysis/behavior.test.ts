import { describe, expect, it } from "vitest";

import type { AccessLogEntry } from "../parser/access-log.js";
import { BehaviorTracker } from "./behavior.js";
import { accessLogTimestampToEpochSeconds } from "./timestamp.js";

describe("behavior tracker", () => {
  it("parses Apache timestamps to UTC epoch seconds", () => {
    expect(accessLogTimestampToEpochSeconds("25/May/2026:03:12:49 +0200")).toBe(
      Date.parse("2026-05-25T01:12:49.000Z") / 1000
    );
  });

  it("skips invalid timestamps and counts them", () => {
    const tracker = new BehaviorTracker();
    tracker.observe(entry({ timestamp: "nope" }));

    expect(tracker.finalize().timeStats.invalidTimestampLines).toBe(1);
  });

  it("accepts out-of-order entries and counts large regressions", () => {
    const tracker = new BehaviorTracker();
    tracker.observe(entry({ timestamp: ts(100) }));
    tracker.observe(entry({ timestamp: ts(20) }));

    expect(tracker.finalize().timeStats.outOfOrderTimestamps).toBe(1);
  });

  it("detects a three-second single-IP burst", () => {
    const tracker = new BehaviorTracker();

    for (let second = 0; second < 3; second += 1) {
      for (let index = 0; index < 50; index += 1) {
        tracker.observe(entry({ timestamp: ts(second) }));
      }
    }

    expect(tracker.finalize().incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "ddos_rps_burst_single_ip:203.0.113.10" })
      ])
    );
  });

  it("breaks a burst run when a second has no traffic", () => {
    const tracker = new BehaviorTracker();

    for (const second of [0, 1, 3]) {
      for (let index = 0; index < 50; index += 1) {
        tracker.observe(entry({ timestamp: ts(second) }));
      }
    }

    expect(tracker.finalize().incidents).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "ddos_rps_burst_single_ip:203.0.113.10" })
      ])
    );
  });

  it("requires ten consecutive global spike buckets and fills zeros for p95", () => {
    const tracker = new BehaviorTracker();
    tracker.observe(entry({ timestamp: ts(0), ip: "203.0.113.1" }));

    for (let second = 1000; second < 1010; second += 1) {
      for (let index = 0; index < 100; index += 1) {
        tracker.observe(entry({ timestamp: ts(second), ip: `203.0.113.${index}` }));
      }
    }

    const result = tracker.finalize();
    expect(result.timeStats.globalRpsP95).toBe(0);
    expect(result.incidents).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: "ddos_global_rps_spike" })])
    );
  });

  it("detects a 4xx storm across adjacent minute buckets", () => {
    const tracker = new BehaviorTracker();

    for (let index = 0; index < 100; index += 1) {
      tracker.observe(entry({ timestamp: ts(59), status: 404 }));
    }

    for (let index = 0; index < 100; index += 1) {
      tracker.observe(entry({ timestamp: ts(60), status: 404 }));
    }

    expect(tracker.finalize().incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "http_4xx_storm:203.0.113.10" })
      ])
    );
  });

  it("drops new IP stats when cap is full and no stale IP exists", () => {
    const tracker = new BehaviorTracker({ maxTrackedIps: 1 });
    tracker.observe(entry({ ip: "203.0.113.1", timestamp: ts(0) }));
    tracker.observe(entry({ ip: "203.0.113.2", timestamp: ts(1) }));

    expect(tracker.finalize().timeStats.droppedIpCount).toBe(1);
  });

  it("evicts stale lower-volume IPs before higher-volume stale IPs", () => {
    const tracker = new BehaviorTracker({ maxTrackedIps: 2 });
    tracker.observe(entry({ ip: "203.0.113.1", timestamp: ts(0) }));
    tracker.observe(entry({ ip: "203.0.113.2", timestamp: ts(0) }));
    tracker.observe(entry({ ip: "203.0.113.2", timestamp: ts(1) }));
    tracker.observe(entry({ ip: "203.0.113.3", timestamp: ts(901) }));

    const stats = tracker.finalize().ipBehaviorStats;
    expect(stats.map((item) => item.ip)).toContain("203.0.113.2");
    expect(stats.map((item) => item.ip)).toContain("203.0.113.3");
  });

  it("keeps evicted top IPs in the continuous top summary", () => {
    const tracker = new BehaviorTracker({ maxTrackedIps: 1 });

    for (let index = 0; index < 10; index += 1) {
      tracker.observe(entry({ ip: "203.0.113.1", timestamp: ts(index) }));
    }

    tracker.observe(entry({ ip: "203.0.113.2", timestamp: ts(901) }));

    expect(tracker.finalize().ipBehaviorStats[0]).toEqual(
      expect.objectContaining({ ip: "203.0.113.1", totalRequests: 10 })
    );
  });

  it("does not overwrite an evicted top snapshot when the same IP returns with fewer requests", () => {
    const tracker = new BehaviorTracker({ maxTrackedIps: 1 });

    for (let index = 0; index < 10; index += 1) {
      tracker.observe(entry({ ip: "203.0.113.1", timestamp: ts(index) }));
    }

    tracker.observe(entry({ ip: "203.0.113.2", timestamp: ts(911) }));
    tracker.observe(entry({ ip: "203.0.113.1", timestamp: ts(1822) }));

    expect(tracker.finalize().ipBehaviorStats[0]).toEqual(
      expect.objectContaining({ ip: "203.0.113.1", totalRequests: 10 })
    );
  });
});

function entry(overrides: Partial<AccessLogEntry> = {}): AccessLogEntry {
  return {
    ip: "203.0.113.10",
    timestamp: ts(0),
    method: "GET",
    target: "/",
    path: "/",
    protocol: "HTTP/1.1",
    status: 200,
    bytes: 123,
    referer: null,
    userAgent: "Mozilla/5.0",
    ...overrides
  };
}

function ts(secondOffset: number): string {
  const date = new Date(Date.parse("2026-05-25T00:00:00.000Z") + secondOffset * 1000);
  return date.toISOString();
}
