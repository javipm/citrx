import { describe, expect, it } from "vitest";

import type { AccessLogEntry } from "../parser/access-log.js";
import {
  buildAggregateIncidents,
  detectRequestHits,
  querySignature,
  redactTarget
} from "./local.js";

function entry(target: string, overrides: Partial<AccessLogEntry> = {}): AccessLogEntry {
  const path = target.split("?")[0] ?? target;

  return {
    ip: "203.0.113.10",
    timestamp: "25/May/2026:03:12:49 +0200",
    method: "GET",
    target,
    path,
    protocol: "HTTP/1.1",
    status: 200,
    bytes: 123,
    referer: null,
    userAgent: "Mozilla/5.0",
    ...overrides
  };
}

describe("local rules", () => {
  it("detects request attack payloads", () => {
    const hits = detectRequestHits(
      entry("/search?q=1%20UNION%20SELECT%20password%20FROM%20information_schema")
    );

    expect(hits).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ruleId: "sqli",
          severity: "critical"
        })
      ])
    );
  });

  it("redacts sensitive query values in samples", () => {
    expect(redactTarget("/login?token=secret&next=/admin")).toBe(
      "/login?token=%5BREDACTED%5D&next=%2Fadmin"
    );
    expect(querySignature("/api?password=hunter2&page=1")).toBe(
      "?password=%5BREDACTED%5D&page=1"
    );
    expect(redactTarget(`/search?q=${"a".repeat(400)}`)).toHaveLength(300);
  });

  it("builds aggregate incidents from path stats", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/hot",
        count: 1000,
        bytes: 50_000,
        ips: new Set(Array.from({ length: 20 }, (_, index) => `203.0.113.${index}`)),
        queryVariants: new Set(),
        postCount: 0
      },
      {
        path: "/login",
        count: 60,
        bytes: 1000,
        ips: new Set(["203.0.113.10"]),
        queryVariants: new Set(),
        postCount: 60
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "abusive_crawl:/hot" }),
        expect.objectContaining({ id: "post_hotspot:/login" })
      ])
    );
  });
});
