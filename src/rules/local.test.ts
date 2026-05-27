import { describe, expect, it } from "vitest";

import type { AccessLogEntry } from "../parser/access-log.js";
import {
  buildAggregateIncidents,
  detectRequestHits,
  mergeRuleHit,
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

function ipCounts(totalIps: number, totalRequests: number): Map<string, number> {
  const counts = new Map<string, number>();

  for (let index = 0; index < totalRequests; index += 1) {
    const ip = `203.0.113.${index % totalIps}`;
    counts.set(ip, (counts.get(ip) ?? 0) + 1);
  }

  return counts;
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

  it("downgrades payload incidents when every response is 404", () => {
    const incidents = new Map();
    const first = entry("/search?q=1%20UNION%20SELECT%20password", { status: 404 });
    const second = entry("/search?q=1%20UNION%20SELECT%20email", { status: 404 });
    const [firstHit] = detectRequestHits(first);
    const [secondHit] = detectRequestHits(second);

    const incidentId = mergeRuleHit(incidents, firstHit!, first);
    mergeRuleHit(incidents, secondHit!, second);

    expect(incidents.get(incidentId)).toMatchObject({
      severity: "low",
      score: 30,
      evidence: expect.arrayContaining([
        { key: "count", value: 2 },
        { key: "outcome", value: "all_404" },
        { key: "status4xx", value: 2 },
        { key: "status404", value: 2 }
      ])
    });
  });

  it("keeps payload incidents critical when responses include a successful status", () => {
    const incidents = new Map();
    const notFound = entry("/search?q=1%20UNION%20SELECT%20password", { status: 404 });
    const ok = entry("/search?q=1%20UNION%20SELECT%20email", { status: 200 });
    const [notFoundHit] = detectRequestHits(notFound);
    const [okHit] = detectRequestHits(ok);

    const incidentId = mergeRuleHit(incidents, notFoundHit!, notFound);
    mergeRuleHit(incidents, okHit!, ok);

    expect(incidents.get(incidentId)).toMatchObject({
      severity: "critical",
      score: 100,
      successful: true,
      evidence: expect.arrayContaining([
        { key: "count", value: 2 },
        { key: "outcome", value: "successful" },
        { key: "status2xx", value: 1 },
        { key: "status4xx", value: 1 },
        { key: "status404", value: 1 }
      ])
    });
  });

  it("redacts sensitive query values in samples", () => {
    expect(redactTarget("/login?token=secret&next=/admin")).toBe(
      "/login?token=%5BREDACTED%5D&next=%2Fadmin"
    );
    expect(querySignature("/api?password=hunter2&page=1")).toBe("?password=%5BREDACTED%5D&page=1");
    expect(redactTarget(`/search?q=${"a".repeat(400)}`)).toHaveLength(300);
  });

  it("builds aggregate incidents from path stats", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/hot",
        count: 1000,
        bytes: 50_000,
        ipCounts: ipCounts(20, 1000),
        queryVariants: new Set(Array.from({ length: 250 }, (_, index) => `?page=${index}`)),
        postCount: 0
      },
      {
        path: "/login",
        count: 200,
        bytes: 1000,
        ipCounts: ipCounts(1, 200),
        queryVariants: new Set(),
        postCount: 200
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "abusive_crawl:/hot", kind: "noise" }),
        expect.objectContaining({ id: "post_hotspot:/login" })
      ])
    );
  });

  it("promotes material distributed URL pressure to saturation", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/zapatillas-mujer-trail",
        count: 10_000,
        bytes: 520_508_800,
        ipCounts: ipCounts(50, 10_000),
        queryVariants: new Set(Array.from({ length: 5_000 }, (_, index) => `?fbclid=${index}`)),
        postCount: 0
      }
    ]);

    expect(incidents).toEqual([
      expect.objectContaining({
        id: "abusive_crawl:/zapatillas-mujer-trail",
        kind: "saturation",
        severity: "high",
        score: 75,
        title: "Distributed URL saturation"
      })
    ]);
  });

  it("does not report entrypoint traffic as distributed crawling", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/",
        count: 4355,
        bytes: 201_149_997,
        ipCounts: ipCounts(1056, 4355),
        queryVariants: new Set(Array.from({ length: 387 }, (_, index) => `?utm=${index}`)),
        postCount: 0
      }
    ]);

    expect(incidents).toEqual([]);
  });
});
