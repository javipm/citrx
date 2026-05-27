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

  it("strips tracking params from query signature to avoid marketing-traffic false positives", () => {
    // Pure tracking params → empty signature (not counted as variant).
    expect(querySignature("/page?fbclid=abc123")).toBe("");
    expect(querySignature("/page?utm_source=fb&utm_medium=cpc&utm_campaign=summer")).toBe("");
    expect(querySignature("/page?gclid=xyz&msclkid=foo")).toBe("");

    // Tracking mixed with real params → only real params kept.
    expect(querySignature("/search?q=zapatos&fbclid=abc&utm_source=ig")).toBe("?q=zapatos");

    // Real app params untouched.
    expect(querySignature("/search?q=zapatos&page=2")).toBe("?q=zapatos&page=2");
  });

  it("builds aggregate incidents from path stats", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/hot",
        count: 1000,
        bytes: 50_000,
        ipCounts: ipCounts(20, 1000),
        queryVariants: new Set(Array.from({ length: 250 }, (_, index) => `?page=${index}`)),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 1000,
        status3xx: 0,
        status4xx: 0,
        status5xx: 0,
        samples: []
      },
      {
        path: "/login",
        count: 200,
        bytes: 1000,
        ipCounts: ipCounts(1, 200),
        queryVariants: new Set(),
        postCount: 200,
        firstSeen: null,
        lastSeen: null,
        status2xx: 200,
        status3xx: 0,
        status4xx: 0,
        status5xx: 0,
        samples: []
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "abusive_crawl:/hot", kind: "noise" }),
        expect.objectContaining({ id: "post_hotspot:/login" })
      ])
    );
  });

  it("promotes material distributed URL pressure to saturation (real app params)", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/zapatillas-mujer-trail",
        count: 10_000,
        bytes: 520_508_800,
        ipCounts: ipCounts(50, 10_000),
        // Real application query variants (page + filter combos) — NOT tracking params.
        queryVariants: new Set(
          Array.from({ length: 5_000 }, (_, index) => `?page=${index}&order=asc`)
        ),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 10_000,
        status3xx: 0, // 3xx does NOT count toward servedCount
        status4xx: 0,
        status5xx: 0,
        samples: ["/zapatillas-mujer-trail?page=1&order=asc"]
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

  it("escalates distributed saturation to critical when server shows 5xx distress", () => {
    // 10k served (2xx) + 2.5k 5xx crashes = real backend saturation with distress signal.
    const incidents = buildAggregateIncidents([
      {
        path: "/api/search",
        count: 12_500,
        bytes: 50_000_000,
        ipCounts: ipCounts(50, 12_500),
        queryVariants: new Set(Array.from({ length: 6_500 }, (_, index) => `?q=term${index}`)),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 10_000,
        status3xx: 0,
        status4xx: 0,
        status5xx: 2_500,
        samples: ["/api/search?q=term1"]
      }
    ]);

    expect(incidents).toEqual([
      expect.objectContaining({
        id: "abusive_crawl:/api/search",
        kind: "saturation",
        severity: "critical",
        score: 85,
        title: "Distributed URL saturation"
      })
    ]);
  });

  it("labels concentrated repeat-IP pressure differently from distributed churn", () => {
    // 20+ IPs each hitting the same URL many times (botnet / scraper fleet) but
    // low query-variant count — not query churn, but concentrated load.
    const counts = new Map<string, number>();
    for (let i = 0; i < 25; i += 1) {
      counts.set(`203.0.113.${i}`, 500); // 25 IPs × 500 = 12500 reqs, 100% repeat share
    }

    const incidents = buildAggregateIncidents([
      {
        path: "/producto/123",
        count: 12_500,
        bytes: 10_000_000,
        ipCounts: counts,
        queryVariants: new Set(["?ref=botnet"]), // negligible variant count
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 12_500,
        status3xx: 0,
        status4xx: 0,
        status5xx: 0,
        samples: ["/producto/123?ref=botnet"]
      }
    ]);

    expect(incidents).toEqual([
      expect.objectContaining({
        id: "abusive_crawl:/producto/123",
        kind: "saturation",
        title: "Concentrated URL pressure"
      })
    ]);
  });

  it("does NOT flag saturation when query variants are exclusively tracking params", () => {
    // URL popular en redes: todos los parámetros son fbclid únicos por clic.
    // Después del strip de tracking params → 0 variantes reales.
    // IPs muy distribuidas (1 req/IP) → ninguna supera el umbral de repetición.
    // Sin churn de query NI repeat_pressure → sin incidente de saturación.
    const incidents = buildAggregateIncidents([
      {
        path: "/zapatillas-mujer-trail",
        count: 10_000,
        bytes: 520_508_800,
        // 10 000 IPs únicas con 1 req cada una: ninguna es "repetida" (threshold=5).
        ipCounts: ipCounts(10_000, 10_000),
        // Post-strip: all fbclid/utm params collapsed to 0 real variants.
        queryVariants: new Set(), // simulates what happens after tracking strip
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 10_000,
        status3xx: 0,
        status4xx: 0,
        status5xx: 0,
        samples: []
      }
    ]);

    expect(incidents).toEqual([]);
  });

  it("does NOT flag saturation when URL returns 403 to almost all requests", () => {
    // /running: 70k requests but server blocks 99.98% with 403. Only 12 × 200.
    // 3xx/4xx → no real backend load → not saturation regardless of signal strength.
    const incidents = buildAggregateIncidents([
      {
        path: "/running",
        count: 70_708,
        bytes: 1_000_000,
        ipCounts: ipCounts(1103, 70_708),
        queryVariants: new Set(Array.from({ length: 69_582 }, (_, i) => `?q=probe${i}`)),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 12,
        status3xx: 0,
        status4xx: 70_696,
        status5xx: 0,
        samples: []
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "abusive_crawl:/running", kind: "noise" })
      ])
    );
  });

  it("does NOT flag saturation when URL returns 301 redirects to almost all requests", () => {
    // /running → 301 → /running/ canonical redirect. Handled by nginx, no app load.
    const incidents = buildAggregateIncidents([
      {
        path: "/running",
        count: 70_708,
        bytes: 1_000_000,
        ipCounts: ipCounts(1103, 70_708),
        queryVariants: new Set(Array.from({ length: 69_582 }, (_, i) => `?q=probe${i}`)),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 12,
        status3xx: 70_696, // all 301 redirects — trivial, no app processing
        status4xx: 0,
        status5xx: 0,
        samples: []
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "abusive_crawl:/running", kind: "noise" })
      ])
    );
  });

  it("does NOT flag saturation when served traffic is spread thinly over time", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/zapatillas-mujer-trail",
        count: 10_000,
        bytes: 520_508_800,
        ipCounts: ipCounts(50, 10_000),
        queryVariants: new Set(Array.from({ length: 5_000 }, (_, index) => `?page=${index}`)),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 10_000,
        status3xx: 0,
        status4xx: 0,
        status5xx: 0,
        maxServedPerMinute: 12,
        samples: []
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "abusive_crawl:/zapatillas-mujer-trail", kind: "noise" })
      ])
    );
  });

  it("flags large sustained query churn even below the short-burst peak threshold", () => {
    const path = "/catalog/product-with-many-faceted-filters";
    const incidents = buildAggregateIncidents([
      {
        path,
        count: 91_771,
        bytes: 4_721_196_901,
        ipCounts: ipCounts(2_257, 91_771),
        queryVariants: new Set(Array.from({ length: 91_578 }, (_, index) => `?q=facet-${index}`)),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 91_537,
        status3xx: 225,
        status4xx: 9,
        status5xx: 0,
        maxServedPerMinute: 72,
        samples: []
      }
    ]);

    expect(incidents).toEqual([
      expect.objectContaining({
        id: `abusive_crawl:${path}`,
        kind: "saturation",
        severity: "high",
        title: "Distributed URL saturation"
      })
    ]);
  });

  it("promotes to saturation at lower volume when query-variant signal is very strong", () => {
    // Real case: /calzado-trekking-hombre-goretex with 1160 req, 1034 unique variants (~89%).
    // Ratio ≥ 0.75 (high-signal threshold) → saturation applies even below 10k served.
    const incidents = buildAggregateIncidents([
      {
        path: "/calzado-trekking-hombre-goretex",
        count: 1160,
        bytes: 5_000_000,
        ipCounts: ipCounts(205, 1160),
        queryVariants: new Set(Array.from({ length: 1034 }, (_, i) => `?ref=bot${i}&q=${i}`)),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 1160,
        status3xx: 0,
        status4xx: 0,
        status5xx: 0,
        samples: []
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "abusive_crawl:/calzado-trekking-hombre-goretex",
          kind: "saturation"
        })
      ])
    );
  });

  it("does not report entrypoint traffic as distributed crawling", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/",
        count: 4355,
        bytes: 201_149_997,
        ipCounts: ipCounts(1056, 4355),
        queryVariants: new Set(Array.from({ length: 387 }, (_, index) => `?page=${index}`)),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 4355,
        status3xx: 0,
        status4xx: 0,
        status5xx: 0,
        samples: []
      }
    ]);

    expect(incidents).toEqual([]);
  });
});
