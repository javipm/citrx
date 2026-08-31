import { describe, expect, it } from "vitest";

import type { AccessLogEntry } from "../parser/access-log.js";
import type { Incident } from "../analysis/types.js";
import type { RuleHit } from "./local.js";
import {
  buildAggregateIncidents,
  demoteSoftServedRecon,
  demoteVerifiedCrawlerPayloads,
  detectRequestHits,
  mergeRuleHit,
  parseTargetUrl,
  pruneNoise,
  querySignature,
  redactTarget
} from "./local.js";

function reconHit(sample: string): RuleHit {
  return {
    ruleId: "recon_sensitive_file",
    category: "recon",
    kind: "compromise",
    severity: "medium",
    score: 60,
    title: "Sensitive file probe",
    description: "Probe for a sensitive file.",
    sample
  };
}

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
    host: null,
    requestTime: null,
    upstreamTime: null,
    forwardedFor: null,
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
      "/login?token=[REDACTED]&next=/admin"
    );
    expect(querySignature("/api?password=hunter2&page=1")).toBe("?password=[REDACTED]&page=1");
    expect(redactTarget(`/search?q=${"a".repeat(400)}`)).toHaveLength(300);
  });

  it("strips tracking params from query signature to avoid marketing-traffic false positives", () => {
    // Pure tracking params → empty signature (not counted as variant).
    expect(querySignature("/page?fbclid=abc123")).toBe("");
    expect(querySignature("/page?utm_source=fb&utm_medium=cpc&utm_campaign=summer")).toBe("");
    expect(querySignature("/page?gclid=xyz&msclkid=foo")).toBe("");
    expect(querySignature("/api?_=1770000000&rand=12345&cachebuster=abc")).toBe("");

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

  // The Googlebot address below is deliberately literal: the whole point is
  // that it falls inside Google's published ranges. Every other address in
  // these tests uses RFC 5737 documentation space.
  it("demotes an attack payload fetched by verified Googlebot", () => {
    const incidents = new Map<string, Incident>([
      [
        "command_injection:66.249.70.165",
        {
          id: "command_injection:66.249.70.165",
          category: "command_injection",
          kind: "compromise",
          severity: "critical",
          score: 100,
          title: "Command injection payload",
          description: "…",
          evidence: [
            { key: "ip", value: "66.249.70.165" },
            { key: "count", value: 1 },
            { key: "status2xx", value: 1 }
          ],
          samples: [],
          successful: true
        }
      ],
      [
        "command_injection:198.51.100.201",
        {
          id: "command_injection:198.51.100.201",
          category: "command_injection",
          kind: "compromise",
          severity: "critical",
          score: 100,
          title: "Command injection payload",
          description: "…",
          evidence: [
            { key: "ip", value: "198.51.100.201" },
            { key: "count", value: 1 },
            { key: "status2xx", value: 1 }
          ],
          samples: [],
          successful: true
        }
      ]
    ]);

    demoteVerifiedCrawlerPayloads(incidents);

    const crawler = incidents.get("command_injection:66.249.70.165");
    expect(crawler?.kind).toBe("noise");
    expect(crawler?.severity).toBe("low");
    expect(crawler?.successful).toBe(false);

    // An unrelated IP sending the same payload stays a critical finding.
    const attacker = incidents.get("command_injection:198.51.100.201");
    expect(attacker?.kind).toBe("compromise");
    expect(attacker?.severity).toBe("critical");
  });

  it("escalates a served high-value file even when almost every probe failed", () => {
    const incidents = new Map<string, Incident>();
    // 231 failed probes and a single 200 on phpinfo.php: a 0.4% success ratio,
    // far under the ratio gate, but that one response is the disclosure.
    for (let index = 0; index < 231; index += 1) {
      mergeRuleHit(
        incidents,
        reconHit(`/.env.${index}`),
        entry(`/.env.${index}`, { ip: "192.0.2.10", status: 404, bytes: 0 })
      );
    }
    mergeRuleHit(
      incidents,
      reconHit("/phpinfo.php"),
      entry("/phpinfo.php", { ip: "192.0.2.10", status: 200, bytes: 12_447 })
    );

    const incident = incidents.get("recon_sensitive_file:192.0.2.10");
    expect(incident?.severity).toBe("high");
    expect(incident?.successful).toBe(true);
    expect(incident?.evidence.find((item) => item.key === "servedSensitivePath")?.value).toBe(
      "/phpinfo.php"
    );
  });

  it("withdraws the escalation when the served body is the site's generic page", () => {
    const incidents = new Map<string, Incident>();
    for (let index = 0; index < 100; index += 1) {
      mergeRuleHit(
        incidents,
        reconHit(`/.env.${index}`),
        entry(`/.env.${index}`, { ip: "192.0.2.10", status: 404, bytes: 3419 })
      );
    }
    mergeRuleHit(
      incidents,
      reconHit("/phpinfo.php"),
      entry("/phpinfo.php", { ip: "192.0.2.10", status: 200, bytes: 12_447 })
    );

    expect(incidents.get("recon_sensitive_file:192.0.2.10")?.severity).toBe("high");

    // The same byte count is what the site serves for its homepage.
    demoteSoftServedRecon(incidents, new Map([[12_447, 5]]));

    const incident = incidents.get("recon_sensitive_file:192.0.2.10");
    expect(incident?.severity).not.toBe("high");
    expect(incident?.successful).toBe(false);
    expect(
      incident?.evidence.find((item) => item.key === "servedBodyMatchesGenericPage")?.value
    ).toBe(true);
  });

  it("keeps the escalation when the served size is not boilerplate", () => {
    const incidents = new Map<string, Incident>();
    for (let index = 0; index < 100; index += 1) {
      mergeRuleHit(
        incidents,
        reconHit(`/.env.${index}`),
        entry(`/.env.${index}`, { ip: "203.0.113.66", status: 404, bytes: 3419 })
      );
    }
    mergeRuleHit(
      incidents,
      reconHit("/.env"),
      entry("/.env", { ip: "203.0.113.66", status: 200, bytes: 1340 })
    );

    // 1340 is served twice elsewhere — under the boilerplate threshold.
    demoteSoftServedRecon(incidents, new Map([[1340, 2]]));

    expect(incidents.get("recon_sensitive_file:203.0.113.66")?.severity).toBe("high");
  });

  it("does not escalate an empty response on a sensitive path", () => {
    const incidents = new Map<string, Incident>();
    for (let index = 0; index < 50; index += 1) {
      mergeRuleHit(
        incidents,
        reconHit(`/.env.${index}`),
        entry(`/.env.${index}`, { ip: "192.0.2.11", status: 404, bytes: 0 })
      );
    }
    // 200 with a zero-byte body is a stub, not a leak.
    mergeRuleHit(
      incidents,
      reconHit("/phpinfo.php"),
      entry("/phpinfo.php", { ip: "192.0.2.11", status: 200, bytes: 0 })
    );

    expect(incidents.get("recon_sensitive_file:192.0.2.11")?.severity).not.toBe("high");
  });

  it("reports distributed credential stuffing on an auth endpoint", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/wp-login.php",
        count: 404,
        bytes: 100_000,
        // One request per IP: the shape used to stay under per-IP rate limits.
        ipCounts: ipCounts(400, 400),
        queryVariants: new Set(),
        postCount: 403,
        firstSeen: 1_780_000_000,
        lastSeen: 1_780_000_120,
        status2xx: 133,
        status3xx: 0,
        status4xx: 271,
        status5xx: 0,
        maxRequestsPerMinute: 237,
        samples: []
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "auth_abuse:/wp-login.php",
          kind: "compromise",
          title: "Distributed credential stuffing"
        })
      ])
    );
    // The plain POST count is redundant once the auth rule describes the path.
    expect(incidents.map((incident) => incident.id)).not.toContain("post_hotspot:/wp-login.php");
  });

  it("leaves a busy but mostly successful login endpoint alone", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/login",
        count: 400,
        bytes: 100_000,
        ipCounts: ipCounts(200, 400),
        queryVariants: new Set(),
        postCount: 400,
        firstSeen: 1_780_000_000,
        lastSeen: 1_780_000_600,
        status2xx: 360,
        status3xx: 0,
        status4xx: 40,
        status5xx: 0,
        maxRequestsPerMinute: 60,
        samples: []
      }
    ]);

    expect(incidents.map((incident) => incident.id)).not.toContain("auth_abuse:/login");
  });

  it("does not let a filled query-variant cap hide a large saturation", () => {
    // A path with 90 000 requests and a distinct query string on nearly every
    // one. Only 256 variants fit in the bounded set, so queryVariants/count is
    // 0.003 — far below every ratio threshold — even though the real ratio is
    // ~1.0. The cap flag has to stop that ratio from vetoing the finding.
    const incidents = buildAggregateIncidents([
      {
        path: "/en/20-category",
        count: 90_000,
        bytes: 4_000_000_000,
        ipCounts: ipCounts(64, 90_000),
        queryVariants: new Set(Array.from({ length: 256 }, (_, index) => `?q=${index}`)),
        queryVariantCount: 256,
        queryVariantsIsLowerBound: true,
        queryVariantsAtOwnCap: true,
        uniqueIpCount: 2257,
        uniqueIpsIsLowerBound: true,
        uniqueIpsAtOwnCap: true,
        postCount: 0,
        firstSeen: 1_780_000_000,
        lastSeen: 1_780_200_000,
        status2xx: 89_500,
        status3xx: 400,
        status4xx: 100,
        status5xx: 0,
        maxRequestsPerMinute: 80,
        maxServedPerMinute: 80,
        samples: []
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "abusive_crawl:/en/20-category",
          kind: "saturation"
        })
      ])
    );
  });

  it("does not read a trickle of errors on a busy path as server distress", () => {
    // 130 errors in 83 323 requests is 0.16%: the background rate any busy URL
    // accumulates, not a backend failing under load.
    const incidents = buildAggregateIncidents([
      {
        path: "/admin7788/index.php",
        count: 83_323,
        bytes: 297_382_141,
        ipCounts: ipCounts(13, 83_323),
        queryVariants: new Set(Array.from({ length: 256 }, (_, index) => `?token=${index}`)),
        queryVariantCount: 256,
        queryVariantsIsLowerBound: true,
        queryVariantsAtOwnCap: true,
        postCount: 0,
        firstSeen: 1_780_000_000,
        lastSeen: 1_782_000_000,
        status2xx: 83_140,
        status3xx: 53,
        status4xx: 0,
        status5xx: 130,
        maxRequestsPerMinute: 61,
        maxServedPerMinute: 61,
        samples: []
      }
    ]);

    const incident = incidents.find((item) => item.id === "abusive_crawl:/admin7788/index.php");
    expect(incident?.severity).not.toBe("critical");
  });

  it("still reports distress when errors dominate the path", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/api/search",
        count: 12_000,
        bytes: 50_000_000,
        ipCounts: ipCounts(30, 12_000),
        queryVariants: new Set(Array.from({ length: 6_000 }, (_, index) => `?q=term${index}`)),
        postCount: 0,
        firstSeen: 1_780_000_000,
        lastSeen: 1_780_002_000,
        status2xx: 2_000,
        status3xx: 0,
        status4xx: 0,
        // 83% of requests failing: the backend is genuinely falling over.
        status5xx: 10_000,
        maxRequestsPerMinute: 400,
        maxServedPerMinute: 400,
        samples: []
      }
    ]);

    const incident = incidents.find((item) => item.id === "abusive_crawl:/api/search");
    expect(incident?.severity).toBe("critical");
  });

  it("trusts a high observed ratio even when the counter filled", () => {
    // Truncation can only push a ratio down, so an observed 0.99 needs no
    // corroboration: the served peak here (42/min) is deliberately below the
    // corroboration threshold to prove the ratio alone carries the decision.
    const incidents = buildAggregateIncidents([
      {
        path: "/facet-category",
        count: 2957,
        bytes: 14_409_529,
        ipCounts: ipCounts(35, 2957),
        queryVariants: new Set(Array.from({ length: 256 }, (_, index) => `?q=${index}`)),
        queryVariantCount: 2934,
        queryVariantsIsLowerBound: true,
        queryVariantsAtOwnCap: true,
        postCount: 0,
        firstSeen: 1_780_000_000,
        lastSeen: 1_780_010_800,
        status2xx: 356,
        status3xx: 0,
        status4xx: 2601,
        status5xx: 0,
        maxRequestsPerMinute: 140,
        maxServedPerMinute: 42,
        samples: []
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "abusive_crawl:/facet-category", kind: "saturation" })
      ])
    );
  });

  it("needs corroboration when a filled counter leaves the ratio collapsed", () => {
    // Same shape, but the observed ratio is low *and* the counter filled, so it
    // proves nothing. Without a served peak the path must not be promoted.
    const incidents = buildAggregateIncidents([
      {
        path: "/en/6-other-category",
        count: 8124,
        bytes: 2_042_649_965,
        // Mirrors the real shape: a wide audience where no single client
        // repeats enough to count as crawl pressure.
        ipCounts: new Map(
          Array.from({ length: 64 }, (_, index) => [`198.51.100.${index}`, 4] as const)
        ),
        queryVariants: new Set(Array.from({ length: 256 }, (_, index) => `?q=${index}`)),
        queryVariantCount: 256,
        queryVariantsIsLowerBound: true,
        queryVariantsAtOwnCap: true,
        uniqueIpCount: 959,
        uniqueIpsIsLowerBound: true,
        postCount: 0,
        firstSeen: 1_780_000_000,
        lastSeen: 1_780_600_000,
        status2xx: 6960,
        status3xx: 0,
        status4xx: 0,
        status5xx: 1164,
        maxRequestsPerMinute: 12,
        maxServedPerMinute: 12,
        samples: []
      }
    ]);

    expect(incidents.filter((incident) => incident.kind === "saturation")).toEqual([]);
  });

  it("still rejects a low-churn path whose counters never filled", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/estable",
        count: 90_000,
        bytes: 4_000_000_000,
        ipCounts: ipCounts(3, 90_000),
        queryVariants: new Set(["?page=1", "?page=2"]),
        postCount: 0,
        firstSeen: 1_780_000_000,
        lastSeen: 1_780_200_000,
        status2xx: 89_500,
        status3xx: 400,
        status4xx: 100,
        status5xx: 0,
        maxRequestsPerMinute: 80,
        maxServedPerMinute: 80,
        samples: []
      }
    ]);

    const saturation = incidents.filter((incident) => incident.kind === "saturation");
    expect(saturation).toEqual([]);
  });

  it("names the IPs responsible for a saturated path", () => {
    const ipCountsMap = new Map<string, number>([
      ["203.0.113.201", 2810],
      ["203.0.113.202", 14]
    ]);
    const incidents = buildAggregateIncidents([
      {
        path: "/facet-category",
        count: 2957,
        bytes: 14_409_529,
        ipCounts: ipCountsMap,
        // 35 distinct IPs seen overall; only the two heaviest were still
        // storable, which is exactly why the evidence must name them.
        uniqueIpCount: 35,
        uniqueIpsIsLowerBound: true,
        queryVariants: new Set(Array.from({ length: 2934 }, (_, index) => `?q=${index}`)),
        postCount: 0,
        firstSeen: 1_780_000_000,
        lastSeen: 1_780_010_000,
        status2xx: 356,
        status4xx: 2601,
        status3xx: 0,
        status5xx: 0,
        maxRequestsPerMinute: 140,
        maxServedPerMinute: 42,
        samples: []
      }
    ]);

    const incident = incidents.find((item) => item.id === "abusive_crawl:/facet-category");
    const topIps = incident?.evidence.find((item) => item.key === "topIps");
    expect(String(topIps?.value)).toContain("203.0.113.201 (2810)");
    expect(incident?.evidence.find((item) => item.key === "topIpShare")?.value).toBeGreaterThan(
      0.9
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
        maxServedPerMinute: 120,
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
        maxServedPerMinute: 120,
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

  it("flags high-peak blocked query churn when it still serves some expensive responses", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/facet-category",
        count: 2_957,
        bytes: 80_000_000,
        ipCounts: ipCounts(35, 2_957),
        queryVariants: new Set(Array.from({ length: 2_934 }, (_, index) => `?q=facet${index}`)),
        postCount: 0,
        firstSeen: 1_780_406_400,
        lastSeen: 1_780_417_200,
        status2xx: 356,
        status3xx: 0,
        status4xx: 2_601,
        status5xx: 0,
        maxRequestsPerMinute: 140,
        maxServedPerMinute: 42,
        samples: []
      }
    ]);

    expect(incidents).toEqual([
      expect.objectContaining({
        id: "abusive_crawl:/facet-category",
        kind: "saturation",
        severity: "high",
        score: 75,
        title: "Distributed URL saturation"
      })
    ]);
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

  it("flags sustained distributed query churn even when the monthly peak is modest", () => {
    const path = "/catalog/faceted-category";
    const incidents = buildAggregateIncidents([
      {
        path,
        count: 8_600,
        bytes: 430_000_000,
        ipCounts: ipCounts(2_100, 8_600),
        queryVariants: new Set(Array.from({ length: 8_400 }, (_, index) => `?q=facet-${index}`)),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 8_300,
        status3xx: 250,
        status4xx: 50,
        status5xx: 0,
        maxServedPerMinute: 22,
        samples: []
      }
    ]);

    expect(incidents).toEqual([
      expect.objectContaining({
        id: `abusive_crawl:${path}`,
        kind: "saturation",
        title: "Distributed URL saturation"
      })
    ]);
  });

  it("flags concentrated crawler query churn from a small IP set", () => {
    const path = "/localized/faceted-category";
    const incidents = buildAggregateIncidents([
      {
        path,
        count: 10_500,
        bytes: 445_000_000,
        ipCounts: ipCounts(22, 10_500),
        queryVariants: new Set(Array.from({ length: 9_900 }, (_, index) => `?q=facet-${index}`)),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 10_480,
        status3xx: 0,
        status4xx: 20,
        status5xx: 0,
        maxServedPerMinute: 58,
        samples: []
      }
    ]);

    expect(incidents).toEqual([
      expect.objectContaining({
        id: `abusive_crawl:${path}`,
        kind: "saturation",
        title: "Distributed URL saturation"
      })
    ]);
  });

  it("flags sustained repeated endpoint pressure below the old 120/minute burst gate", () => {
    const path = "/module/search/live";
    const incidents = buildAggregateIncidents([
      {
        path,
        count: 26_700,
        bytes: 420_000_000,
        ipCounts: ipCounts(2_400, 26_700),
        queryVariants: new Set(Array.from({ length: 4_000 }, (_, index) => `?s=term-${index}`)),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 25_600,
        status3xx: 0,
        status4xx: 1_000,
        status5xx: 40,
        maxServedPerMinute: 83,
        samples: []
      }
    ]);

    expect(incidents).toEqual([
      expect.objectContaining({
        id: `abusive_crawl:${path}`,
        kind: "saturation",
        title: "Concentrated URL pressure"
      })
    ]);
  });

  it("does not suppress admin endpoints when they show material pressure", () => {
    const path = "/admin/index.php";
    const counts = new Map<string, number>();
    for (let index = 0; index < 13; index += 1) {
      counts.set(`203.0.113.${index}`, 6_400);
    }

    const incidents = buildAggregateIncidents([
      {
        path,
        count: 83_200,
        bytes: 297_000_000,
        ipCounts: counts,
        queryVariants: new Set(Array.from({ length: 1_500 }, (_, index) => `?controller=${index}`)),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 83_000,
        status3xx: 50,
        status4xx: 0,
        status5xx: 150,
        maxServedPerMinute: 61,
        samples: []
      }
    ]);

    expect(incidents).toEqual([
      expect.objectContaining({
        id: `abusive_crawl:${path}`,
        kind: "saturation"
      })
    ]);
  });

  it("keeps mostly blocked query churn out of saturation even with huge request count", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/catalog/blocked-category",
        count: 187_000,
        bytes: 520_000_000,
        ipCounts: ipCounts(525, 187_000),
        queryVariants: new Set(Array.from({ length: 185_000 }, (_, index) => `?q=facet-${index}`)),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 7_300,
        status3xx: 0,
        status4xx: 179_700,
        status5xx: 0,
        maxServedPerMinute: 21,
        samples: []
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "abusive_crawl:/catalog/blocked-category", kind: "noise" })
      ])
    );
  });

  it("does not let 5xx distress override a dominant 4xx block outcome", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/catalog/blocked-but-crashing",
        count: 11_000,
        bytes: 100_000_000,
        ipCounts: ipCounts(500, 11_000),
        queryVariants: new Set(Array.from({ length: 10_500 }, (_, index) => `?q=facet-${index}`)),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 900,
        status3xx: 0,
        status4xx: 10_000,
        status5xx: 100,
        maxServedPerMinute: 100,
        samples: []
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "abusive_crawl:/catalog/blocked-but-crashing",
          kind: "noise"
        })
      ])
    );
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
        maxServedPerMinute: 120,
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

  it("does not treat missing maxServedPerMinute as an implicit traffic peak", () => {
    const counts = new Map<string, number>();
    for (let index = 0; index < 20; index += 1) {
      counts.set(`203.0.113.${index}`, 300);
    }

    const incidents = buildAggregateIncidents([
      {
        path: "/module/live-search",
        count: 6_000,
        bytes: 30_000_000,
        ipCounts: counts,
        queryVariants: new Set(),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 6_000,
        status3xx: 0,
        status4xx: 0,
        status5xx: 0,
        samples: []
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "abusive_crawl:/module/live-search", kind: "noise" })
      ])
    );
  });

  it("does not flag sustained repeat pressure below the per-minute peak floor", () => {
    const counts = new Map<string, number>();
    for (let index = 0; index < 20; index += 1) {
      counts.set(`203.0.113.${index}`, 300);
    }

    const incidents = buildAggregateIncidents([
      {
        path: "/module/live-search",
        count: 6_000,
        bytes: 30_000_000,
        ipCounts: counts,
        queryVariants: new Set(),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 6_000,
        status3xx: 0,
        status4xx: 0,
        status5xx: 0,
        maxServedPerMinute: 19,
        samples: []
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "abusive_crawl:/module/live-search", kind: "noise" })
      ])
    );
  });

  it("does not suppress admin index endpoints with material pressure and no query", () => {
    const counts = new Map<string, number>();
    for (let index = 0; index < 13; index += 1) {
      counts.set(`203.0.113.${index}`, 6_400);
    }

    const incidents = buildAggregateIncidents([
      {
        path: "/admin/index.php",
        count: 83_200,
        bytes: 297_000_000,
        ipCounts: counts,
        queryVariants: new Set(),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 83_200,
        status3xx: 0,
        status4xx: 0,
        status5xx: 0,
        maxServedPerMinute: 61,
        samples: []
      }
    ]);

    expect(incidents).toEqual([
      expect.objectContaining({
        id: "abusive_crawl:/admin/index.php",
        kind: "saturation",
        title: "Concentrated URL pressure"
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

  it("does not report plain index.php homepage traffic without app query or errors", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/index.php",
        count: 10_000,
        bytes: 250_000_000,
        ipCounts: ipCounts(500, 10_000),
        queryVariants: new Set(),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 10_000,
        status3xx: 0,
        status4xx: 0,
        status5xx: 0,
        maxServedPerMinute: 60,
        samples: []
      }
    ]);

    expect(incidents).toEqual([]);
  });

  it("does report exact index.php when server distress shows real app impact", () => {
    const counts = new Map<string, number>();
    for (let index = 0; index < 20; index += 1) {
      counts.set(`203.0.113.${index}`, 600);
    }

    const incidents = buildAggregateIncidents([
      {
        path: "/index.php",
        count: 12_000,
        bytes: 250_000_000,
        ipCounts: counts,
        queryVariants: new Set(),
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 11_900,
        status3xx: 0,
        status4xx: 0,
        status5xx: 100,
        maxServedPerMinute: 20,
        samples: []
      }
    ]);

    expect(incidents).toEqual([
      expect.objectContaining({
        id: "abusive_crawl:/index.php",
        kind: "saturation",
        title: "Concentrated URL pressure"
      })
    ]);
  });

  it("detects /running saturation from distinguished cardinality when maps are capped", () => {
    const storedIps = new Map<string, number>();
    for (let index = 0; index < 64; index += 1) {
      storedIps.set(`10.0.0.${index}`, 1);
    }

    const incidents = buildAggregateIncidents([
      {
        path: "/running",
        count: 1_100,
        bytes: 132_000,
        ipCounts: storedIps,
        queryVariants: new Set(Array.from({ length: 256 }, (_, index) => `?q=${index}`)),
        uniqueIpCount: 1_100,
        uniqueIpsIsLowerBound: true,
        queryVariantCount: 1_100,
        queryVariantsIsLowerBound: true,
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 1_100,
        status3xx: 0,
        status4xx: 0,
        status5xx: 0,
        maxServedPerMinute: 200,
        samples: ["/running?q=1"]
      }
    ]);

    expect(incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "abusive_crawl:/running",
          kind: "saturation",
          evidence: expect.arrayContaining([
            { key: "uniqueIps", value: 1_100 },
            { key: "queryVariants", value: 1_100 },
            { key: "uniqueIpsLowerBound", value: true },
            { key: "queryVariantsLowerBound", value: true }
          ])
        })
      ])
    );
  });

  it("does not treat request total as unique IP or query-variant cardinality", () => {
    const incidents = buildAggregateIncidents([
      {
        path: "/running",
        count: 10_000,
        bytes: 1_000_000,
        ipCounts: ipCounts(5, 10_000),
        queryVariants: new Set(["?q=stable"]),
        uniqueIpCount: 5,
        queryVariantCount: 1,
        postCount: 0,
        firstSeen: null,
        lastSeen: null,
        status2xx: 10_000,
        status3xx: 0,
        status4xx: 0,
        status5xx: 0,
        maxServedPerMinute: 400,
        samples: []
      }
    ]);

    expect(incidents.find((incident) => incident.id === "abusive_crawl:/running")).toBeUndefined();
    expect(
      incidents.find((incident) => incident.id === "query_explosion:/running")
    ).toBeUndefined();
  });
});

describe("payload signatures — Phase 1 (D1-D5)", () => {
  it("D1: strips null bytes before matching (bypass attempt via %00)", () => {
    const hits = detectRequestHits(entry("/etc/passwd%00.jpg?x=%2e%2e%2fetc%2fpasswd%00"));
    expect(hits).toEqual(expect.arrayContaining([expect.objectContaining({ ruleId: "lfi_rfi" })]));
  });

  describe("D2: SQLi comment/exfiltration signatures", () => {
    it("detects quote-anchored -- comment terminator", () => {
      const hits = detectRequestHits(entry("/login?user=admin'--%20"));
      expect(hits).toEqual(expect.arrayContaining([expect.objectContaining({ ruleId: "sqli" })]));
    });

    it("detects numeric-anchored -- comment terminator", () => {
      const hits = detectRequestHits(entry("/item?id=1-- "));
      expect(hits).toEqual(expect.arrayContaining([expect.objectContaining({ ruleId: "sqli" })]));
    });

    it("does NOT flag a legitimate slug containing bare --", () => {
      const hits = detectRequestHits(entry("/blog/foo--bar-review"));
      expect(hits.some((h) => h.ruleId === "sqli")).toBe(false);
    });

    it("does NOT flag a legitimate #top-style fragment token in query", () => {
      const hits = detectRequestHits(entry("/page?section=%23top"));
      expect(hits.some((h) => h.ruleId === "sqli")).toBe(false);
    });

    it("detects UNION(SELECT with no space", () => {
      const hits = detectRequestHits(
        entry("/search?q=1%20UNION(SELECT%20password%20FROM%20users)")
      );
      expect(hits).toEqual(expect.arrayContaining([expect.objectContaining({ ruleId: "sqli" })]));
    });

    it("detects exfiltration functions only when called with parens", () => {
      const hits = detectRequestHits(entry("/search?q=1%20AND%20substring(password,1,1)=%27a%27"));
      expect(hits).toEqual(expect.arrayContaining([expect.objectContaining({ ruleId: "sqli" })]));
    });

    it("does NOT flag bare mentions of function names without parens", () => {
      const hits = detectRequestHits(entry("/blog/concat-of-two-strings-tutorial"));
      expect(hits.some((h) => h.ruleId === "sqli")).toBe(false);
    });
  });

  describe("D3: XSS execution sinks and expanded event handlers", () => {
    it("detects eval( sink", () => {
      const hits = detectRequestHits(entry("/page?x=%22);eval(atob('YWxlcnQoMSk='))//"));
      expect(hits).toEqual(expect.arrayContaining([expect.objectContaining({ ruleId: "xss" })]));
    });

    it("detects innerHTML sink", () => {
      const hits = detectRequestHits(
        entry("/page?x=<img src=x onerror=this.parentNode.innerHTML=1>")
      );
      expect(hits).toEqual(expect.arrayContaining([expect.objectContaining({ ruleId: "xss" })]));
    });

    it("detects onwheel handler", () => {
      const hits = detectRequestHits(entry("/page?x=<div onwheel=alert(1)>"));
      expect(hits).toEqual(expect.arrayContaining([expect.objectContaining({ ruleId: "xss" })]));
    });

    it("detects onpointerover handler", () => {
      const hits = detectRequestHits(entry("/page?x=<div onpointerover=alert(1)>"));
      expect(hits).toEqual(expect.arrayContaining([expect.objectContaining({ ruleId: "xss" })]));
    });

    it("does NOT flag ?onsale=1 as XSS (X1 anti-FP)", () => {
      const hits = detectRequestHits(entry("/products?onsale=1"));
      expect(hits.some((h) => h.ruleId === "xss")).toBe(false);
    });

    it("does NOT flag ?onboarding=step2 as XSS (X1 anti-FP)", () => {
      const hits = detectRequestHits(entry("/app?onboarding=step2"));
      expect(hits.some((h) => h.ruleId === "xss")).toBe(false);
    });
  });

  describe("D4: LFI/traversal expanded signatures", () => {
    it("detects double-encoded traversal %252e%252e", () => {
      const hits = detectRequestHits(
        entry("/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd")
      );
      expect(hits).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: "lfi_rfi" })])
      );
    });

    it("detects Windows backslash traversal", () => {
      const hits = detectRequestHits(entry("/download?file=..\\..\\windows\\win.ini"));
      expect(hits).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: "lfi_rfi" })])
      );
    });

    it("detects URL-encoded backslash traversal ..%5c", () => {
      const hits = detectRequestHits(entry("/download?file=..%5c..%5cwindows%5cwin.ini"));
      expect(hits).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: "lfi_rfi" })])
      );
    });

    it("detects /etc/shadow probe", () => {
      const hits = detectRequestHits(entry("/download?file=/etc/shadow"));
      expect(hits).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: "lfi_rfi" })])
      );
    });

    it("detects /etc/sudoers probe", () => {
      const hits = detectRequestHits(entry("/download?file=/etc/sudoers"));
      expect(hits).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: "lfi_rfi" })])
      );
    });

    it("detects /proc/self/cmdline probe", () => {
      const hits = detectRequestHits(entry("/download?file=/proc/self/cmdline"));
      expect(hits).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: "lfi_rfi" })])
      );
    });

    it("detects php://input wrapper", () => {
      const hits = detectRequestHits(entry("/index.php?page=php://input"));
      expect(hits).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: "lfi_rfi" })])
      );
    });

    it("detects php://fd wrapper", () => {
      const hits = detectRequestHits(entry("/index.php?page=php://fd/3"));
      expect(hits).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: "lfi_rfi" })])
      );
    });

    it("detects phar:// wrapper", () => {
      const hits = detectRequestHits(entry("/index.php?page=phar://evil.phar/x.php"));
      expect(hits).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: "lfi_rfi" })])
      );
    });
  });

  describe("D5: command injection expanded binaries and %0a separator", () => {
    it("detects base64 binary via pipe metachar", () => {
      const hits = detectRequestHits(entry("/ping?host=127.0.0.1|base64%20/etc/passwd"));
      expect(hits).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: "command_injection" })])
      );
    });

    it("detects xxd binary via semicolon metachar", () => {
      const hits = detectRequestHits(entry("/ping?host=127.0.0.1;xxd%20/etc/passwd"));
      expect(hits).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: "command_injection" })])
      );
    });

    it("detects openssl binary via backtick metachar", () => {
      const hits = detectRequestHits(entry("/ping?host=`openssl enc -d`"));
      expect(hits).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: "command_injection" })])
      );
    });

    it("detects relaxed %0a separator followed by shell metachar (no metachar+known binary elsewhere)", () => {
      // "reboot" is not in the known-binary list and there is no metachar
      // anywhere else in the payload, so this can only be caught by the
      // decoded-newline branch (\n followed by a metachar), not by the
      // metachar+binary branch above.
      const hits = detectRequestHits(entry("/ping?host=127.0.0.1%0a$(reboot)"));
      expect(hits).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: "command_injection" })])
      );
    });

    it("detects %0d%0a followed by shell metachar with no metachar+binary elsewhere", () => {
      const hits = detectRequestHits(entry("/ping?host=127.0.0.1%0d%0a;shutdown"));
      expect(hits).toEqual(
        expect.arrayContaining([expect.objectContaining({ ruleId: "command_injection" })])
      );
    });

    it("does NOT flag %0a followed by a harmless letter with no metachar/binary", () => {
      const hits = detectRequestHits(entry("/search?q=line1%0aline2"));
      expect(hits.some((h) => h.ruleId === "command_injection")).toBe(false);
    });
  });

  it("guards that every RULES pattern has prefix coverage in PAYLOAD_PREFIXES", async () => {
    // Import the module source to introspect RULES/PAYLOAD_PREFIXES indirectly:
    // we can't reach the private arrays directly, so this guard instead asserts
    // known representative payloads for each rule id pass the public fast-path
    // by successfully producing a hit through detectRequestHits. This catches
    // the R1 hard-rule regression (new pattern added without a prefix entry).
    const representativePayloads: Array<{ ruleId: string; target: string }> = [
      { ruleId: "sqli", target: "/x?q=1%20union%20select%201" },
      { ruleId: "sqli", target: "/x?q=admin'--%20" },
      { ruleId: "sqli", target: "/x?q=1%20UNION(SELECT%201)" },
      { ruleId: "sqli", target: "/x?q=substring(a,1,1)" },
      { ruleId: "xss", target: "/x?q=<script>alert(1)</script>" },
      { ruleId: "xss", target: "/x?q=<div onwheel=alert(1)>" },
      { ruleId: "xss", target: "/x?q=eval(1)" },
      { ruleId: "lfi_rfi", target: "/x?f=../../etc/passwd" },
      { ruleId: "lfi_rfi", target: "/x?f=..%5c..%5cwin.ini" },
      { ruleId: "lfi_rfi", target: "/x?f=php://input" },
      { ruleId: "ssrf", target: "/x?url=http://169.254.169.254/latest/meta-data" },
      { ruleId: "command_injection", target: "/x?q=;base64%20/etc/passwd" },
      { ruleId: "recon_sensitive_file", target: "/.env.local" },
      { ruleId: "recon_sensitive_file", target: "/.git/HEAD" }
    ];

    for (const { ruleId, target } of representativePayloads) {
      const hits = detectRequestHits(entry(target));
      expect(
        hits.some((h) => h.ruleId === ruleId),
        `expected ${ruleId} to fire for ${target}`
      ).toBe(true);
    }
  });
});

describe("D7: SSRF anti-FP — requires internal/loopback/metadata destination", () => {
  it("does NOT flag ?redirect=https://accounts.google.com/o/oauth2 (legit OAuth)", () => {
    const hits = detectRequestHits(
      entry("/auth/callback?redirect=https://accounts.google.com/o/oauth2")
    );
    expect(hits.some((h) => h.ruleId === "ssrf")).toBe(false);
  });

  it("does NOT flag ?callback=https://api.stripe.com (legit payment callback)", () => {
    const hits = detectRequestHits(entry("/checkout?callback=https://api.stripe.com"));
    expect(hits.some((h) => h.ruleId === "ssrf")).toBe(false);
  });

  it("detects ?url=http://169.254.169.254/latest/meta-data (cloud metadata SSRF)", () => {
    const hits = detectRequestHits(entry("/fetch?url=http://169.254.169.254/latest/meta-data"));
    expect(hits).toEqual(expect.arrayContaining([expect.objectContaining({ ruleId: "ssrf" })]));
  });

  it("detects ?next=http://127.0.0.1:8080/admin (loopback SSRF)", () => {
    const hits = detectRequestHits(entry("/login?next=http://127.0.0.1:8080/admin"));
    expect(hits).toEqual(expect.arrayContaining([expect.objectContaining({ ruleId: "ssrf" })]));
  });

  it("detects ?target=http://192.168.1.1/ (private-range SSRF)", () => {
    const hits = detectRequestHits(entry("/proxy?target=http://192.168.1.1/"));
    expect(hits).toEqual(expect.arrayContaining([expect.objectContaining({ ruleId: "ssrf" })]));
  });
});

describe("D6: recon sensitive file probes (Phase 2)", () => {
  const positives = [
    "/.env.local",
    "/.env.production",
    "/.git/HEAD",
    "/.git/config",
    "/backup/site.tar",
    "/backup/site.7z",
    "/backup/site.rar",
    "/config.php.orig",
    "/config.php.bkp",
    "/.ssh/id_rsa",
    "/.kube/config",
    "/wp-config.php",
    "/docker-compose.yml",
    "/.DS_Store"
  ];

  it.each(positives)("flags sensitive file probe: %s", (target) => {
    const hits = detectRequestHits(entry(target));
    expect(hits).toEqual(
      expect.arrayContaining([expect.objectContaining({ ruleId: "recon_sensitive_file" })])
    );
  });

  it("prunes a single 404 sensitive-file probe as noise (not persistent)", () => {
    const incidents = new Map();
    const req = entry("/.env.local", { status: 404 });
    const [hit] = detectRequestHits(req);
    const incidentId = mergeRuleHit(incidents, hit!, req);

    pruneNoise(incidents);

    expect(incidents.has(incidentId)).toBe(false);
  });
});

describe("P1 perf refactor: single-parse equivalence (R4 anti-regression guard)", () => {
  it("redactTarget and querySignature produce identical output whether or not a pre-parsed URL is reused", () => {
    const target = "/checkout?token=abc&q=x";
    const parsed = parseTargetUrl(target);

    // Reusing a single pre-parsed URL (the hot-path optimization) must yield
    // byte-identical results to each function parsing independently — secret
    // redaction and tracking-param stripping must not regress silently.
    expect(redactTarget(target, parsed)).toBe(redactTarget(target));
    expect(querySignature(target, parsed)).toBe(querySignature(target));

    expect(redactTarget(target, parsed)).toBe("/checkout?token=[REDACTED]&q=x");
    expect(querySignature(target, parsed)).toBe("?token=[REDACTED]&q=x");
  });

  it("passing an explicit null (simulated parse failure) uses the same raw-string fallback as before the refactor", () => {
    // Passing `null` simulates parseTargetUrl having failed to parse the
    // target upstream. Both functions must still redact secrets on the raw
    // string via redactSecretPairs, matching the original pre-refactor catch
    // branch exactly (no new fallback behavior introduced).
    const target = "/checkout?token=abc&q=x";
    expect(redactTarget(target, null)).toBe("/checkout?token=[REDACTED]&q=x");
    expect(querySignature(target, null)).toBe("?token=[REDACTED]&q=x");
  });
});
