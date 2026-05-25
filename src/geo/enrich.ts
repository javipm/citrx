import type {
  AnalyzeReport,
  GeoIpInfo,
  GeoSummary,
  Incident,
  TopItem
} from "../analysis/types.js";
import type { GeoLookup } from "./ipwhois.js";

export interface GeoEnrichOptions {
  lookup: GeoLookup;
  limit: number;
  delayMs?: number;
}

export async function enrichReportWithGeo(
  report: AnalyzeReport,
  options: GeoEnrichOptions
): Promise<AnalyzeReport> {
  const ips = report.topIps.slice(0, options.limit);
  const infos: GeoIpInfo[] = [];
  let failed = 0;

  for (const [index, item] of ips.entries()) {
    if (index > 0 && options.delayMs && options.delayMs > 0) {
      await delay(options.delayMs);
    }

    const info = await options.lookup(item.value).catch(() => null);
    if (!info) {
      failed += 1;
      continue;
    }

    infos.push(info);
  }

  return {
    ...report,
    geo: buildGeoSummary(infos, ips, failed),
    incidents: [
      ...report.incidents,
      ...buildGeoIncidents(infos, ips),
      ...buildGeoDiagnostics(infos, ips, failed)
    ]
  };
}

function buildGeoSummary(
  infos: GeoIpInfo[],
  topIps: TopItem[],
  failed: number
): GeoSummary {
  const requestsByIp = new Map(topIps.map((item) => [item.value, item.count]));
  const countries = new Map<string, number>();
  const asns = new Map<string, number>();

  for (const info of infos) {
    const requests = requestsByIp.get(info.ip) ?? 0;

    if (info.country) {
      increment(countries, info.country, requests);
    }

    if (info.asn || info.org) {
      increment(asns, [info.asn, info.org].filter(Boolean).join(" "), requests);
    }
  }

  return {
    provider: "ipwho.is",
    lookedUp: infos.length,
    failed,
    topCountries: topItems(countries),
    topAsns: topItems(asns),
    ips: infos
  };
}

function increment(map: Map<string, number>, key: string, value: number): void {
  map.set(key, (map.get(key) ?? 0) + value);
}

function buildGeoIncidents(infos: GeoIpInfo[], topIps: TopItem[]): Incident[] {
  const requestsByIp = new Map(topIps.map((item) => [item.value, item.count]));
  const totalRequests = topIps.reduce((sum, item) => sum + item.count, 0);
  const byAsn = new Map<
    string,
    {
      asn: string;
      org: string | null;
      country: string | null;
      requests: number;
      ips: string[];
    }
  >();

  for (const info of infos) {
    if (!info.asn) {
      continue;
    }

    const current = byAsn.get(info.asn) ?? {
      asn: info.asn,
      org: info.org,
      country: info.country,
      requests: 0,
      ips: []
    };
    current.requests += requestsByIp.get(info.ip) ?? 0;
    current.ips.push(info.ip);
    byAsn.set(info.asn, current);
  }

  return [...byAsn.values()]
    .filter((group) => {
      const share = totalRequests === 0 ? 0 : group.requests / totalRequests;
      return group.requests >= 1000 || group.ips.length >= 2 || share >= 0.5;
    })
    .sort((a, b) => b.requests - a.requests)
    .map((group) => {
      const share = totalRequests === 0 ? 0 : group.requests / totalRequests;
      const wafValue = [group.asn, group.org].filter(Boolean).join(" ");

      return {
        id: `geo_asn_concentration:${group.asn}`,
        category: "geo_asn_concentration",
        severity: share >= 0.5 || group.requests >= 10000 ? "high" : "medium",
        score: share >= 0.5 ? 82 : 70,
        title: "High request concentration from ASN",
        description:
          "Top requesting IPs are concentrated in one ASN. Consider a WAF rate-limit, challenge, or temporary ASN rule if traffic is unwanted.",
        evidence: [
          { key: "wafScope", value: "asn" },
          { key: "wafValue", value: wafValue },
          { key: "asn", value: group.asn },
          ...(group.org ? [{ key: "org", value: group.org }] : []),
          ...(group.country ? [{ key: "country", value: group.country }] : []),
          { key: "requestsInTopIps", value: group.requests },
          { key: "uniqueIpsInTopIps", value: group.ips.length },
          { key: "topIpSharePercent", value: Math.round(share * 100) }
        ],
        samples: group.ips.slice(0, 5)
      } satisfies Incident;
    });
}

function buildGeoDiagnostics(
  infos: GeoIpInfo[],
  topIps: TopItem[],
  failed: number
): Incident[] {
  if (topIps.length === 0 || infos.length > 0 || failed === 0) {
    return [];
  }

  return [
    {
      id: "geo_lookup_failed",
      category: "geo_diagnostic",
      severity: "low",
      score: 20,
      title: "GeoIP lookup failed",
      description:
        "GeoIP was requested, but no top IP could be enriched. Check network access, provider availability, or rate limits.",
      evidence: [
        { key: "provider", value: "ipwho.is" },
        { key: "attemptedIps", value: topIps.length },
        { key: "failed", value: failed }
      ],
      samples: topIps.slice(0, 5).map((item) => item.value)
    }
  ];
}

function topItems(map: Map<string, number>): TopItem[] {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([value, count]) => ({ value, count }));
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
