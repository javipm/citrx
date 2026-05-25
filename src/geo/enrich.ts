import type { AnalyzeReport, GeoIpInfo, GeoSummary, TopItem } from "../analysis/types.js";
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
    geo: buildGeoSummary(infos, ips, failed)
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
