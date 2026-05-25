import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

import type { GeoIpInfo } from "../analysis/types.js";

export type GeoLookup = (ip: string) => Promise<GeoIpInfo | null>;

interface CacheFile {
  version: 1;
  entries: Record<string, Omit<GeoIpInfo, "cached"> & { updatedAt: string }>;
}

const PROVIDER_URL = "https://ipwho.is";
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export function createIpWhoisLookup(env: NodeJS.ProcessEnv): GeoLookup {
  const cachePath = path.join(resolveCacheDir(env), "geo-cache.json");
  let cachePromise: Promise<CacheFile> | null = null;

  async function loadCache(): Promise<CacheFile> {
    if (!cachePromise) {
      cachePromise = readFile(cachePath, "utf8")
        .then((content) => JSON.parse(content) as CacheFile)
        .catch(() => ({ version: 1, entries: {} }));
    }

    return cachePromise;
  }

  return async (ip: string) => {
    const cache = await loadCache();
    const cached = cache.entries[ip];

    if (cached && Date.now() - Date.parse(cached.updatedAt) < CACHE_TTL_MS) {
      return {
        ip: cached.ip,
        country: cached.country,
        countryCode: cached.countryCode,
        asn: cached.asn,
        org: cached.org,
        cached: true
      };
    }

    const fresh = await lookupIp(ip);
    if (!fresh) {
      return null;
    }

    cache.entries[ip] = {
      ip: fresh.ip,
      country: fresh.country,
      countryCode: fresh.countryCode,
      asn: fresh.asn,
      org: fresh.org,
      updatedAt: new Date().toISOString()
    };
    await mkdir(path.dirname(cachePath), { recursive: true });
    await writeFile(cachePath, `${JSON.stringify(cache, null, 2)}\n`, "utf8");

    return fresh;
  };
}

async function lookupIp(ip: string): Promise<GeoIpInfo | null> {
  const response = await fetch(
    `${PROVIDER_URL}/${encodeURIComponent(ip)}?fields=success,message,ip,country,country_code,connection`
  );

  if (!response.ok) {
    return null;
  }

  const data = (await response.json()) as {
    success?: boolean;
    ip?: string;
    country?: string;
    country_code?: string;
    connection?: {
      asn?: number | string;
      org?: string;
      isp?: string;
    };
  };

  if (data.success === false || !data.ip) {
    return null;
  }

  return {
    ip: data.ip,
    country: data.country ?? null,
    countryCode: data.country_code ?? null,
    asn:
      data.connection?.asn === undefined || data.connection.asn === null
        ? null
        : `AS${data.connection.asn}`,
    org: data.connection?.org ?? data.connection?.isp ?? null,
    cached: false
  };
}

function resolveCacheDir(env: NodeJS.ProcessEnv): string {
  if (env.CITRX_CACHE_DIR) {
    return env.CITRX_CACHE_DIR;
  }

  if (env.XDG_CACHE_HOME) {
    return path.join(env.XDG_CACHE_HOME, "citrx");
  }

  if (env.LOCALAPPDATA) {
    return path.join(env.LOCALAPPDATA, "citrx", "Cache");
  }

  return path.join(homedir(), "Library", "Caches", "citrx");
}
