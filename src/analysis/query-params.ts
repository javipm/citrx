import { isSensitiveParamName } from "../utils/redact.js";

export interface QueryParamEntry {
  name: string;
  value: string;
}

export interface QueryParamLabels {
  names: string[];
  values: string[];
}

const UA_LABEL_CACHE_MAX = 20_000;
const UA_LABEL_CACHE_EVICT = 5_000;
const uaLabelCache = new Map<string, string>();

export function requestParamEntries(target: string): QueryParamEntry[] {
  const queryStart = target.indexOf("?");

  if (queryStart === -1 || queryStart === target.length - 1) {
    return [];
  }

  return target
    .slice(queryStart + 1)
    .split("&")
    .map(parseQueryPart)
    .filter((entry) => entry.name.length > 0);
}

export function requestParamNames(target: string): string[] {
  return requestParamLabels(target).names;
}

export function requestParamValueLabels(target: string): string[] {
  return requestParamLabels(target).values;
}

export function requestParamLabels(target: string): QueryParamLabels {
  const names: string[] = [];
  const values: string[] = [];

  for (const entry of requestParamEntries(target)) {
    const name = entry.name.trim();

    if (!name) {
      continue;
    }

    names.push(name);

    const value = paramValueLabel(name, entry.value.trim());
    if (value) {
      values.push(value);
    }
  }

  return {
    names: unique(names),
    values: unique(values)
  };
}

export function userAgentLabel(userAgent: string | null): string {
  if (!userAgent || userAgent === "-") {
    return "-";
  }

  const cached = uaLabelCache.get(userAgent);
  if (cached !== undefined) {
    return cached;
  }

  const label = computeUserAgentLabel(userAgent);
  cacheUserAgentLabel(userAgent, label);
  return label;
}

function computeUserAgentLabel(userAgent: string): string {
  const normalized = userAgent.replace(/\s+/g, " ").trim();
  const bot = normalized.match(
    /([A-Za-z0-9_.-]*(?:bot|crawler|spider|slurp|searchbot)[A-Za-z0-9_.-]*\/[^\s;)]+)/i
  );

  if (bot) {
    return bot[1] ?? normalized;
  }

  const browser =
    normalized.match(/(?:Chrome|Firefox|Version|OPR|Edg)\/[^\s;)]+/)?.[0] ??
    normalized.match(/Safari\/[^\s;)]+/)?.[0] ??
    "UA";
  const os =
    normalized.match(/Android [^;)]+/)?.[0] ??
    normalized.match(/Windows NT [^;)]+/)?.[0] ??
    normalized.match(/Mac OS X [^;)]+/)?.[0] ??
    normalized.match(/Linux [^;)]+/)?.[0];

  if (browser !== "UA") {
    return os ? `${browser} ${os}` : browser;
  }

  return normalized;
}

function cacheUserAgentLabel(userAgent: string, label: string): void {
  if (uaLabelCache.size >= UA_LABEL_CACHE_MAX) {
    let evicted = 0;
    for (const key of uaLabelCache.keys()) {
      uaLabelCache.delete(key);
      evicted += 1;

      if (evicted >= UA_LABEL_CACHE_EVICT) {
        break;
      }
    }
  }

  uaLabelCache.set(userAgent, label);
}

function parseQueryPart(part: string): QueryParamEntry {
  const separator = part.indexOf("=");

  if (separator === -1) {
    return { name: safeDecode(part), value: "" };
  }

  return {
    name: safeDecode(part.slice(0, separator)),
    value: safeDecode(part.slice(separator + 1))
  };
}

function paramValueLabel(name: string, value: string): string | undefined {
  if (!name) {
    return undefined;
  }

  if (isSensitiveParamName(name)) {
    return `${name}=<redacted>`;
  }

  return `${name}=${value || "<empty>"}`;
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}
