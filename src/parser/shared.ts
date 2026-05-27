import type { AccessLogEntry } from "./types.js";

const HTTP_METHODS = new Set([
  "GET",
  "POST",
  "HEAD",
  "PUT",
  "DELETE",
  "PATCH",
  "OPTIONS",
  "TRACE",
  "CONNECT",
  "PROPFIND"
]);

interface BuildEntryInput {
  ip: string;
  timestamp: string;
  request?: string;
  method?: string;
  target?: string;
  protocol?: string;
  status: string;
  bytes?: string;
  referer?: string;
  userAgent?: string;
}

export function buildAccessLogEntry(input: BuildEntryInput): AccessLogEntry | null {
  const requestParts = input.request?.trim().split(/\s+/) ?? [];
  const method = (input.method ?? requestParts[0])?.toUpperCase();
  const protocol = input.protocol ?? requestParts.at(-1) ?? "";
  const target =
    input.target ??
    (requestParts.length >= 3 ? requestParts.slice(1, -1).join(" ") : requestParts[1]) ??
    "";

  if (!method || !HTTP_METHODS.has(method)) {
    return null;
  }

  if (!protocol.startsWith("HTTP/")) {
    return null;
  }

  const status = Number.parseInt(input.status, 10);
  const bytesText = input.bytes ?? "-";
  const bytes = bytesText === "-" ? null : Number.parseInt(bytesText, 10);

  if (!Number.isInteger(status) || status < 100 || status > 599) {
    return null;
  }

  if (bytes !== null && (!Number.isInteger(bytes) || bytes < 0)) {
    return null;
  }

  return {
    ip: input.ip,
    timestamp: input.timestamp,
    method,
    target,
    path: normalizePath(target),
    protocol,
    status,
    bytes,
    referer: normalizeOptional(input.referer),
    userAgent: normalizeOptional(input.userAgent)
  };
}

export function normalizePath(target: string): string {
  try {
    return new URL(target, "http://citrx.local").pathname || "/";
  } catch {
    const queryStart = target.indexOf("?");
    return queryStart === -1 ? target || "/" : target.slice(0, queryStart) || "/";
  }
}

function normalizeOptional(value: string | undefined): string | null {
  return value && value !== "-" ? value : null;
}
