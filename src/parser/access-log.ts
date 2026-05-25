export interface AccessLogEntry {
  ip: string;
  timestamp: string;
  method: string;
  target: string;
  path: string;
  protocol: string;
  status: number;
  bytes: number | null;
  referer: string | null;
  userAgent: string | null;
}

const ACCESS_LOG_PATTERN =
  /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)]\s+"([^"]*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?\s*$/;

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

export function parseAccessLogLine(line: string): AccessLogEntry | null {
  const match = ACCESS_LOG_PATTERN.exec(line);

  if (!match) {
    return null;
  }

  const [, ip, timestamp, request, statusText, bytesText, referer, userAgent] =
    match;
  const requestParts = request.trim().split(/\s+/);

  if (requestParts.length < 2) {
    return null;
  }

  const method = requestParts[0]?.toUpperCase();
  const protocol = requestParts.at(-1) ?? "";
  const target = requestParts.slice(1, -1).join(" ") || (requestParts[1] ?? "");

  if (!method || !HTTP_METHODS.has(method)) {
    return null;
  }

  if (!protocol.startsWith("HTTP/")) {
    return null;
  }

  const status = Number.parseInt(statusText, 10);
  const bytes = bytesText === "-" ? null : Number.parseInt(bytesText, 10);

  if (!Number.isInteger(status) || status < 100 || status > 599) {
    return null;
  }

  if (bytes !== null && (!Number.isInteger(bytes) || bytes < 0)) {
    return null;
  }

  return {
    ip,
    timestamp,
    method,
    target,
    path: normalizePath(target),
    protocol,
    status,
    bytes,
    referer: referer && referer !== "-" ? referer : null,
    userAgent: userAgent && userAgent !== "-" ? userAgent : null
  };
}

function normalizePath(target: string): string {
  try {
    return new URL(target, "http://citrx.local").pathname || "/";
  } catch {
    const queryStart = target.indexOf("?");
    return queryStart === -1 ? target || "/" : target.slice(0, queryStart) || "/";
  }
}
