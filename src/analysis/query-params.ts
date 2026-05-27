export interface QueryParamEntry {
  name: string;
  value: string;
}

const SENSITIVE_PARAM_PATTERN = /pass(word)?|token|secret|key|auth|session|sid|jwt|credential/i;

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
  return unique(requestParamEntries(target).map((entry) => entry.name.trim()).filter(Boolean));
}

export function requestParamValueLabels(target: string): string[] {
  return unique(
    requestParamEntries(target)
      .map((entry) => paramValueLabel(entry.name.trim(), entry.value.trim()))
      .filter((value): value is string => Boolean(value))
  );
}

export function userAgentLabel(userAgent: string | null): string {
  if (!userAgent || userAgent === "-") {
    return "-";
  }

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

  return normalized.length <= 42 ? normalized : `${normalized.slice(0, 41)}…`;
}

export function isSensitiveParamName(name: string): boolean {
  return SENSITIVE_PARAM_PATTERN.test(name);
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
