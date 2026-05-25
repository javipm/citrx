import { buildAccessLogEntry } from "./shared.js";
import type { AccessLogParser, BuiltInFormatId } from "./types.js";

const APACHE_COMMON_PATTERN =
  /^(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<timestamp>[^\]]+)]\s+"(?<request>[^"]*)"\s+(?<status>\d{3})\s+(?<bytes>\S+)\s*$/;

const COMBINED_PATTERN =
  /^(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<timestamp>[^\]]+)]\s+"(?<request>[^"]*)"\s+(?<status>\d{3})\s+(?<bytes>\S+)\s+"(?<referer>[^"]*)"\s+"(?<userAgent>[^"]*)"\s*$/;

export const builtInParsers: AccessLogParser[] = [
  createRegexParser("apache_combined", "Apache combined", COMBINED_PATTERN),
  createRegexParser("nginx_combined", "Nginx combined", COMBINED_PATTERN),
  createRegexParser("apache_common", "Apache common", APACHE_COMMON_PATTERN)
];

export function getBuiltInParser(id: BuiltInFormatId): AccessLogParser {
  const parser = builtInParsers.find((candidate) => candidate.id === id);

  if (!parser) {
    throw new Error(`Unknown built-in format: ${id}`);
  }

  return parser;
}

function createRegexParser(
  id: BuiltInFormatId,
  label: string,
  pattern: RegExp
): AccessLogParser {
  return {
    id,
    label,
    parse(line) {
      const match = pattern.exec(line);

      if (!match?.groups) {
        return null;
      }

      return buildAccessLogEntry({
        ip: match.groups.ip ?? "",
        timestamp: match.groups.timestamp ?? "",
        request: match.groups.request,
        status: match.groups.status ?? "",
        bytes: match.groups.bytes,
        referer: match.groups.referer,
        userAgent: match.groups.userAgent
      });
    }
  };
}
