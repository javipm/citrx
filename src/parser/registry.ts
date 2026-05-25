import { builtInParsers, getBuiltInParser } from "./built-in.js";
import type {
  AccessLogFormatId,
  AccessLogParser,
  BuiltInFormatId,
  FormatChoice
} from "./types.js";

export interface FormatDetectionResult {
  parser: AccessLogParser;
  sampledLines: number;
  parsedLines: number;
  parseRatio: number;
}

const MIN_PARSE_RATIO = 0.8;
const MIN_SAMPLE_LINES = 1;

export function resolveParser(
  format: FormatChoice,
  customParsers: AccessLogParser[]
): AccessLogParser | null {
  if (format === "auto") {
    return null;
  }

  if (format.startsWith("custom:")) {
    return customParsers.find((parser) => parser.id === format) ?? null;
  }

  return getBuiltInParser(format as BuiltInFormatId);
}

export function detectParser(
  lines: string[],
  customParsers: AccessLogParser[]
): FormatDetectionResult | null {
  const parsers = [...customParsers, ...builtInParsers];
  const results = parsers
    .map((parser) => scoreParser(parser, lines))
    .filter((result) => result.sampledLines >= MIN_SAMPLE_LINES)
    .sort((a, b) => b.parseRatio - a.parseRatio || b.parsedLines - a.parsedLines);
  const best = results[0];

  if (!best || best.parseRatio < MIN_PARSE_RATIO) {
    return null;
  }

  return best;
}

export function validateParserOnSample(
  parser: AccessLogParser,
  lines: string[]
): FormatDetectionResult {
  return scoreParser(parser, lines);
}

export function isAccessLogFormatId(value: string): value is AccessLogFormatId {
  return (
    value === "apache_common" ||
    value === "apache_combined" ||
    value === "nginx_combined" ||
    value.startsWith("custom:")
  );
}

function scoreParser(
  parser: AccessLogParser,
  lines: string[]
): FormatDetectionResult {
  const sampledLines = lines.length;
  const parsedLines = lines.filter((line) => parser.parse(line)).length;

  return {
    parser,
    sampledLines,
    parsedLines,
    parseRatio: sampledLines === 0 ? 0 : parsedLines / sampledLines
  };
}
