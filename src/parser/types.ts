export type BuiltInFormatId = "apache_common" | "apache_combined" | "nginx_combined";

export type AccessLogFormatId = BuiltInFormatId | `custom:${string}`;

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

export interface AccessLogParser {
  id: AccessLogFormatId;
  label: string;
  parse(line: string): AccessLogEntry | null;
}

export type FormatChoice = "auto" | AccessLogFormatId;
