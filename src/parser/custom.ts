import { readFile } from "node:fs/promises";
import { z, ZodError } from "zod";

import { buildAccessLogEntry } from "./shared.js";
import type { AccessLogFormatId, AccessLogParser } from "./types.js";

const namedGroupName = z
  .string()
  .min(1)
  .regex(/^[A-Za-z_][A-Za-z0-9_]*$/, {
    message: "Field mappings must be named group names, not numeric capture indices."
  });

const customFormatSchema = z.object({
  formats: z
    .array(
      z
        .object({
          name: z
            .string()
            .min(1)
            .regex(/^[a-zA-Z0-9_-]+$/),
          label: z.string().min(1).optional(),
          pattern: z.string().min(1),
          fields: z.object({
            ip: namedGroupName,
            timestamp: namedGroupName,
            method: namedGroupName.optional(),
            target: namedGroupName.optional(),
            protocol: namedGroupName.optional(),
            request: namedGroupName.optional(),
            status: namedGroupName,
            bytes: namedGroupName.optional(),
            referer: namedGroupName.optional(),
            userAgent: namedGroupName.optional(),
            host: namedGroupName.optional(),
            requestTime: namedGroupName.optional(),
            upstreamTime: namedGroupName.optional(),
            forwardedFor: namedGroupName.optional()
          })
        })
        .superRefine((format, context) => {
          const hasRequest = Boolean(format.fields.request);
          const hasRequestParts = Boolean(
            format.fields.method && format.fields.target && format.fields.protocol
          );

          if (!hasRequest && !hasRequestParts) {
            context.addIssue({
              code: "custom",
              path: ["fields"],
              message:
                "Custom format must define either fields.request or fields.method + fields.target + fields.protocol."
            });
          }

          const patternIssue = validateCustomPattern(format.pattern, format.fields);
          if (patternIssue) {
            context.addIssue({
              code: "custom",
              path: ["pattern"],
              message: patternIssue
            });
          }
        })
    )
    .min(1)
    .superRefine((formats, context) => {
      const seen = new Set<string>();

      for (const [index, format] of formats.entries()) {
        if (seen.has(format.name)) {
          context.addIssue({
            code: "custom",
            path: [index, "name"],
            message: `duplicate format name "${format.name}". Each format name must be unique.`
          });
        }
        seen.add(format.name);
      }
    })
});

type CustomFormatConfig = z.infer<typeof customFormatSchema>["formats"][number];

export async function loadCustomParsers(configPath?: string): Promise<AccessLogParser[]> {
  if (!configPath) {
    return [];
  }

  const raw = await readFile(configPath, "utf8");
  const parsed = customFormatSchema.safeParse(parseJsonConfig(raw, configPath));

  if (!parsed.success) {
    throw new Error(formatCustomConfigError(parsed.error, configPath));
  }

  const config = parsed.data;

  return config.formats.map((format): AccessLogParser => {
    const pattern = new RegExp(format.pattern);
    const id: AccessLogFormatId = `custom:${format.name}`;

    return {
      id,
      label: format.label ?? format.name,
      parse(line) {
        const match = pattern.exec(line);

        if (!match?.groups) {
          return null;
        }

        return buildAccessLogEntry({
          ip: valueFor(match.groups, format.fields.ip),
          timestamp: valueFor(match.groups, format.fields.timestamp),
          method: optionalValueFor(match.groups, format.fields.method),
          target: optionalValueFor(match.groups, format.fields.target),
          protocol: optionalValueFor(match.groups, format.fields.protocol),
          request: optionalValueFor(match.groups, format.fields.request),
          status: valueFor(match.groups, format.fields.status),
          bytes: optionalValueFor(match.groups, format.fields.bytes),
          referer: optionalValueFor(match.groups, format.fields.referer),
          userAgent: optionalValueFor(match.groups, format.fields.userAgent),
          host: optionalValueFor(match.groups, format.fields.host),
          requestTime: optionalValueFor(match.groups, format.fields.requestTime),
          upstreamTime: optionalValueFor(match.groups, format.fields.upstreamTime),
          forwardedFor: optionalValueFor(match.groups, format.fields.forwardedFor)
        });
      }
    };
  });
}

export function formatCustomConfigError(error: unknown, configPath: string): string {
  if (error instanceof ZodError) {
    const details = error.issues
      .map((issue) => {
        const path = issue.path.length > 0 ? issue.path.join(".") : "(root)";
        return `${path}: ${issue.message}`;
      })
      .join("; ");
    return `Invalid custom format config ${configPath}: ${details}`;
  }

  return error instanceof Error ? error.message : String(error);
}

function parseJsonConfig(raw: string, configPath: string): unknown {
  try {
    return JSON.parse(raw);
  } catch (error) {
    const detail = error instanceof SyntaxError ? error.message : String(error);
    throw new Error(
      `Invalid JSON in custom format config ${configPath}: ${detail}. ` +
        `Expected { "formats": [ { "name", "pattern", "fields" } ] }.`
    );
  }
}

function validateCustomPattern(
  pattern: string,
  fields: CustomFormatConfig["fields"]
): string | undefined {
  if (!pattern.startsWith("^") || !endsWithUnescaped(pattern, "$")) {
    return "pattern must be anchored with ^ at the start and $ at the end so it cannot match a substring of an unrelated line.";
  }

  let compiled: RegExp;
  try {
    compiled = new RegExp(pattern);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return `invalid regex: ${detail}. Fix the pattern or escape special characters.`;
  }

  if (compiled.global || compiled.sticky) {
    return "pattern must not use global or sticky flags; citrx compiles one match per line.";
  }

  if (hasTopLevelAlternation(pattern)) {
    return "pattern has top-level alternation, so ^ and $ do not anchor every alternative (for example ^foo|evil$). Wrap the body in (?:...) or split into separate formats.";
  }

  if (hasNestedQuantifiers(pattern) || hasQuantifiedAlternation(pattern)) {
    return "pattern contains nested quantifiers or quantified overlapping alternation that can cause catastrophic backtracking (for example (.+)+ or (a|aa)+). Simplify the regex.";
  }

  if (/\.\*.*\.\*/.test(pattern) || /\\S\*\\S\*/.test(pattern)) {
    return "pattern is ambiguous (multiple unbounded wildcards). Use tighter character classes such as [^ ] or [^|].";
  }

  const namedGroups = extractNamedGroups(pattern);
  if (namedGroups.size === 0) {
    return "pattern must use named groups such as (?<ip>...). Numeric capture groups are not accepted as field mappings.";
  }

  const referenced = Object.values(fields).filter((value): value is string => Boolean(value));
  for (const field of referenced) {
    if (!namedGroups.has(field)) {
      const found = [...namedGroups].join(", ");
      return `fields reference named group "${field}", but the pattern has no (?<${field}>...). Named groups found: ${found}.`;
    }
  }

  return undefined;
}

function extractNamedGroups(pattern: string): Set<string> {
  const names = new Set<string>();
  const named = /\(\?<([A-Za-z_][A-Za-z0-9_]*)>/g;
  let match = named.exec(pattern);

  while (match) {
    names.add(match[1] ?? "");
    match = named.exec(pattern);
  }

  return names;
}

function hasNestedQuantifiers(pattern: string): boolean {
  const groupStarts: number[] = [];
  let inClass = false;

  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];

    if (char === "\\") {
      index += 1;
      continue;
    }

    if (inClass) {
      if (char === "]") {
        inClass = false;
      }
      continue;
    }

    if (char === "[") {
      inClass = true;
      continue;
    }

    if (char === "(") {
      groupStarts.push(index + 1);
      continue;
    }

    if (char === ")" && groupStarts.length > 0) {
      const body = pattern.slice(groupStarts.pop(), index);
      if (
        index + 1 < pattern.length &&
        isQuantifierStart(pattern, index + 1) &&
        groupBodyHasQuantifier(body)
      ) {
        return true;
      }
    }
  }

  return false;
}

function groupBodyHasQuantifier(body: string): boolean {
  let index = 0;

  if (body.startsWith("?<")) {
    const end = body.indexOf(">");
    if (end !== -1) {
      index = end + 1;
    }
  } else if (body.startsWith("?:") || body.startsWith("?=") || body.startsWith("?!")) {
    index = 2;
  }

  let inClass = false;

  for (; index < body.length; index += 1) {
    const char = body[index];

    if (char === "\\") {
      index += 1;
      continue;
    }

    if (inClass) {
      if (char === "]") {
        inClass = false;
      }
      continue;
    }

    if (char === "[") {
      inClass = true;
      continue;
    }

    if (isQuantifierStart(body, index)) {
      if (char === "{") {
        if (/^\{\d+(?:,\d*)?\}/.test(body.slice(index))) {
          return true;
        }
        continue;
      }

      return true;
    }
  }

  return false;
}

function isQuantifierStart(pattern: string, index: number): boolean {
  const char = pattern[index];
  return char === "+" || char === "*" || char === "?" || char === "{";
}

function endsWithUnescaped(pattern: string, char: string): boolean {
  if (!pattern.endsWith(char)) {
    return false;
  }

  let slashes = 0;
  for (let index = pattern.length - 2; index >= 0 && pattern[index] === "\\"; index -= 1) {
    slashes += 1;
  }

  return slashes % 2 === 0;
}

function hasQuantifiedAlternation(pattern: string): boolean {
  return /\((?:\?<[^>]+>)?[^)]*\|[^)]*\)[+*{]/.test(pattern);
}

function hasTopLevelAlternation(pattern: string): boolean {
  let body = pattern;
  if (body.startsWith("^")) {
    body = body.slice(1);
  }
  if (endsWithUnescaped(body, "$")) {
    body = body.slice(0, -1);
  }

  let depth = 0;
  let inClass = false;

  for (let index = 0; index < body.length; index += 1) {
    const char = body[index];

    if (char === "\\") {
      index += 1;
      continue;
    }

    if (inClass) {
      if (char === "]") {
        inClass = false;
      }
      continue;
    }

    if (char === "[") {
      inClass = true;
      continue;
    }

    if (char === "(") {
      depth += 1;
      continue;
    }

    if (char === ")" && depth > 0) {
      depth -= 1;
      continue;
    }

    if (char === "|" && depth === 0) {
      return true;
    }
  }

  return false;
}

function valueFor(groups: Record<string, string>, field: string): string {
  return groups[field] ?? "";
}

function optionalValueFor(
  groups: Record<string, string>,
  field: string | undefined
): string | undefined {
  return field ? groups[field] : undefined;
}
