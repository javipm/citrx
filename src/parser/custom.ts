import { readFile } from "node:fs/promises";
import { z } from "zod";

import { buildAccessLogEntry } from "./shared.js";
import type { AccessLogFormatId, AccessLogParser } from "./types.js";

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
            ip: z.string().min(1),
            timestamp: z.string().min(1),
            method: z.string().min(1).optional(),
            target: z.string().min(1).optional(),
            protocol: z.string().min(1).optional(),
            request: z.string().min(1).optional(),
            status: z.string().min(1),
            bytes: z.string().min(1).optional(),
            referer: z.string().min(1).optional(),
            userAgent: z.string().min(1).optional()
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
        })
    )
    .min(1)
});

export async function loadCustomParsers(configPath?: string): Promise<AccessLogParser[]> {
  if (!configPath) {
    return [];
  }

  const raw = await readFile(configPath, "utf8");
  const config = customFormatSchema.parse(JSON.parse(raw));

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
          userAgent: optionalValueFor(match.groups, format.fields.userAgent)
        });
      }
    };
  });
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
