import OpenAI from "openai";

import type { AnalyzeReport, Incident, IncidentLogLine, TopItem } from "../analysis/types.js";

/** Input parameters for asking an AI question about an incident or report. */
export interface AskIncidentQuestionInput {
  /** Full analysis report providing summary, stats, and incident list. */
  report: AnalyzeReport;
  /** Specific incident to focus on; omit for a report-level question. */
  incident?: Incident;
  /** Log lines associated with the report or incident. */
  lines: IncidentLogLine[];
  /** The question to send to the AI. */
  question: string;
  /** Process environment supplying API keys and config vars. */
  env: NodeJS.ProcessEnv;
  /** Whether the question targets the overall summary or a single incident. Defaults to "incident" when `incident` is set, otherwise "summary". */
  scope?: "summary" | "incident";
}

/** Result returned after the AI answers an incident question. */
export interface AskIncidentQuestionResult {
  /** The AI-generated answer text. */
  answer: string;
  /** OpenAI model name used for the request. */
  model: string;
  /** Number of log lines included in the payload sent to the AI. */
  sentLines: number;
  /** Total character count of the payload sent to the AI. */
  sentChars: number;
}

/** Contract for a client that can answer questions about incidents using AI. */
export interface IncidentQuestionClient {
  ask(input: AskIncidentQuestionInput): Promise<AskIncidentQuestionResult>;
}

type ResponseCreate = (body: {
  model: string;
  instructions: string;
  input: string;
}) => Promise<{ output_text: string }>;

/**
 * OpenAI-backed implementation of {@link IncidentQuestionClient}.
 *
 * Reads `OPENAI_API_KEY` from `input.env`. Optionally accepts a custom
 * `createResponse` factory (useful for testing without hitting the API).
 *
 * Env vars consumed:
 * - `OPENAI_API_KEY` — required; the OpenAI secret key.
 * - `CITRX_OPENAI_MODEL` — model to use (default: `gpt-5.4-mini`).
 * - `CITRX_AI_MAX_LINES` — max log lines to include (default: 200).
 * - `CITRX_AI_MAX_CHARS` — max payload character budget (default: 60 000).
 */
export class OpenAiIncidentQuestionClient implements IncidentQuestionClient {
  constructor(private readonly createResponse?: ResponseCreate) {}

  async ask(input: AskIncidentQuestionInput): Promise<AskIncidentQuestionResult> {
    const apiKey = input.env.OPENAI_API_KEY;

    if (!apiKey) {
      throw new Error("OPENAI_API_KEY is required to ask OpenAI about an incident.");
    }

    const model = input.env.CITRX_OPENAI_MODEL ?? "gpt-5.4-mini";
    const maxLines = parseMaxLines(input.env.CITRX_AI_MAX_LINES);
    const maxChars = parseMaxChars(input.env.CITRX_AI_MAX_CHARS);
    const context = buildAiContext(input, maxLines, maxChars);
    const createResponse =
      this.createResponse ??
      ((body) => {
        const client = new OpenAI({ apiKey });
        return client.responses.create(body);
      });
    const response = await createResponse({
      model,
      instructions:
        "You are a web security analyst. Analyze only the compact citrx access-log context. " +
        "Return concise, actionable guidance with evidence, WAF ideas, cautions, and next checks. " +
        "Do not invent ASN, country, or owner data unless it is present in the context.",
      input: context.payload
    });

    return {
      answer: response.output_text,
      model,
      sentLines: context.sentLines,
      sentChars: context.payload.length
    };
  }
}

/**
 * Serializes the report, incident, and log lines from `input` into a compact
 * JSON string suitable for sending to the OpenAI responses API.
 *
 * Log lines are pipe-delimited and user-agents are pooled into a reference map
 * to reduce token usage. If the resulting payload exceeds `maxChars` it is
 * progressively shrunk: lines are trimmed first, then optional fields
 * (`ipBehavior`, `time`) are dropped.
 *
 * @param input - The question input containing report data and log lines.
 * @param maxLines - Maximum number of log lines to include before truncating. Defaults to `CITRX_AI_MAX_LINES` or 200.
 * @param maxChars - Character budget for the final payload. Defaults to `CITRX_AI_MAX_CHARS` or 60 000.
 * @returns The serialized payload string and the number of log lines it contains.
 */
export function buildAiContext(
  input: AskIncidentQuestionInput,
  maxLines = parseMaxLines(input.env.CITRX_AI_MAX_LINES),
  maxChars = parseMaxChars(input.env.CITRX_AI_MAX_CHARS)
): { payload: string; sentLines: number } {
  const lines = input.lines.slice(0, maxLines);
  const userAgents = new Map<string, string>();
  const compactLines = lines.map((line) => {
    const uaRef = line.userAgent ? userAgentRef(userAgents, line.userAgent) : "-";
    return [
      line.lineNumber,
      compactTime(line.timestamp),
      line.ip,
      line.method,
      line.status,
      line.bytes ?? "-",
      compactPath(line.target || line.path),
      uaRef
    ].join("|");
  });
  const context = {
    question: input.question,
    scope: input.scope ?? (input.incident ? "incident" : "summary"),
    summary: input.report.summary,
    time: input.report.timeStats,
    ipBehavior: input.report.ipBehaviorStats.slice(0, 12),
    aiBots: input.report.aiBotStats.slice(0, 12),
    inputs: input.report.inputs,
    formats: input.report.inputFormats.map((item) => item.format),
    top: {
      ips: compactTop(input.report.topIps),
      paths: compactTop(input.report.topPaths),
      methods: compactTop(input.report.topMethods),
      statuses: compactTop(input.report.topStatuses)
    },
    incidents: input.report.incidents.slice(0, 12).map(compactIncident),
    incident: input.incident ? compactIncident(input.incident) : undefined,
    lines: compactLines,
    userAgents: Object.fromEntries(userAgents)
  };
  let payload = JSON.stringify(context);

  if (payload.length > maxChars) {
    payload = shrinkContextForBudget(context, compactLines, maxChars);
  }

  return {
    payload,
    sentLines: JSON.parse(payload).lines?.length ?? 0
  };
}

function shrinkContextForBudget(
  context: Record<string, unknown> & { lines: string[] },
  lines: string[],
  maxChars: number
): string {
  let keptLines = shrinkLinesForBudget(lines, JSON.stringify(context).length, maxChars);
  let payload = JSON.stringify({ ...context, lines: keptLines });

  while (payload.length > maxChars && keptLines.length > 1) {
    keptLines = keptLines.slice(0, Math.max(1, Math.floor(keptLines.length * 0.75)));
    payload = JSON.stringify({ ...context, lines: keptLines });
  }

  if (payload.length <= maxChars) {
    return payload;
  }

  payload = JSON.stringify({ ...context, ipBehavior: [], lines: keptLines });

  if (payload.length <= maxChars) {
    return payload;
  }

  return JSON.stringify({ ...context, time: undefined, ipBehavior: [], lines: keptLines });
}

/**
 * Parses the `CITRX_AI_MAX_LINES` env var string into a positive integer.
 * Returns 200 if the value is missing, non-numeric, or less than 1.
 */
export function parseMaxLines(value: string | undefined): number {
  const parsed = Number.parseInt(value ?? "200", 10);

  if (!Number.isInteger(parsed) || parsed < 1) {
    return 200;
  }

  return parsed;
}

/**
 * Parses the `CITRX_AI_MAX_CHARS` env var string into a positive integer.
 * Returns 60 000 if the value is missing, non-numeric, or less than 1 000.
 */
export function parseMaxChars(value: string | undefined): number {
  const parsed = Number.parseInt(value ?? "60000", 10);

  if (!Number.isInteger(parsed) || parsed < 1000) {
    return 60000;
  }

  return parsed;
}

function compactTop(items: TopItem[]): string[] {
  return items.slice(0, 12).map((item) => `${item.value}:${item.count}`);
}

function compactIncident(incident: Incident): Record<string, unknown> {
  return {
    id: incident.id,
    cat: incident.category,
    sev: incident.severity,
    score: incident.score,
    title: incident.title,
    evidence: incident.evidence.map((item) => `${item.key}=${item.value}`)
  };
}

function userAgentRef(userAgents: Map<string, string>, userAgent: string): string {
  for (const [ref, value] of userAgents) {
    if (value === userAgent) {
      return ref;
    }
  }

  const ref = `ua${userAgents.size + 1}`;
  userAgents.set(ref, truncate(userAgent, 120));
  return ref;
}

function compactTime(timestamp: string): string {
  const match = timestamp.match(/:(\d{2}:\d{2}:\d{2})/);
  return match?.[1] ?? timestamp;
}

function compactPath(path: string): string {
  return truncate(path, 180);
}

function shrinkLinesForBudget(lines: string[], currentChars: number, maxChars: number): string[] {
  if (currentChars <= maxChars) {
    return lines;
  }

  const ratio = Math.max(0.05, maxChars / currentChars);
  return lines.slice(0, Math.max(1, Math.floor(lines.length * ratio)));
}

function truncate(value: string, length: number): string {
  return value.length <= length ? value : `${value.slice(0, length - 1)}…`;
}
