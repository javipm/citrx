import OpenAI from "openai";

import type { AnalyzeReport, Incident, IncidentLogLine, TopItem } from "../analysis/types.js";

export interface AskIncidentQuestionInput {
  report: AnalyzeReport;
  incident?: Incident;
  lines: IncidentLogLine[];
  question: string;
  env: NodeJS.ProcessEnv;
  scope?: "summary" | "incident";
}

export interface AskIncidentQuestionResult {
  answer: string;
  model: string;
  sentLines: number;
  sentChars: number;
}

export interface IncidentQuestionClient {
  ask(input: AskIncidentQuestionInput): Promise<AskIncidentQuestionResult>;
}

type ResponseCreate = (body: {
  model: string;
  instructions: string;
  input: string;
}) => Promise<{ output_text: string }>;

export class OpenAiIncidentQuestionClient implements IncidentQuestionClient {
  constructor(private readonly createResponse?: ResponseCreate) {}

  async ask(input: AskIncidentQuestionInput): Promise<AskIncidentQuestionResult> {
    const apiKey = input.env.OPENAI_API_KEY;

    if (!apiKey) {
      throw new Error("OPENAI_API_KEY is required to ask OpenAI about an incident.");
    }

    const model = input.env.CITRX_OPENAI_MODEL ?? "gpt-5-mini";
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

export function parseMaxLines(value: string | undefined): number {
  const parsed = Number.parseInt(value ?? "200", 10);

  if (!Number.isInteger(parsed) || parsed < 1) {
    return 200;
  }

  return parsed;
}

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
