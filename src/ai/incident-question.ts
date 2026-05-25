import OpenAI from "openai";

import type { AnalyzeReport, Incident, IncidentLogLine } from "../analysis/types.js";

export interface AskIncidentQuestionInput {
  report: AnalyzeReport;
  incident: Incident;
  lines: IncidentLogLine[];
  question: string;
  env: NodeJS.ProcessEnv;
}

export interface AskIncidentQuestionResult {
  answer: string;
  model: string;
  sentLines: number;
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
    const lines = input.lines.slice(0, maxLines);
    const createResponse =
      this.createResponse ??
      ((body) => {
        const client = new OpenAI({ apiKey });
        return client.responses.create(body);
      });
    const response = await createResponse({
      model,
      instructions:
        "You are a web security analyst. Analyze only the provided citrx incident context. " +
        "Return concise, actionable guidance with evidence, WAF ideas, cautions, and next checks.",
      input: JSON.stringify(
        {
          question: input.question,
          summary: input.report.summary,
          topIps: input.report.topIps,
          topPaths: input.report.topPaths,
          incident: input.incident,
          lines
        },
        null,
        2
      )
    });

    return {
      answer: response.output_text,
      model,
      sentLines: lines.length
    };
  }
}

export function parseMaxLines(value: string | undefined): number {
  const parsed = Number.parseInt(value ?? "200", 10);

  if (!Number.isInteger(parsed) || parsed < 1) {
    return 200;
  }

  return parsed;
}
