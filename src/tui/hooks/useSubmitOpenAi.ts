import { OpenAiIncidentQuestionClient } from "../../ai/incident-question.js";
import type { Incident, IncidentLogLine } from "../../analysis/types.js";
import type { CitrxRun } from "../../run/types.js";
import type { TuiRuntime, OpenAiAnswerState } from "../types.js";

/**
 * Sends a natural-language question about an incident or run summary to the
 * configured AI client and writes the result into TUI state.
 *
 * Side effects (in order):
 * 1. Calls `setBusy(true)` before the request and `setBusy(false)` in the
 *    `finally` block, regardless of outcome.
 * 2. On success: populates `setOpenAiAnswer` with title, model metadata, and
 *    the answer text, resets the answer panel scroll to 0, and sets the status
 *    message to `"OpenAI answer ready"`.
 * 3. On error: passes the error message string to `setMessage`; answer state
 *    is left unchanged.
 *
 * Falls back to a fresh `OpenAiIncidentQuestionClient` when
 * `runtime.aiClient` is not provided (useful for testing via dependency
 * injection).
 *
 * @param run - The current citrx run containing the analysis report.
 * @param runtime - TUI runtime context (env vars, optional AI client override).
 * @param scope - `"summary"` to ask about the whole run; `"incident"` to focus
 *   on a specific incident.
 * @param incident - The incident to analyse. Required when `scope` is
 *   `"incident"`; ignored for `"summary"`.
 * @param lines - Log lines to include as context for the AI prompt.
 * @param question - The user's question string.
 * @param setBusy - State setter; toggled to `true` during the request.
 * @param setMessage - State setter for the TUI status/error message bar.
 * @param setOpenAiAnswer - State setter that receives the structured AI answer,
 *   or `undefined` to clear it.
 * @param setOpenAiAnswerScroll - State setter that resets the answer panel
 *   scroll position to 0 on success.
 * @returns A `Promise` that resolves when the request and all state updates
 *   are complete. Always resolves (errors are surfaced via `setMessage`).
 */
export async function submitOpenAi({
  run,
  runtime,
  scope,
  incident,
  lines,
  question,
  setBusy,
  setMessage,
  setOpenAiAnswer,
  setOpenAiAnswerScroll
}: {
  run: CitrxRun;
  runtime: TuiRuntime;
  scope: "summary" | "incident";
  incident?: Incident;
  lines: IncidentLogLine[];
  question: string;
  setBusy: (value: boolean) => void;
  setMessage: (value: string) => void;
  setOpenAiAnswer: (value: OpenAiAnswerState | undefined) => void;
  setOpenAiAnswerScroll: (value: number) => void;
}): Promise<void> {
  setBusy(true);
  try {
    const client = runtime.aiClient ?? new OpenAiIncidentQuestionClient();
    const result = await client.ask({
      report: run.report,
      incident,
      lines,
      question,
      env: runtime.env,
      scope
    });
    setOpenAiAnswer({
      title: scope === "summary" ? "OpenAI analysis" : `OpenAI incident analysis`,
      meta: `${result.model} | sent ${result.sentLines} lines | ${result.sentChars} chars`,
      answer: result.answer
    });
    setOpenAiAnswerScroll(0);
    setMessage("OpenAI answer ready");
  } catch (error) {
    setMessage(error instanceof Error ? error.message : String(error));
  } finally {
    setBusy(false);
  }
}
