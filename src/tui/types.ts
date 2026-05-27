import type { IncidentLogLine, Incident } from "../analysis/types.js";
import type { IncidentQuestionClient } from "../ai/incident-question.js";
import type { Readable, Writable } from "node:stream";

/** I/O handles and optional AI client injected into the TUI at startup. */
export interface TuiRuntime {
  /** Process environment variables (used for feature flags and config). */
  env: NodeJS.ProcessEnv;
  /** Readable stream connected to the terminal input. */
  stdin: Readable;
  /** Writable stream for primary terminal output. */
  stdout: Writable;
  /** Writable stream for error / diagnostic output. */
  stderr: Writable;
  /** Optional AI client used to answer incident questions inline. */
  aiClient?: IncidentQuestionClient;
}

/** The top-level screen currently rendered in the TUI. */
export type Screen = "summary" | "incident" | "tops";

/** Which incident-kind tab is focused on the summary screen. */
export type SummaryFocus = "accesses" | "compromise" | "saturation" | "noise";

/** Whether the tops panel is showing report-level or incident-level data. */
export type TopScope = "summary" | "incident";

/** Which top-N panel is currently active in the tops screen. */
export type TopPanelKey = "ips" | "paths" | "userAgents" | "params" | "paramValues";

/** Column by which the access log table is currently sorted. */
export type SortKey = "timestamp" | "ip" | "status" | "method" | "path" | "bytes";

/** Direction of the current sort applied to the access log table. */
export type SortDirection = "asc" | "desc";

/** Which element of the sort menu is focused (key selector, direction toggle, or apply button). */
export type SortMenuFocus = "key" | "direction" | "apply";

/** Text input state shared by any prompt that accepts keyboard input. */
export interface PromptInputState {
  /** Current text entered by the user. */
  value: string;
  /** Caret position within `value` (0-based character index). */
  cursor: number;
}

/** State for an AI answer panel displaying a streamed or completed response. */
export interface OpenAiAnswerState {
  /** Heading displayed above the answer (usually the question text). */
  title: string;
  /** Secondary metadata line (model name, latency, token counts, etc.). */
  meta: string;
  /** The answer text, potentially still streaming in. */
  answer: string;
}

/** A single rendered terminal line with optional styling attributes. */
export interface RenderLine {
  /** Text content of the line. */
  text: string;
  /** Foreground color applied to the line, if any. */
  color?: "cyan" | "gray" | "yellow" | "green";
  /** Whether the line is rendered in bold. */
  bold?: boolean;
}

/**
 * Active prompt overlay shown over the TUI.
 * - `filter`: user is typing a log-line filter expression.
 * - `ai`: user is typing a question to send to the AI client.
 */
export type PromptState =
  | ({ kind: "filter" } & PromptInputState)
  | {
      kind: "ai";
      /** Whether the question is scoped to the full report or a single incident. */
      scope: "summary" | "incident";
      /** The incident in context when scope is "incident". */
      incident?: Incident;
      /** Log lines associated with the current incident, sent as context to the AI. */
      lines: IncidentLogLine[];
      /** Any additional context string appended to the AI prompt. */
      extraContext?: string;
    } & PromptInputState;

/** Pre-computed top-N insight lists derived from a single incident's matched log lines. */
export interface IncidentInsights {
  /** Top IPs involved in this incident. */
  ips: import("../analysis/types.js").TopItem[];
  /** Top paths targeted by this incident. */
  paths: import("../analysis/types.js").TopItem[];
  /** Top User-Agent strings seen in this incident's log lines. */
  userAgents: import("../analysis/types.js").TopItem[];
  /** Top query parameter names seen in this incident's log lines. */
  params: import("../analysis/types.js").TopItem[];
  /** Top query parameter values seen in this incident's log lines. */
  paramValues: import("../analysis/types.js").TopItem[];
}

/** Column widths (in terminal characters) for the access log table layout. */
export interface AccessTableColumns {
  /** Width of the selection/checkbox column. */
  sel: number;
  /** Width of the line-number column. */
  line: number;
  /** Width of the timestamp column. */
  time: number;
  /** Width of the IP address column. */
  ip: number;
  /** Width of the HTTP method column. */
  method: number;
  /** Width of the status code column. */
  status: number;
  /** Width of the response bytes column. */
  bytes: number;
  /** Width of the path column. */
  path: number;
  /** Width of the User-Agent column. */
  ua: number;
}

export const TOP_PANEL_KEYS: TopPanelKey[] = ["ips", "paths", "userAgents", "params", "paramValues"];
export const SORT_KEYS: SortKey[] = ["timestamp", "ip", "status", "method", "path", "bytes"];
export const SPINNER_FRAMES = ["-", "\\", "|", "/"];
