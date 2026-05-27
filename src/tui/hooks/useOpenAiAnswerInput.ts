// Handles keyboard input when the OpenAI answer panel is open (scroll, close).
import type { RenderLine } from "../types.js";

/**
 * Subset of ink's Key object relevant to AI answer panel navigation.
 */
type Key = {
  upArrow?: boolean;
  downArrow?: boolean;
  escape?: boolean;
  backspace?: boolean;
  pageUp?: boolean;
  pageDown?: boolean;
};

function isPageUp(inputValue: string, key: Key): boolean {
  return Boolean(key.pageUp) || inputValue === "[5~";
}

function isPageDown(inputValue: string, key: Key): boolean {
  return Boolean(key.pageDown) || inputValue === "[6~";
}

/**
 * Handles keyboard input while the AI answer panel is visible.
 *
 * Key bindings:
 * - `q`                    — quit the app
 * - `b` | Escape | Backspace — close the answer panel (sets openAiAnswer to undefined, resets scroll)
 * - Up arrow               — scroll up one line
 * - Down arrow             — scroll down one line (clamped to content length)
 * - Page Up / `[5~`        — scroll up one page (answerRows lines)
 * - Page Down / `[6~`      — scroll down one page (clamped to content length)
 *
 * @param inputValue         Raw character value from ink's `useInput`.
 * @param key                Structured key flags from ink's `useInput`.
 * @param openAiAnswerLines  Full array of rendered lines in the answer panel (used for scroll clamping).
 * @param answerRows         Number of visible rows in the answer panel viewport.
 * @param exit               Callback to quit the application.
 * @param setOpenAiAnswer    Setter to clear the active AI answer (always called with `undefined` to close).
 * @param setOpenAiAnswerScroll Setter for the answer panel's vertical scroll offset.
 * @param setMessage         Setter for the TUI status/message bar text.
 */
export function handleOpenAiAnswerInput({
  inputValue,
  key,
  openAiAnswerLines,
  answerRows,
  exit,
  setOpenAiAnswer,
  setOpenAiAnswerScroll,
  setMessage
}: {
  inputValue: string;
  key: Key;
  openAiAnswerLines: RenderLine[];
  answerRows: number;
  exit: () => void;
  setOpenAiAnswer: (value: undefined) => void;
  setOpenAiAnswerScroll: (updaterOrValue: number | ((v: number) => number)) => void;
  setMessage: (value: string) => void;
}): void {
  if (inputValue === "q") {
    exit();
    return;
  }

  if (inputValue === "b" || key.escape || key.backspace) {
    setOpenAiAnswer(undefined);
    setOpenAiAnswerScroll(0);
    setMessage("Back to analysis");
    return;
  }

  if (key.upArrow) {
    setOpenAiAnswerScroll((value) => Math.max(0, value - 1));
    return;
  }

  if (key.downArrow) {
    setOpenAiAnswerScroll((value) =>
      Math.min(Math.max(0, openAiAnswerLines.length - answerRows), value + 1)
    );
    return;
  }

  if (isPageUp(inputValue, key)) {
    setOpenAiAnswerScroll((value) => Math.max(0, value - answerRows));
    return;
  }

  if (isPageDown(inputValue, key)) {
    setOpenAiAnswerScroll((value) =>
      Math.min(Math.max(0, openAiAnswerLines.length - answerRows), value + answerRows)
    );
  }
}
