// Handles keyboard input when a request detail line is open (scroll, close).
import type { IncidentLogLine } from "../../analysis/types.js";
import type { Screen } from "../types.js";

/**
 * Subset of ink's Key object relevant to detail-view navigation.
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
 * Handles keyboard input while the request detail panel is visible.
 *
 * Key bindings:
 * - `q`                    — quit the app
 * - `d` | `b` | Escape | Backspace — close the detail panel (sets detailLine to undefined, resets scroll)
 * - Up arrow               — scroll up one line
 * - Down arrow             — scroll down one line (clamped to content length)
 * - Page Up / `[5~`        — scroll up one page (detailRows lines)
 * - Page Down / `[6~`      — scroll down one page (clamped to content length)
 *
 * @param inputValue  Raw character value from ink's `useInput`.
 * @param key         Structured key flags from ink's `useInput`.
 * @param screen      Current screen context; determines the "back" status message.
 * @param detailLines Full array of rendered lines in the detail panel (used for scroll clamping).
 * @param detailRows  Number of visible rows in the detail panel viewport.
 * @param exit        Callback to quit the application.
 * @param setDetailLine   Setter to clear the active detail line (pass `undefined` to close).
 * @param setDetailScroll Setter for the detail panel's vertical scroll offset.
 * @param setMessage      Setter for the TUI status/message bar text.
 */
export function handleDetailViewInput({
  inputValue,
  key,
  screen,
  detailLines,
  detailRows,
  exit,
  setDetailLine,
  setDetailScroll,
  setMessage
}: {
  inputValue: string;
  key: Key;
  screen: Screen;
  detailLines: string[];
  detailRows: number;
  exit: () => void;
  setDetailLine: (line: IncidentLogLine | undefined) => void;
  setDetailScroll: (updaterOrValue: number | ((v: number) => number)) => void;
  setMessage: (value: string) => void;
}): void {
  if (inputValue === "q") {
    exit();
    return;
  }

  if (inputValue === "d" || inputValue === "b" || key.escape || key.backspace) {
    setDetailLine(undefined);
    setDetailScroll(0);
    setMessage(screen === "summary" ? "Back to summary" : "Back to incident");
    return;
  }

  if (key.upArrow) {
    setDetailScroll((value) => Math.max(0, value - 1));
    return;
  }

  if (key.downArrow) {
    setDetailScroll((value) => Math.min(Math.max(0, detailLines.length - detailRows), value + 1));
    return;
  }

  if (isPageUp(inputValue, key)) {
    setDetailScroll((value) => Math.max(0, value - detailRows));
    return;
  }

  if (isPageDown(inputValue, key)) {
    setDetailScroll((value) => Math.min(Math.max(0, detailLines.length - detailRows), value + detailRows));
  }
}
