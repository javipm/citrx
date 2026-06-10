// Handles keyboard input in the filter prompt bar overlay.
import type { IncidentLogLine } from "../../analysis/types.js";
import type { PromptState } from "../types.js";
import { FILTER_PRESETS } from "../types.js";
import { validateAccessLogFilter } from "../filter.js";

function isPrintableInput(inputValue: string): boolean {
  return inputValue.length > 0 && !inputValue.startsWith("\x1b");
}

/**
 * Handles keyboard input for the prompt bar overlay.
 *
 * Supports the `"filter"` prompt, validating and applying an access-log filter
 * expression on Enter.
 *
 * Key bindings:
 * - `Escape`     — cancel prompt, clear overlay, show "Prompt cancelled" message.
 * - `Enter`      — confirm: validate+apply filter.
 * - `←` / `→`   — move cursor left / right within the input value.
 * - `Backspace`  — delete character before cursor.
 * - `Delete`     — delete character after cursor.
 * - Printable    — insert character at cursor position.
 * - Ctrl / ESC sequences — ignored.
 *
 * @param params.inputValue       - Raw character(s) received from the terminal.
 * @param params.key              - Parsed key flags from ink's `useInput`.
 * @param params.prompt           - Current prompt state (kind, value, cursor position).
 * @param params.setPrompt        - Setter to update or close the prompt overlay.
 * @param params.setFilter        - Setter to apply a validated filter string.
 * @param params.setLineIndex     - Setter to reset the selected line index to 0 after filter apply.
 * @param params.setSelectedLineKeys - Setter to clear the selection set after filter apply.
 * @param params.setMessage       - Setter to display a status message in the TUI.
 */
export function handlePromptInput({
  inputValue,
  key,
  prompt,
  setPrompt,
  setFilter,
  setLineIndex,
  setSelection,
  setMessage
}: {
  inputValue: string;
  key: {
    return?: boolean;
    escape?: boolean;
    backspace?: boolean;
    delete?: boolean;
    ctrl?: boolean;
    leftArrow?: boolean;
    rightArrow?: boolean;
    tab?: boolean;
  };
  prompt: PromptState;
  setPrompt: (value: PromptState | undefined) => void;
  setFilter: (value: string) => void;
  setLineIndex: (value: number) => void;
  setSelection: (value: Map<string, IncidentLogLine>) => void;
  setMessage: (value: string) => void;
}): void {
  if (key.tab) {
    const presets = FILTER_PRESETS as readonly string[];
    const currentIdx = presets.indexOf(prompt.value);
    const nextIdx = currentIdx === -1 ? 0 : (currentIdx + 1) % presets.length;
    const nextPreset = presets[nextIdx];
    setPrompt({ ...prompt, value: nextPreset, cursor: nextPreset.length });
    return;
  }

  if (key.escape) {
    setPrompt(undefined);
    setMessage("Prompt cancelled");
    return;
  }

  if (key.return) {
    const value = prompt.value.trim();

    const validation = validateAccessLogFilter(value);

    if (!validation.ok) {
      setMessage(`Invalid filter: ${validation.error}`);
      setPrompt(prompt);
      return;
    }

    setPrompt(undefined);
    setFilter(value);
    setLineIndex(0);
    setSelection(new Map());
    setMessage(value ? `Filter: ${value}` : "Filter cleared");
    return;
  }

  if (key.leftArrow) {
    setPrompt({ ...prompt, cursor: Math.max(0, prompt.cursor - 1) });
    return;
  }

  if (key.rightArrow) {
    setPrompt({ ...prompt, cursor: Math.min(prompt.value.length, prompt.cursor + 1) });
    return;
  }

  if (key.backspace) {
    if (prompt.cursor === 0) {
      return;
    }

    setPrompt({
      ...prompt,
      value: `${prompt.value.slice(0, prompt.cursor - 1)}${prompt.value.slice(prompt.cursor)}`,
      cursor: prompt.cursor - 1
    });
    return;
  }

  if (key.delete) {
    if (prompt.cursor >= prompt.value.length) {
      return;
    }

    setPrompt({
      ...prompt,
      value: `${prompt.value.slice(0, prompt.cursor)}${prompt.value.slice(prompt.cursor + 1)}`
    });
    return;
  }

  if (key.ctrl || !isPrintableInput(inputValue)) {
    return;
  }

  setPrompt({
    ...prompt,
    value: `${prompt.value.slice(0, prompt.cursor)}${inputValue}${prompt.value.slice(prompt.cursor)}`,
    cursor: prompt.cursor + inputValue.length
  });
}
