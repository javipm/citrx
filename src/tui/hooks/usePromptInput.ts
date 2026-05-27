// Handles keyboard input in the prompt bar overlay (filter input and AI query input).
import type { PromptState } from "../types.js";
import { validateAccessLogFilter } from "../filter.js";

function isPrintableInput(inputValue: string): boolean {
  return inputValue.length > 0 && !inputValue.startsWith("\x1b");
}

/**
 * Handles keyboard input for the prompt bar overlay.
 *
 * Supports two prompt kinds:
 * - `"filter"`: validates and applies an access-log filter expression on Enter.
 * - `"ai"`: submits the typed question to the AI panel on Enter.
 *
 * Key bindings:
 * - `Escape`     — cancel prompt, clear overlay, show "Prompt cancelled" message.
 * - `Enter`      — confirm: validate+apply filter or submit AI question.
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
 * @param params.submitAi         - Callback to submit the AI question with its prompt state.
 */
export function handlePromptInput({
  inputValue,
  key,
  prompt,
  setPrompt,
  setFilter,
  setLineIndex,
  setSelectedLineKeys,
  setMessage,
  submitAi
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
  };
  prompt: PromptState;
  setPrompt: (value: PromptState | undefined) => void;
  setFilter: (value: string) => void;
  setLineIndex: (value: number) => void;
  setSelectedLineKeys: (value: Set<string>) => void;
  setMessage: (value: string) => void;
  submitAi: (question: string, state: Extract<PromptState, { kind: "ai" }>) => void;
}): void {
  if (key.escape) {
    setPrompt(undefined);
    setMessage("Prompt cancelled");
    return;
  }

  if (key.return) {
    const value = prompt.value.trim();

    if (prompt.kind === "filter") {
      const validation = validateAccessLogFilter(value);

      if (!validation.ok) {
        setMessage(`Invalid filter: ${validation.error}`);
        setPrompt(prompt);
        return;
      }

      setPrompt(undefined);
      setFilter(value);
      setLineIndex(0);
      setSelectedLineKeys(new Set());
      setMessage(value ? `Filter: ${value}` : "Filter cleared");
      return;
    }

    setPrompt(undefined);

    if (value) {
      submitAi(value, prompt);
    }
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
