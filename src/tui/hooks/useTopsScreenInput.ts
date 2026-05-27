// Handles keyboard input on the top values screen: panel navigation, drill-down to AI.
import type { Incident } from "../../analysis/types.js";
import type { AnalyzeReport } from "../../analysis/types.js";
import type { TopScope, TopPanelKey, PromptState } from "../types.js";
import { nextTopPanel, currentTopContext } from "../screens/tops.js";

/** Subset of ink's Key shape used by this handler. */
type Key = {
  upArrow?: boolean;
  downArrow?: boolean;
  tab?: boolean;
};

/**
 * Processes a single keypress on the "top values" screen.
 *
 * Mapping:
 * - Tab        → move focus to the next panel
 * - Up / Down  → scroll the selected-index of the focused panel (clamped 0–9)
 * - "t"        → navigate back to summary or incident screen
 * - "a"        → open the AI prompt pre-loaded with the current top-panel context
 *
 * @param inputValue  - Raw character string produced by ink's `useInput`.
 * @param key         - Modifier/arrow flags from ink's `useInput`.
 * @param run         - The active analysis run containing the full report.
 * @param incident    - Currently selected incident, or `undefined` when scope is summary.
 * @param topScope    - Whether the tops screen was opened from a summary or incident context.
 * @param topFocus    - Which panel (column) currently has keyboard focus.
 * @param topIndexes  - Per-panel selected-row indexes.
 * @param filter      - Active log-line filter string (forwarded to context builder).
 * @param setTopFocus    - State setter for `topFocus`.
 * @param setTopIndexes  - State setter for `topIndexes`.
 * @param setScreen      - Navigates back to `"summary"` or `"incident"`.
 * @param setPrompt      - Opens the AI prompt with pre-populated context.
 * @param setMessage     - Displays a transient status message in the UI.
 */
export function handleTopsScreenInput({
  inputValue,
  key,
  run,
  incident,
  topScope,
  topFocus,
  topIndexes,
  filter,
  setTopFocus,
  setTopIndexes,
  setScreen,
  setPrompt,
  setMessage
}: {
  inputValue: string;
  key: Key;
  run: { report: AnalyzeReport };
  incident: Incident | undefined;
  topScope: TopScope;
  topFocus: TopPanelKey;
  topIndexes: Record<TopPanelKey, number>;
  filter: string;
  setTopFocus: (updater: (value: TopPanelKey) => TopPanelKey) => void;
  setTopIndexes: (
    updater: (value: Record<TopPanelKey, number>) => Record<TopPanelKey, number>
  ) => void;
  setScreen: (screen: "summary" | "incident") => void;
  setPrompt: (value: PromptState) => void;
  setMessage: (value: string) => void;
}): void {
  if (key.tab) {
    setTopFocus((value) => nextTopPanel(value));
    return;
  }

  if (key.upArrow) {
    setTopIndexes((value) => ({
      ...value,
      [topFocus]: Math.max(0, value[topFocus] - 1)
    }));
    return;
  }

  if (key.downArrow) {
    setTopIndexes((value) => ({
      ...value,
      [topFocus]: Math.min(9, value[topFocus] + 1)
    }));
    return;
  }

  if (inputValue === "t") {
    setScreen(topScope === "summary" ? "summary" : "incident");
    setMessage(topScope === "summary" ? "Back to summary" : "Back to incident");
    return;
  }

  if (inputValue === "a") {
    const topContext = currentTopContext(
      run.report,
      topScope,
      incident,
      filter,
      topFocus,
      topIndexes
    );
    setPrompt({
      kind: "ai",
      value: "",
      cursor: 0,
      scope: topScope === "summary" ? "summary" : "incident",
      incident: topScope === "summary" ? undefined : incident,
      lines: [],
      extraContext: topContext
    });
  }
}
