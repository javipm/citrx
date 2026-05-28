// Handles keyboard input on the incident screen: line navigation, sort, filter, export, AI.
import type { Incident, IncidentLogLine } from "../../analysis/types.js";
import type { SortKey, SortDirection, PromptState } from "../types.js";
import { lineKey, toggleSelection } from "../utils/table.js";

/**
 * Subset of ink's Key object representing keys used by the incident screen.
 */
type Key = {
  upArrow?: boolean;
  downArrow?: boolean;
  return?: boolean;
  tab?: boolean;
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
 * Pure keyboard-dispatch function for the incident detail screen.
 *
 * Maps raw ink key/input events to state-setter calls. No return value;
 * all side-effects happen through the provided setters.
 *
 * Key bindings handled:
 * - `↑` / `↓`          — move cursor one line up/down.
 * - `PageUp` / `[5~`   — move cursor one page up.
 * - `PageDown` / `[6~` — move cursor one page down.
 * - `s` / `S`          — open sort menu.
 * - `Space`            — toggle selection on the focused line.
 * - `d` / `Enter`      — open line detail view.
 * - `t`                — switch to top-values screen scoped to incident.
 * - `A`                — select all visible lines.
 * - `r`                — reset filter and selection.
 * - `/` / `f` / `F`    — open filter prompt.
 * - `e`                — open the export format menu.
 * - `a`                — open AI prompt scoped to incident.
 *
 * @param inputValue  Raw character string from ink's `useInput`.
 * @param key         Structured key flags from ink's `useInput`.
 * @param incident    Currently displayed incident, or `undefined` if none.
 * @param lines       Filtered and sorted log lines currently visible.
 * @param selectedLines  Lines explicitly selected by the user (subset of `lines`).
 * @param lineIndex   Zero-based cursor position within `lines`.
 * @param pageSize    Number of lines per page, used for page-up/down jumps.
 * @param filter      Current filter string, forwarded to the filter prompt.
 * @param sortKey     Active sort column, forwarded to the sort menu.
 * @param sortDirection Active sort direction, forwarded to the sort menu.
 * @param runId       Run identifier carried by the caller for export context.
 * @param exportReady Whether all incident rows are loaded and export can run.
 * @param setLineIndex        Functional updater for the cursor position.
 * @param setFilter           Setter to clear or update the filter string.
 * @param setSelectedLineKeys Setter/updater for the set of selected line keys.
 * @param setDetailLine       Opens the detail panel for a log line.
 * @param setDetailScroll     Resets the detail panel scroll offset.
 * @param setSortMenu         Opens or closes the sort menu overlay.
 * @param setTopScope         Scopes the tops screen to `"incident"`.
 * @param setScreen           Navigates to the `"tops"` screen.
 * @param setPrompt           Opens the filter or AI prompt overlay.
 * @param setMessage          Updates the TUI status-bar message.
 * @param setExportMenu       Opens the export format menu.
 */
export function handleIncidentScreenInput({
  inputValue,
  key,
  incident,
  lines,
  selectedLines,
  lineIndex,
  pageSize,
  filter,
  sortKey,
  sortDirection,
  runId,
  exportReady,
  setLineIndex,
  setFilter,
  setSelectedLineKeys,
  setDetailLine,
  setDetailScroll,
  setSortMenu,
  setTopScope,
  setScreen,
  setPrompt,
  setExportMenu,
  setMessage
}: {
  inputValue: string;
  key: Key;
  incident: Incident | undefined;
  lines: IncidentLogLine[];
  selectedLines: IncidentLogLine[];
  lineIndex: number;
  pageSize: number;
  filter: string;
  sortKey: SortKey;
  sortDirection: SortDirection;
  runId: string;
  exportReady: boolean;
  setLineIndex: (updater: (value: number) => number) => void;
  setFilter: (value: string) => void;
  setSelectedLineKeys: (updaterOrValue: Set<string> | ((v: Set<string>) => Set<string>)) => void;
  setDetailLine: (line: IncidentLogLine | undefined) => void;
  setDetailScroll: (value: number) => void;
  setSortMenu: (
    value: { sortKey: SortKey; sortDirection: SortDirection; focus: "key" } | undefined
  ) => void;
  setTopScope: (scope: "incident") => void;
  setScreen: (screen: "tops") => void;
  setPrompt: (value: PromptState) => void;
  setExportMenu: (value: { format: "csv" | "json" | "tsv" }) => void;
  setMessage: (value: string) => void;
}): void {
  void runId;
  if (key.upArrow) {
    setLineIndex((value) => Math.max(0, value - 1));
    return;
  }

  if (key.downArrow) {
    setLineIndex((value) => Math.min(Math.max(0, lines.length - 1), value + 1));
    return;
  }

  if (isPageUp(inputValue, key)) {
    setLineIndex((value) => Math.max(0, value - pageSize));
    return;
  }

  if (isPageDown(inputValue, key)) {
    setLineIndex((value) => Math.min(Math.max(0, lines.length - 1), value + pageSize));
    return;
  }

  if (inputValue === "s" || inputValue === "S") {
    setSortMenu({ sortKey, sortDirection, focus: "key" });
    setMessage("Choose sort field and direction");
    return;
  }

  if (key.tab) {
    return;
  }

  if (inputValue === " ") {
    const line = lines[lineIndex];
    if (line) {
      setSelectedLineKeys((current) => toggleSelection(current, line));
    }
    return;
  }

  if (inputValue === "d" || key.return) {
    const line = lines[lineIndex];
    if (line) {
      setDetailLine(line);
      setDetailScroll(0);
    }
    return;
  }

  if (inputValue === "t") {
    setTopScope("incident");
    setScreen("tops");
    setMessage(`Top values for ${incident?.id ?? "incident"}`);
    return;
  }

  if (inputValue === "A") {
    setSelectedLineKeys(new Set(lines.map(lineKey)));
    setMessage(`Selected ${lines.length} visible lines`);
    return;
  }

  if (inputValue === "r") {
    setFilter("");
    setLineIndex(() => 0);
    setSelectedLineKeys(new Set());
    setMessage("Filter and selection reset");
    return;
  }

  if (inputValue === "/" || inputValue === "f" || inputValue === "F") {
    setPrompt({ kind: "filter", value: filter, cursor: filter.length });
    return;
  }

  if (inputValue === "e") {
    if (!exportReady) {
      setMessage("Still loading incident rows before export...");
      return;
    }

    setExportMenu({ format: "json" });
    setMessage(
      selectedLines.length > 0 ? "Choose export format for selected rows" : "Choose export format"
    );
    return;
  }

  if (inputValue === "a") {
    setPrompt({
      kind: "ai",
      value: "",
      cursor: 0,
      scope: "incident",
      incident,
      lines: selectedLines.length > 0 ? selectedLines : lines
    });
  }
}
