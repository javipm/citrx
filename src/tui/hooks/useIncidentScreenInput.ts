// Handles keyboard input on the incident screen: line navigation, sort, filter, export.
import type { Incident, IncidentLogLine } from "../../analysis/types.js";
import type { SortKey, SortDirection, PromptState } from "../types.js";
import { lineKey } from "../utils/table.js";
import {
  addLinesToSelectionWithCap,
  INCIDENT_MANUAL_SELECT_LIMIT,
  INCIDENT_SELECT_ALL_LIMIT
} from "../utils/selection.js";

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
  escape?: boolean;
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
 * - `Esc`              — go back (activeAbort handled by caller before this fires).
 * - `s` / `S`          — open sort menu.
 * - `Space`            — toggle selection on the focused line.
 * - `d` / `Enter`      — open line detail view.
 * - `t`                — switch to top-values screen scoped to incident.
 * - `A`                — select all: page-only above INCIDENT_SELECT_ALL_LIMIT, async full below.
 * - `r`                — reset filter and selection.
 * - `/` / `f` / `F`    — open filter prompt.
 * - `e`                — open the export format menu.
 */
export function handleIncidentScreenInput({
  inputValue,
  key,
  incident,
  total,
  pageLines,
  pageStart,
  pageLoading,
  selectedLines,
  lineIndex,
  pageSize,
  filter,
  sortKey,
  sortDirection,
  setLineIndex,
  setFilter,
  setSelection,
  setDetailLine,
  setDetailScroll,
  setSortMenu,
  setTopScope,
  setScreen,
  setPrompt,
  setExportMenu,
  setMessage,
  onSelectAll
}: {
  inputValue: string;
  key: Key;
  incident: Incident | undefined;
  /** Total filtered lines for the incident (from useIncidentQuery). */
  total: number;
  /** Currently rendered page of log lines. */
  pageLines: IncidentLogLine[];
  /** Absolute offset of the first line in pageLines. */
  pageStart: number;
  /** True while the bucket for the current cursor position is loading. */
  pageLoading: boolean;
  selectedLines: IncidentLogLine[];
  lineIndex: number;
  pageSize: number;
  filter: string;
  sortKey: SortKey;
  sortDirection: SortDirection;
  setLineIndex: (updater: (value: number) => number) => void;
  setFilter: (value: string) => void;
  setSelection: (
    updater: (prev: Map<string, IncidentLogLine>) => Map<string, IncidentLogLine>
  ) => void;
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
  /** Called when A is pressed and total <= INCIDENT_SELECT_ALL_LIMIT to do async full select. */
  onSelectAll?: () => void;
}): void {
  if (key.escape) {
    // Esc without active abort → handled by caller (back navigation)
    return;
  }

  if (key.upArrow) {
    setLineIndex((value) => Math.max(0, value - 1));
    return;
  }

  if (key.downArrow) {
    setLineIndex((value) => Math.min(Math.max(0, total - 1), value + 1));
    return;
  }

  if (isPageUp(inputValue, key)) {
    setLineIndex((value) => Math.max(0, value - pageSize));
    return;
  }

  if (isPageDown(inputValue, key)) {
    setLineIndex((value) => Math.min(Math.max(0, total - 1), value + pageSize));
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

  // Row actions blocked while page is loading to avoid operating on stale snapshot
  if (pageLoading) {
    setMessage("Loading…");
    return;
  }

  if (inputValue === " ") {
    const line = pageLines[lineIndex - pageStart];
    if (line) {
      setSelection((prev) => {
        const next = new Map(prev);
        const k = lineKey(line);
        if (next.has(k)) {
          next.delete(k);
        } else {
          if (next.size < INCIDENT_MANUAL_SELECT_LIMIT) {
            next.set(k, line);
          } else {
            setMessage(`Selection cap reached (${INCIDENT_MANUAL_SELECT_LIMIT})`);
          }
        }
        return next;
      });
    }
    return;
  }

  if (inputValue === "d" || key.return) {
    const line = pageLines[lineIndex - pageStart];
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
    if (total > INCIDENT_SELECT_ALL_LIMIT || !onSelectAll) {
      setSelection((prev) => {
        const { selection: next, capHit } = addLinesToSelectionWithCap(
          prev,
          pageLines,
          INCIDENT_MANUAL_SELECT_LIMIT
        );
        if (capHit) setMessage(`Selection cap reached (${INCIDENT_MANUAL_SELECT_LIMIT})`);
        return next;
      });
      setMessage(`Selected ${pageLines.length} visible lines`);
    } else {
      onSelectAll();
    }
    return;
  }

  if (inputValue === "r") {
    setFilter("");
    setLineIndex(() => 0);
    setSelection(() => new Map());
    setMessage("Filter and selection reset");
    return;
  }

  if (inputValue === "/" || inputValue === "f" || inputValue === "F") {
    setPrompt({ kind: "filter", value: filter, cursor: filter.length });
    return;
  }

  if (inputValue === "e") {
    if (selectedLines.length === 0 && total > 0) {
      setExportMenu({ format: "json" });
      setMessage("Choose export format");
      return;
    }
    if (selectedLines.length > 0) {
      setExportMenu({ format: "json" });
      setMessage("Choose export format for selected rows");
      return;
    }
    setMessage("No rows to export");
    return;
  }

}
