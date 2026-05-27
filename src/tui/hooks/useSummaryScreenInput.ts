// Handles keyboard input on the summary screen: navigation, filtering, selection, export, AI.
import type { Incident, IncidentLogLine } from "../../analysis/types.js";
import type { SummaryFocus, SortKey, SortDirection, PromptState } from "../types.js";
import { lineKey, toggleSelection } from "../utils/table.js";

type Key = {
  upArrow?: boolean;
  downArrow?: boolean;
  return?: boolean;
  tab?: boolean;
  pageUp?: boolean;
  pageDown?: boolean;
};

/**
 * Returns true if the input represents a Page Up key press.
 * Handles both the `key.pageUp` flag and the raw escape sequence `[5~`.
 * @param inputValue - Raw string value from the key event.
 * @param key - Parsed key flags object.
 * @returns `true` when Page Up is detected.
 */
function isPageUp(inputValue: string, key: Key): boolean {
  return Boolean(key.pageUp) || inputValue === "[5~";
}

/**
 * Returns true if the input represents a Page Down key press.
 * Handles both the `key.pageDown` flag and the raw escape sequence `[6~`.
 * @param inputValue - Raw string value from the key event.
 * @param key - Parsed key flags object.
 * @returns `true` when Page Down is detected.
 */
function isPageDown(inputValue: string, key: Key): boolean {
  return Boolean(key.pageDown) || inputValue === "[6~";
}

/**
 * Narrows a `SummaryFocus` value to an incident category focus.
 * Returns `true` for `"compromise"`, `"saturation"`, or `"noise"`;
 * returns `false` for `"accesses"`.
 * @param focus - The current summary panel focus value.
 * @returns Type predicate narrowing `focus` to an incident-kind union.
 */
export function isIncidentFocus(
  focus: SummaryFocus
): focus is "compromise" | "saturation" | "noise" {
  return focus !== "accesses";
}

/**
 * Computes the contiguous index range within the `incidents` array for a given kind.
 * Assumes incidents of the same kind appear as a contiguous block (sorted by kind).
 * Returns `{ start: -1, end: -1 }` when no incidents of that kind exist.
 * @param incidents - Full flat list of incidents.
 * @param kind - The incident kind to locate (`"compromise"`, `"saturation"`, or `"noise"`).
 * @returns Object with inclusive `start` index and exclusive `end` index.
 */
export function kindRange(
  incidents: Incident[],
  kind: "compromise" | "saturation" | "noise"
): { start: number; end: number } {
  let start = -1;
  let end = -1;
  for (let index = 0; index < incidents.length; index += 1) {
    if (incidents[index]!.kind === kind) {
      if (start === -1) start = index;
      end = index + 1;
    }
  }
  return { start, end };
}

/**
 * Builds the ordered list of focus tabs that are available given the current incidents.
 * `"accesses"` is always first. Incident-kind tabs are appended only when at least one
 * incident of that kind exists, in the order: saturation → compromise → noise.
 * @param incidents - Full flat list of incidents.
 * @returns Array of `SummaryFocus` values representing tabs shown in the UI.
 */
export function availableFocuses(incidents: Incident[]): SummaryFocus[] {
  const order: SummaryFocus[] = ["accesses"];
  if (incidents.some((i) => i.kind === "saturation")) order.push("saturation");
  if (incidents.some((i) => i.kind === "compromise")) order.push("compromise");
  if (incidents.some((i) => i.kind === "noise")) order.push("noise");
  return order;
}

/**
 * Main keyboard handler for the summary screen.
 *
 * Key bindings handled:
 * - `↑` / `↓`         — Move selection up/down (incident list or access log, clamped to bounds).
 * - `PageUp` / `[5~`  — Jump backward by page (7 rows for incidents, `summaryPageSize` for accesses).
 * - `PageDown` / `[6~`— Jump forward by page.
 * - `Tab`             — Cycle focus through available tabs (accesses → saturation → compromise → noise → …).
 *                       Resets incident selection to the first item of the new tab's kind.
 * - `Enter`           — Drill into the selected incident (incident-kind focus) → navigates to `"incident"` screen,
 *                       resets line index, filter, selection, and detail line.
 *                       On `"accesses"` focus: same as `d` — opens inline detail panel.
 * - `d`               — Open the detail panel for the currently highlighted access log line.
 * - `s` / `S`         — Open the sort menu with current sort state pre-filled.
 * - `Space`           — Toggle selection of the highlighted access log line.
 * - `A`               — Select all currently visible (page) access log lines.
 * - `r`               — Reset filter, scroll position, and line selection.
 * - `/` / `f` / `F`   — Open the filter prompt, pre-filled with the current filter string.
 * - `t`               — Navigate to the tops screen scoped to the summary.
 * - `a`               — Open the AI prompt scoped to the summary, using selected lines or visible page lines.
 * - `e`               — Export selected lines (or visible page) to JSON via `exportContext`.
 *
 * @param params.inputValue             - Raw character string from the key event.
 * @param params.key                    - Parsed key flags (arrows, return, tab, page keys).
 * @param params.incidents              - Full incident list for the current run.
 * @param params.incident               - The currently focused incident (undefined when none).
 * @param params.summaryFocus           - Active focus tab (`"accesses"` | `"compromise"` | `"saturation"` | `"noise"`).
 * @param params.summaryPageLines       - Access log lines on the current virtual page.
 * @param params.summaryLineIndex       - Absolute line index of the highlighted access log row.
 * @param params.computedSummaryPageStart - Absolute index of the first line on the current page; used to
 *                                          translate `summaryLineIndex` to a page-local offset.
 * @param params.globalTotal            - Total number of access log lines across all pages.
 * @param params.summaryPageSize        - Number of access log lines per page.
 * @param params.selectedGlobalLines    - Currently selected access log lines (may span pages).
 * @param params.filter                 - Current filter string (pre-filled when opening filter prompt).
 * @param params.sortKey                - Active sort column key.
 * @param params.sortDirection          - Active sort direction.
 * @param params.runId                  - Identifier for the current analysis run (passed to `exportContext`).
 * @param params.exit                   - Callback to exit the application (reserved; not invoked by this handler).
 * @param params.setSummaryFocus        - Sets the active focus tab.
 * @param params.setIncidentIndex       - Functional updater for the selected incident index.
 * @param params.setSummaryLineIndex    - Functional updater for the highlighted access log line index.
 * @param params.setScreen              - Navigates to a named screen (`"incident"`, `"tops"`, or `"summary"`).
 * @param params.setLineIndex           - Sets the line index on the incident detail screen (reset to 0 on drill-in).
 * @param params.setFilter              - Sets the active filter string.
 * @param params.setSelectedLineKeys    - Sets or updates the set of selected line keys.
 * @param params.setDetailLine          - Sets the line shown in the inline detail panel (undefined to close).
 * @param params.setDetailScroll        - Resets the detail panel scroll position.
 * @param params.setSortMenu            - Opens the sort menu with a pre-populated state, or closes it (undefined).
 * @param params.setTopScope            - Sets the scope context before navigating to the tops screen.
 * @param params.setPrompt              - Opens a prompt overlay (filter or AI kind).
 * @param params.setExportNotice        - Displays the post-export confirmation banner.
 * @param params.setMessage             - Sets the status-bar message string.
 * @param params.exportContext          - Async function that serialises lines to a JSON file and returns the path.
 */
export function handleSummaryScreenInput({
  inputValue,
  key,
  incidents,
  incident,
  summaryFocus,
  summaryPageLines,
  summaryLineIndex,
  computedSummaryPageStart,
  globalTotal,
  summaryPageSize,
  selectedGlobalLines,
  filter,
  sortKey,
  sortDirection,
  runId,
  setSummaryFocus,
  setIncidentIndex,
  setSummaryLineIndex,
  setScreen,
  setLineIndex,
  setFilter,
  setSelectedLineKeys,
  setDetailLine,
  setDetailScroll,
  setSortMenu,
  setTopScope,
  setPrompt,
  setExportNotice,
  setMessage,
  exportContext
}: {
  inputValue: string;
  key: Key;
  incidents: Incident[];
  incident: Incident | undefined;
  summaryFocus: SummaryFocus;
  summaryPageLines: IncidentLogLine[];
  summaryLineIndex: number;
  computedSummaryPageStart: number;
  globalTotal: number;
  summaryPageSize: number;
  selectedGlobalLines: IncidentLogLine[];
  filter: string;
  sortKey: SortKey;
  sortDirection: SortDirection;
  runId: string;
  setSummaryFocus: (value: SummaryFocus) => void;
  setIncidentIndex: (updater: (value: number) => number) => void;
  setSummaryLineIndex: (updater: (value: number) => number) => void;
  setScreen: (screen: "incident" | "tops" | "summary") => void;
  setLineIndex: (value: number) => void;
  setFilter: (value: string) => void;
  setSelectedLineKeys: (updaterOrValue: Set<string> | ((v: Set<string>) => Set<string>)) => void;
  setDetailLine: (line: IncidentLogLine | undefined) => void;
  setDetailScroll: (value: number) => void;
  setSortMenu: (
    value: { sortKey: SortKey; sortDirection: SortDirection; focus: "key" } | undefined
  ) => void;
  setTopScope: (scope: "summary") => void;
  setPrompt: (value: PromptState) => void;
  setExportNotice: (value: { file: string; lines: number }) => void;
  setMessage: (value: string) => void;
  exportContext: (
    runId: string,
    incident: Incident | undefined,
    lines: IncidentLogLine[]
  ) => Promise<string>;
}): void {
  const incidentBounds = isIncidentFocus(summaryFocus)
    ? kindRange(incidents, summaryFocus)
    : { start: -1, end: -1 };

  if (key.upArrow) {
    if (isIncidentFocus(summaryFocus) && incidentBounds.start >= 0) {
      setIncidentIndex((value) => Math.max(incidentBounds.start, value - 1));
    } else {
      setSummaryLineIndex((value) => Math.max(0, value - 1));
    }
    return;
  }

  if (key.downArrow) {
    if (isIncidentFocus(summaryFocus) && incidentBounds.start >= 0) {
      setIncidentIndex((value) => Math.min(incidentBounds.end - 1, value + 1));
    } else {
      setSummaryLineIndex((value) => Math.min(Math.max(0, globalTotal - 1), value + 1));
    }
    return;
  }

  if (isPageUp(inputValue, key)) {
    if (isIncidentFocus(summaryFocus) && incidentBounds.start >= 0) {
      setIncidentIndex((value) => Math.max(incidentBounds.start, value - 7));
    } else {
      setSummaryLineIndex((value) => Math.max(0, value - summaryPageSize));
    }
    return;
  }

  if (isPageDown(inputValue, key)) {
    if (isIncidentFocus(summaryFocus) && incidentBounds.start >= 0) {
      setIncidentIndex((value) => Math.min(incidentBounds.end - 1, value + 7));
    } else {
      setSummaryLineIndex((value) =>
        Math.min(Math.max(0, globalTotal - 1), value + summaryPageSize)
      );
    }
    return;
  }

  if (key.tab) {
    const order = availableFocuses(incidents);
    const idx = order.indexOf(summaryFocus);
    const next = order[(idx === -1 ? 0 : idx + 1) % order.length]!;
    setSummaryFocus(next);
    if (isIncidentFocus(next)) {
      const range = kindRange(incidents, next);
      if (range.start >= 0) {
        setIncidentIndex(() => range.start);
      }
    }
    return;
  }

  if (key.return && isIncidentFocus(summaryFocus) && incident) {
    setScreen("incident");
    setLineIndex(0);
    setFilter("");
    setSelectedLineKeys(new Set());
    setDetailLine(undefined);
    setMessage(`Opened ${incident.id}`);
    return;
  }

  if ((inputValue === "d" || key.return) && summaryFocus === "accesses") {
    const line = summaryPageLines[summaryLineIndex - computedSummaryPageStart];
    if (line) {
      setDetailLine(line);
      setDetailScroll(0);
    }
    return;
  }

  if (inputValue === "s" || inputValue === "S") {
    setSortMenu({ sortKey, sortDirection, focus: "key" });
    setMessage("Choose sort field and direction");
    return;
  }

  if (inputValue === " ") {
    const line = summaryPageLines[summaryLineIndex - computedSummaryPageStart];
    if (line) {
      setSelectedLineKeys((current) => toggleSelection(current, line));
    }
    return;
  }

  if (inputValue === "A") {
    setSelectedLineKeys(new Set(summaryPageLines.map(lineKey)));
    setMessage(`Selected ${summaryPageLines.length} visible lines`);
    return;
  }

  if (inputValue === "r") {
    setFilter("");
    setSummaryLineIndex(() => 0);
    setSelectedLineKeys(new Set());
    setMessage("Filter and selection reset");
    return;
  }

  if (inputValue === "/" || inputValue === "f" || inputValue === "F") {
    setPrompt({ kind: "filter", value: filter, cursor: filter.length });
    return;
  }

  if (inputValue === "t") {
    setTopScope("summary");
    setScreen("tops");
    setMessage("Global top values");
    return;
  }

  if (inputValue === "a") {
    setPrompt({
      kind: "ai",
      value: "",
      cursor: 0,
      scope: "summary",
      lines: selectedGlobalLines.length > 0 ? selectedGlobalLines : summaryPageLines
    });
    return;
  }

  if (inputValue === "e") {
    const exportable = selectedGlobalLines.length > 0 ? selectedGlobalLines : summaryPageLines;
    setMessage("Exporting JSON...");
    void exportContext(runId, undefined, exportable)
      .then((file) => {
        setExportNotice({ file, lines: exportable.length });
        setMessage(`Export OK: ${exportable.length} rows saved`);
      })
      .catch((error) => {
        setMessage(`Export failed: ${error instanceof Error ? error.message : String(error)}`);
      });
  }
}
