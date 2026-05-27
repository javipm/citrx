// Manages navigation-related state: which screen is active, which incident is focused,
// and top-values panel positions.
import { useState } from "react";
import type { Screen, SummaryFocus, TopScope, TopPanelKey } from "../types.js";
import type { CitrxRun } from "../../run/types.js";

/**
 * Manages navigation-related state for the TUI.
 *
 * @param run - The current CitrxRun whose incidents seed the initial `incidentIndex`.
 * @returns An object containing:
 *   - `screen` / `setScreen` — Active screen (`"summary"`, `"top"`, `"incidents"`, etc.).
 *   - `summaryFocus` / `setSummaryFocus` — Which summary panel row is focused (`"saturation"` | `"abuse"` | …).
 *   - `topScope` / `setTopScope` — Whether the top-values panel shows summary or per-incident data.
 *   - `topFocus` / `setTopFocus` — Which top-values sub-panel (column) is keyboard-focused.
 *   - `topIndexes` / `setTopIndexes` — Selected row index within each top-values sub-panel, keyed by `TopPanelKey`.
 *   - `incidentIndex` / `setIncidentIndex` — Index into `run.report.incidents`; initialised to the first saturation incident (or 0).
 */
export function useNavigationState(run: CitrxRun) {
  const [screen, setScreen] = useState<Screen>("summary");
  const [summaryFocus, setSummaryFocus] = useState<SummaryFocus>("accesses");
  const [topScope, setTopScope] = useState<TopScope>("summary");
  const [topFocus, setTopFocus] = useState<TopPanelKey>("ips");
  const [topIndexes, setTopIndexes] = useState<Record<TopPanelKey, number>>({
    ips: 0,
    paths: 0,
    userAgents: 0,
    params: 0,
    paramValues: 0
  });
  const [incidentIndex, setIncidentIndex] = useState(() => {
    const satStart = run.report.incidents.findIndex((i) => i.kind === "saturation");
    return satStart >= 0 ? satStart : 0;
  });

  return {
    screen,
    setScreen,
    summaryFocus,
    setSummaryFocus,
    topScope,
    setTopScope,
    topFocus,
    setTopFocus,
    topIndexes,
    setTopIndexes,
    incidentIndex,
    setIncidentIndex
  };
}
