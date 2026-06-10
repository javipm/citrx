// Manages content display state: scroll positions and selected detail lines.
import { useState } from "react";
import type { IncidentLogLine } from "../../analysis/types.js";

/**
 * Manages content display state for scroll positions and selected lines.
 *
 * @returns Object containing state values and setters:
 * - `lineIndex` / `setLineIndex` — selected row index in the incident list.
 * - `summaryLineIndex` / `setSummaryLineIndex` — selected row index in the summary list.
 * - `detailLine` / `setDetailLine` — the `IncidentLogLine` currently open in the detail panel, or `undefined`.
 * - `detailScroll` / `setDetailScroll` — vertical scroll offset of the detail panel.
 */
export function useContentState() {
  const [lineIndex, setLineIndex] = useState(0);
  const [summaryLineIndex, setSummaryLineIndex] = useState(0);
  const [detailLine, setDetailLine] = useState<IncidentLogLine | undefined>();
  const [detailScroll, setDetailScroll] = useState(0);

  return {
    lineIndex,
    setLineIndex,
    summaryLineIndex,
    setSummaryLineIndex,
    detailLine,
    setDetailLine,
    detailScroll,
    setDetailScroll
  };
}
