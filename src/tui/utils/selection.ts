import type { IncidentLogLine } from "../../analysis/types.js";
import { lineKey } from "./table.js";

export const INCIDENT_MANUAL_SELECT_LIMIT = 5000;
export const INCIDENT_SELECT_ALL_LIMIT = 5000;

export function addLinesToSelectionWithCap(
  selection: Map<string, IncidentLogLine>,
  lines: Iterable<IncidentLogLine>,
  cap: number
): { selection: Map<string, IncidentLogLine>; capHit: boolean } {
  const next = new Map(selection);
  let capHit = false;
  for (const line of lines) {
    if (next.size >= cap) {
      capHit = true;
      break;
    }
    const k = lineKey(line);
    if (!next.has(k)) next.set(k, line);
  }
  return { selection: next, capHit };
}
