// Manages filter, sort, selection, prompt overlay, export notice, and status message state.
import { useState } from "react";
import type { SortKey, SortDirection, SortMenuFocus, PromptState } from "../types.js";

/**
 * Manages filter, sort, selection, and UI overlay state for the incidents list.
 *
 * @returns An object containing:
 *   - `filter` / `setFilter` — Current free-text filter string applied to the incident list.
 *   - `sortKey` / `setSortKey` — Column currently used for sorting (`"timestamp"`, `"count"`, …).
 *   - `sortDirection` / `setSortDirection` — `"asc"` or `"desc"` sort order.
 *   - `selectedLineKeys` / `setSelectedLineKeys` — Set of line-key strings for checked/selected rows.
 *   - `prompt` / `setPrompt` — Active prompt overlay state (`PromptState`), or `undefined` when hidden.
 *   - `sortMenu` / `setSortMenu` — Transient sort-menu overlay state (key, direction, focus), or `undefined` when closed.
 *   - `exportNotice` / `setExportNotice` — Post-export confirmation payload (`{ file, lines }`), or `undefined`.
 *   - `message` / `setMessage` — Status-bar message string; defaults to `"Ready"`.
 *   - `busy` / `setBusy` — `true` while an async operation (e.g. AI query) is in-flight.
 *   - `indexLoading` / `setIndexLoading` — `true` while the access-log index is being built/cached.
 */
export function useFilterSortState() {
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [selectedLineKeys, setSelectedLineKeys] = useState<Set<string>>(new Set());
  const [prompt, setPrompt] = useState<PromptState | undefined>();
  const [sortMenu, setSortMenu] = useState<{
    sortKey: SortKey;
    sortDirection: SortDirection;
    focus: SortMenuFocus;
  }>();
  const [exportNotice, setExportNotice] = useState<{
    file: string;
    lines: number;
  }>();
  const [message, setMessage] = useState("Ready");
  const [busy, setBusy] = useState(false);
  const [indexLoading, setIndexLoading] = useState(false);

  return {
    filter,
    setFilter,
    sortKey,
    setSortKey,
    sortDirection,
    setSortDirection,
    selectedLineKeys,
    setSelectedLineKeys,
    prompt,
    setPrompt,
    sortMenu,
    setSortMenu,
    exportNotice,
    setExportNotice,
    message,
    setMessage,
    busy,
    setBusy,
    indexLoading,
    setIndexLoading
  };
}
