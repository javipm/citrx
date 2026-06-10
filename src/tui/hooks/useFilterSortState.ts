// Manages filter, sort, selection, prompt overlay, export notice, and status message state.
import { useMemo, useState } from "react";
import type { IncidentLogLine } from "../../analysis/types.js";
import type { ExportFormat, SortKey, SortDirection, SortMenuFocus, PromptState } from "../types.js";

export function useFilterSortState() {
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [selection, setSelection] = useState<Map<string, IncidentLogLine>>(new Map());
  const [prompt, setPrompt] = useState<PromptState | undefined>();
  const [sortMenu, setSortMenu] = useState<{
    sortKey: SortKey;
    sortDirection: SortDirection;
    focus: SortMenuFocus;
  }>();
  const [exportMenu, setExportMenu] = useState<{
    format: ExportFormat;
  }>();
  const [exportNotice, setExportNotice] = useState<{
    file: string;
    lines: number;
    format: ExportFormat;
  }>();
  const [message, setMessage] = useState("h: help  |  Tab: switch type  |  Enter: drill  |  /: filter  |  q: quit");
  const [exportLoading, setExportLoading] = useState(false);
  const [indexLoading, setIndexLoading] = useState(false);

  const selectedLineKeys = useMemo(() => new Set(selection.keys()), [selection]);

  return {
    filter,
    setFilter,
    sortKey,
    setSortKey,
    sortDirection,
    setSortDirection,
    selection,
    setSelection,
    selectedLineKeys,
    prompt,
    setPrompt,
    sortMenu,
    setSortMenu,
    exportMenu,
    setExportMenu,
    exportNotice,
    setExportNotice,
    message,
    setMessage,
    exportLoading,
    setExportLoading,
    indexLoading,
    setIndexLoading
  };
}
