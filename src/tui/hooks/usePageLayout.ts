// Computes layout dimensions based on terminal size, active screen, and overlay state.
import { useMemo } from "react";
import type { Screen } from "../types.js";
import type { PromptState } from "../types.js";

/**
 * Options for `usePageLayout`.
 */
interface PageLayoutOptions {
  /** Active screen, used to adjust the main incident list height. */
  screen: Screen;
  /** Terminal height in rows. */
  rows: number;
  /** Terminal width in columns. */
  columns: number;
  /** Active prompt overlay, or `undefined` when no prompt is shown. Adds 3 reserved rows when set. */
  prompt: PromptState | undefined;
  /** Active export-notice overlay, or `undefined` when hidden. Adds 4 reserved rows when set. */
  exportNotice: { file: string; lines: number } | undefined;
}

/**
 * Computes layout dimensions for all TUI panels from the current terminal size and overlay state.
 *
 * @param options - See {@link PageLayoutOptions}.
 * @returns Memoized layout object:
 * - `controlRows` — rows consumed by active overlays (prompt + exportNotice).
 * - `pageSize` — visible row count for the main incident list.
 * - `summaryPageSize` — visible row count for the summary list.
 * - `detailRows` — visible row count for the detail panel.
 * - `detailWidth` — character width of the detail panel.
 * - `answerRows` — visible row count for the AI answer panel.
 * - `answerWidth` — character width of the AI answer panel.
 */
export function usePageLayout({ screen, rows, columns, prompt, exportNotice }: PageLayoutOptions) {
  return useMemo(() => {
    const controlRows = (prompt ? 3 : 0) + (exportNotice ? 4 : 0);
    const pageSize = screen === "incident"
      ? Math.max(4, rows - 13 - controlRows)
      : Math.max(4, rows - 16 - controlRows);
    const summaryPageSize = Math.max(4, rows - 16 - controlRows);
    const detailRows = Math.max(4, rows - 6 - controlRows);
    const detailWidth = Math.max(40, columns - 10);
    const answerRows = Math.max(4, rows - 7 - controlRows);
    const answerWidth = Math.max(40, columns - 10);
    return { controlRows, pageSize, summaryPageSize, detailRows, detailWidth, answerRows, answerWidth };
  }, [screen, rows, columns, prompt, exportNotice]);
}
