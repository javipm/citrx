import React from "react";
import { Box, Text } from "ink";
import type { PromptState, SortKey, SortDirection, SortMenuFocus, Screen, SummaryFocus } from "../types.js";
import { SORT_KEYS } from "../types.js";
import { fitText } from "../utils/format.js";
import { useSpinner } from "../hooks/useSpinner.js";

export function PromptBar({ prompt, columns }: { prompt: PromptState; columns: number }): React.ReactElement {
  const label =
    prompt.kind === "filter"
      ? "Filter"
      : prompt.scope === "summary"
        ? "Ask OpenAI about analysis"
        : "Ask OpenAI about incident";
  const display = promptDisplay(prompt, columns - label.length - 8);

  return React.createElement(
    Box,
    { borderStyle: "single", paddingX: 1 },
    React.createElement(Text, { color: "cyan", wrap: "truncate" }, `${label}: `),
    React.createElement(Text, { wrap: "truncate" }, display.beforeCursor),
    React.createElement(Text, { inverse: true }, display.cursorValue),
    React.createElement(Text, { wrap: "truncate" }, display.afterCursor)
  );
}

function promptDisplay(
  prompt: { value: string; cursor: number },
  width: number
): { beforeCursor: string; cursorValue: string; afterCursor: string } {
  const safeCursor = Math.max(0, Math.min(prompt.cursor, prompt.value.length));
  const available = Math.max(8, width);

  if (prompt.value.length < available) {
    return {
      beforeCursor: prompt.value.slice(0, safeCursor),
      cursorValue: prompt.value[safeCursor] ?? " ",
      afterCursor: prompt.value.slice(safeCursor + 1)
    };
  }

  const hasCursorChar = safeCursor < prompt.value.length;
  const textSlots = available - 1;
  let start = Math.max(0, safeCursor - Math.floor(textSlots / 2));

  if (safeCursor === prompt.value.length) {
    start = Math.max(0, prompt.value.length - textSlots);
  }

  let end = Math.min(prompt.value.length, start + textSlots);

  if (safeCursor >= end) {
    end = Math.min(prompt.value.length, safeCursor + (hasCursorChar ? 1 : 0));
    start = Math.max(0, end - textSlots);
  }

  const prefix = start > 0 ? "..." : "";
  const suffix = end < prompt.value.length ? "..." : "";
  const visibleBefore = prompt.value.slice(start, safeCursor);
  const visibleAfter = hasCursorChar
    ? prompt.value.slice(safeCursor + 1, end)
    : prompt.value.slice(safeCursor, end);

  return {
    beforeCursor: `${prefix}${visibleBefore}`,
    cursorValue: prompt.value[safeCursor] ?? " ",
    afterCursor: `${visibleAfter}${suffix}`
  };
}

export function SortMenuOverlay({
  sortMenu,
  columns,
  rows
}: {
  sortMenu: {
    sortKey: SortKey;
    sortDirection: SortDirection;
    focus: SortMenuFocus;
  };
  columns: number;
  rows: number;
}): React.ReactElement {
  const width = Math.min(62, Math.max(42, columns - 6));
  const innerWidth = width - 6;
  const fieldWidth = Math.floor((width - 10) * 0.58);
  const directionWidth = Math.floor((width - 10) * 0.3);
  const top = Math.max(1, Math.floor((rows - 13) / 2));
  const left = Math.max(0, Math.floor((columns - width) / 2));
  const blankLine = " ".repeat(innerWidth);

  return React.createElement(
    Box,
    {
      position: "absolute",
      top,
      left,
      width,
      flexDirection: "column",
      borderStyle: "double",
      borderColor: "cyan",
      backgroundColor: "black",
      paddingX: 2,
      paddingY: 1
    },
    React.createElement(
      Text,
      { bold: true, color: "cyan", backgroundColor: "black", wrap: "truncate" },
      fitText("Sort log", innerWidth).padEnd(innerWidth)
    ),
    React.createElement(Text, { backgroundColor: "black" }, blankLine),
    React.createElement(
      Box,
      { flexDirection: "row", gap: 4, backgroundColor: "black" },
      React.createElement(
        Box,
        { flexDirection: "column", width: fieldWidth, backgroundColor: "black" },
        React.createElement(
          Text,
          { bold: true, color: sortMenu.focus === "key" ? "cyan" : "gray", backgroundColor: "black" },
          "Field".padEnd(fieldWidth)
        ),
        ...SORT_KEYS.map((key) => {
          const active = sortMenu.sortKey === key;
          const focused = sortMenu.focus === "key" && active;
          return React.createElement(
            Text,
            {
              key,
              bold: active,
              color: focused ? "black" : active ? "yellow" : undefined,
              backgroundColor: focused ? "yellow" : "black",
              wrap: "truncate"
            },
            fitText(`${active ? ">" : " "} ${sortLabel(key)}`, fieldWidth).padEnd(fieldWidth)
          );
        })
      ),
      React.createElement(
        Box,
        { flexDirection: "column", width: directionWidth, backgroundColor: "black" },
        React.createElement(
          Text,
          { bold: true, color: sortMenu.focus === "direction" ? "cyan" : "gray", backgroundColor: "black" },
          "Direction".padEnd(directionWidth)
        ),
        ...(["desc", "asc"] as const).map((direction) => {
          const active = sortMenu.sortDirection === direction;
          const focused = sortMenu.focus === "direction" && active;
          return React.createElement(
            Text,
            {
              key: direction,
              bold: active,
              color: focused ? "black" : active ? "yellow" : undefined,
              backgroundColor: focused ? "yellow" : "black"
            },
            `${active ? ">" : " "} ${direction}`.padEnd(directionWidth)
          );
        })
      )
    ),
    React.createElement(Text, { backgroundColor: "black" }, blankLine),
    React.createElement(
      Box,
      { justifyContent: "center", backgroundColor: "black" },
      React.createElement(
        Text,
        {
          bold: true,
          color: sortMenu.focus === "apply" ? "black" : "yellow",
          backgroundColor: sortMenu.focus === "apply" ? "yellow" : "black"
        },
        "  Filter  "
      )
    ),
    React.createElement(
      Text,
      { color: "gray", backgroundColor: "black", wrap: "truncate" },
      fitText("Arrows move | Space select | Enter apply | Esc cancel", innerWidth).padEnd(innerWidth)
    )
  );
}

function sortLabel(sortKey: SortKey): string {
  switch (sortKey) {
    case "timestamp":
      return "time";
    case "ip":
      return "ip";
    case "status":
      return "status";
    case "method":
      return "method";
    case "path":
      return "path";
    case "bytes":
      return "bytes";
  }
}

export function ExportNoticeBar({
  notice,
  columns
}: {
  notice: {
    file: string;
    lines: number;
  };
  columns: number;
}): React.ReactElement {
  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "single", borderColor: "green", paddingX: 1 },
    React.createElement(
      Text,
      { bold: true, color: "green", wrap: "truncate" },
      fitText(`Export OK: ${notice.lines} rows saved as JSON`, columns - 4)
    ),
    React.createElement(
      Text,
      { color: "green", wrap: "truncate" },
      fitText(`Saved to: ${notice.file}`, columns - 4)
    )
  );
}

export function Footer({
  screen,
  summaryFocus,
  detailOpen,
  answerOpen,
  busy,
  loading,
  message,
  selected,
  columns
}: {
  screen: Screen;
  summaryFocus: SummaryFocus;
  detailOpen: boolean;
  answerOpen: boolean;
  busy: boolean;
  loading: boolean;
  message: string;
  selected: number;
  columns: number;
}): React.ReactElement {
  const spinner = useSpinner(loading || busy);
  const shortcuts = answerOpen
    ? "↑/↓ PgUp/PgDn scroll | b/Esc close answer | q quit"
    : detailOpen
    ? "↑/↓ PgUp/PgDn scroll | d/b/Esc close | q quit"
    : screen === "summary"
      ? `Tab focus(${summaryFocus}) | ↑/↓ PgUp/PgDn navigate panel | Enter/d open | f filter | s sort menu | t tops | a ask | e export | q quit`
      : screen === "tops"
        ? "Tab panel | ↑/↓ row | Enter filter by value | a ask about tops | t/b/Esc back | q quit"
        : "↑/↓ PgUp/PgDn rows | Enter/d detail | t tops | Space select | A select visible | f filter | s sort menu | a ask | e export | b back | q quit";
  const prefix = loading || busy ? `${spinner} ` : "";
  const status = `${prefix}${busy ? "Asking OpenAI..." : message}${selected ? ` | selected=${selected}` : ""}`;

  return React.createElement(
    Box,
    { flexDirection: "column" },
    React.createElement(Text, { color: busy || loading ? "yellow" : "cyan", wrap: "truncate" }, fitText(status, columns - 2)),
    React.createElement(Text, { color: "cyan", wrap: "truncate" }, fitText(shortcuts, columns - 2))
  );
}
