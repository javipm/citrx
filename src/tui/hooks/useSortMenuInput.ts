// Handles keyboard input within the sort menu overlay (field selection, direction, apply).
import type { SortKey, SortDirection, SortMenuFocus } from "../types.js";
import { SORT_KEYS } from "../types.js";

/**
 * Handles keyboard input for the sort menu overlay.
 *
 * The overlay has three focusable sections: `"key"` (sort field list),
 * `"direction"` (asc / desc toggle), and `"apply"` (confirm button).
 *
 * Key bindings:
 * - `Escape` / `Backspace` — close overlay, show "Sort cancelled" message.
 * - `Enter`                — apply current sort key + direction.
 * - `Space`                — on `"apply"` focus: apply sort; otherwise advance focus
 *                            (`"key"` → `"direction"` → `"apply"`).
 * - `Tab`                  — cycle focus: `"key"` → `"direction"` → `"apply"` → `"key"`.
 * - `←` / `→`             — navigate between sections (arrow semantics vary by focus).
 * - `↑` / `↓`             — in `"key"`: move through `SORT_KEYS` list;
 *                            in `"direction"`: toggle between `"asc"` and `"desc"`;
 *                            in `"apply"`: move back to `"key"` (↑) or stay (↓).
 * - `S`                    — jump focus directly to `"direction"` section.
 *
 * @param params.inputValue      - Raw character(s) received from the terminal.
 * @param params.key             - Parsed key flags from ink's `useInput`.
 * @param params.sortMenu        - Current sort menu state: active key, direction, and focused section.
 * @param params.setSortMenu     - Setter to update or close the sort menu overlay.
 * @param params.applySort       - Callback invoked with the chosen `SortKey` and `SortDirection`.
 * @param params.setMessage      - Setter to display a status message in the TUI.
 */
export function handleSortMenuInput({
  inputValue,
  key,
  sortMenu,
  setSortMenu,
  applySort,
  setMessage
}: {
  inputValue: string;
  key: {
    return?: boolean;
    escape?: boolean;
    backspace?: boolean;
    tab?: boolean;
    upArrow?: boolean;
    downArrow?: boolean;
    leftArrow?: boolean;
    rightArrow?: boolean;
  };
  sortMenu: {
    sortKey: SortKey;
    sortDirection: SortDirection;
    focus: SortMenuFocus;
  };
  setSortMenu: (value: typeof sortMenu | undefined) => void;
  applySort: (sortKey: SortKey, sortDirection: SortDirection) => void;
  setMessage: (value: string) => void;
}): void {
  if (key.escape || key.backspace) {
    setSortMenu(undefined);
    setMessage("Sort cancelled");
    return;
  }

  if (key.return) {
    applySort(sortMenu.sortKey, sortMenu.sortDirection);
    return;
  }

  if (inputValue === " ") {
    if (sortMenu.focus === "apply") {
      applySort(sortMenu.sortKey, sortMenu.sortDirection);
      return;
    }

    setSortMenu({
      ...sortMenu,
      focus: sortMenu.focus === "key" ? "direction" : "apply"
    });
    return;
  }

  if (key.tab) {
    setSortMenu({
      ...sortMenu,
      focus: sortMenu.focus === "key" ? "direction" : sortMenu.focus === "direction" ? "apply" : "key"
    });
    return;
  }

  if (key.leftArrow || key.rightArrow) {
    if (sortMenu.focus === "apply") {
      setSortMenu({
        ...sortMenu,
        focus: key.leftArrow ? "key" : "direction"
      });
      return;
    }

    if (sortMenu.focus === "key") {
      setSortMenu({
        ...sortMenu,
        focus: "direction"
      });
      return;
    }

    setSortMenu({
      ...sortMenu,
      focus: "key"
    });
    return;
  }

  if (key.upArrow || key.downArrow) {
    const step = key.upArrow ? -1 : 1;

    if (sortMenu.focus === "apply") {
      setSortMenu({
        ...sortMenu,
        focus: step < 0 ? "key" : "apply"
      });
      return;
    }

    if (sortMenu.focus === "key") {
      const currentIndex = SORT_KEYS.indexOf(sortMenu.sortKey);

      if (step > 0 && currentIndex === SORT_KEYS.length - 1) {
        setSortMenu({
          ...sortMenu,
          focus: "apply"
        });
        return;
      }

      if (step < 0 && currentIndex === 0) {
        return;
      }

      setSortMenu({
        ...sortMenu,
        sortKey: SORT_KEYS[currentIndex + step] ?? sortMenu.sortKey
      });
      return;
    }

    if (step > 0 && sortMenu.sortDirection === "asc") {
      setSortMenu({
        ...sortMenu,
        focus: "apply"
      });
      return;
    }

    if (step < 0 && sortMenu.sortDirection === "desc") {
      return;
    }

    setSortMenu({
      ...sortMenu,
      sortDirection: sortMenu.sortDirection === "desc" ? "asc" : "desc"
    });
    return;
  }

  if (inputValue === "S") {
    setSortMenu({
      ...sortMenu,
      focus: "direction"
    });
  }
}
