import { describe, expect, it } from "vitest";

import type { ActiveAbortEntry } from "../types.js";
import { clearAbortIfCurrent } from "./active-abort.js";

describe("clearAbortIfCurrent", () => {
  it("clears only when the setter still owns that controller", () => {
    const mine = new AbortController();
    const other = new AbortController();
    let current: ActiveAbortEntry | undefined = {
      kind: "select-all",
      controller: other,
      label: "other"
    };

    clearAbortIfCurrent((update) => {
      current = typeof update === "function" ? update(current) : update;
    }, mine);
    expect(current?.controller).toBe(other);

    current = { kind: "select-all", controller: mine, label: "mine" };
    clearAbortIfCurrent((update) => {
      current = typeof update === "function" ? update(current) : update;
    }, mine);
    expect(current).toBeUndefined();
  });
});
