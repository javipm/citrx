import { describe, expect, it } from "vitest";

import { addCappedSet, incrementCapped, rememberDroppedKey } from "./capped-counter.js";

describe("capped counters", () => {
  it("counts existing keys after the cap and drops new keys", () => {
    const map = new Map<string, number>([
      ["a", 1],
      ["b", 1]
    ]);

    expect(incrementCapped(map, "a", 2)).toBe(true);
    expect(map.get("a")).toBe(2);
    expect(incrementCapped(map, "c", 2)).toBe(false);
    expect(map.has("c")).toBe(false);
    expect(map.size).toBe(2);
  });

  it("stops adding unique set members at the cap", () => {
    const set = new Set(["x"]);
    expect(addCappedSet(set, "x", 1)).toBe(true);
    expect(addCappedSet(set, "y", 1)).toBe(false);
    expect(set.size).toBe(1);
  });

  it("counts a dropped key only once", () => {
    const dropped = new Set<string>();
    expect(rememberDroppedKey(dropped, "a", 2)).toBe(true);
    expect(rememberDroppedKey(dropped, "a", 2)).toBe(false);
    expect(rememberDroppedKey(dropped, "b", 2)).toBe(true);
    expect(rememberDroppedKey(dropped, "c", 2)).toBe(false);
    expect(dropped.size).toBe(2);
  });
});
