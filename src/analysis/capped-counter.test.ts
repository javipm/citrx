import { describe, expect, it } from "vitest";

import {
  addCappedSet,
  admitHeavyHitter,
  incrementCapped,
  rememberDroppedKey
} from "./capped-counter.js";

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

describe("heavy hitter admission", () => {
  it("admits a busy key that first appears after the cap is full", () => {
    const map = new Map<string, number>();

    // Fill the cap with one-off keys, the shape of a long-tailed path list.
    for (let index = 0; index < 10; index += 1) {
      admitHeavyHitter(map, `tail-${index}`, 10);
    }
    expect(map.has("late-heavy-hitter")).toBe(false);

    // The genuinely busiest key only starts appearing now.
    for (let index = 0; index < 1000; index += 1) {
      admitHeavyHitter(map, "late-heavy-hitter", 10);
    }

    expect(map.get("late-heavy-hitter")).toBeGreaterThanOrEqual(1000);
    const top = [...map.entries()].sort((a, b) => b[1] - a[1])[0];
    expect(top[0]).toBe("late-heavy-hitter");
  });

  it("counts a key present from the start exactly", () => {
    const map = new Map<string, number>();

    for (let index = 0; index < 50; index += 1) {
      admitHeavyHitter(map, "steady", 10);
    }

    expect(map.get("steady")).toBe(50);
  });

  it("never grows past the cap", () => {
    const map = new Map<string, number>();

    for (let index = 0; index < 5000; index += 1) {
      admitHeavyHitter(map, `key-${index}`, 32);
    }

    expect(map.size).toBeLessThanOrEqual(32);
  });
});
