import { describe, expect, it } from "vitest";

import { binarySearchIncludes } from "./useVisibleLines.js";

describe("binarySearchIncludes", () => {
  it("finds a present value", () => {
    expect(binarySearchIncludes([1, 3, 5, 7, 9], 5)).toBe(true);
  });

  it("returns false for an absent value", () => {
    expect(binarySearchIncludes([1, 3, 5, 7, 9], 4)).toBe(false);
  });

  it("finds the first element", () => {
    expect(binarySearchIncludes([1, 3, 5, 7, 9], 1)).toBe(true);
  });

  it("finds the last element", () => {
    expect(binarySearchIncludes([1, 3, 5, 7, 9], 9)).toBe(true);
  });

  it("returns false for an empty array", () => {
    expect(binarySearchIncludes([], 1)).toBe(false);
  });

  it("handles a single-element array (present)", () => {
    expect(binarySearchIncludes([42], 42)).toBe(true);
  });

  it("handles a single-element array (absent)", () => {
    expect(binarySearchIncludes([42], 1)).toBe(false);
  });
});
