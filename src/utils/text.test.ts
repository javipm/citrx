import { describe, expect, it } from "vitest";

import { truncateForDisplay } from "./text.js";

describe("truncateForDisplay", () => {
  it("returns short values unchanged", () => {
    expect(truncateForDisplay("Mozilla/5.0", 42)).toBe("Mozilla/5.0");
  });

  it("truncates long values with an ellipsis, respecting maxLength", () => {
    const value = "X".repeat(100);
    const result = truncateForDisplay(value, 42);
    expect(result.length).toBe(42);
    expect(result.endsWith("…")).toBe(true);
    expect(result.slice(0, 41)).toBe(value.slice(0, 41));
  });

  it("does not mutate the aggregation value, only the returned display string", () => {
    const value = "Y".repeat(50);
    truncateForDisplay(value, 10);
    expect(value.length).toBe(50);
  });
});
