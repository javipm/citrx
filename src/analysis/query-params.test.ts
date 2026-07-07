import { describe, expect, it } from "vitest";

import {
  requestParamEntries,
  requestParamNames,
  requestParamValueLabels,
  userAgentLabel
} from "./query-params.js";

describe("query param extraction", () => {
  it("extracts repeated names and decoded values without URL parsing", () => {
    expect(requestParamEntries("/search?q=camper&q=roof+rack&empty")).toEqual([
      { name: "q", value: "camper" },
      { name: "q", value: "roof rack" },
      { name: "empty", value: "" }
    ]);
    expect(requestParamNames("/search?q=camper&q=roof+rack&empty")).toEqual(["q", "empty"]);
  });

  it("redacts sensitive parameter values", () => {
    expect(requestParamValueLabels("/login?token=abc&password=secret&q=camper")).toEqual([
      "token=<redacted>",
      "password=<redacted>",
      "q=camper"
    ]);
  });

  it("keeps malformed escapes deterministic", () => {
    expect(requestParamValueLabels("/x?bad=%E0%A4%A&q=ok")).toEqual(["bad=%E0%A4%A", "q=ok"]);
  });
});

describe("userAgentLabel", () => {
  it("does not truncate long, unrecognized user agents (aggregation must stay filterable)", () => {
    const longUa =
      "SomeCustomClient/1.0 (+https://example.invalid/client-info; contact=ops@example.invalid) extra-suffix-to-exceed-forty-two-chars";
    const label = userAgentLabel(longUa);
    expect(label).toBe(longUa);
    expect(label.length).toBeGreaterThan(42);
  });

  it("collapses internal whitespace but keeps full length", () => {
    const messyUa = "Weird-Agent/9.9   with    lots  of\tspaces  and-a-tail-well-past-forty-two-characters";
    const label = userAgentLabel(messyUa);
    expect(label).toBe(messyUa.replace(/\s+/g, " ").trim());
    expect(label).not.toMatch(/…$/);
  });

  it("still extracts a short bot/browser signature when recognizable", () => {
    expect(userAgentLabel("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")).toBe(
      "Googlebot/2.1"
    );
  });
});
