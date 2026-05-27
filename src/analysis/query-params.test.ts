import { describe, expect, it } from "vitest";

import {
  requestParamEntries,
  requestParamNames,
  requestParamValueLabels
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
    expect(requestParamValueLabels("/x?bad=%E0%A4%A&q=ok")).toEqual([
      "bad=%E0%A4%A",
      "q=ok"
    ]);
  });
});
