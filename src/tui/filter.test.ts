import { describe, expect, it } from "vitest";

import type { IncidentLogLine } from "../analysis/types.js";
import { createAccessLogLineFilter, validateAccessLogFilter } from "./filter.js";

const postAdmin: IncidentLogLine = {
  row: 0,
  source: "access.log",
  lineNumber: 10,
  raw: `198.51.100.10 - - [25/May/2026:10:00:00 +0200] "POST /admin/login?q=camper&debug=true HTTP/1.1" 200 56072 "-" "Mozilla/5.0 BotProbe"`,
  ip: "198.51.100.10",
  timestamp: "25/May/2026:10:00:00 +0200",
  method: "POST",
  path: "/admin/login",
  target: "/admin/login?q=camper&debug=true",
  status: 200,
  bytes: 56072,
  userAgent: "Mozilla/5.0 BotProbe"
};

const getMissing: IncidentLogLine = {
  row: 1,
  source: "access.log",
  lineNumber: 11,
  raw: `66.249.70.174 - - [25/May/2026:10:01:00 +0200] "GET /missing.php?order=price HTTP/1.1" 404 1024 "-" "Googlebot/2.1"`,
  ip: "66.249.70.174",
  timestamp: "25/May/2026:10:01:00 +0200",
  method: "GET",
  path: "/missing.php",
  target: "/missing.php?order=price",
  status: 404,
  bytes: 1024,
  userAgent: "Googlebot/2.1"
};

const putApi: IncidentLogLine = {
  row: 2,
  source: "api.log",
  lineNumber: 12,
  raw: `203.0.113.55 - - [25/May/2026:10:02:00 +0200] "PUT /api/products?token=secret&q=SELECT%201 HTTP/1.1" 204 0 "-" "curl/8.0"`,
  ip: "203.0.113.55",
  timestamp: "25/May/2026:10:02:00 +0200",
  method: "PUT",
  path: "/api/products",
  target: "/api/products?token=secret&q=SELECT%201",
  status: 204,
  bytes: 0,
  userAgent: "curl/8.0"
};

const lines = [postAdmin, getMissing, putApi];

describe("access log TUI filter", () => {
  it("combines structured terms with implicit AND", () => {
    const filter = createAccessLogLineFilter("method:POST status:200 url:*admin*");

    expect(lines.filter(filter)).toEqual([postAdmin]);
  });

  it("supports OR and grouped expressions", () => {
    const filter = createAccessLogLineFilter("(method:POST OR method:PUT) status:2xx");

    expect(lines.filter(filter)).toEqual([postAdmin, putApi]);
  });

  it("supports pipe OR, negation and wildcards", () => {
    const filter = createAccessLogLineFilter("(status:404 | status:403) !ua:*Googlebot*");

    expect(lines.filter(filter)).toEqual([]);
  });

  it("supports numeric comparisons", () => {
    const filter = createAccessLogLineFilter("bytes>50000");

    expect(lines.filter(filter)).toEqual([postAdmin]);
  });

  it("supports parameter name filters", () => {
    const filter = createAccessLogLineFilter("param:q");

    expect(lines.filter(filter)).toEqual([postAdmin, putApi]);
  });

  it("supports parameter value filters", () => {
    const filter = createAccessLogLineFilter("param:q=*select*");

    expect(lines.filter(filter)).toEqual([putApi]);
  });

  it("supports quoted values", () => {
    const filter = createAccessLogLineFilter(`url:"/admin/login?q=camper"`);

    expect(lines.filter(filter)).toEqual([postAdmin]);
  });

  it("validates grouped syntax", () => {
    expect(validateAccessLogFilter("(method:POST OR status:200").ok).toBe(false);
  });
});
