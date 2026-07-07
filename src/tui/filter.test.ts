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

const realGooglebot: IncidentLogLine = {
  row: 3,
  source: "access.log",
  lineNumber: 13,
  raw: `66.249.70.175 - - [25/May/2026:10:03:00 +0200] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"`,
  ip: "66.249.70.175",
  timestamp: "25/May/2026:10:03:00 +0200",
  method: "GET",
  path: "/",
  target: "/",
  status: 200,
  bytes: 512,
  userAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
};

const encodedSpaceQuery: IncidentLogLine = {
  row: 4,
  source: "access.log",
  lineNumber: 14,
  raw: `192.0.2.20 - - [25/May/2026:10:04:00 +0200] "GET /search?q=camper%20van HTTP/1.1" 200 2048 "-" "curl/8.0"`,
  ip: "192.0.2.20",
  timestamp: "25/May/2026:10:04:00 +0200",
  method: "GET",
  path: "/search",
  target: "/search?q=camper%20van",
  status: 200,
  bytes: 2048,
  userAgent: "curl/8.0"
};

const plusEncodedParam: IncidentLogLine = {
  row: 5,
  source: "access.log",
  lineNumber: 15,
  raw: `192.0.2.21 - - [25/May/2026:10:05:00 +0200] "GET /search?q=camper+van HTTP/1.1" 200 2048 "-" "curl/8.0"`,
  ip: "192.0.2.21",
  timestamp: "25/May/2026:10:05:00 +0200",
  method: "GET",
  path: "/search",
  target: "/search?q=camper+van",
  status: 200,
  bytes: 2048,
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

  describe("literal `+` vs query-string `+` decoding", () => {
    it("matches a literal `+` in the user agent (e.g. Googlebot's bot.html URL)", () => {
      const filter = createAccessLogLineFilter("ua:*(+http://www.google.com/bot.html)*");

      expect(filter(realGooglebot)).toBe(true);
    });

    it("matches a literal `+` in ua with a plain (non-wildcard) contains pattern", () => {
      const filter = createAccessLogLineFilter(`ua:"+http://www.google.com"`);

      expect(filter(realGooglebot)).toBe(true);
    });

    it("still percent-decodes %20 to a space in the filter pattern for free-text fields", () => {
      // The pattern is written with a literal space; matchPattern must decode
      // any %20 in the pattern the same way (percent-decoding, unaffected by
      // this fix) while the raw target keeps its original %20 encoding.
      const filter = createAccessLogLineFilter(`ua:"Mozilla%205.0"`);

      expect(filter({ ...encodedSpaceQuery, userAgent: "Mozilla 5.0" })).toBe(true);
    });

    it("decodes `+` to space when matching query-param values via param:", () => {
      const filter = createAccessLogLineFilter(`param:q="camper van"`);

      expect(filter(plusEncodedParam)).toBe(true);
      expect(filter(encodedSpaceQuery)).toBe(true);
    });

    it("end-to-end: ua filter matches the full Googlebot UA including a literal +", () => {
      const filter = createAccessLogLineFilter(
        `ua:"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"`
      );

      expect([...lines, realGooglebot].filter(filter)).toEqual([realGooglebot]);
    });
  });

  describe("memoization caches (wildcard regex + searchable line)", () => {
    it("applies the same wildcard query correctly across distinct lines", () => {
      const filter = createAccessLogLineFilter("path:/api/*");

      expect(filter(postAdmin)).toBe(false);
      expect(filter(putApi)).toBe(true);
      // Re-evaluate to exercise the memoized regex path for both lines.
      expect(filter(postAdmin)).toBe(false);
      expect(filter(putApi)).toBe(true);
    });

    it("re-evaluates a plain-text term against the same line correctly", () => {
      const filter = createAccessLogLineFilter("camper admin");

      expect(filter(postAdmin)).toBe(true);
      // Second call must hit the memoized searchable-line string and still match.
      expect(filter(postAdmin)).toBe(true);
      expect(filter(getMissing)).toBe(false);
    });

    it("does not share the wildcard regex cache between separate filter instances", () => {
      // First instance compiles "*select*" as a param-value pattern (positive match).
      const first = createAccessLogLineFilter("param:q=*select*");
      expect([postAdmin, getMissing, putApi].filter(first)).toEqual([putApi]);

      // A second, independently created instance with an unrelated query must not
      // be affected by any state cached inside the first instance's closure.
      const second = createAccessLogLineFilter("path:/admin/*");
      expect([postAdmin, getMissing, putApi].filter(second)).toEqual([postAdmin]);

      // Re-running the first instance's query must still be correct afterwards.
      expect([postAdmin, getMissing, putApi].filter(first)).toEqual([putApi]);
    });

    it("does not share the searchable-line cache between separate filter instances", () => {
      const first = createAccessLogLineFilter("camper");
      const second = createAccessLogLineFilter("SELECT");

      expect([postAdmin, getMissing, putApi].filter(first)).toEqual([postAdmin]);
      expect([postAdmin, getMissing, putApi].filter(second)).toEqual([putApi]);
    });

    it("matches previous (non-memoized) behavior for wildcard, text, and param queries", () => {
      const wildcardFilter = createAccessLogLineFilter("path:/api/*");
      const textFilter = createAccessLogLineFilter("botprobe");
      const paramFilter = createAccessLogLineFilter("param:q=*select*");

      expect(lines.filter(wildcardFilter)).toEqual([putApi]);
      expect(lines.filter(textFilter)).toEqual([postAdmin]);
      expect(lines.filter(paramFilter)).toEqual([putApi]);
    });
  });
});
