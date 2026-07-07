import { describe, expect, it } from "vitest";

import { builtInParsers, getBuiltInParser } from "./built-in.js";
import type { BuiltInFormatId } from "./types.js";

function parserFor(id: BuiltInFormatId) {
  return getBuiltInParser(id);
}

describe("apache_common parser", () => {
  const parser = parserFor("apache_common");

  it("parses an IPv4 request line", () => {
    const entry = parser.parse(
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /path HTTP/1.1" 200 1234'
    );

    expect(entry).toMatchObject({
      ip: "203.0.113.10",
      timestamp: "25/May/2026:03:12:49 +0200",
      method: "GET",
      target: "/path",
      path: "/path",
      protocol: "HTTP/1.1",
      status: 200,
      bytes: 1234,
      referer: null,
      userAgent: null
    });
  });

  it("parses an IPv6 client address", () => {
    const entry = parser.parse(
      '2001:db8::1 - - [25/May/2026:03:12:49 +0200] "GET / HTTP/1.1" 200 500'
    );

    expect(entry?.ip).toBe("2001:db8::1");
  });

  it("parses a hostname identity", () => {
    const entry = parser.parse(
      'host.example.com - - [25/May/2026:03:12:49 +0200] "GET / HTTP/1.1" 200 500'
    );

    expect(entry?.ip).toBe("host.example.com");
  });

  it("parses a non-dash identity/user field", () => {
    const entry = parser.parse(
      '203.0.113.10 - alice [25/May/2026:03:12:49 +0200] "GET / HTTP/1.1" 200 500'
    );

    expect(entry?.ip).toBe("203.0.113.10");
  });

  it("parses request lines with query strings and spaces in the path", () => {
    const entry = parser.parse(
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /a/b path?x=1&y=2 HTTP/1.1" 200 500'
    );

    expect(entry?.target).toBe("/a/b path?x=1&y=2");
  });

  it("treats a dash byte count as null", () => {
    const entry = parser.parse(
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET / HTTP/1.1" 304 -'
    );

    expect(entry?.bytes).toBeNull();
  });

  it("parses a numeric byte count", () => {
    const entry = parser.parse(
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET / HTTP/1.1" 200 987'
    );

    expect(entry?.bytes).toBe(987);
  });

  it("returns null for referer/userAgent (not present in common format)", () => {
    const entry = parser.parse(
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET / HTTP/1.1" 200 500'
    );

    expect(entry?.referer).toBeNull();
    expect(entry?.userAgent).toBeNull();
  });

  it("returns null for an invalid line", () => {
    expect(parser.parse("this is not an access log line")).toBeNull();
  });

  it("returns null when the HTTP method is not recognized", () => {
    const entry = parser.parse(
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "FOO / HTTP/1.1" 200 500'
    );

    expect(entry).toBeNull();
  });

  it("returns null when the status code is out of range", () => {
    const entry = parser.parse(
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET / HTTP/1.1" 999 500'
    );

    expect(entry).toBeNull();
  });
});

describe("apache_combined / nginx_combined parsers", () => {
  it("parses referer and user-agent for apache_combined", () => {
    const parser = parserFor("apache_combined");
    const entry = parser.parse(
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /path HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64)"'
    );

    expect(entry).toMatchObject({
      ip: "203.0.113.10",
      referer: "https://example.com/",
      userAgent: "Mozilla/5.0 (X11; Linux x86_64)"
    });
  });

  it("treats a dash referer/user-agent as null", () => {
    const parser = parserFor("apache_combined");
    const entry = parser.parse(
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET / HTTP/1.1" 200 500 "-" "-"'
    );

    expect(entry?.referer).toBeNull();
    expect(entry?.userAgent).toBeNull();
  });

  it("parses nginx_combined the same shape as apache_combined", () => {
    const parser = parserFor("nginx_combined");
    const entry = parser.parse(
      '198.51.100.5 - - [25/May/2026:03:12:49 +0200] "POST /checkout HTTP/1.1" 500 12 "https://ref.example/" "curl/8.0"'
    );

    expect(entry).toMatchObject({
      ip: "198.51.100.5",
      method: "POST",
      target: "/checkout",
      status: 500,
      bytes: 12,
      referer: "https://ref.example/",
      userAgent: "curl/8.0"
    });
  });

  it("returns null for a line missing the trailing quoted fields", () => {
    const parser = parserFor("apache_combined");
    const entry = parser.parse(
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET / HTTP/1.1" 200 500'
    );

    expect(entry).toBeNull();
  });

  it("returns null for a completely malformed line", () => {
    const parser = parserFor("nginx_combined");
    expect(parser.parse("")).toBeNull();
    expect(parser.parse("random garbage 12345")).toBeNull();
  });
});

describe("getBuiltInParser", () => {
  it("returns a parser for every known format id", () => {
    const ids: BuiltInFormatId[] = ["apache_common", "apache_combined", "nginx_combined"];

    for (const id of ids) {
      expect(getBuiltInParser(id).id).toBe(id);
    }
  });

  it("exposes all built-in parsers via builtInParsers", () => {
    const ids = builtInParsers.map((parser) => parser.id);
    expect(ids).toEqual(
      expect.arrayContaining(["apache_common", "apache_combined", "nginx_combined"])
    );
  });

  it("throws for an unknown format id", () => {
    expect(() => getBuiltInParser("unknown" as BuiltInFormatId)).toThrow(
      /Unknown built-in format/
    );
  });
});
