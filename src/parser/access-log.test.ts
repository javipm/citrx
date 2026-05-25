import { describe, expect, it } from "vitest";

import { parseAccessLogLine } from "./access-log.js";

describe("parseAccessLogLine", () => {
  it("parses combined access logs", () => {
    expect(
      parseAccessLogLine(
        '47.82.14.57 - - [25/May/2026:03:12:49 +0200] "GET /foo?bar=1 HTTP/1.1" 200 52935 "-" "Mozilla/5.0"'
      )
    ).toMatchObject({
      ip: "47.82.14.57",
      method: "GET",
      target: "/foo?bar=1",
      path: "/foo",
      status: 200,
      bytes: 52935,
      referer: null,
      userAgent: "Mozilla/5.0"
    });
  });

  it("parses IPv6 and missing byte size", () => {
    expect(
      parseAccessLogLine(
        '2001:db8::1 - - [25/May/2026:03:12:51 +0200] "HEAD /health HTTP/2.0" 204 - "-" "-"'
      )
    ).toMatchObject({
      ip: "2001:db8::1",
      method: "HEAD",
      path: "/health",
      protocol: "HTTP/2.0",
      status: 204,
      bytes: null
    });
  });

  it("rejects non-access log lines", () => {
    expect(parseAccessLogLine('{"level":"info","message":"hello"}')).toBeNull();
  });
});
