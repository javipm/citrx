import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { detectParser, loadCustomParsers } from "./access-log.js";
import { getBuiltInParser } from "./built-in.js";

describe("access log parsers", () => {
  it("parses combined access logs", () => {
    const parser = getBuiltInParser("apache_combined");

    expect(
      parser.parse(
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

  it("parses common access logs", () => {
    const parser = getBuiltInParser("apache_common");

    expect(
      parser.parse('2001:db8::1 - - [25/May/2026:03:12:51 +0200] "HEAD /health HTTP/2.0" 204 -')
    ).toMatchObject({
      ip: "2001:db8::1",
      method: "HEAD",
      path: "/health",
      protocol: "HTTP/2.0",
      status: 204,
      bytes: null
    });
  });

  it("auto-detects a built-in format", () => {
    const detection = detectParser(
      [
        '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"',
        '203.0.113.11 - - [25/May/2026:03:12:50 +0200] "GET /foo HTTP/1.1" 404 42 "-" "Mozilla/5.0"'
      ],
      []
    );

    expect(detection?.parser.id).toBe("apache_combined");
    expect(detection?.parseRatio).toBe(1);
  });

  it("rejects non-access log lines", () => {
    const parser = getBuiltInParser("apache_combined");

    expect(parser.parse('{"level":"info","message":"hello"}')).toBeNull();
  });

  it("loads and parses custom formats", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-format-"));
    const configPath = join(directory, "formats.json");
    await writeFile(
      configPath,
      JSON.stringify({
        formats: [
          {
            name: "pipe",
            pattern:
              "^(?<ip>\\S+)\\|(?<timestamp>[^|]+)\\|(?<method>\\S+)\\|(?<target>\\S+)\\|(?<protocol>HTTP/[^|]+)\\|(?<status>\\d{3})\\|(?<bytes>\\S+)\\|(?<userAgent>.*)$",
            fields: {
              ip: "ip",
              timestamp: "timestamp",
              method: "method",
              target: "target",
              protocol: "protocol",
              status: "status",
              bytes: "bytes",
              userAgent: "userAgent"
            }
          }
        ]
      })
    );

    const [parser] = await loadCustomParsers(configPath);

    expect(parser?.id).toBe("custom:pipe");
    expect(
      parser?.parse(
        "198.51.100.3|25/May/2026:03:12:49 +0200|GET|/custom?x=1|HTTP/1.1|200|321|Custom UA"
      )
    ).toMatchObject({
      ip: "198.51.100.3",
      method: "GET",
      path: "/custom",
      status: 200,
      bytes: 321,
      userAgent: "Custom UA"
    });
  });
});
