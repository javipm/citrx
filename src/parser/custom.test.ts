import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { loadCustomParsers } from "./custom.js";

async function withTempDir(fn: (directory: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "citrx-custom-"));

  try {
    await fn(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("loadCustomParsers", () => {
  it("returns an empty array when no config path is given", async () => {
    expect(await loadCustomParsers(undefined)).toEqual([]);
  });

  it("parses a valid config with named groups", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "pipe",
              label: "Pipe format",
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

      const parsers = await loadCustomParsers(configFile);
      expect(parsers).toHaveLength(1);

      const parser = parsers[0]!;
      expect(parser.id).toBe("custom:pipe");
      expect(parser.label).toBe("Pipe format");

      const entry = parser.parse(
        "198.51.100.3|25/May/2026:03:12:49 +0200|GET|/custom?x=1|HTTP/1.1|200|321|Custom UA"
      );

      expect(entry).toMatchObject({
        ip: "198.51.100.3",
        timestamp: "25/May/2026:03:12:49 +0200",
        method: "GET",
        target: "/custom?x=1",
        status: 200,
        bytes: 321,
        userAgent: "Custom UA"
      });
    });
  });

  it("parses a valid config using the combined request field instead of method/target/protocol", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "combined-request",
              pattern:
                '^(?<ip>\\S+)\\s+\\[(?<timestamp>[^\\]]+)]\\s+"(?<request>[^"]*)"\\s+(?<status>\\d{3})$',
              fields: {
                ip: "ip",
                timestamp: "timestamp",
                request: "request",
                status: "status"
              }
            }
          ]
        })
      );

      const parsers = await loadCustomParsers(configFile);
      const entry = parsers[0]!.parse(
        '203.0.113.10 [25/May/2026:03:12:49 +0200] "GET /path HTTP/1.1" 200'
      );

      expect(entry).toMatchObject({
        ip: "203.0.113.10",
        method: "GET",
        target: "/path",
        protocol: "HTTP/1.1",
        status: 200
      });
    });
  });

  it("returns null when a line does not match the custom pattern", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "pipe",
              pattern:
                "^(?<ip>\\S+)\\|(?<timestamp>[^|]+)\\|(?<method>\\S+)\\|(?<target>\\S+)\\|(?<protocol>HTTP/[^|]+)\\|(?<status>\\d{3})$",
              fields: {
                ip: "ip",
                timestamp: "timestamp",
                method: "method",
                target: "target",
                protocol: "protocol",
                status: "status"
              }
            }
          ]
        })
      );

      const parsers = await loadCustomParsers(configFile);
      expect(parsers[0]!.parse("not matching at all")).toBeNull();
    });
  });

  it("rejects a config missing a required field (fields.ip)", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "broken",
              pattern: "^(?<timestamp>.+)$",
              fields: {
                timestamp: "timestamp",
                status: "status"
              }
            }
          ]
        })
      );

      await expect(loadCustomParsers(configFile)).rejects.toThrow();
    });
  });

  it("rejects a config missing method/target/protocol AND request", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "no-request-shape",
              pattern: "^(?<ip>\\S+)\\s+(?<timestamp>.+)\\s+(?<status>\\d{3})$",
              fields: {
                ip: "ip",
                timestamp: "timestamp",
                status: "status"
              }
            }
          ]
        })
      );

      await expect(loadCustomParsers(configFile)).rejects.toThrow(
        /fields\.request.*fields\.method.*fields\.target.*fields\.protocol/
      );
    });
  });

  it("rejects a config with an invalid format name", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "not a valid name!",
              pattern: "^(?<ip>\\S+)\\s+(?<timestamp>.+)\\s+(?<status>\\d{3})$",
              fields: {
                ip: "ip",
                timestamp: "timestamp",
                method: "method",
                target: "target",
                protocol: "protocol",
                status: "status"
              }
            }
          ]
        })
      );

      await expect(loadCustomParsers(configFile)).rejects.toThrow();
    });
  });

  it("rejects a config whose regex pattern string is syntactically invalid", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "invalid-regex",
              pattern: "^(?<ip>\\S+(",
              fields: {
                ip: "ip",
                timestamp: "timestamp",
                method: "method",
                target: "target",
                protocol: "protocol",
                status: "status"
              }
            }
          ]
        })
      );

      await expect(loadCustomParsers(configFile)).rejects.toThrow();
    });
  });

  it("rejects malformed JSON in the config file", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(configFile, "{not valid json");

      await expect(loadCustomParsers(configFile)).rejects.toThrow(
        /Invalid JSON in custom format config/
      );
    });
  });

  it("rejects an unanchored pattern", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "unanchored",
              pattern: "(?<ip>\\S+) (?<timestamp>.+) (?<status>\\d{3})",
              fields: {
                ip: "ip",
                timestamp: "timestamp",
                method: "method",
                target: "target",
                protocol: "protocol",
                status: "status"
              }
            }
          ]
        })
      );

      await expect(loadCustomParsers(configFile)).rejects.toThrow(/anchored/);
    });
  });

  it("rejects a field mapping to a missing named group", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "missing-group",
              pattern: "^(?<ip>\\S+)\\|(?<timestamp>[^|]+)\\|(?<status>\\d{3})$",
              fields: {
                ip: "ip",
                timestamp: "timestamp",
                method: "method",
                target: "target",
                protocol: "protocol",
                status: "status"
              }
            }
          ]
        })
      );

      await expect(loadCustomParsers(configFile)).rejects.toThrow(/named group "method"/);
    });
  });

  it("rejects numeric capture indices as field mappings", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "numeric",
              pattern: "^(\\S+)\\|([^|]+)\\|(GET)\\|(/\\S+)\\|(HTTP/\\S+)\\|(\\d{3})$",
              fields: {
                ip: "1",
                timestamp: "2",
                method: "3",
                target: "4",
                protocol: "5",
                status: "6"
              }
            }
          ]
        })
      );

      await expect(loadCustomParsers(configFile)).rejects.toThrow(/named group names/);
    });
  });

  it("rejects a pattern whose final $ is escaped", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "escaped-dollar",
              pattern:
                "^(?<ip>\\S+)\\|(?<timestamp>[^|]+)\\|(?<method>\\S+)\\|(?<target>\\S+)\\|(?<protocol>HTTP/[^|]+)\\|(?<status>\\d{3})\\$",
              fields: {
                ip: "ip",
                timestamp: "timestamp",
                method: "method",
                target: "target",
                protocol: "protocol",
                status: "status"
              }
            }
          ]
        })
      );

      await expect(loadCustomParsers(configFile)).rejects.toThrow(/anchored/);
    });
  });

  it("rejects nested optional quantifiers such as (a?)+", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "nested-optional",
              pattern:
                "^(?<ip>a?)+(?<timestamp>x)\\|(?<method>GET)\\|(?<target>/)\\|(?<protocol>HTTP/1.1)\\|(?<status>200)$",
              fields: {
                ip: "ip",
                timestamp: "timestamp",
                method: "method",
                target: "target",
                protocol: "protocol",
                status: "status"
              }
            }
          ]
        })
      );

      await expect(loadCustomParsers(configFile)).rejects.toThrow(/nested quantifiers/);
    });
  });

  it("rejects nested ranged quantifiers such as (a{1,3})+", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "nested-range",
              pattern:
                "^(?<ip>a{1,3})+(?<timestamp>x)\\|(?<method>GET)\\|(?<target>/)\\|(?<protocol>HTTP/1.1)\\|(?<status>200)$",
              fields: {
                ip: "ip",
                timestamp: "timestamp",
                method: "method",
                target: "target",
                protocol: "protocol",
                status: "status"
              }
            }
          ]
        })
      );

      await expect(loadCustomParsers(configFile)).rejects.toThrow(/nested quantifiers/);
    });
  });

  it("rejects nested quantifiers that can backtrack catastrophically", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "redos",
              pattern:
                "^(?<ip>\\S+)\\|(?<timestamp>(.+)+)\\|(?<method>\\S+)\\|(?<target>\\S+)\\|(?<protocol>HTTP/[^|]+)\\|(?<status>\\d{3})$",
              fields: {
                ip: "ip",
                timestamp: "timestamp",
                method: "method",
                target: "target",
                protocol: "protocol",
                status: "status"
              }
            }
          ]
        })
      );

      await expect(loadCustomParsers(configFile)).rejects.toThrow(/nested quantifiers/);
    });
  });

  it("parses optional host, requestTime, upstreamTime, and forwardedFor fields", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "nginx-extra",
              pattern:
                "^(?<ip>\\S+)\\|(?<timestamp>[^|]+)\\|(?<method>\\S+)\\|(?<target>\\S+)\\|(?<protocol>HTTP/[^|]+)\\|(?<status>\\d{3})\\|(?<host>[^|]+)\\|(?<requestTime>[^|]+)\\|(?<upstreamTime>[^|]+)\\|(?<forwardedFor>[^|]+)$",
              fields: {
                ip: "ip",
                timestamp: "timestamp",
                method: "method",
                target: "target",
                protocol: "protocol",
                status: "status",
                host: "host",
                requestTime: "requestTime",
                upstreamTime: "upstreamTime",
                forwardedFor: "forwardedFor"
              }
            }
          ]
        })
      );

      const parsers = await loadCustomParsers(configFile);
      expect(
        parsers[0]!.parse(
          "198.51.100.3|25/May/2026:03:12:49 +0200|GET|/x|HTTP/1.1|200|shop.test|0.012|0.010|203.0.113.1"
        )
      ).toMatchObject({
        host: "shop.test",
        requestTime: 0.012,
        upstreamTime: 0.01,
        forwardedFor: "203.0.113.1"
      });
    });
  });

  it("rejects a config with no formats", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(configFile, JSON.stringify({ formats: [] }));

      await expect(loadCustomParsers(configFile)).rejects.toThrow();
    });
  });

  it("throws a clear error when the config path does not exist", async () => {
    await withTempDir(async (directory) => {
      const missingFile = join(directory, "does-not-exist.json");

      await expect(loadCustomParsers(missingFile)).rejects.toThrow(/ENOENT/);
    });
  });

  it("rejects false anchors from top-level alternation", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "false-anchor",
              pattern: "^(?<ip>foo)|evil$",
              fields: {
                ip: "ip",
                timestamp: "timestamp",
                method: "method",
                target: "target",
                protocol: "protocol",
                status: "status"
              }
            }
          ]
        })
      );

      await expect(loadCustomParsers(configFile)).rejects.toThrow(/top-level alternation/);
    });
  });

  it("rejects quantified overlapping alternation that can backtrack catastrophically", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      await writeFile(
        configFile,
        JSON.stringify({
          formats: [
            {
              name: "overlap",
              pattern:
                "^(?<ip>a|aa)+(?<timestamp>x)\\|(?<method>GET)\\|(?<target>/)\\|(?<protocol>HTTP/1.1)\\|(?<status>200)$",
              fields: {
                ip: "ip",
                timestamp: "timestamp",
                method: "method",
                target: "target",
                protocol: "protocol",
                status: "status"
              }
            }
          ]
        })
      );

      await expect(loadCustomParsers(configFile)).rejects.toThrow(
        /quantified overlapping alternation|nested quantifiers/
      );
    });
  });

  it("rejects duplicate format names", async () => {
    await withTempDir(async (directory) => {
      const configFile = join(directory, "formats.json");
      const format = {
        name: "pipe",
        pattern:
          "^(?<ip>\\S+)\\|(?<timestamp>[^|]+)\\|(?<method>\\S+)\\|(?<target>\\S+)\\|(?<protocol>HTTP/[^|]+)\\|(?<status>\\d{3})$",
        fields: {
          ip: "ip",
          timestamp: "timestamp",
          method: "method",
          target: "target",
          protocol: "protocol",
          status: "status"
        }
      };
      await writeFile(configFile, JSON.stringify({ formats: [format, { ...format }] }));

      await expect(loadCustomParsers(configFile)).rejects.toThrow(/duplicate format name "pipe"/);
    });
  });
});
