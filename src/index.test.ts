import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import { brotliCompressSync, crc32, gzipSync } from "node:zlib";
import * as tar from "tar-stream";
import { describe, expect, it } from "vitest";

import { runCli } from "./index.js";
import { VERSION } from "./version.js";

function memoryStream() {
  let output = "";
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      output += chunk.toString();
      callback();
    }
  });

  return {
    stream,
    output: () => output
  };
}

async function streamToBuffer(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];

  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  return Buffer.concat(chunks);
}

function createStoredZip(entryName: string, content: Buffer): Buffer {
  const name = Buffer.from(entryName);
  const checksum = crc32(content) >>> 0;
  const local = Buffer.alloc(30 + name.length);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 6);
  local.writeUInt16LE(0, 8);
  local.writeUInt16LE(0, 10);
  local.writeUInt16LE(0, 12);
  local.writeUInt32LE(checksum, 14);
  local.writeUInt32LE(content.length, 18);
  local.writeUInt32LE(content.length, 22);
  local.writeUInt16LE(name.length, 26);
  local.writeUInt16LE(0, 28);
  name.copy(local, 30);

  const central = Buffer.alloc(46 + name.length);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0, 8);
  central.writeUInt16LE(0, 10);
  central.writeUInt16LE(0, 12);
  central.writeUInt16LE(0, 14);
  central.writeUInt32LE(checksum, 16);
  central.writeUInt32LE(content.length, 20);
  central.writeUInt32LE(content.length, 24);
  central.writeUInt16LE(name.length, 28);
  central.writeUInt16LE(0, 30);
  central.writeUInt16LE(0, 32);
  central.writeUInt16LE(0, 34);
  central.writeUInt16LE(0, 36);
  central.writeUInt32LE(0, 38);
  central.writeUInt32LE(0, 42);
  name.copy(central, 46);

  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(local.length + content.length, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([local, content, central, end]);
}

describe("citrx CLI", () => {
  it("prints the version", async () => {
    const stdout = memoryStream();
    const stderr = memoryStream();

    const code = await runCli(["node", "citrx", "--version"], {
      stdout: stdout.stream,
      stderr: stderr.stream,
      stdinIsTTY: true
    });

    expect(code).toBe(0);
    expect(stdout.output().trim()).toBe(VERSION);
    expect(stderr.output()).toBe("");
  });

  it("prints help", async () => {
    const stdout = memoryStream();
    const stderr = memoryStream();

    const code = await runCli(["node", "citrx", "--help"], {
      stdout: stdout.stream,
      stderr: stderr.stream,
      stdinIsTTY: true
    });

    expect(code).toBe(0);
    expect(stdout.output()).toContain("Usage: citrx");
    expect(stdout.output()).not.toContain("session");
    expect(stderr.output()).toBe("");
  });

  it("does not expose the old analyze subcommand", async () => {
    const stderr = memoryStream();

    const code = await runCli(["node", "citrx", "analyze", "--json"], {
      stdout: memoryStream().stream,
      stderr: stderr.stream,
      stdinIsTTY: true
    });

    expect(code).toBe(1);
    expect(stderr.output()).toContain("analyze subcommand was removed");
  });

  it("analyzes an access log with JSON output", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const logFile = join(directory, "access.log");
    await writeFile(
      logFile,
      [
        '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /products?id=1 HTTP/1.1" 200 123 "-" "Mozilla/5.0"',
        '203.0.113.10 - - [25/May/2026:03:12:50 +0200] "POST /login HTTP/1.1" 302 42 "https://example.test/" "Mozilla/5.0"',
        '2001:db8::1 - - [25/May/2026:03:12:51 +0200] "GET /products?id=2 HTTP/1.1" 404 - "-" "-"'
      ].join("\n")
    );
    const stdout = memoryStream();
    const stderr = memoryStream();

    const code = await runCli(["node", "citrx", logFile, "--json"], {
      stdout: stdout.stream,
      stderr: stderr.stream,
      stdinIsTTY: true
    });

    expect(code).toBe(0);
    const report = JSON.parse(stdout.output()) as Record<string, unknown>;
    expect(report).toMatchObject({
      app: "citrx",
      phase: 1,
      status: "ok",
      inputFormats: [
        expect.objectContaining({
          format: "apache_combined",
          sampledLines: 3,
          parsedSampleLines: 3,
          sampleParseRatio: 1
        })
      ],
      summary: {
        files: 1,
        totalLines: 3,
        parsedLines: 3,
        filteredLines: 0,
        invalidLines: 0,
        totalBytes: 165
      },
      timeStats: expect.objectContaining({
        peakGlobalRps: 1,
        invalidTimestampLines: 0,
        outOfOrderTimestamps: 0,
        droppedIpCount: 0,
        droppedSubnetCount: 0
      }),
      ipBehaviorStats: expect.arrayContaining([
        expect.objectContaining({
          ip: "203.0.113.10",
          totalRequests: 2,
          peakRps: 1
        })
      ])
    });
    expect(report.topIps).toEqual(expect.arrayContaining([{ value: "203.0.113.10", count: 2 }]));
    expect(report.topPaths).toEqual(expect.arrayContaining([{ value: "/products", count: 2 }]));
    expect(report.incidents).toEqual([]);
    expect(stderr.output()).toBe("");
  });

  it("reports local security incidents", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const logFile = join(directory, "attack.log");
    await writeFile(
      logFile,
      [
        '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /search?q=1%20UNION%20SELECT%20password%20FROM%20information_schema HTTP/1.1" 200 123 "-" "Mozilla/5.0"',
        // 3 recon probes from same IP across 3 different paths — survives noise pruning.
        '203.0.113.11 - - [25/May/2026:03:12:50 +0200] "GET /.env?token=secret HTTP/1.1" 404 12 "-" "Mozilla/5.0"',
        '203.0.113.11 - - [25/May/2026:03:12:51 +0200] "GET /.git/config HTTP/1.1" 404 12 "-" "Mozilla/5.0"',
        '203.0.113.11 - - [25/May/2026:03:12:52 +0200] "GET /phpinfo.php HTTP/1.1" 404 12 "-" "Mozilla/5.0"'
      ].join("\n")
    );
    const stdout = memoryStream();

    const code = await runCli(["node", "citrx", logFile, "--json"], {
      stdout: stdout.stream,
      stderr: memoryStream().stream,
      stdinIsTTY: true
    });

    expect(code).toBe(0);
    const report = JSON.parse(stdout.output()) as {
      accessLog: {
        totalLines: number;
        indexedLines: number;
      };
      incidents: Array<{ id: string; samples: string[] }>;
      incidentMatches: Array<{
        incidentId: string;
        totalMatches: number;
        lines: Array<{ raw: string; path: string; lineNumber: number }>;
      }>;
    };

    // Incidents are now keyed by ruleId:ip (grouped per attacker, not per path).
    expect(report.incidents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "sqli:203.0.113.10" }),
        expect.objectContaining({ id: "recon_sensitive_file:203.0.113.11" })
      ])
    );
    expect(report.incidents.flatMap((incident) => incident.samples).join("\n")).toContain(
      "token=%5BREDACTED%5D"
    );
    expect(report.accessLog).toEqual(
      expect.objectContaining({
        totalLines: 4,
        indexedLines: 4
      })
    );
    expect(report.incidentMatches).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          incidentId: "sqli:203.0.113.10",
          totalMatches: 1,
          lines: [
            expect.objectContaining({
              path: "/search",
              raw: expect.stringContaining("UNION")
            })
          ]
        }),
        expect.objectContaining({
          incidentId: "recon_sensitive_file:203.0.113.11",
          totalMatches: 3,
          lines: expect.arrayContaining([
            expect.objectContaining({
              raw: expect.stringContaining("token=[REDACTED]")
            })
          ])
        })
      ])
    );
  });

  it("rejects removed --incident-lines option", async () => {
    const stderr = memoryStream();

    const code = await runCli(["node", "citrx", "--incident-lines", "2"], {
      stdout: memoryStream().stream,
      stderr: stderr.stream,
      stdinIsTTY: true
    });

    expect(code).toBe(1);
    expect(stderr.output()).toContain("unknown option '--incident-lines'");
  });

  it("rejects removed --geo option", async () => {
    const stderr = memoryStream();

    const code = await runCli(["node", "citrx", "--geo"], {
      stdout: memoryStream().stream,
      stderr: stderr.stream,
      stdinIsTTY: true
    });

    expect(code).toBe(1);
    expect(stderr.output()).toContain("unknown option '--geo'");
  });

  it("rejects removed --no-session option", async () => {
    const stderr = memoryStream();

    const code = await runCli(["node", "citrx", "--no-session"], {
      stdout: memoryStream().stream,
      stderr: stderr.stream,
      stdinIsTTY: true
    });

    expect(code).toBe(1);
    expect(stderr.output()).toContain("unknown option '--no-session'");
  });

  it("writes Markdown and HTML reports", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-output-"));
    const logFile = join(directory, "access.log");
    const htmlFile = join(directory, "report.html");
    await writeFile(
      logFile,
      // Multiple recon paths from one IP — survives noise pruning.
      [
        '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /.env?token=secret HTTP/1.1" 404 12 "-" "Mozilla/5.0"',
        '203.0.113.10 - - [25/May/2026:03:12:50 +0200] "GET /.git/config HTTP/1.1" 404 12 "-" "Mozilla/5.0"',
        '203.0.113.10 - - [25/May/2026:03:12:51 +0200] "GET /phpinfo.php HTTP/1.1" 404 12 "-" "Mozilla/5.0"'
      ].join("\n") + "\n"
    );

    const markdownOut = memoryStream();
    const markdownCode = await runCli(["node", "citrx", logFile, "--markdown"], {
      stdout: markdownOut.stream,
      stderr: memoryStream().stream,
      stdinIsTTY: true
    });

    expect(markdownCode).toBe(0);
    expect(markdownOut.output()).toContain("# citrx access log analysis");
    expect(markdownOut.output()).toContain("Sensitive file probe");

    const htmlCode = await runCli(["node", "citrx", logFile, "--html", "--out", htmlFile], {
      stdout: memoryStream().stream,
      stderr: memoryStream().stream,
      stdinIsTTY: true
    });

    expect(htmlCode).toBe(0);
    const html = await readFile(htmlFile, "utf8");
    expect(html).toContain("<!doctype html>");
    expect(html).toContain("citrx access log analysis");
    expect(html).toContain("Sensitive file probe");
    expect(html).not.toMatch(/https?:\/\//);
  });

  it("rejects multiple report output formats", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-output-"));
    const logFile = join(directory, "access.log");
    await writeFile(
      logFile,
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET / HTTP/1.1" 200 12 "-" "Mozilla/5.0"\n'
    );
    const stderr = memoryStream();

    const code = await runCli(["node", "citrx", logFile, "--json", "--html"], {
      stdout: memoryStream().stream,
      stderr: stderr.stream,
      stdinIsTTY: true
    });

    expect(code).toBe(1);
    expect(stderr.output()).toContain("Choose only one output format");
  });

  it("requires input paths when no stdin is piped", async () => {
    const stderr = memoryStream();

    const code = await runCli(["node", "citrx"], {
      stdout: memoryStream().stream,
      stderr: stderr.stream,
      stdinIsTTY: true
    });

    expect(code).toBe(1);
    expect(stderr.output()).toContain("No input paths provided");
  });

  it("requires input paths when flags are provided without paths", async () => {
    const stderr = memoryStream();

    const code = await runCli(["node", "citrx", "--json"], {
      stdout: memoryStream().stream,
      stderr: stderr.stream,
      stdinIsTTY: true
    });

    expect(code).toBe(1);
    expect(stderr.output()).toContain("No input paths provided.");
  });

  it("opens the interactive explorer by default on a TTY", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const logFile = join(directory, "access.log");
    await writeFile(
      logFile,
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /.env HTTP/1.1" 404 123 "-" "Mozilla/5.0"\n'
    );
    const opened: string[] = [];
    const tempDirs: string[] = [];

    const code = await runCli(["node", "citrx", logFile], {
      stdout: memoryStream().stream,
      stderr: memoryStream().stream,
      stdinIsTTY: true,
      openInteractive: async (run) => {
        opened.push(run.id);
        tempDirs.push(run.tempDir);
        await expect(stat(run.tempDir)).resolves.toMatchObject({
          isDirectory: expect.any(Function)
        });
      }
    });

    expect(code).toBe(0);
    expect(opened).toHaveLength(1);
    await expect(stat(tempDirs[0] ?? "")).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("prints the terminal report when --no-interactive is used", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const logFile = join(directory, "access.log");
    await writeFile(
      logFile,
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /plain HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n'
    );
    const stdout = memoryStream();
    const opened: string[] = [];

    const code = await runCli(["node", "citrx", logFile, "--no-interactive"], {
      stdout: stdout.stream,
      stderr: memoryStream().stream,
      stdinIsTTY: true,
      openInteractive: async (run) => {
        opened.push(run.id);
      }
    });

    expect(code).toBe(0);
    expect(opened).toEqual([]);
    // Strip ANSI codes before checking — color may be enabled depending on env.
    const plainOutput = stdout.output().replace(/\[[0-9;]*m/g, "");
    expect(plainOutput).toContain("citrx access log analysis");
    expect(plainOutput).toContain("/plain");
  });

  it("reads access logs from stdin", async () => {
    const stdout = memoryStream();
    const stderr = memoryStream();
    const input = Readable.from([
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /stdin HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n'
    ]);

    const code = await runCli(["node", "citrx", "-", "--json"], {
      stdout: stdout.stream,
      stderr: stderr.stream,
      stdin: input,
      stdinIsTTY: false
    });

    expect(code).toBe(0);
    expect(JSON.parse(stdout.output())).toMatchObject({
      inputs: ["-"],
      summary: {
        totalLines: 1,
        parsedLines: 1,
        totalBytes: 123
      },
      topPaths: [{ value: "/stdin", count: 1 }]
    });
    expect(stderr.output()).toBe("");
  });

  it("reads piped stdin when no paths are provided", async () => {
    const stdout = memoryStream();
    const input = Readable.from([
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /implicit-stdin HTTP/1.1" 200 10 "-" "Mozilla/5.0"\n'
    ]);

    const code = await runCli(["node", "citrx", "--json"], {
      stdout: stdout.stream,
      stderr: memoryStream().stream,
      stdin: input,
      stdinIsTTY: false
    });

    expect(code).toBe(0);
    expect(JSON.parse(stdout.output())).toMatchObject({
      inputs: ["-"],
      topPaths: [{ value: "/implicit-stdin", count: 1 }]
    });
  });

  it("applies since and until filters", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const logFile = join(directory, "access.log");
    await writeFile(
      logFile,
      [
        '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /old HTTP/1.1" 200 100 "-" "Mozilla/5.0"',
        '203.0.113.10 - - [25/May/2026:04:12:49 +0200] "GET /kept HTTP/1.1" 200 200 "-" "Mozilla/5.0"',
        '203.0.113.10 - - [25/May/2026:05:12:49 +0200] "GET /new HTTP/1.1" 200 300 "-" "Mozilla/5.0"'
      ].join("\n")
    );
    const stdout = memoryStream();

    const code = await runCli(
      [
        "node",
        "citrx",
        logFile,
        "--json",
        "--since",
        "2026-05-25T02:00:00Z",
        "--until",
        "2026-05-25T02:30:59Z"
      ],
      {
        stdout: stdout.stream,
        stderr: memoryStream().stream,
        stdinIsTTY: true
      }
    );

    expect(code).toBe(0);
    expect(JSON.parse(stdout.output())).toMatchObject({
      summary: {
        totalLines: 3,
        parsedLines: 1,
        filteredLines: 2,
        totalBytes: 200
      },
      topPaths: [{ value: "/kept", count: 1 }]
    });
  });

  it("discovers access logs inside directories", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-dir-"));
    await writeFile(
      join(directory, "a.log"),
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /a HTTP/1.1" 200 10 "-" "Mozilla/5.0"\n'
    );
    await writeFile(
      join(directory, "b.log"),
      '203.0.113.11 - - [25/May/2026:03:12:50 +0200] "GET /b HTTP/1.1" 200 20 "-" "Mozilla/5.0"\n'
    );
    const stdout = memoryStream();

    const code = await runCli(["node", "citrx", directory, "--json"], {
      stdout: stdout.stream,
      stderr: memoryStream().stream,
      stdinIsTTY: true
    });

    expect(code).toBe(0);
    expect(JSON.parse(stdout.output())).toMatchObject({
      summary: {
        files: 2,
        totalLines: 2,
        parsedLines: 2,
        totalBytes: 30
      }
    });
  });

  it("analyzes compressed access logs", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-compressed-"));
    const content = Buffer.from(
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /compressed HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n'
    );
    const tarPack = tar.pack();
    tarPack.entry({ name: "access.log" }, content);
    tarPack.finalize();

    const cases = [
      ["access.log.gz", gzipSync(content)],
      ["access.log.br", brotliCompressSync(content)],
      ["access.zip", createStoredZip("access.log", content)],
      ["access.tar.gz", gzipSync(await streamToBuffer(tarPack))]
    ] as const;

    for (const [name, data] of cases) {
      const logFile = join(directory, name);
      await writeFile(logFile, data);
      const stdout = memoryStream();

      const code = await runCli(["node", "citrx", logFile, "--json"], {
        stdout: stdout.stream,
        stderr: memoryStream().stream,
        stdinIsTTY: true
      });

      expect(code, name).toBe(0);
      expect(JSON.parse(stdout.output()), name).toMatchObject({
        summary: {
          files: 1,
          totalLines: 1,
          parsedLines: 1,
          totalBytes: 123
        },
        topPaths: [{ value: "/compressed", count: 1 }]
      });
    }
  });

  it("rejects files that are not access logs", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const logFile = join(directory, "app.log");
    await writeFile(
      logFile,
      [
        '{"level":"info","message":"booted"}',
        "Error: application failed",
        "    at service.ts:10:1"
      ].join("\n")
    );
    const stdout = memoryStream();
    const stderr = memoryStream();

    const code = await runCli(["node", "citrx", logFile], {
      stdout: stdout.stream,
      stderr: stderr.stream,
      stdinIsTTY: true
    });

    expect(code).toBe(1);
    expect(stdout.output()).toBe("");
    expect(stderr.output()).toContain("does not look like an Apache/Nginx access log");
  });

  it("analyzes logs with a custom format config", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const logFile = join(directory, "custom.log");
    const configFile = join(directory, "formats.json");
    await writeFile(
      logFile,
      [
        "198.51.100.3|25/May/2026:03:12:49 +0200|GET|/custom?x=1|HTTP/1.1|200|321|Custom UA",
        "198.51.100.4|25/May/2026:03:12:50 +0200|POST|/checkout|HTTP/1.1|500|12|Custom UA"
      ].join("\n")
    );
    await writeFile(
      configFile,
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
    const stdout = memoryStream();
    const stderr = memoryStream();

    const code = await runCli(
      [
        "node",
        "citrx",
        logFile,
        "--format",
        "custom:pipe",
        "--format-config",
        configFile,
        "--json"
      ],
      {
        stdout: stdout.stream,
        stderr: stderr.stream,
        stdinIsTTY: true
      }
    );

    expect(code).toBe(0);
    expect(JSON.parse(stdout.output())).toMatchObject({
      inputFormats: [expect.objectContaining({ format: "custom:pipe" })],
      summary: {
        totalLines: 2,
        parsedLines: 2,
        filteredLines: 0,
        totalBytes: 333
      },
      topPaths: [
        { value: "/checkout", count: 1 },
        { value: "/custom", count: 1 }
      ]
    });
    expect(stderr.output()).toBe("");
  });
});
