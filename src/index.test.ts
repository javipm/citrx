import { mkdtemp, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
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
    expect(stdout.output()).toContain("analyze");
    expect(stderr.output()).toBe("");
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

    const code = await runCli(
      ["node", "citrx", "analyze", logFile, "--json", "--no-session"],
      {
        stdout: stdout.stream,
        stderr: stderr.stream,
        stdinIsTTY: true
      }
    );

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
        invalidLines: 0,
        totalBytes: 165
      }
    });
    expect(report.topIps).toEqual(
      expect.arrayContaining([{ value: "203.0.113.10", count: 2 }])
    );
    expect(report.topPaths).toEqual(
      expect.arrayContaining([{ value: "/products", count: 2 }])
    );
    expect(stderr.output()).toBe("");
  });

  it("persists analysis sessions by default", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const sessionDir = join(directory, "sessions");
    const logFile = join(directory, "access.log");
    await writeFile(
      logFile,
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n'
    );
    const stdout = memoryStream();
    const stderr = memoryStream();

    const analyzeCode = await runCli(["node", "citrx", "analyze", logFile, "--json"], {
      stdout: stdout.stream,
      stderr: stderr.stream,
      stdinIsTTY: true,
      env: { CITRX_SESSION_DIR: sessionDir }
    });

    expect(analyzeCode).toBe(0);
    const report = JSON.parse(stdout.output()) as { sessionId: string };
    expect(report.sessionId).toMatch(/^[a-f0-9-]+$/);
    await expect(readdir(sessionDir)).resolves.toEqual([`${report.sessionId}.json`]);

    const listOut = memoryStream();
    const listCode = await runCli(["node", "citrx", "session", "list", "--json"], {
      stdout: listOut.stream,
      stderr: memoryStream().stream,
      stdinIsTTY: true,
      env: { CITRX_SESSION_DIR: sessionDir }
    });

    expect(listCode).toBe(0);
    expect(JSON.parse(listOut.output())).toMatchObject({
      sessions: [expect.objectContaining({ id: report.sessionId, parsedLines: 1 })]
    });

    const showOut = memoryStream();
    const showCode = await runCli(
      ["node", "citrx", "session", "show", report.sessionId, "--json"],
      {
        stdout: showOut.stream,
        stderr: memoryStream().stream,
        stdinIsTTY: true,
        env: { CITRX_SESSION_DIR: sessionDir }
      }
    );

    expect(showCode).toBe(0);
    expect(JSON.parse(showOut.output())).toMatchObject({
      id: report.sessionId,
      report: { sessionId: report.sessionId }
    });

    const deleteCode = await runCli(["node", "citrx", "session", "delete", report.sessionId], {
      stdout: memoryStream().stream,
      stderr: memoryStream().stream,
      stdinIsTTY: true,
      env: { CITRX_SESSION_DIR: sessionDir }
    });

    expect(deleteCode).toBe(0);
    await expect(readdir(sessionDir)).resolves.toEqual([]);
  });

  it("skips session persistence with --no-session", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-"));
    const sessionDir = join(directory, "sessions");
    const logFile = join(directory, "access.log");
    await writeFile(
      logFile,
      '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n'
    );
    const stdout = memoryStream();

    const code = await runCli(
      ["node", "citrx", "analyze", logFile, "--json", "--no-session"],
      {
        stdout: stdout.stream,
        stderr: memoryStream().stream,
        stdinIsTTY: true,
        env: { CITRX_SESSION_DIR: sessionDir }
      }
    );

    expect(code).toBe(0);
    expect(JSON.parse(stdout.output())).not.toHaveProperty("sessionId");
    await expect(readdir(sessionDir)).rejects.toMatchObject({ code: "ENOENT" });
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

    const code = await runCli(["node", "citrx", "analyze", logFile], {
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
        "analyze",
        logFile,
        "--format",
        "custom:pipe",
        "--format-config",
        configFile,
        "--json",
        "--no-session"
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
