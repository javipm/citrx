import { mkdtemp, writeFile } from "node:fs/promises";
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

    const code = await runCli(["node", "citrx", "analyze", logFile, "--json"], {
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
});
