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

  it("wires analyze with JSON output", async () => {
    const stdout = memoryStream();
    const stderr = memoryStream();

    const code = await runCli(
      ["node", "citrx", "analyze", "examples/access_ssl_log", "--json"],
      {
        stdout: stdout.stream,
        stderr: stderr.stream,
        stdinIsTTY: true
      }
    );

    expect(code).toBe(0);
    expect(JSON.parse(stdout.output())).toMatchObject({
      app: "citrx",
      phase: 0,
      status: "scaffold-ready",
      paths: ["examples/access_ssl_log"]
    });
    expect(stderr.output()).toBe("");
  });
});
