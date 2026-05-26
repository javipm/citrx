import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  createAccessLogIndexWriter,
  passThroughFilter,
  readAccessLogIndexPage
} from "./access-index.js";
import type { IncidentLogLine } from "../analysis/types.js";

describe("access log temp index", () => {
  it("pages timestamp order without scanning and supports filtered sorted reads", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-index-test-"));
    const writer = await createAccessLogIndexWriter(directory);

    try {
      for (const line of [
        accessLine(1, "203.0.113.10", "GET", "/a", 200, 100),
        accessLine(2, "203.0.113.20", "POST", "/b", 404, 300),
        accessLine(3, "203.0.113.10", "POST", "/c", 200, 200)
      ]) {
        writer.write(line);
      }

      writer.close();

      await expect(
        readAccessLogIndexPage(writer.index, {
          filter: passThroughFilter,
          sortKey: "timestamp",
          sortDirection: "desc",
          start: 0,
          limit: 2
        })
      ).resolves.toMatchObject({
        total: 3,
        lines: [
          expect.objectContaining({ lineNumber: 3 }),
          expect.objectContaining({ lineNumber: 2 })
        ]
      });

      await expect(
        readAccessLogIndexPage(writer.index, {
          filter: (line) => line.method === "POST",
          sortKey: "bytes",
          sortDirection: "asc",
          start: 0,
          limit: 10
        })
      ).resolves.toMatchObject({
        total: 2,
        lines: [
          expect.objectContaining({ path: "/c" }),
          expect.objectContaining({ path: "/b" })
        ]
      });
    } finally {
      writer.close();
      await rm(directory, { recursive: true, force: true });
    }
  });
});

function accessLine(
  lineNumber: number,
  ip: string,
  method: string,
  path: string,
  status: number,
  bytes: number
): IncidentLogLine {
  return {
    source: "/tmp/access.log",
    lineNumber,
    raw: `${ip} - - [25/May/2026:03:12:0${lineNumber} +0200] "${method} ${path} HTTP/1.1" ${status} ${bytes} "-" "UA"`,
    ip,
    timestamp: `25/May/2026:03:12:0${lineNumber} +0200`,
    method,
    path,
    target: path,
    status,
    bytes,
    userAgent: "UA"
  };
}
