import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  AccessLogIndexQueryCache,
  createAccessLogIndexWriter,
  passThroughFilter,
  readAccessLogIndexCachedPage,
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
        lines: [expect.objectContaining({ path: "/c" }), expect.objectContaining({ path: "/b" })]
      });

      await expect(
        readAccessLogIndexPage(writer.index, {
          filter: passThroughFilter,
          sortKey: "path",
          sortDirection: "asc",
          start: 1,
          limit: 1
        })
      ).resolves.toMatchObject({
        total: 3,
        lines: [expect.objectContaining({ path: "/b", row: 1 })]
      });

      const cache = new AccessLogIndexQueryCache();
      const cases = [
        ["ip", "asc", ["203.0.113.10", "203.0.113.10", "203.0.113.20"]],
        ["status", "desc", [404, 200, 200]],
        ["path", "desc", ["/c", "/b", "/a"]],
        ["bytes", "asc", [100, 200, 300]]
      ] as const;

      for (const [sortKey, sortDirection, expected] of cases) {
        const page = await readAccessLogIndexCachedPage(
          writer.index,
          cache,
          `${sortKey}:${sortDirection}`,
          {
            filter: passThroughFilter,
            sortKey,
            sortDirection,
            start: 0,
            limit: 3
          }
        );

        expect(page.total).toBe(3);
        expect(page.lines.map((line) => line[sortKey])).toEqual(expected);
      }
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
    row: lineNumber - 1,
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
