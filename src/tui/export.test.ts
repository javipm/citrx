import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";

import type { IncidentLogLine } from "../analysis/types.js";
import { createAccessLogIndexWriter, arrayOrderedRowNumbers } from "../run/access-index.js";
import type { CitrxRun } from "../run/types.js";
import { serializeExport, streamSerializeExport } from "./export.js";

describe("serializeExport", () => {
  it("keeps the existing JSON shape", () => {
    expect(JSON.parse(serializeExport(undefined, [line()], "json"))).toEqual({
      lines: [line()]
    });
  });

  it("serializes CSV with escaped cells", () => {
    const csv = serializeExport(
      undefined,
      [{ ...line(), target: "/a,b", userAgent: 'bot "x"' }],
      "csv"
    );

    expect(csv.split("\n")[0]).toBe(
      "row,source,lineNumber,timestamp,ip,method,target,path,status,bytes,userAgent,raw"
    );
    expect(csv).toContain('"/a,b"');
    expect(csv).toContain('"bot ""x"""');
  });

  it("serializes TSV using tab separators", () => {
    const tsv = serializeExport(undefined, [line()], "tsv");

    expect(tsv.split("\n")[0]).toBe(
      "row\tsource\tlineNumber\ttimestamp\tip\tmethod\ttarget\tpath\tstatus\tbytes\tuserAgent\traw"
    );
  });
});

describe("streamSerializeExport", () => {
  async function makeIndex(lines: IncidentLogLine[]) {
    const directory = await mkdtemp(join(tmpdir(), "citrx-export-test-"));
    const writer = await createAccessLogIndexWriter(directory);
    for (const l of lines) writer.write(l);
    writer.close();
    return { index: writer.index, directory };
  }

  async function collectStream(fn: (s: PassThrough) => Promise<void>): Promise<string> {
    const stream = new PassThrough();
    const chunks: Buffer[] = [];
    stream.on("data", (c: Buffer) => chunks.push(c));
    await fn(stream);
    return Buffer.concat(chunks).toString("utf8");
  }

  it("streams valid JSON output", async () => {
    const ls = [line(1), line(2)];
    const { index, directory } = await makeIndex(ls);

    try {
      const run = { accessIndex: index } as unknown as CitrxRun;
      const rowNumbers = arrayOrderedRowNumbers([0, 1]);

      const output = await collectStream(async (s) => {
        await streamSerializeExport(undefined, { run, orderedRowNumbers: rowNumbers }, "json", s);
      });

      const parsed = JSON.parse(output) as { lines: IncidentLogLine[] };
      expect(parsed.lines).toHaveLength(2);
      expect(parsed.lines[0]!.row).toBe(0);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("streams valid CSV output with header row", async () => {
    const ls = [line(1)];
    const { index, directory } = await makeIndex(ls);

    try {
      const run = { accessIndex: index } as unknown as CitrxRun;
      const rowNumbers = arrayOrderedRowNumbers([0]);

      const output = await collectStream(async (s) => {
        await streamSerializeExport(undefined, { run, orderedRowNumbers: rowNumbers }, "csv", s);
      });

      const rows = output.trim().split("\n");
      expect(rows[0]).toBe(
        "row,source,lineNumber,timestamp,ip,method,target,path,status,bytes,userAgent,raw"
      );
      expect(rows).toHaveLength(2);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("streams valid TSV output with header row", async () => {
    const ls = [line(1)];
    const { index, directory } = await makeIndex(ls);

    try {
      const run = { accessIndex: index } as unknown as CitrxRun;
      const rowNumbers = arrayOrderedRowNumbers([0]);

      const output = await collectStream(async (s) => {
        await streamSerializeExport(undefined, { run, orderedRowNumbers: rowNumbers }, "tsv", s);
      });

      const rows = output.trim().split("\n");
      expect(rows[0]).toBe(
        "row\tsource\tlineNumber\ttimestamp\tip\tmethod\ttarget\tpath\tstatus\tbytes\tuserAgent\traw"
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("aborts mid-stream and throws AbortError", async () => {
    const ls = [line(1), line(2), line(3)];
    const { index, directory } = await makeIndex(ls);

    try {
      const run = { accessIndex: index } as unknown as CitrxRun;
      const rowNumbers = arrayOrderedRowNumbers([0, 1, 2]);
      const controller = new AbortController();
      controller.abort(); // abort immediately

      const stream = new PassThrough();
      await expect(
        streamSerializeExport(undefined, { run, orderedRowNumbers: rowNumbers }, "json", stream, {
          signal: controller.signal
        })
      ).rejects.toMatchObject({ name: "AbortError" });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("reports progress", async () => {
    const ls = [line(1), line(2)];
    const { index, directory } = await makeIndex(ls);

    try {
      const run = { accessIndex: index } as unknown as CitrxRun;
      const rowNumbers = arrayOrderedRowNumbers([0, 1]);
      const progress: Array<[number, number]> = [];

      const stream = new PassThrough();
      stream.resume();
      await streamSerializeExport(
        undefined,
        { run, orderedRowNumbers: rowNumbers },
        "csv",
        stream,
        {
          onProgress: (done, total) => progress.push([done, total])
        }
      );

      // Final progress call at completion
      expect(progress[progress.length - 1]).toEqual([2, 2]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

function line(row = 1): IncidentLogLine {
  return {
    row,
    source: "access.log",
    lineNumber: row + 1,
    raw: '198.51.100.10 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "UA"',
    ip: "198.51.100.10",
    timestamp: "2026-01-01T00:00:00.000Z",
    method: "GET",
    path: "/",
    target: "/",
    status: 200,
    bytes: 123,
    userAgent: "UA"
  };
}
