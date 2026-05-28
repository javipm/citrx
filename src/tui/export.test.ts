import { describe, expect, it } from "vitest";

import type { IncidentLogLine } from "../analysis/types.js";
import { serializeExport } from "./export.js";

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

function line(): IncidentLogLine {
  return {
    row: 1,
    source: "access.log",
    lineNumber: 2,
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
