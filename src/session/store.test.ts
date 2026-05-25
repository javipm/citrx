import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import type { AnalyzeReport } from "../analysis/types.js";
import { deleteSession, listSessions, readSession, saveSession } from "./store.js";

function reportFixture(): AnalyzeReport {
  return {
    app: "citrx",
    phase: 1,
    status: "ok",
    generatedAt: "2026-05-25T00:00:00.000Z",
    inputs: ["/tmp/access.log"],
    inputFormats: [
      {
        file: "/tmp/access.log",
        format: "apache_combined",
        sampledLines: 1,
        parsedSampleLines: 1,
        sampleParseRatio: 1
      }
    ],
    summary: {
      files: 1,
      totalLines: 1,
      parsedLines: 1,
      filteredLines: 0,
      invalidLines: 0,
      totalBytes: 123
    },
    topIps: [{ value: "203.0.113.10", count: 1 }],
    topPaths: [{ value: "/", count: 1 }],
    topMethods: [{ value: "GET", count: 1 }],
    topStatuses: [{ value: "200", count: 1 }],
    incidents: []
  };
}

describe("session store", () => {
  it("saves, lists, reads, and deletes sessions", async () => {
    const sessionDir = await mkdtemp(join(tmpdir(), "citrx-sessions-"));
    const session = await saveSession(reportFixture(), ["/tmp/access.log"], sessionDir);

    expect(session.report.sessionId).toBe(session.id);
    await expect(readSession(session.id, sessionDir)).resolves.toMatchObject({
      id: session.id,
      sourcePaths: ["/tmp/access.log"],
      report: { sessionId: session.id }
    });
    await expect(listSessions(sessionDir)).resolves.toEqual([
      expect.objectContaining({
        id: session.id,
        files: 1,
        parsedLines: 1,
        formats: ["apache_combined"]
      })
    ]);

    await deleteSession(session.id, sessionDir);
    await expect(listSessions(sessionDir)).resolves.toEqual([]);
  });
});
