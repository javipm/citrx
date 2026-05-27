import { describe, expect, it, vi } from "vitest";

import type { Incident, IncidentLogLine } from "../../analysis/types.js";
import { handleIncidentScreenInput } from "./useIncidentScreenInput.js";

describe("incident export", () => {
  it("does not export while incident rows are still loading", async () => {
    const exportContext = vi.fn(async () => "incident.json");
    const setExportLoading = vi.fn();
    const setMessage = vi.fn();

    handleIncidentScreenInput({
      ...incidentInputDefaults(),
      inputValue: "e",
      exportReady: false,
      exportContext,
      setExportLoading,
      setMessage
    });

    await flushDeferredExport();

    expect(exportContext).not.toHaveBeenCalled();
    expect(setExportLoading).not.toHaveBeenCalled();
    expect(setMessage).toHaveBeenCalledWith("Still loading incident rows before export...");
  });

  it("shows export progress before writing selected rows", async () => {
    const selectedLine = line(7);
    const exportContext = vi.fn(async () => "incident.json");
    const setExportNotice = vi.fn();
    const setExportLoading = vi.fn();
    const setMessage = vi.fn();

    handleIncidentScreenInput({
      ...incidentInputDefaults(),
      inputValue: "e",
      lines: [line(1)],
      selectedLines: [selectedLine],
      exportContext,
      setExportNotice,
      setExportLoading,
      setMessage
    });

    expect(setExportLoading).toHaveBeenCalledWith(true);
    expect(setMessage).toHaveBeenCalledWith("Exporting JSON...");
    expect(exportContext).not.toHaveBeenCalled();

    await flushDeferredExport();

    expect(exportContext).toHaveBeenCalledWith("run-1", incident(), [selectedLine]);
    expect(setExportNotice).toHaveBeenCalledWith({ file: "incident.json", lines: 1 });
    expect(setExportLoading).toHaveBeenLastCalledWith(false);
    expect(setMessage).toHaveBeenLastCalledWith("Export OK: 1 rows saved");
  });
});

function incident(): Incident {
  return {
    id: "abusive_crawl:/hot",
    kind: "saturation",
    category: "abusive_crawling",
    severity: "high",
    score: 75,
    title: "Distributed URL saturation",
    description: "test",
    evidence: [],
    samples: []
  };
}

function line(row: number): IncidentLogLine {
  return {
    row,
    source: "access.log",
    lineNumber: row + 1,
    raw: `${row}`,
    ip: "198.51.100.10",
    timestamp: "2026-01-01T00:00:00.000Z",
    method: "GET",
    path: "/",
    target: "/",
    status: 200,
    bytes: 123,
    userAgent: "test"
  };
}

function incidentInputDefaults(): Parameters<typeof handleIncidentScreenInput>[0] {
  return {
    inputValue: "",
    key: {},
    incident: incident(),
    lines: [line(0)],
    selectedLines: [],
    lineIndex: 0,
    pageSize: 10,
    filter: "",
    sortKey: "timestamp",
    sortDirection: "desc",
    runId: "run-1",
    exportReady: true,
    setLineIndex: vi.fn(),
    setFilter: vi.fn(),
    setSelectedLineKeys: vi.fn(),
    setDetailLine: vi.fn(),
    setDetailScroll: vi.fn(),
    setSortMenu: vi.fn(),
    setTopScope: vi.fn(),
    setScreen: vi.fn(),
    setPrompt: vi.fn(),
    setExportNotice: vi.fn(),
    setExportLoading: vi.fn(),
    setMessage: vi.fn(),
    exportContext: vi.fn(async () => "incident.json")
  };
}

async function flushDeferredExport(): Promise<void> {
  await new Promise((resolve) => {
    setTimeout(resolve, 0);
  });
  await Promise.resolve();
}
