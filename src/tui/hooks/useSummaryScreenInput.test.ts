import { describe, expect, it, vi } from "vitest";

import type { Incident, IncidentLogLine } from "../../analysis/types.js";
import {
  defaultSummaryFocus,
  firstIncidentIndexForFocus,
  handleSummaryScreenInput
} from "./useSummaryScreenInput.js";

describe("summary incident focus", () => {
  it("defaults to saturation when saturation incidents exist", () => {
    const incidents = [
      incident("sqli:1", "compromise"),
      incident("abusive_crawl:/hot", "saturation"),
      incident("query_explosion:/hot", "noise")
    ];

    expect(defaultSummaryFocus(incidents)).toBe("saturation");
    expect(firstIncidentIndexForFocus(incidents, defaultSummaryFocus(incidents))).toBe(1);
  });

  it("falls back to accesses when no incidents exist", () => {
    expect(defaultSummaryFocus([])).toBe("accesses");
    expect(firstIncidentIndexForFocus([], "accesses")).toBe(0);
  });
});

describe("summary export", () => {
  it("opens the export menu when no rows are selected", () => {
    const exportContext = vi.fn(async () => "selected.json");
    const exportAllFilteredContext = vi.fn(async () => ({ file: "all.json", lines: 42 }));
    const setExportMenu = vi.fn();
    const setExportLoading = vi.fn();
    const setMessage = vi.fn();

    handleSummaryScreenInput({
      ...summaryInputDefaults(),
      inputValue: "e",
      selectedGlobalLines: [],
      setExportMenu,
      setExportLoading,
      setMessage
    });

    expect(setExportMenu).toHaveBeenCalledWith({ format: "json" });
    expect(setMessage).toHaveBeenCalledWith("Choose export format");
    expect(setExportLoading).not.toHaveBeenCalled();
    expect(exportContext).not.toHaveBeenCalled();
    expect(exportAllFilteredContext).not.toHaveBeenCalled();
  });

  it("opens the export menu for selected rows", () => {
    const selectedLine = line(7);
    const exportContext = vi.fn(async () => "selected.json");
    const exportAllFilteredContext = vi.fn(async () => ({ file: "all.json", lines: 42 }));
    const setExportMenu = vi.fn();
    const setExportLoading = vi.fn();
    const setMessage = vi.fn();

    handleSummaryScreenInput({
      ...summaryInputDefaults(),
      inputValue: "e",
      selectedGlobalLines: [selectedLine],
      setExportMenu,
      setExportLoading,
      setMessage
    });

    expect(setExportMenu).toHaveBeenCalledWith({ format: "json" });
    expect(setMessage).toHaveBeenCalledWith("Choose export format for selected rows");
    expect(setExportLoading).not.toHaveBeenCalled();
    expect(exportContext).not.toHaveBeenCalled();
    expect(exportAllFilteredContext).not.toHaveBeenCalled();
  });
});

function incident(id: string, kind: Incident["kind"]): Incident {
  return {
    id,
    kind,
    category: "test",
    severity: "medium",
    score: 50,
    title: id,
    description: id,
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

function summaryInputDefaults(): Parameters<typeof handleSummaryScreenInput>[0] {
  return {
    inputValue: "",
    key: {},
    incidents: [],
    incident: undefined,
    summaryFocus: "accesses",
    summaryPageLines: [line(0)],
    summaryLineIndex: 0,
    computedSummaryPageStart: 0,
    globalTotal: 1,
    summaryPageSize: 10,
    selectedGlobalLines: [],
    filter: "",
    sortKey: "timestamp",
    sortDirection: "desc",
    runId: "run-1",
    setSummaryFocus: vi.fn(),
    setIncidentIndex: vi.fn(),
    setSummaryLineIndex: vi.fn(),
    setScreen: vi.fn(),
    setLineIndex: vi.fn(),
    setFilter: vi.fn(),
    setSelection: vi.fn(),
    setDetailLine: vi.fn(),
    setDetailScroll: vi.fn(),
    setSortMenu: vi.fn(),
    setTopScope: vi.fn(),
    setPrompt: vi.fn(),
    setExportMenu: vi.fn(),
    setMessage: vi.fn()
  };
}
