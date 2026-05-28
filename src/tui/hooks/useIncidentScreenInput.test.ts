import { describe, expect, it, vi } from "vitest";

import type { Incident, IncidentLogLine } from "../../analysis/types.js";
import { handleIncidentScreenInput } from "./useIncidentScreenInput.js";
import { lineKey } from "../utils/table.js";

describe("incident export", () => {
  it("opens export menu when no rows selected but incident loaded", () => {
    const setExportMenu = vi.fn();
    const setMessage = vi.fn();

    handleIncidentScreenInput({
      ...incidentInputDefaults(),
      inputValue: "e",
      selectedLines: [],
      total: 5,
      setExportMenu,
      setMessage
    });

    expect(setExportMenu).toHaveBeenCalledWith({ format: "json" });
    expect(setMessage).toHaveBeenCalledWith("Choose export format");
  });

  it("opens the export menu for selected rows", () => {
    const selectedLine = line(7);
    const setExportMenu = vi.fn();
    const setMessage = vi.fn();

    handleIncidentScreenInput({
      ...incidentInputDefaults(),
      inputValue: "e",
      selectedLines: [selectedLine],
      setExportMenu,
      setMessage
    });

    expect(setExportMenu).toHaveBeenCalledWith({ format: "json" });
    expect(setMessage).toHaveBeenCalledWith("Choose export format for selected rows");
  });
});

describe("incident navigation", () => {
  it("clamps cursor to total on down arrow", () => {
    const setLineIndex = vi.fn();

    handleIncidentScreenInput({
      ...incidentInputDefaults(),
      inputValue: "",
      key: { downArrow: true },
      lineIndex: 4,
      total: 5,
      setLineIndex
    });

    // total-1 = 4, so setLineIndex updater should clamp to 4
    const updater = (setLineIndex.mock.calls[0] as [Function])[0] as (v: number) => number;
    expect(updater(4)).toBe(4);
    expect(updater(3)).toBe(4);
  });

  it("does not abort on Escape (global abort handles this now)", () => {
    // Esc in the new design is handled by app.ts activeAbort check before
    // handleIncidentScreenInput is called; the handler itself just returns.
    const setMessage = vi.fn();

    handleIncidentScreenInput({
      ...incidentInputDefaults(),
      inputValue: "",
      key: { escape: true },
      setMessage
    });

    // No abort called, no message set — caller handles it
    expect(setMessage).not.toHaveBeenCalled();
  });
});

describe("A select-all", () => {
  it("merges page lines into selection map when above limit", () => {
    const setSelection = vi.fn();
    const setMessage = vi.fn();
    const pages = [line(10), line(11), line(12)];

    handleIncidentScreenInput({
      ...incidentInputDefaults(),
      inputValue: "A",
      pageLines: pages,
      total: 10000, // above INCIDENT_SELECT_ALL_LIMIT → page-only path
      setSelection,
      setMessage
    });

    expect(setSelection).toHaveBeenCalledOnce();
    // The updater should add the 3 lines to an empty map
    const updater = (setSelection.mock.calls[0] as [Function])[0] as (
      v: Map<string, IncidentLogLine>
    ) => Map<string, IncidentLogLine>;
    const result = updater(new Map());
    expect(result.size).toBe(3);
    expect(result.has(lineKey(pages[0]!))).toBe(true);
    expect(setMessage).toHaveBeenCalledWith("Selected 3 visible lines");
  });

  it("calls onSelectAll when total is within limit", () => {
    const onSelectAll = vi.fn();
    const setSelection = vi.fn();
    const setMessage = vi.fn();
    const pages = [line(10), line(11)];

    handleIncidentScreenInput({
      ...incidentInputDefaults(),
      inputValue: "A",
      pageLines: pages,
      total: 100, // within INCIDENT_SELECT_ALL_LIMIT
      setSelection,
      setMessage,
      onSelectAll
    });

    expect(onSelectAll).toHaveBeenCalledOnce();
    expect(setSelection).not.toHaveBeenCalled();
  });

  it("falls back to page-only if onSelectAll not provided", () => {
    const setSelection = vi.fn();
    const setMessage = vi.fn();
    const pages = [line(10)];

    handleIncidentScreenInput({
      ...incidentInputDefaults(),
      inputValue: "A",
      pageLines: pages,
      total: 100, // within limit but no onSelectAll
      setSelection,
      setMessage
      // onSelectAll not provided
    });

    expect(setSelection).toHaveBeenCalledOnce();
    expect(setMessage).toHaveBeenCalledWith("Selected 1 visible lines");
  });
});

describe("Space selection", () => {
  it("toggles a line into the selection map", () => {
    const setSelection = vi.fn();
    const lineToSelect = line(5);

    handleIncidentScreenInput({
      ...incidentInputDefaults(),
      inputValue: " ",
      pageLines: [lineToSelect],
      lineIndex: 0,
      pageStart: 0,
      setSelection
    });

    const updater = (setSelection.mock.calls[0] as [Function])[0] as (
      v: Map<string, IncidentLogLine>
    ) => Map<string, IncidentLogLine>;
    const result = updater(new Map());
    expect(result.size).toBe(1);
    expect(result.has(lineKey(lineToSelect))).toBe(true);
  });

  it("removes a line already in the selection map", () => {
    const setSelection = vi.fn();
    const lineToDeselect = line(5);
    const existing = new Map([[lineKey(lineToDeselect), lineToDeselect]]);

    handleIncidentScreenInput({
      ...incidentInputDefaults(),
      inputValue: " ",
      pageLines: [lineToDeselect],
      lineIndex: 0,
      pageStart: 0,
      setSelection
    });

    const updater = (setSelection.mock.calls[0] as [Function])[0] as (
      v: Map<string, IncidentLogLine>
    ) => Map<string, IncidentLogLine>;
    const result = updater(existing);
    expect(result.size).toBe(0);
  });
});

describe("r reset", () => {
  it("resets filter and selection", () => {
    const setSelection = vi.fn();
    const setFilter = vi.fn();
    const setLineIndex = vi.fn();
    const setMessage = vi.fn();

    handleIncidentScreenInput({
      ...incidentInputDefaults(),
      inputValue: "r",
      setSelection,
      setFilter,
      setLineIndex,
      setMessage
    });

    expect(setFilter).toHaveBeenCalledWith("");
    expect(setSelection).toHaveBeenCalledOnce();
    const updater = (setSelection.mock.calls[0] as [Function])[0] as (
      v: Map<string, IncidentLogLine>
    ) => Map<string, IncidentLogLine>;
    expect(updater(new Map([["k", line(1)]])).size).toBe(0);
    expect(setMessage).toHaveBeenCalledWith("Filter and selection reset");
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
    total: 1,
    pageLines: [line(0)],
    pageStart: 0,
    pageLoading: false,
    selectedLines: [],
    lineIndex: 0,
    pageSize: 10,
    filter: "",
    sortKey: "timestamp",
    sortDirection: "desc",
    setLineIndex: vi.fn(),
    setFilter: vi.fn(),
    setSelection: vi.fn(),
    setDetailLine: vi.fn(),
    setDetailScroll: vi.fn(),
    setSortMenu: vi.fn(),
    setTopScope: vi.fn(),
    setScreen: vi.fn(),
    setPrompt: vi.fn(),
    setExportMenu: vi.fn(),
    setMessage: vi.fn()
  };
}
