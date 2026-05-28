import { describe, expect, it, vi } from "vitest";

import { handleExportMenuInput } from "./useExportMenuInput.js";

describe("export menu input", () => {
  it("cycles formats with arrow keys", () => {
    const setExportMenu = vi.fn();

    handleExportMenuInput({
      inputValue: "",
      key: { downArrow: true },
      exportMenu: { format: "json" },
      setExportMenu,
      applyExport: vi.fn(),
      setMessage: vi.fn()
    });

    expect(setExportMenu).toHaveBeenCalledWith({ format: "tsv" });
  });

  it("applies the selected format on enter", () => {
    const applyExport = vi.fn();

    handleExportMenuInput({
      inputValue: "",
      key: { return: true },
      exportMenu: { format: "csv" },
      setExportMenu: vi.fn(),
      applyExport,
      setMessage: vi.fn()
    });

    expect(applyExport).toHaveBeenCalledWith("csv");
  });

  it("applies direct c/j/t shortcuts", () => {
    const applyExport = vi.fn();

    handleExportMenuInput({
      inputValue: "t",
      key: {},
      exportMenu: { format: "json" },
      setExportMenu: vi.fn(),
      applyExport,
      setMessage: vi.fn()
    });

    expect(applyExport).toHaveBeenCalledWith("tsv");
  });
});
