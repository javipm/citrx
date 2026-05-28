import type { ExportFormat } from "../types.js";

const EXPORT_FORMATS: ExportFormat[] = ["csv", "json", "tsv"];

export function handleExportMenuInput({
  inputValue,
  key,
  exportMenu,
  setExportMenu,
  applyExport,
  setMessage
}: {
  inputValue: string;
  key: {
    return?: boolean;
    escape?: boolean;
    backspace?: boolean;
    tab?: boolean;
    upArrow?: boolean;
    downArrow?: boolean;
  };
  exportMenu: {
    format: ExportFormat;
  };
  setExportMenu: (value: typeof exportMenu | undefined) => void;
  applyExport: (format: ExportFormat) => void;
  setMessage: (value: string) => void;
}): void {
  if (key.escape || key.backspace) {
    setExportMenu(undefined);
    setMessage("Export cancelled");
    return;
  }

  if (key.return) {
    applyExport(exportMenu.format);
    return;
  }

  const directFormat = EXPORT_FORMATS.find((format) => inputValue.toLowerCase() === format[0]);
  if (directFormat) {
    applyExport(directFormat);
    return;
  }

  if (key.tab || key.upArrow || key.downArrow) {
    const currentIndex = EXPORT_FORMATS.indexOf(exportMenu.format);
    const step = key.upArrow ? -1 : 1;
    const nextIndex = (currentIndex + step + EXPORT_FORMATS.length) % EXPORT_FORMATS.length;
    setExportMenu({ format: EXPORT_FORMATS[nextIndex] ?? exportMenu.format });
  }
}
