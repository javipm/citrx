export type SanitizeSink = "terminal" | "tui" | "html" | "markdown" | "csv" | "tsv" | "json";

const OSC = /\u001B][^\u0007\u001B]*(?:\u0007|\u001B\\)/g;
const CSI = /\u001B\[[0-9;?]*[ -/]*[@-~]/g;
const C1_CSI = /\u009B[0-9;?]*[ -/]*[@-~]/g;
const OTHER_ESC = /\u001B[@-Z\\-_]/g;
const CONTROLS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;

/**
 * Destination-aware sanitization for untrusted log text.
 * JSON is left unchanged so machine output is not double-escaped.
 */
export function sanitizeText(value: string, sink: SanitizeSink): string {
  if (sink === "json") {
    return value;
  }

  const stripped = stripUnsafeControls(value);

  switch (sink) {
    case "terminal":
    case "tui":
      return stripped.replace(/\r\n|\n|\r/g, " ");
    case "html":
      return escapeHtmlEntities(stripped);
    case "markdown":
      return sanitizeMarkdownCell(stripped);
    case "csv":
    case "tsv":
      return neutralizeFormula(stripped);
  }
}

export function stripUnsafeControls(value: string): string {
  return value
    .replace(OSC, "")
    .replace(CSI, "")
    .replace(C1_CSI, "")
    .replace(OTHER_ESC, "")
    .replace(CONTROLS, "");
}

function sanitizeMarkdownCell(value: string): string {
  return value
    .replaceAll("\r\n", " ")
    .replaceAll("\n", " ")
    .replaceAll("\r", " ")
    .replaceAll("\\", "\\\\")
    .replaceAll("|", "\\|")
    .replaceAll("`", "'")
    .replaceAll("[", "\\[")
    .replaceAll("]", "\\]")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

export function escapeHtmlEntities(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function neutralizeFormula(value: string): string {
  const inspect = value.replace(/^\uFEFF+/, "").replace(/^[\p{Zs}\f\v]+/u, "");
  if (/^[=+\-@\t\r]/.test(inspect)) {
    return `'${value}`;
  }

  return value;
}
