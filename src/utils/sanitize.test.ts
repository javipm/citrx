import { describe, expect, it } from "vitest";

import { neutralizeFormula, sanitizeText } from "./sanitize.js";

const ansi = "\u001B[31mred\u001B[0m";
const osc = "\u001B]8;;https://evil.test\u0007click\u001B]8;;\u0007";

describe("sanitizeText", () => {
  it("leaves JSON values unchanged", () => {
    const raw = `${ansi}=1+1\n<script>\``;
    expect(sanitizeText(raw, "json")).toBe(raw);
  });

  it("strips ANSI and OSC from terminal and TUI text", () => {
    expect(sanitizeText(`${ansi} ${osc}`, "terminal")).toBe("red click");
    expect(sanitizeText(`ok\u0007bell`, "tui")).toBe("okbell");
  });

  it("escapes HTML after stripping controls", () => {
    expect(sanitizeText(`<script>${ansi}</script>`, "html")).toBe(
      "&lt;script&gt;red&lt;/script&gt;"
    );
    expect(sanitizeText(`it's "quoted"`, "html")).toBe("it&#39;s &quot;quoted&quot;");
  });

  it("neutralizes backticks, HTML, links, and backslash+pipe in Markdown", () => {
    expect(sanitizeText("a `code` | b <em>x</em>", "markdown")).toBe(
      "a 'code' \\| b &lt;em&gt;x&lt;/em&gt;"
    );
    expect(sanitizeText("foo\\|bar", "markdown")).toBe("foo\\\\\\|bar");
    expect(sanitizeText("[x](javascript:alert(1))", "markdown")).toBe(
      "\\[x\\](javascript:alert(1))"
    );
    expect(sanitizeText("![img](https://evil.test/x.png)", "markdown")).toBe(
      "!\\[img\\](https://evil.test/x.png)"
    );
  });

  it("prefixes spreadsheet formulas in CSV and TSV", () => {
    expect(sanitizeText("=1+1", "csv")).toBe("'=1+1");
    expect(sanitizeText("+cmd", "tsv")).toBe("'+cmd");
    expect(sanitizeText("@SUM(A1)", "csv")).toBe("'@SUM(A1)");
    expect(sanitizeText("plain", "csv")).toBe("plain");
    expect(sanitizeText("  =1+1", "csv")).toBe("'  =1+1");
    expect(sanitizeText("\uFEFF@SUM(A1)", "tsv")).toBe("'\uFEFF@SUM(A1)");
    expect(sanitizeText(" hello", "csv")).toBe(" hello");
    expect(neutralizeFormula("  =1+1")).toBe("'  =1+1");
    expect(neutralizeFormula("\uFEFF@hidden")).toBe("'\uFEFF@hidden");
    expect(neutralizeFormula(" hello")).toBe(" hello");
  });
});
