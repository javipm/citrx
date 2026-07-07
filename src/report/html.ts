import type { AnalyzeReport, Incident, TopItem } from "../analysis/types.js";
import { truncateForDisplay } from "../utils/text.js";

/** Max rendered length for a user agent value in top-value tables. */
const UA_DISPLAY_MAX_LENGTH = 60;

/**
 * Renders a complete, self-contained HTML report from an `AnalyzeReport`.
 * Embeds all CSS inline; the returned string is a full `<!doctype html>` document.
 *
 * @param report - The analysis result produced by the detection pipeline.
 * @returns A UTF-8 HTML string ready to be written to a file or served over HTTP.
 */
export function renderHtmlReport(report: AnalyzeReport): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>citrx access log analysis</title>
  <style>
    :root { color-scheme: light; --ink:#18212f; --muted:#667085; --line:#d7dde8; --panel:#f7f9fc; --accent:#0f766e; --danger:#b42318; --warn:#b54708; --high:#7a2e8e; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--ink); background: #fff; }
    header { padding: 28px 32px 20px; border-bottom: 1px solid var(--line); background: linear-gradient(180deg, #f9fbff 0%, #fff 100%); }
    main { padding: 24px 32px 40px; max-width: 1220px; margin: 0 auto; }
    h1 { margin: 0 0 6px; font-size: 30px; line-height: 1.1; letter-spacing: 0; }
    h2 { margin: 30px 0 12px; font-size: 18px; letter-spacing: 0; }
    .meta { color: var(--muted); font-size: 14px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; }
    .metric { border: 1px solid var(--line); border-radius: 8px; padding: 14px; background: var(--panel); }
    .metric span { display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .metric strong { display: block; margin-top: 6px; font-size: 22px; }
    table { width: 100%; border-collapse: collapse; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
    th, td { padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 14px; }
    th { background: var(--panel); color: #344054; font-size: 12px; text-transform: uppercase; }
    tr:last-child td { border-bottom: 0; }
    code { word-break: break-all; white-space: pre-wrap; }
    .two { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 18px; }
    .severity-critical { color: var(--danger); font-weight: 700; }
    .severity-high { color: var(--high); font-weight: 700; }
    .severity-medium { color: var(--warn); font-weight: 700; }
    .severity-low, .severity-info { color: var(--accent); font-weight: 700; }
    @media (max-width: 640px) { header, main { padding-left: 16px; padding-right: 16px; } th, td { font-size: 13px; padding: 8px; } }
  </style>
</head>
<body>
  <header>
    <h1>citrx access log analysis</h1>
    <div class="meta">${escapeHtml(report.generatedAt)}</div>
  </header>
  <main>
    <section class="grid">
      ${metric("Files", report.summary.files)}
      ${metric("Parsed Lines", `${report.summary.parsedLines} / ${report.summary.totalLines}`)}
      ${metric("Filtered", report.summary.filteredLines)}
      ${metric("Invalid", report.summary.invalidLines)}
      ${metric("Bytes served", report.summary.totalBytes)}
      ${metric("Peak RPS", report.timeStats.peakGlobalRps)}
      ${metric("RPS p95", report.timeStats.globalRpsP95)}
      ${metric("Incidents", report.incidents.length)}
    </section>
    <section>
      <h2>Inputs</h2>
      <table>
        <thead><tr><th>Input</th><th>Format</th><th>Parsed Sample</th></tr></thead>
        <tbody>${report.inputFormats
          .map(
            (input) =>
              `<tr><td><code>${escapeHtml(input.file)}</code></td><td>${escapeHtml(input.format)}</td><td>${input.parsedSampleLines} / ${input.sampledLines}</td></tr>`
          )
          .join("")}</tbody>
      </table>
    </section>
    <section class="two">
      ${topTable("Top IPs", report.topIps)}
      ${topTable("Top Paths", report.topPaths)}
      ${topTable("Top User Agents", report.topUserAgents, UA_DISPLAY_MAX_LENGTH)}
      ${topTable("Top Query Params", report.topParams)}
      ${topTable("Top Query Param Values", report.topParamValues)}
      ${topTable("Methods", report.topMethods)}
      ${topTable("Statuses", report.topStatuses)}
    </section>
    ${report.aiBotStats.length > 0 ? `<section><h2>Known AI Bots</h2>${aiBotTable(report)}</section>` : ""}
    <section>
      <h2>Incidents</h2>
      ${incidentTable(report.incidents)}
    </section>
  </main>
</body>
</html>
`;
}

/**
 * Builds an HTML `<table>` summarising per-bot AI crawler statistics.
 * Columns: Bot name, total requests, unique IPs, unique paths, robots.txt hit.
 *
 * @param report - Full analysis report; only `aiBotStats` is consumed.
 * @returns An HTML table string (no surrounding `<section>` wrapper).
 */
function aiBotTable(report: AnalyzeReport): string {
  return `<table>
    <thead><tr><th>Bot</th><th>Requests</th><th>IPs</th><th>Paths</th><th>Robots.txt</th></tr></thead>
    <tbody>${report.aiBotStats
      .map(
        (bot) =>
          `<tr><td>${escapeHtml(bot.botName)}</td><td>${bot.requests}</td><td>${bot.ipCount}</td><td>${bot.pathCount}</td><td>${bot.requestedRobotsTxt ? "yes" : "no"}</td></tr>`
      )
      .join("")}</tbody>
  </table>`;
}

/**
 * Renders a single summary metric card `<div>` with a label and a bold value.
 *
 * @param label - Short human-readable label (e.g. `"Files"`).
 * @param value - Numeric or string value to display prominently.
 * @returns An HTML `<div class="metric">` string.
 */
function metric(label: string, value: string | number): string {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

/**
 * Builds a titled `<div>` containing a two-column (Count / Value) HTML table
 * for a ranked list of top items. Renders "none" when the list is empty.
 *
 * @param title - Section heading rendered as an `<h2>`.
 * @param items - Ranked items, each with a `count` and a `value` string. The
 *   value is the full untruncated aggregation key; truncation happens here.
 * @param maxValueLength - Optional max rendered length for `item.value`
 *   (e.g. user agents, which can be much longer than IPs/paths).
 * @returns An HTML `<div>` wrapping the heading and table.
 */
function topTable(title: string, items: TopItem[], maxValueLength?: number): string {
  const rows =
    items.length === 0
      ? '<tr><td colspan="2">none</td></tr>'
      : items
          .map((item) => {
            const value = maxValueLength
              ? truncateForDisplay(item.value, maxValueLength)
              : item.value;
            return `<tr><td>${item.count}</td><td><code>${escapeHtml(value)}</code></td></tr>`;
          })
          .join("");

  return `<div><h2>${escapeHtml(title)}</h2><table><thead><tr><th>Count</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

/**
 * Builds a full HTML `<table>` for all detected incidents.
 * Returns a `<p>` message when there are no incidents.
 * Delegates each row to {@link incidentRow}.
 *
 * @param incidents - Array of incidents from the analysis report.
 * @returns An HTML table string, or a "No incidents" paragraph.
 */
function incidentTable(incidents: Incident[]): string {
  if (incidents.length === 0) {
    return "<p>No incidents detected.</p>";
  }

  return `<table>
    <thead><tr><th>Severity</th><th>Score</th><th>Title</th><th>Evidence</th><th>Samples</th></tr></thead>
    <tbody>${incidents.map(incidentRow).join("")}</tbody>
  </table>`;
}

/**
 * Renders a single incident as an HTML `<tr>`.
 * Severity gets a CSS class (`severity-critical`, `severity-high`, etc.) for colour coding.
 * Up to 3 sample request lines are shown as `<code>` blocks in the last cell.
 *
 * @param incident - A single detected incident.
 * @returns An HTML `<tr>` string.
 */
function incidentRow(incident: Incident): string {
  const evidence = incident.evidence.map((item) => `${item.key}=${item.value}`).join("; ");
  const samples = incident.samples
    .slice(0, 3)
    .map((sample) => `<code>${escapeHtml(sample)}</code>`)
    .join("<br>");

  return `<tr>
    <td class="severity-${incident.severity}">${escapeHtml(incident.severity)}</td>
    <td>${incident.score}</td>
    <td>${escapeHtml(incident.title)}<br><span class="meta">${escapeHtml(incident.category)}</span></td>
    <td>${escapeHtml(evidence)}</td>
    <td>${samples}</td>
  </tr>`;
}

/**
 * Escapes a value for safe inline HTML insertion.
 * Replaces `&`, `<`, `>`, and `"` with their HTML entity equivalents.
 *
 * @param value - Raw string, number, or boolean to escape.
 * @returns The HTML-safe string representation.
 */
function escapeHtml(value: string | number | boolean): string {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
