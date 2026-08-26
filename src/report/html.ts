import type { AnalyzeReport, Incident, IncidentEvidence, TopItem } from "../analysis/types.js";
import { sanitizeText } from "../utils/sanitize.js";
import { truncateForDisplay } from "../utils/text.js";
import { formatTruncation } from "./truncation.js";

/** Max rendered length for a user agent value in top-value tables. */
const UA_DISPLAY_MAX_LENGTH = 60;

const PAYLOAD_EVIDENCE_KEYS = new Set(["payload", "sample", "prefix"]);

export interface HtmlTimelineEvent {
  at: string;
  label: string;
}

export interface HtmlPayloadRow {
  incidentId: string;
  title: string;
  value: string;
}

export interface HtmlActionRow {
  action: string;
  detail: string;
}

/**
 * Renders a complete, self-contained HTML report from an `AnalyzeReport`.
 * Embeds CSS and JS inline; the returned string is a full `<!doctype html>` document.
 */
export function renderHtmlReport(report: AnalyzeReport): string {
  const payloads = collectPayloadRows(report.incidents);
  const actions = collectActionRows(report.incidents);
  const timeline = collectTimelineEvents(report);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>citrx access log analysis</title>
  <style>
    :root { color-scheme: light; --ink:#18212f; --muted:#667085; --line:#d7dde8; --panel:#f7f9fc; --accent:#0f766e; --danger:#b42318; --warn:#b54708; --high:#7a2e8e; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--ink); background: #fff; }
    header { padding: 28px 32px 20px; border-bottom: 1px solid var(--line); background: linear-gradient(180deg, #f9fbff 0%, #fff 100%); }
    main { padding: 24px 32px 40px; max-width: 1220px; margin: 0 auto; }
    h1 { margin: 0 0 6px; font-size: 30px; line-height: 1.1; }
    h2 { margin: 30px 0 12px; font-size: 18px; }
    .meta { color: var(--muted); font-size: 14px; }
    .lede { max-width: 72ch; line-height: 1.5; }
    nav { display: flex; flex-wrap: wrap; gap: 8px 14px; margin-top: 14px; font-size: 13px; }
    nav a { color: var(--accent); }
    .toolbar { display: flex; gap: 12px; align-items: center; margin: 18px 0 8px; }
    .toolbar input { flex: 1; min-width: 12rem; padding: 8px 10px; border: 1px solid var(--line); border-radius: 6px; font: inherit; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; }
    .metric { border: 1px solid var(--line); border-radius: 8px; padding: 14px; background: var(--panel); }
    .metric span { display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .metric strong { display: block; margin-top: 6px; font-size: 22px; }
    table { width: 100%; border-collapse: collapse; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
    th, td { padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 14px; }
    th { background: var(--panel); color: #344054; font-size: 12px; text-transform: uppercase; }
    th[data-sort] { cursor: pointer; user-select: none; }
    th[data-dir="asc"]::after { content: " ▲"; }
    th[data-dir="desc"]::after { content: " ▼"; }
    tr:last-child td { border-bottom: 0; }
    code { word-break: break-all; white-space: pre-wrap; }
    .two { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 18px; }
    .severity-critical { color: var(--danger); font-weight: 700; }
    .severity-high { color: var(--high); font-weight: 700; }
    .severity-medium { color: var(--warn); font-weight: 700; }
    .severity-low, .severity-info { color: var(--accent); font-weight: 700; }
    @media (max-width: 640px) { header, main { padding-left: 16px; padding-right: 16px; } th, td { font-size: 13px; padding: 8px; } }
    @media print {
      body { background: #fff; }
      header { background: #fff; border-bottom: 1px solid #ccc; padding: 12px 0; }
      main { padding: 12px 0; max-width: none; }
      nav, .toolbar, .no-print { display: none !important; }
      table { break-inside: avoid; border-color: #bbb; }
      a { color: inherit; text-decoration: none; }
    }
  </style>
</head>
<body>
  <header>
    <h1>citrx access log analysis</h1>
    <div class="meta">${escapeHtml(report.generatedAt)}</div>
    <nav>
      <a href="#summary">Summary</a>
      <a href="#timeline">Timeline</a>
      <a href="#incidents">Incidents</a>
      <a href="#paths">Paths</a>
      <a href="#ips">IPs</a>
      <a href="#uas">User agents</a>
      ${payloads.length > 0 ? '<a href="#payloads">Payloads</a>' : ""}
      ${actions.length > 0 ? '<a href="#actions">Actions</a>' : ""}
    </nav>
  </header>
  <main>
    <section id="summary">
      <h2>Executive summary</h2>
      <p class="lede">${escapeHtml(executiveSummary(report))}</p>
    </section>
    <div class="toolbar no-print">
      <label for="report-filter">Filter tables</label>
      <input id="report-filter" type="search" placeholder="Filter visible table rows">
    </div>
    <section class="grid">
      ${metric("Files", report.summary.files)}
      ${metric("Parsed Lines", `${report.summary.parsedLines} / ${report.summary.totalLines}`)}
      ${metric("Filtered", report.summary.filteredLines)}
      ${metric("Invalid", report.summary.invalidLines)}
      ${metric("Bytes served", report.summary.totalBytes)}
      ${formatTruncation(report.summary) ? metric("Truncation", formatTruncation(report.summary) ?? "") : ""}
      ${metric("Peak RPS", report.timeStats.peakGlobalRps)}
      ${metric("RPS p95", report.timeStats.globalRpsP95)}
      ${metric("Incidents", report.incidents.length)}
    </section>
    <section id="timeline">
      <h2>Timeline</h2>
      ${timelineTable(timeline)}
    </section>
    <section>
      <h2>Inputs</h2>
      ${inputsTable(report)}
    </section>
    <section class="two">
      <div id="ips">${topTable("Top IPs", report.topIps)}</div>
      <div id="paths">${topTable("Top Paths", report.topPaths)}</div>
      <div id="uas">${topTable("Top User Agents", report.topUserAgents, UA_DISPLAY_MAX_LENGTH)}</div>
      ${topTable("Top Query Params", report.topParams)}
      ${topTable("Top Query Param Values", report.topParamValues)}
      ${topTable("Methods", report.topMethods)}
      ${topTable("Statuses", report.topStatuses)}
    </section>
    ${report.aiBotStats.length > 0 ? `<section><h2>Known AI Bots</h2>${aiBotTable(report)}</section>` : ""}
    <section id="incidents">
      <h2>Incidents</h2>
      ${incidentTable(report.incidents)}
    </section>
    ${payloads.length > 0 ? `<section id="payloads"><h2>Payloads</h2>${payloadTable(payloads)}</section>` : ""}
    ${actions.length > 0 ? `<section id="actions"><h2>Suggested actions</h2>${actionTable(actions)}</section>` : ""}
  </main>
  <script>
${REPORT_SCRIPT}
  </script>
</body>
</html>
`;
}

const REPORT_SCRIPT = `(function () {
  var filter = document.getElementById("report-filter");
  function applyFilter() {
    var q = ((filter && filter.value) || "").toLowerCase();
    var tables = document.querySelectorAll("table.js-filter");
    for (var t = 0; t < tables.length; t++) {
      var body = tables[t].tBodies[0];
      if (!body) continue;
      var rows = body.rows;
      for (var i = 0; i < rows.length; i++) {
        var hay = (rows[i].textContent || "").toLowerCase();
        rows[i].hidden = q !== "" && hay.indexOf(q) === -1;
      }
    }
  }
  if (filter) filter.addEventListener("input", applyFilter);

  document.addEventListener("click", function (ev) {
    var target = ev.target;
    if (!target || typeof target.closest !== "function") return;
    var th = target.closest("th[data-sort]");
    if (!th) return;
    var table = th.closest("table");
    if (!table || !table.tBodies[0] || !th.parentNode) return;
    var col = Array.prototype.indexOf.call(th.parentNode.children, th);
    var type = th.getAttribute("data-sort") || "text";
    var dir = th.getAttribute("data-dir") === "asc" ? "desc" : "asc";
    var headers = th.parentNode.children;
    for (var h = 0; h < headers.length; h++) headers[h].removeAttribute("data-dir");
    th.setAttribute("data-dir", dir);
    var rows = Array.prototype.slice.call(table.tBodies[0].rows);
    rows.sort(function (a, b) {
      var av = (a.cells[col] && a.cells[col].textContent || "").trim();
      var bv = (b.cells[col] && b.cells[col].textContent || "").trim();
      var cmp = type === "num"
        ? (parseFloat(av) || 0) - (parseFloat(bv) || 0)
        : av.localeCompare(bv);
      return dir === "asc" ? cmp : -cmp;
    });
    for (var r = 0; r < rows.length; r++) table.tBodies[0].appendChild(rows[r]);
  });
})();`;

export function executiveSummary(report: AnalyzeReport): string {
  const critical = report.incidents.filter((item) => item.severity === "critical").length;
  const high = report.incidents.filter((item) => item.severity === "high").length;
  const range =
    report.timeStats.firstSeen && report.timeStats.lastSeen
      ? `Window ${report.timeStats.firstSeen} to ${report.timeStats.lastSeen}.`
      : "Time range unavailable.";
  const peak = report.timeStats.peakGlobalRpsAt
    ? `Peak RPS ${report.timeStats.peakGlobalRps} at ${report.timeStats.peakGlobalRpsAt}.`
    : `Peak RPS ${report.timeStats.peakGlobalRps}.`;
  const headline =
    report.incidents[0] !== undefined
      ? ` Highest-scoring incident: ${report.incidents[0].title}.`
      : " No incidents detected.";
  return (
    `Analyzed ${report.summary.files} input(s), ${report.summary.parsedLines}/${report.summary.totalLines} parsed lines. ` +
    `${range} ${peak} ${report.incidents.length} incident(s) (` +
    `${critical} critical, ${high} high).${headline}`
  );
}

export function collectTimelineEvents(report: AnalyzeReport): HtmlTimelineEvent[] {
  const events: HtmlTimelineEvent[] = [];
  if (report.timeStats.firstSeen) {
    events.push({ at: report.timeStats.firstSeen, label: "Log window start" });
  }
  if (report.timeStats.lastSeen) {
    events.push({ at: report.timeStats.lastSeen, label: "Log window end" });
  }
  if (report.timeStats.peakGlobalRpsAt) {
    events.push({
      at: report.timeStats.peakGlobalRpsAt,
      label: `Peak global RPS ${report.timeStats.peakGlobalRps}`
    });
  }
  for (const bot of report.aiBotStats) {
    events.push({ at: bot.firstSeen, label: `${bot.botName} first seen` });
    events.push({ at: bot.lastSeen, label: `${bot.botName} last seen` });
  }
  for (const incident of report.incidents) {
    for (const item of incident.evidence) {
      if (typeof item.value !== "string" || !/^\d{4}-\d{2}-\d{2}T/.test(item.value)) {
        continue;
      }
      if (
        item.key === "peakRpsAt" ||
        item.key === "burstStart" ||
        item.key === "burstEnd" ||
        item.key === "firstSeen" ||
        item.key === "lastSeen"
      ) {
        events.push({ at: item.value, label: `${incident.title}: ${item.key}` });
      }
    }
  }
  events.sort((a, b) => a.at.localeCompare(b.at) || a.label.localeCompare(b.label));
  return events;
}

export function collectPayloadRows(incidents: Incident[]): HtmlPayloadRow[] {
  const rows: HtmlPayloadRow[] = [];
  for (const incident of incidents) {
    for (const item of incident.evidence) {
      if (!PAYLOAD_EVIDENCE_KEYS.has(item.key)) {
        continue;
      }
      rows.push({
        incidentId: incident.id,
        title: incident.title,
        value: String(item.value)
      });
    }
    if (incident.kind === "compromise") {
      for (const sample of incident.samples.slice(0, 3)) {
        rows.push({
          incidentId: incident.id,
          title: incident.title,
          value: sample
        });
      }
    }
  }
  return rows;
}

export function collectActionRows(incidents: Incident[]): HtmlActionRow[] {
  const rows: HtmlActionRow[] = [];
  for (const incident of incidents) {
    if (incident.severity !== "critical" && incident.severity !== "high") {
      continue;
    }
    const ip = evidenceValue(incident.evidence, "ip");
    const path = evidenceValue(incident.evidence, "path");
    if (ip !== undefined) {
      rows.push({
        action: `Inspect IP ${ip}`,
        detail: incident.title
      });
    }
    if (path !== undefined) {
      rows.push({
        action: `Review path ${path}`,
        detail: incident.title
      });
    }
    if (incident.successful) {
      rows.push({
        action: `Review 2XX_HIT for ${incident.title}`,
        detail: "Possible successful HTTP response, not proven compromise"
      });
    }
  }
  return rows;
}

function evidenceValue(
  evidence: IncidentEvidence[],
  key: string
): string | number | boolean | undefined {
  return evidence.find((item) => item.key === key)?.value;
}

function timelineTable(events: HtmlTimelineEvent[]): string {
  if (events.length === 0) {
    return "<p>No timeline events available.</p>";
  }
  const rows = events
    .map((event) => `<tr><td>${escapeHtml(event.at)}</td><td>${escapeHtml(event.label)}</td></tr>`)
    .join("");
  return sortableTable(
    [
      { label: "Time", sort: "text" },
      { label: "Event", sort: "text" }
    ],
    rows
  );
}

function inputsTable(report: AnalyzeReport): string {
  const rows = report.inputFormats
    .map(
      (input) =>
        `<tr><td><code>${escapeHtml(input.file)}</code></td><td>${escapeHtml(input.format)}</td><td>${input.parsedSampleLines} / ${input.sampledLines}</td></tr>`
    )
    .join("");
  return sortableTable(
    [
      { label: "Input", sort: "text" },
      { label: "Format", sort: "text" },
      { label: "Parsed Sample", sort: "text" }
    ],
    rows
  );
}

function aiBotTable(report: AnalyzeReport): string {
  const rows = report.aiBotStats
    .map(
      (bot) =>
        `<tr><td>${escapeHtml(bot.botName)}</td><td>${bot.requests}</td><td>${bot.ipCount}</td><td>${bot.pathCount}</td><td>${bot.requestedRobotsTxt ? "yes" : "no"}</td></tr>`
    )
    .join("");
  return sortableTable(
    [
      { label: "Bot", sort: "text" },
      { label: "Requests", sort: "num" },
      { label: "IPs", sort: "num" },
      { label: "Paths", sort: "num" },
      { label: "Robots.txt", sort: "text" }
    ],
    rows
  );
}

function metric(label: string, value: string | number): string {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

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

  return `<div><h2>${escapeHtml(title)}</h2>${sortableTable(
    [
      { label: "Count", sort: "num" },
      { label: "Value", sort: "text" }
    ],
    rows
  )}</div>`;
}

function incidentTable(incidents: Incident[]): string {
  if (incidents.length === 0) {
    return "<p>No incidents detected.</p>";
  }

  const rows = incidents.map(incidentRow).join("");
  return sortableTable(
    [
      { label: "Severity", sort: "text" },
      { label: "Score", sort: "num" },
      { label: "Title", sort: "text" },
      { label: "Evidence", sort: "text" },
      { label: "Samples", sort: "text" }
    ],
    rows
  );
}

function incidentRow(incident: Incident): string {
  const evidence = incident.evidence.map((item) => `${item.key}=${item.value}`).join("; ");
  const samples = incident.samples
    .slice(0, 3)
    .map((sample) => `<code>${escapeHtml(sample)}</code>`)
    .join("<br>");
  const severityClass = severityClassName(incident.severity);

  return `<tr>
    <td class="${severityClass}">${escapeHtml(incident.severity)}</td>
    <td>${incident.score}</td>
    <td>${escapeHtml(incident.title)}<br><span class="meta">${escapeHtml(incident.category)}</span></td>
    <td>${escapeHtml(evidence)}</td>
    <td>${samples}</td>
  </tr>`;
}

function payloadTable(rows: HtmlPayloadRow[]): string {
  const body = rows
    .map(
      (row) =>
        `<tr><td>${escapeHtml(row.incidentId)}</td><td>${escapeHtml(row.title)}</td><td><code>${escapeHtml(row.value)}</code></td></tr>`
    )
    .join("");
  return sortableTable(
    [
      { label: "Incident", sort: "text" },
      { label: "Title", sort: "text" },
      { label: "Payload", sort: "text" }
    ],
    body
  );
}

function actionTable(rows: HtmlActionRow[]): string {
  const body = rows
    .map((row) => `<tr><td>${escapeHtml(row.action)}</td><td>${escapeHtml(row.detail)}</td></tr>`)
    .join("");
  return sortableTable(
    [
      { label: "Action", sort: "text" },
      { label: "Detail", sort: "text" }
    ],
    body
  );
}

function sortableTable(
  headers: Array<{ label: string; sort: "text" | "num" }>,
  bodyRows: string
): string {
  const head = headers
    .map((header) => `<th data-sort="${header.sort}">${escapeHtml(header.label)}</th>`)
    .join("");
  return `<table class="js-filter"><thead><tr>${head}</tr></thead><tbody>${bodyRows}</tbody></table>`;
}

function severityClassName(severity: Incident["severity"]): string {
  switch (severity) {
    case "critical":
      return "severity-critical";
    case "high":
      return "severity-high";
    case "medium":
      return "severity-medium";
    case "low":
      return "severity-low";
    case "info":
      return "severity-info";
  }
}

function escapeHtml(value: string | number | boolean): string {
  return sanitizeText(String(value), "html");
}
