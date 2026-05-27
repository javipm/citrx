import type { AnalyzeReport, Incident, TopItem } from "../analysis/types.js";

/**
 * Renders a GitHub-Flavored Markdown report from an `AnalyzeReport`.
 * Sections: summary metrics, inputs, top-N tables, AI bot stats, incidents.
 * The returned string always ends with a trailing newline.
 *
 * @param report - The analysis result produced by the detection pipeline.
 * @returns A Markdown string ready to be written to a `.md` file.
 */
export function renderMarkdownReport(report: AnalyzeReport): string {
  const lines: string[] = [
    "# citrx access log analysis",
    "",
    `Generated: ${report.generatedAt}`,
    "",
    "## Summary",
    "",
    "| Metric | Value |",
    "| --- | ---: |",
    `| Files | ${report.summary.files} |`,
    `| Lines parsed | ${report.summary.parsedLines} / ${report.summary.totalLines} |`,
    `| Lines filtered | ${report.summary.filteredLines} |`,
    `| Invalid lines | ${report.summary.invalidLines} |`,
    `| Bytes served | ${report.summary.totalBytes} |`,
    `| First seen | ${report.timeStats.firstSeen ?? "unknown"} |`,
    `| Last seen | ${report.timeStats.lastSeen ?? "unknown"} |`,
    `| Peak global RPS | ${report.timeStats.peakGlobalRps} |`,
    `| Global RPS p95 | ${report.timeStats.globalRpsP95} |`,
    "",
    "## Inputs",
    "",
    "| Input | Format | Parsed sample |",
    "| --- | --- | ---: |",
    ...report.inputFormats.map(
      (input) =>
        `| ${escapeCell(input.file)} | ${escapeCell(input.format)} | ${input.parsedSampleLines} / ${input.sampledLines} |`
    ),
    "",
    topSection("Top IPs", report.topIps),
    topSection("Top Paths", report.topPaths),
    topSection("Top User Agents", report.topUserAgents),
    topSection("Top Query Params", report.topParams),
    topSection("Top Query Param Values", report.topParamValues),
    topSection("Methods", report.topMethods),
    topSection("Statuses", report.topStatuses),
    aiBotSection(report),
    incidentSection(report.incidents)
  ];

  return `${lines.join("\n")}\n`;
}

/**
 * Builds the "Known AI Bots" Markdown section as a pipe table.
 * Columns: Bot, Requests, IPs, Paths, Robots.txt.
 * Renders a zero-row placeholder when no AI bot stats are present.
 *
 * @param report - Full analysis report; only `aiBotStats` is consumed.
 * @returns A Markdown string for the AI bots section (no trailing newline).
 */
function aiBotSection(report: AnalyzeReport): string {
  const lines = [
    "## Known AI Bots",
    "",
    "| Bot | Requests | IPs | Paths | Robots.txt |",
    "| --- | ---: | ---: | ---: | --- |"
  ];

  if (report.aiBotStats.length === 0) {
    lines.push("| none | 0 | 0 | 0 | no |");
  } else {
    lines.push(
      ...report.aiBotStats.map(
        (bot) =>
          `| ${escapeCell(bot.botName)} | ${bot.requests} | ${bot.ipCount} | ${bot.pathCount} | ${bot.requestedRobotsTxt ? "yes" : "no"} |`
      )
    );
  }

  return lines.join("\n");
}

/**
 * Builds a Markdown `##` section with a two-column (Count / Value) pipe table
 * for a ranked list of top items. Renders a "none" row when the list is empty.
 *
 * @param title - Section heading text (rendered as `## title`).
 * @param items - Ranked items, each with a `count` and a `value` string.
 * @returns A Markdown string for the section (no trailing newline).
 */
function topSection(title: string, items: TopItem[]): string {
  const lines = [`## ${title}`, "", "| Count | Value |", "| ---: | --- |"];

  if (items.length === 0) {
    lines.push("| 0 | none |");
  } else {
    lines.push(...items.map((item) => `| ${item.count} | ${escapeCell(item.value)} |`));
  }

  return lines.join("\n");
}

/**
 * Builds the "Incidents" Markdown section as a pipe table.
 * Each incident row is followed by up to 3 sample sub-rows (severity cell empty,
 * category cell `sample`, evidence cell contains the backtick-wrapped request line).
 * Renders a placeholder row when there are no incidents.
 *
 * @param incidents - Array of incidents from the analysis report.
 * @returns A Markdown string for the incidents section (no trailing newline).
 */
function incidentSection(incidents: Incident[]): string {
  const lines = [
    "## Incidents",
    "",
    "| Severity | Score | Category | Title | Evidence |",
    "| --- | ---: | --- | --- | --- |"
  ];

  if (incidents.length === 0) {
    lines.push("| info | 0 | none | No incidents detected |  |");
    return lines.join("\n");
  }

  for (const incident of incidents) {
    const evidence = incident.evidence
      .map((item) => `${item.key}=${item.value}`)
      .join("; ");
    lines.push(
      `| ${incident.severity} | ${incident.score} | ${escapeCell(incident.category)} | ${escapeCell(incident.title)} | ${escapeCell(evidence)} |`
    );

    for (const sample of incident.samples.slice(0, 3)) {
      lines.push(`|  |  | sample |  | \`${escapeCell(sample)}\` |`);
    }
  }

  return lines.join("\n");
}

/**
 * Escapes a value for safe insertion into a Markdown pipe table cell.
 * Replaces literal `|` with `\|` and collapses newlines to a single space.
 *
 * @param value - Raw string, number, or boolean to escape.
 * @returns The Markdown-safe string representation.
 */
function escapeCell(value: string | number | boolean): string {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
}
