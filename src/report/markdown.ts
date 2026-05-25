import type { AnalyzeReport, Incident, TopItem } from "../analysis/types.js";

export function renderMarkdownReport(report: AnalyzeReport): string {
  const lines: string[] = [
    "# citrx access log analysis",
    "",
    `Generated: ${report.generatedAt}`,
    ...(report.sessionId ? [`Session: ${report.sessionId}`] : []),
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
    topSection("Methods", report.topMethods),
    topSection("Statuses", report.topStatuses),
    ...(report.geo
      ? [
          "## GeoIP / ASN",
          "",
          `Provider: ${report.geo.provider}`,
          `Looked up: ${report.geo.lookedUp}`,
          `Failed: ${report.geo.failed}`,
          "",
          topSection("Countries", report.geo.topCountries),
          topSection("ASNs / Organizations", report.geo.topAsns)
        ]
      : []),
    incidentSection(report.incidents)
  ];

  return `${lines.join("\n")}\n`;
}

function topSection(title: string, items: TopItem[]): string {
  const lines = [`## ${title}`, "", "| Count | Value |", "| ---: | --- |"];

  if (items.length === 0) {
    lines.push("| 0 | none |");
  } else {
    lines.push(...items.map((item) => `| ${item.count} | ${escapeCell(item.value)} |`));
  }

  return lines.join("\n");
}

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

function escapeCell(value: string | number): string {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
}
