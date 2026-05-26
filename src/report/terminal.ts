import pc from "picocolors";

import type { AnalyzeReport, Incident, TopItem } from "../analysis/types.js";

export interface TerminalReportOptions {
  color?: boolean;
}

export function renderTerminalReport(
  report: AnalyzeReport,
  options: TerminalReportOptions = {}
): string {
  const colors = pc.createColors(options.color ?? pc.isColorSupported);
  const lines: string[] = [];

  lines.push(`${colors.bold("citrx")} ${colors.green("access log analysis")}`);
  lines.push("");
  lines.push(`Files: ${report.summary.files}`);
  lines.push(`Lines: ${report.summary.parsedLines}/${report.summary.totalLines}`);
  if (report.summary.filteredLines > 0) {
    lines.push(`Filtered: ${report.summary.filteredLines}`);
  }
  lines.push(`Invalid: ${report.summary.invalidLines}`);
  lines.push(`Bytes served: ${report.summary.totalBytes}`);
  if (report.timeStats.firstSeen && report.timeStats.lastSeen) {
    lines.push(`Time range: ${report.timeStats.firstSeen} to ${report.timeStats.lastSeen}`);
    lines.push(
      `Peak global RPS: ${report.timeStats.peakGlobalRps} at ${report.timeStats.peakGlobalRpsAt ?? "unknown"}`
    );
  }
  lines.push(
    `Formats: ${[...new Set(report.inputFormats.map((input) => input.format))].join(", ")}`
  );
  lines.push("");
  lines.push(section("Top IPs", report.topIps, colors));
  lines.push(section("Top paths", report.topPaths, colors));
  lines.push(section("Methods", report.topMethods, colors));
  lines.push(section("Statuses", report.topStatuses, colors));
  lines.push(incidentSection(report.incidents, colors));

  return `${lines.join("\n")}\n`;
}

function section(
  title: string,
  items: TopItem[],
  colors: ReturnType<typeof pc.createColors>
): string {
  const lines = [colors.bold(title)];

  if (items.length === 0) {
    lines.push("  none");
    return lines.join("\n");
  }

  for (const item of items) {
    lines.push(`  ${item.count.toString().padStart(6, " ")}  ${item.value}`);
  }

  return lines.join("\n");
}

function incidentSection(
  incidents: Incident[],
  colors: ReturnType<typeof pc.createColors>
): string {
  const lines = [colors.bold("Incidents")];

  if (incidents.length === 0) {
    lines.push("  none");
    return lines.join("\n");
  }

  for (const incident of incidents.slice(0, 10)) {
    const count = incident.evidence.find((item) => item.key === "count")?.value;
    const suffix = count ? ` count=${count}` : "";
    lines.push(
      `  ${severity(incident.severity, colors)} ${incident.score.toString().padStart(3, " ")}  ${incident.title}${suffix}`
    );

    const path = incident.evidence.find((item) => item.key === "path")?.value;
    if (path) {
      lines.push(`       ${path}`);
    }

    for (const sample of incident.samples.slice(0, 2)) {
      lines.push(`       sample: ${sample}`);
    }
  }

  return lines.join("\n");
}

function severity(
  value: Incident["severity"],
  colors: ReturnType<typeof pc.createColors>
): string {
  switch (value) {
    case "critical":
      return colors.red(value.padEnd(8, " "));
    case "high":
      return colors.magenta(value.padEnd(8, " "));
    case "medium":
      return colors.yellow(value.padEnd(8, " "));
    case "low":
      return colors.cyan(value.padEnd(8, " "));
    case "info":
      return colors.dim(value.padEnd(8, " "));
  }
}
