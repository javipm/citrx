import pc from "picocolors";

import type { AnalyzeReport, Incident, TopItem } from "../analysis/types.js";

export function renderTerminalReport(report: AnalyzeReport): string {
  const lines: string[] = [];

  lines.push(`${pc.bold("citrx")} ${pc.green("access log analysis")}`);
  lines.push("");
  if (report.sessionId) {
    lines.push(`Session: ${report.sessionId}`);
  }
  lines.push(`Files: ${report.summary.files}`);
  lines.push(`Lines: ${report.summary.parsedLines}/${report.summary.totalLines}`);
  if (report.summary.filteredLines > 0) {
    lines.push(`Filtered: ${report.summary.filteredLines}`);
  }
  lines.push(`Invalid: ${report.summary.invalidLines}`);
  lines.push(`Bytes served: ${report.summary.totalBytes}`);
  lines.push(
    `Formats: ${[...new Set(report.inputFormats.map((input) => input.format))].join(", ")}`
  );
  lines.push("");
  lines.push(section("Top IPs", report.topIps));
  lines.push(section("Top paths", report.topPaths));
  lines.push(section("Methods", report.topMethods));
  lines.push(section("Statuses", report.topStatuses));
  lines.push(incidentSection(report.incidents));

  return `${lines.join("\n")}\n`;
}

function section(title: string, items: TopItem[]): string {
  const lines = [pc.bold(title)];

  if (items.length === 0) {
    lines.push("  none");
    return lines.join("\n");
  }

  for (const item of items) {
    lines.push(`  ${item.count.toString().padStart(6, " ")}  ${item.value}`);
  }

  return lines.join("\n");
}

function incidentSection(incidents: Incident[]): string {
  const lines = [pc.bold("Incidents")];

  if (incidents.length === 0) {
    lines.push("  none");
    return lines.join("\n");
  }

  for (const incident of incidents.slice(0, 10)) {
    const count = incident.evidence.find((item) => item.key === "count")?.value;
    const suffix = count ? ` count=${count}` : "";
    lines.push(
      `  ${severity(incident.severity)} ${incident.score.toString().padStart(3, " ")}  ${incident.title}${suffix}`
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

function severity(value: Incident["severity"]): string {
  switch (value) {
    case "critical":
      return pc.red(value.padEnd(8, " "));
    case "high":
      return pc.magenta(value.padEnd(8, " "));
    case "medium":
      return pc.yellow(value.padEnd(8, " "));
    case "low":
      return pc.cyan(value.padEnd(8, " "));
    case "info":
      return pc.dim(value.padEnd(8, " "));
  }
}
