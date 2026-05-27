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
  lines.push(section("Top user agents", report.topUserAgents, colors));
  lines.push(section("Top query params", report.topParams, colors));
  lines.push(section("Top query param values", report.topParamValues, colors));
  lines.push(section("Methods", report.topMethods, colors));
  lines.push(section("Statuses", report.topStatuses, colors));
  if (report.aiBotStats.length > 0) {
    lines.push(aiBotSection(report, colors));
  }
  const compromise = report.incidents.filter((i) => i.kind === "compromise");
  const saturation = report.incidents.filter((i) => i.kind === "saturation");

  if (compromise.length > 0) {
    lines.push(incidentPanel("Security incidents (attacks)", compromise, colors));
  }
  if (saturation.length > 0) {
    lines.push(incidentPanel("Saturation incidents (traffic abuse)", saturation, colors));
  }
  if (compromise.length === 0 && saturation.length === 0) {
    lines.push(colors.bold("Incidents") + "\n  none");
  }

  return `${lines.join("\n")}\n`;
}

function aiBotSection(
  report: AnalyzeReport,
  colors: ReturnType<typeof pc.createColors>
): string {
  const lines = [colors.bold("Known AI bots")];

  for (const bot of report.aiBotStats.slice(0, 10)) {
    lines.push(
      `  ${bot.requests.toString().padStart(6, " ")}  ${bot.botName} ips=${bot.ipCount} paths=${bot.pathCount} robots=${bot.requestedRobotsTxt ? "yes" : "no"}`
    );
  }

  return lines.join("\n");
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

function incidentPanel(
  title: string,
  incidents: Incident[],
  colors: ReturnType<typeof pc.createColors>
): string {
  const lines = [colors.bold(title)];

  for (const incident of incidents.slice(0, 15)) {
    const count = incident.evidence.find((item) => item.key === "count")?.value;
    const requests = incident.evidence.find((item) => item.key === "requests")?.value;
    const displayCount = count ?? requests;
    const suffix = displayCount ? ` count=${displayCount}` : "";

    const successTag = incident.successful ? colors.red(" !SUCCESS") : "";

    lines.push(
      `  ${severity(incident.severity, colors)} ${incident.score.toString().padStart(3, " ")}  ${incident.title}${suffix}${successTag}`
    );

    const ip = incident.evidence.find((item) => item.key === "ip")?.value;
    const path = incident.evidence.find((item) => item.key === "path")?.value;
    const topPaths = incident.evidence.find((item) => item.key === "topPaths")?.value;
    const prefix = incident.evidence.find((item) => item.key === "prefix")?.value;

    if (ip) {
      lines.push(`       ip: ${ip}`);
    }
    if (path) {
      lines.push(`       ${path}`);
    }
    if (topPaths) {
      const paths = String(topPaths).split(" | ").slice(0, 3);
      for (const p of paths) {
        lines.push(`       ${p}`);
      }
    }
    if (prefix) {
      lines.push(`       subnet: ${prefix}`);
    }

    for (const sample of incident.samples.slice(0, 2)) {
      lines.push(`       sample: ${sample}`);
    }
  }

  if (incidents.length > 15) {
    lines.push(`  ... and ${incidents.length - 15} more`);
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
