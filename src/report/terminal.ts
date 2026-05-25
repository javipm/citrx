import pc from "picocolors";

import type { AnalyzeReport, TopItem } from "../analysis/types.js";

export function renderTerminalReport(report: AnalyzeReport): string {
  const lines: string[] = [];

  lines.push(`${pc.bold("citrx")} ${pc.green("access log analysis")}`);
  lines.push("");
  lines.push(`Files: ${report.summary.files}`);
  lines.push(`Lines: ${report.summary.parsedLines}/${report.summary.totalLines}`);
  lines.push(`Invalid: ${report.summary.invalidLines}`);
  lines.push(`Bytes served: ${report.summary.totalBytes}`);
  lines.push("");
  lines.push(section("Top IPs", report.topIps));
  lines.push(section("Top paths", report.topPaths));
  lines.push(section("Methods", report.topMethods));
  lines.push(section("Statuses", report.topStatuses));

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
