import pc from "picocolors";

import type { AnalyzeReport, Incident, TopItem } from "../analysis/types.js";
import { truncateForDisplay } from "../utils/text.js";

/** Max rendered length for a user agent value in top-value tables. */
const UA_DISPLAY_MAX_LENGTH = 60;

/** Options for controlling terminal report rendering. */
export interface TerminalReportOptions {
  /** Force color output on or off. Defaults to auto-detection via picocolors. */
  color?: boolean;
}

/**
 * Renders a full analysis report as a colored terminal string.
 *
 * Outputs summary stats, top lists (IPs, paths, user agents, etc.), AI bot
 * activity, and incident panels separated by kind ("compromise" vs "saturation").
 *
 * @param report - The analysis report produced by the analysis pipeline.
 * @param options - Optional rendering options (e.g. force color on/off).
 * @returns A newline-terminated string ready to print to stdout.
 */
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
  lines.push(section("Top user agents", report.topUserAgents, colors, UA_DISPLAY_MAX_LENGTH));
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

/**
 * Renders the "Known AI bots" section, listing up to 10 bots with request
 * counts, unique IP/path counts, and whether they requested `robots.txt`.
 *
 * @param report - The full analysis report.
 * @param colors - A picocolors instance (may have color disabled).
 * @returns A newline-joined string block for the AI bot section.
 */
function aiBotSection(report: AnalyzeReport, colors: ReturnType<typeof pc.createColors>): string {
  const lines = [colors.bold("Known AI bots")];

  for (const bot of report.aiBotStats.slice(0, 10)) {
    lines.push(
      `  ${bot.requests.toString().padStart(6, " ")}  ${bot.botName} ips=${bot.ipCount} paths=${bot.pathCount} robots=${bot.requestedRobotsTxt ? "yes" : "no"}`
    );
  }

  return lines.join("\n");
}

/**
 * Renders a titled list of top-N items with right-aligned counts.
 *
 * @param title - Section heading (e.g. `"Top IPs"`).
 * @param items - Array of `{ value, count }` items to display. Values are the
 *   full untruncated aggregation key; truncation for display happens here.
 * @param colors - A picocolors instance.
 * @param maxValueLength - Optional max rendered length for `item.value`
 *   (e.g. user agents, which can be much longer than IPs/paths).
 * @returns A newline-joined string block, showing "none" when the list is empty.
 */
function section(
  title: string,
  items: TopItem[],
  colors: ReturnType<typeof pc.createColors>,
  maxValueLength?: number
): string {
  const lines = [colors.bold(title)];

  if (items.length === 0) {
    lines.push("  none");
    return lines.join("\n");
  }

  for (const item of items) {
    const value = maxValueLength ? truncateForDisplay(item.value, maxValueLength) : item.value;
    lines.push(`  ${item.count.toString().padStart(6, " ")}  ${value}`);
  }

  return lines.join("\n");
}

/**
 * Renders a titled panel of incidents, capped at 15 entries.
 *
 * Each entry shows a color-coded severity label, score, title, and optional
 * evidence fields (ip, path, topPaths, prefix, request samples). Appends a
 * "… and N more" line when the list exceeds 15.
 *
 * @param title - Panel heading (e.g. `"Security incidents (attacks)"`).
 * @param incidents - Array of incidents to display.
 * @param colors - A picocolors instance.
 * @returns A newline-joined string block for the incident panel.
 */
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

    const successTag = incident.successful ? colors.red(" 2XX_HIT") : "";

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

/**
 * Returns a color-coded, fixed-width (8 chars) severity label string.
 *
 * Color mapping: critical → red, high → magenta, medium → yellow,
 * low → cyan, info → dim.
 *
 * @param value - Severity level from the incident.
 * @param colors - A picocolors instance.
 * @returns A padded, colored severity string.
 */
function severity(value: Incident["severity"], colors: ReturnType<typeof pc.createColors>): string {
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
