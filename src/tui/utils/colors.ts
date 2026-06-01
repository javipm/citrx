import type { Incident } from "../../analysis/types.js";

export function severityColor(severity: Incident["severity"]): string {
  switch (severity) {
    case "critical":
      return "red";
    case "high":
      return "magenta";
    case "medium":
      return "yellow";
    case "low":
      return "cyan";
    case "info":
      return "gray";
  }
}

export function severityIcon(severity: Incident["severity"]): string {
  switch (severity) {
    case "critical":
      return "!";
    case "high":
      return "^";
    case "medium":
      return "~";
    case "low":
      return "-";
    case "info":
      return ".";
  }
}
