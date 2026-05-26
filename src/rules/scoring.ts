import type { Incident, IncidentSeverity } from "../analysis/types.js";

const PERSISTENCE_SECONDS = 1800;
const CORRELATION_BONUS = 10;
const PERSISTENCE_BONUS = 15;
const AI_LEGIT_PENALTY = -10;
const AI_LEGIT_MAX_REQUESTS = 5000;

export function applyScoringMultipliers(incidents: Incident[]): Incident[] {
  const correlatedIps = buildCorrelatedIps(incidents);

  return incidents.map((incident) => {
    let score = incident.score;
    const ip = stringEvidence(incident, "ip");

    if (ip && correlatedIps.has(ip)) {
      score += CORRELATION_BONUS;
    }

    if (isPersistent(incident)) {
      score += PERSISTENCE_BONUS;
    }

    if (isLegitAiBot(incident)) {
      score += AI_LEGIT_PENALTY;
    }

    score = Math.max(0, Math.min(100, score));

    return {
      ...incident,
      score,
      severity: severityFromScore(score)
    };
  });
}

export function severityFromScore(score: number): IncidentSeverity {
  if (score >= 90) return "critical";
  if (score >= 75) return "high";
  if (score >= 50) return "medium";
  if (score >= 25) return "low";
  return "info";
}

function buildCorrelatedIps(incidents: Incident[]): Set<string> {
  const counts = new Map<string, number>();

  for (const incident of incidents) {
    const ip = stringEvidence(incident, "ip");

    if (!ip) {
      continue;
    }

    counts.set(ip, (counts.get(ip) ?? 0) + 1);
  }

  return new Set(
    [...counts.entries()].filter(([, count]) => count >= 2).map(([ip]) => ip)
  );
}

function isPersistent(incident: Incident): boolean {
  const start = parseIso(
    stringEvidence(incident, "burstStart") ?? stringEvidence(incident, "firstSeen")
  );
  const end = parseIso(
    stringEvidence(incident, "burstEnd") ?? stringEvidence(incident, "lastSeen")
  );

  if (start === null || end === null) {
    return false;
  }

  return end - start >= PERSISTENCE_SECONDS;
}

function isLegitAiBot(incident: Incident): boolean {
  if (!incident.id.startsWith("ai_scraper_known:")) {
    return false;
  }

  const requests = numberEvidence(incident, "requests");
  const respectsRobots =
    stringEvidence(incident, "requestedRobotsTxt") === "true" ||
    booleanEvidence(incident, "requestedRobotsTxt") === true;

  return requests < AI_LEGIT_MAX_REQUESTS && respectsRobots;
}

function stringEvidence(incident: Incident, key: string): string | undefined {
  const value = evidenceValue(incident, key);
  return typeof value === "string" ? value : undefined;
}

function numberEvidence(incident: Incident, key: string): number {
  const value = evidenceValue(incident, key);
  return typeof value === "number" ? value : 0;
}

function booleanEvidence(incident: Incident, key: string): boolean | undefined {
  const value = evidenceValue(incident, key);
  return typeof value === "boolean" ? value : undefined;
}

function evidenceValue(incident: Incident, key: string): string | number | boolean | undefined {
  return incident.evidence.find((item) => item.key === key)?.value;
}

function parseIso(value: string | undefined): number | null {
  if (!value) {
    return null;
  }

  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}
