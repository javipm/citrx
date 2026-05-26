import type { AccessLogEntry } from "../parser/access-log.js";
import type { Incident, IncidentSeverity } from "../analysis/types.js";

export interface RuleHit {
  ruleId: string;
  category: string;
  severity: IncidentSeverity;
  score: number;
  title: string;
  description: string;
  sample: string;
}

interface RuleDefinition {
  id: string;
  category: string;
  severity: IncidentSeverity;
  score: number;
  title: string;
  description: string;
  patterns: RegExp[];
}

interface RuleOutcomeStats {
  count: number;
  status2xx: number;
  status3xx: number;
  status4xx: number;
  status5xx: number;
  status404: number;
}

export interface PathStats {
  path: string;
  count: number;
  bytes: number;
  ipCounts: Map<string, number>;
  queryVariants: Set<string>;
  postCount: number;
}

const RULES: RuleDefinition[] = [
  {
    id: "sqli",
    category: "sql_injection",
    severity: "critical",
    score: 95,
    title: "SQL injection payload",
    description: "Request target contains SQL injection indicators.",
    patterns: [
      /\bunion\s+select\b/i,
      /\binformation_schema\b/i,
      /\bsleep\s*\(/i,
      /\bbenchmark\s*\(/i,
      /\bwaitfor\s+delay\b/i,
      /\bprepare\s+stmt\b/i,
      /\bexecute\s+stmt\b/i,
      /0x[0-9a-f]{20,}/i,
      /(?:'|%27)\s*(?:or|and)\s+1\s*=\s*1/i
    ]
  },
  {
    id: "xss",
    category: "xss",
    severity: "high",
    score: 85,
    title: "XSS payload",
    description: "Request target contains script or browser execution indicators.",
    patterns: [
      /<script/i,
      /%3cscript/i,
      /\bonerror\s*=/i,
      /\bonload\s*=/i,
      /javascript:/i,
      /%3csvg/i,
      /\balert\s*\(/i,
      /document\.cookie/i
    ]
  },
  {
    id: "lfi_rfi",
    category: "path_traversal",
    severity: "high",
    score: 85,
    title: "LFI/RFI or path traversal payload",
    description: "Request target contains local/remote file inclusion indicators.",
    patterns: [
      /\.\.\//,
      /\.\.%2f/i,
      /%252e%252e/i,
      /\/etc\/passwd/i,
      /\/proc\/self\/environ/i,
      /php:\/\/filter/i,
      /(?:file|path|template)=https?:\/\//i
    ]
  },
  {
    id: "ssrf",
    category: "ssrf",
    severity: "high",
    score: 80,
    title: "SSRF target",
    description: "Request target references metadata, localhost, or internal callback targets.",
    patterns: [
      /169\.254\.169\.254/,
      /metadata\.google\.internal/i,
      /(?:127\.0\.0\.1|localhost|0\.0\.0\.0)/i,
      /(?:url|uri|callback|webhook|next|redirect)=https?:\/\//i
    ]
  },
  {
    id: "command_injection",
    category: "command_injection",
    severity: "critical",
    score: 95,
    title: "Command injection payload",
    description: "Request target contains shell metacharacters with command execution indicators.",
    patterns: [
      /(?:;|%3b|\||%7c|`|%60|\$\(|%24%28).*(?:\bid\b|\bwhoami\b|\bcat\b|\bwget\b|\bcurl\b|\bbash\b|\bnc\b)/i
    ]
  },
  {
    id: "recon_sensitive_file",
    category: "recon",
    severity: "medium",
    score: 65,
    title: "Sensitive file probe",
    description: "Request target probes common sensitive files or application internals.",
    patterns: [
      /\/\.env(?:\.|$|\?)/i,
      /\/\.git(?:\/|$|\?)/i,
      /\/composer\.json(?:$|\?)/i,
      /\/vendor\/(?:autoload\.php|composer\/|phpunit\/|bin\/)/i,
      /\/phpinfo\.php(?:$|\?)/i,
      /\.(?:sql|bak|old|zip|tar\.gz)(?:$|\?)/i
    ]
  }
];
const MAX_SAMPLE_LENGTH = 300;
const CRAWL_MIN_REQUESTS = 1000;
const CRAWL_MIN_UNIQUE_IPS = 20;
const CRAWL_MIN_QUERY_VARIANTS = 100;
const CRAWL_MIN_QUERY_VARIANT_RATIO = 0.2;
const CRAWL_MIN_REPEATED_IPS = 10;
const CRAWL_REPEATED_IP_REQUESTS = 5;
const CRAWL_MIN_REPEATED_REQUEST_SHARE = 0.45;

export function detectRequestHits(entry: AccessLogEntry): RuleHit[] {
  const target = normalizeForMatching(entry.target);
  const hits: RuleHit[] = [];

  for (const rule of RULES) {
    if (rule.patterns.some((pattern) => pattern.test(target))) {
      hits.push({
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        score: rule.score,
        title: rule.title,
        description: rule.description,
        sample: redactTarget(entry.target)
      });
    }
  }

  if (!["GET", "POST", "HEAD", "OPTIONS"].includes(entry.method)) {
    hits.push({
      ruleId: "rare_method",
      category: "http_anomaly",
      severity: "medium",
      score: 55,
      title: "Rare HTTP method",
      description: "Request uses an uncommon HTTP method for public web traffic.",
      sample: `${entry.method} ${redactTarget(entry.target)}`
    });
  }

  return hits;
}

export function buildAggregateIncidents(pathStats: Iterable<PathStats>): Incident[] {
  const incidents: Incident[] = [];

  for (const stats of pathStats) {
    const crawlSignal = highVolumeCrawlSignal(stats);

    if (crawlSignal) {
      incidents.push({
        id: `abusive_crawl:${stats.path}`,
        category: "abusive_crawling",
        severity: "high",
        score: 80,
        title: "Distributed high-volume path crawling",
        description: "Many clients repeatedly requested a non-entrypoint path.",
        evidence: [
          { key: "path", value: stats.path },
          { key: "requests", value: stats.count },
          { key: "uniqueIps", value: stats.ipCounts.size },
          { key: "repeatedIps", value: crawlSignal.repeatedIps },
          { key: "repeatedRequestShare", value: crawlSignal.repeatedRequestShare },
          { key: "queryVariants", value: stats.queryVariants.size },
          { key: "queryVariantRatio", value: crawlSignal.queryVariantRatio },
          { key: "bytes", value: stats.bytes }
        ],
        samples: []
      });
    } else if (
      !isLowSignalEntryPath(stats.path) &&
      stats.queryVariants.size >= 100 &&
      stats.count >= 200
    ) {
      incidents.push({
        id: `query_explosion:${stats.path}`,
        category: "abusive_crawling",
        severity: "medium",
        score: 65,
        title: "Query explosion",
        description: "One path was requested with many query variants.",
        evidence: [
          { key: "path", value: stats.path },
          { key: "requests", value: stats.count },
          { key: "queryVariants", value: stats.queryVariants.size }
        ],
        samples: []
      });
    }

    if (stats.postCount >= 50) {
      incidents.push({
        id: `post_hotspot:${stats.path}`,
        category: "post_hotspot",
        severity: "medium",
        score: 60,
        title: "POST hotspot",
        description: "Endpoint receives a high number of POST requests.",
        evidence: [
          { key: "path", value: stats.path },
          { key: "postRequests", value: stats.postCount }
        ],
        samples: []
      });
    }
  }

  return incidents;
}

function highVolumeCrawlSignal(
  stats: PathStats
): {
  repeatedIps: number;
  repeatedRequestShare: number;
  queryVariantRatio: number;
} | null {
  if (
    isLowSignalEntryPath(stats.path) ||
    stats.count < CRAWL_MIN_REQUESTS ||
    stats.ipCounts.size < CRAWL_MIN_UNIQUE_IPS
  ) {
    return null;
  }

  let repeatedIps = 0;
  let repeatedRequests = 0;

  for (const count of stats.ipCounts.values()) {
    if (count >= CRAWL_REPEATED_IP_REQUESTS) {
      repeatedIps += 1;
      repeatedRequests += count;
    }
  }

  const repeatedRequestShare = roundRatio(repeatedRequests / stats.count);
  const queryVariantRatio = roundRatio(stats.queryVariants.size / stats.count);
  const hasQueryChurn =
    stats.queryVariants.size >= CRAWL_MIN_QUERY_VARIANTS &&
    queryVariantRatio >= CRAWL_MIN_QUERY_VARIANT_RATIO;
  const hasRepeatPressure =
    repeatedIps >= CRAWL_MIN_REPEATED_IPS &&
    repeatedRequestShare >= CRAWL_MIN_REPEATED_REQUEST_SHARE;

  return hasQueryChurn || hasRepeatPressure
    ? {
        repeatedIps,
        repeatedRequestShare,
        queryVariantRatio
      }
    : null;
}

function isLowSignalEntryPath(path: string): boolean {
  const normalized = path.toLowerCase().replace(/\/+$/, "") || "/";
  return ["/", "/index", "/index.html", "/index.htm", "/index.php", "/home"].includes(
    normalized
  );
}

function roundRatio(value: number): number {
  return Math.round(value * 1000) / 1000;
}

export function mergeRuleHit(
  incidents: Map<string, Incident>,
  hit: RuleHit,
  entry: AccessLogEntry
): string {
  const path = entry.path;
  const id = `${hit.ruleId}:${path}`;
  const existing = incidents.get(id);

  if (existing) {
    const stats = readOutcomeStats(existing.evidence);
    applyStatus(stats, entry.status);
    applyOutcomeScore(existing, hit, stats, path);

    if (existing.samples.length < 5 && !existing.samples.includes(hit.sample)) {
      existing.samples.push(hit.sample);
    }

    return id;
  }

  const stats = createOutcomeStats();
  applyStatus(stats, entry.status);

  const incident: Incident = {
    id,
    category: hit.category,
    severity: hit.severity,
    score: hit.score,
    title: hit.title,
    description: hit.description,
    evidence: [],
    samples: [hit.sample]
  };
  applyOutcomeScore(incident, hit, stats, path);
  incidents.set(id, incident);

  return id;
}

function createOutcomeStats(): RuleOutcomeStats {
  return {
    count: 0,
    status2xx: 0,
    status3xx: 0,
    status4xx: 0,
    status5xx: 0,
    status404: 0
  };
}

function applyStatus(stats: RuleOutcomeStats, status: number): void {
  stats.count += 1;

  if (status >= 200 && status < 300) {
    stats.status2xx += 1;
  } else if (status >= 300 && status < 400) {
    stats.status3xx += 1;
  } else if (status >= 400 && status < 500) {
    stats.status4xx += 1;
  } else if (status >= 500 && status < 600) {
    stats.status5xx += 1;
  }

  if (status === 404) {
    stats.status404 += 1;
  }
}

function readOutcomeStats(evidence: Incident["evidence"]): RuleOutcomeStats {
  return {
    count: numberEvidence(evidence, "count"),
    status2xx: numberEvidence(evidence, "status2xx"),
    status3xx: numberEvidence(evidence, "status3xx"),
    status4xx: numberEvidence(evidence, "status4xx"),
    status5xx: numberEvidence(evidence, "status5xx"),
    status404: numberEvidence(evidence, "status404")
  };
}

function numberEvidence(evidence: Incident["evidence"], key: string): number {
  return Number(evidence.find((item) => item.key === key)?.value ?? 0);
}

function applyOutcomeScore(
  incident: Incident,
  hit: RuleHit,
  stats: RuleOutcomeStats,
  path: string
): void {
  const outcome = outcomeFor(hit.ruleId, stats);
  incident.severity = outcome.severity ?? hit.severity;
  incident.score = outcome.score ?? hit.score;
  incident.evidence = buildRuleEvidence(path, stats, outcome.label);
}

function outcomeFor(
  ruleId: string,
  stats: RuleOutcomeStats
): { label: string; severity?: IncidentSeverity; score?: number } {
  if (!isPayloadRule(ruleId)) {
    return { label: "mixed" };
  }

  if (stats.status404 === stats.count) {
    return { label: "all_404", severity: "medium", score: 45 };
  }

  if (stats.status4xx === stats.count) {
    return { label: "all_4xx", severity: "medium", score: 55 };
  }

  return { label: "mixed" };
}

function isPayloadRule(ruleId: string): boolean {
  return ["sqli", "xss", "lfi_rfi", "ssrf", "command_injection"].includes(ruleId);
}

function buildRuleEvidence(
  path: string,
  stats: RuleOutcomeStats,
  outcome: string
): Incident["evidence"] {
  const evidence: Incident["evidence"] = [
    { key: "path", value: path },
    { key: "count", value: stats.count },
    { key: "outcome", value: outcome }
  ];

  if (stats.status2xx > 0) {
    evidence.push({ key: "status2xx", value: stats.status2xx });
  }
  if (stats.status3xx > 0) {
    evidence.push({ key: "status3xx", value: stats.status3xx });
  }
  if (stats.status4xx > 0) {
    evidence.push({ key: "status4xx", value: stats.status4xx });
  }
  if (stats.status5xx > 0) {
    evidence.push({ key: "status5xx", value: stats.status5xx });
  }
  if (stats.status404 > 0) {
    evidence.push({ key: "status404", value: stats.status404 });
  }

  return evidence;
}


export function redactTarget(target: string): string {
  return truncateSample(redactSensitiveTarget(target));
}

export function querySignature(target: string): string {
  const queryStart = target.indexOf("?");
  return queryStart === -1 ? "" : redactSensitiveTarget(`/${target.slice(queryStart)}`).slice(1);
}

function redactSensitiveTarget(target: string): string {
  try {
    const url = new URL(target, "http://citrx.local");

    for (const key of [...url.searchParams.keys()]) {
      if (/token|_token|sid|session|password|passwd|key|secret|jwt|auth|authorization/i.test(key)) {
        url.searchParams.set(key, "[REDACTED]");
      }
    }

    return `${url.pathname}${url.search}`;
  } catch {
    return target.replace(
      /(token|_token|sid|session|password|passwd|key|secret|jwt|auth|authorization)=([^&\s]+)/gi,
      "$1=[REDACTED]"
    );
  }
}

function normalizeForMatching(target: string): string {
  try {
    return decodeURIComponent(target).toLowerCase();
  } catch {
    return target.toLowerCase();
  }
}

function truncateSample(value: string): string {
  return value.length <= MAX_SAMPLE_LENGTH
    ? value
    : `${value.slice(0, MAX_SAMPLE_LENGTH - 3)}...`;
}
