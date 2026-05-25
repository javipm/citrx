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

export interface PathStats {
  path: string;
  count: number;
  bytes: number;
  ips: Set<string>;
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
    if (stats.count >= 1000 && stats.ips.size >= 20) {
      incidents.push({
        id: `abusive_crawl:${stats.path}`,
        category: "abusive_crawling",
        severity: "high",
        score: 80,
        title: "Distributed high-volume path crawling",
        description: "Many unique IPs repeatedly requested the same path.",
        evidence: [
          { key: "path", value: stats.path },
          { key: "requests", value: stats.count },
          { key: "uniqueIps", value: stats.ips.size },
          { key: "queryVariants", value: stats.queryVariants.size },
          { key: "bytes", value: stats.bytes }
        ],
        samples: []
      });
    } else if (stats.queryVariants.size >= 100 && stats.count >= 200) {
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

export function mergeRuleHit(
  incidents: Map<string, Incident>,
  hit: RuleHit,
  path: string
): string {
  const id = `${hit.ruleId}:${path}`;
  const existing = incidents.get(id);

  if (existing) {
    const count = Number(existing.evidence.find((item) => item.key === "count")?.value ?? 0);
    existing.evidence = [
      { key: "path", value: path },
      { key: "count", value: count + 1 }
    ];

    if (existing.samples.length < 5 && !existing.samples.includes(hit.sample)) {
      existing.samples.push(hit.sample);
    }

    return id;
  }

  incidents.set(id, {
    id,
    category: hit.category,
    severity: hit.severity,
    score: hit.score,
    title: hit.title,
    description: hit.description,
    evidence: [
      { key: "path", value: path },
      { key: "count", value: 1 }
    ],
    samples: [hit.sample]
  });

  return id;
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
