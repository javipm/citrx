import type { AccessLogEntry } from "../parser/access-log.js";
import type { Incident, IncidentKind, IncidentSeverity } from "../analysis/types.js";

export interface RuleHit {
  ruleId: string;
  category: string;
  kind: IncidentKind;
  severity: IncidentSeverity;
  score: number;
  title: string;
  description: string;
  sample: string;
}

interface RuleDefinition {
  id: string;
  category: string;
  kind: IncidentKind;
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
  topPaths: Set<string>;
}

export interface PathStats {
  path: string;
  count: number;
  bytes: number;
  ipCounts: Map<string, number>;
  queryVariants: Set<string>;
  postCount: number;
  /** Epoch seconds of first/last entry for this path (null if not tracked). */
  firstSeen: number | null;
  lastSeen: number | null;
  /** HTTP status counters for rate-quality signal. */
  status2xx: number;
  status3xx: number;
  status4xx: number;
  status5xx: number;
  currentMinute?: number | null;
  currentMinuteRequests?: number;
  currentMinuteServed?: number;
  maxRequestsPerMinute?: number;
  maxServedPerMinute?: number;
  /** Up to 5 redacted sample targets for operator review. */
  samples: string[];
}

const RULES: RuleDefinition[] = [
  {
    id: "sqli",
    kind: "compromise" as IncidentKind,
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
      // Require SQL-context prefix (= ( ,) before long hex to avoid matching
      // SHA/MD5 content hashes in versioned static asset filenames.
      /[=(,]\s*0x[0-9a-f]{20,}/i,
      /(?:'|%27)\s*(?:or|and)\s+1\s*=\s*1/i,
      // Blind SQLi / fingerprinting functions
      /\bpg_sleep\s*\(/i,
      /\bversion\s*\(\s*\)/i,
      /\bdatabase\s*\(\s*\)/i,
      /\buser\s*\(\s*\)/i,
      /\bconnection_id\s*\(\s*\)/i,
      // SQL comment injection: /**/ and version-conditional /*!…*/
      /\/\*(?:\d+|\s*)\*\//
    ]
  },
  {
    id: "xss",
    kind: "compromise" as IncidentKind,
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
      /document\.cookie/i,
      // HTML5 event handlers that fire without <script> or onload/onerror
      /\bon(?:mouseover|focus|focusin|click|pointerdown|animationstart|toggle)\s*=/i
    ]
  },
  {
    id: "lfi_rfi",
    kind: "compromise" as IncidentKind,
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
    kind: "compromise" as IncidentKind,
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
    kind: "compromise" as IncidentKind,
    category: "command_injection",
    severity: "critical",
    score: 95,
    title: "Command injection payload",
    description: "Request target contains shell metacharacters with command execution indicators.",
    patterns: [
      // Classic metachar + known Unix binaries
      /(?:;|%3b|\||%7c|`|%60|\$\(|%24%28).*(?:\bid\b|\bwhoami\b|\bcat\b|\bwget\b|\bcurl\b|\bbash\b|\bnc\b|\bsh\b|\bpython\b|\bperl\b|\bphp\b|\bping\b|\bnslookup\b)/i,
      // Windows/PowerShell variants
      /(?:;|%3b|\||%7c|`|%60|\$\(|%24%28).*(?:powershell|cmd\.exe|wscript|cscript)/i,
      // $IFS and newline-based separator bypass
      /\$IFS|\$\{IFS\}|%0a[a-z]|%0d%0a[a-z]/i
    ]
  },
  {
    id: "recon_sensitive_file",
    kind: "compromise" as IncidentKind,
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
const CRAWL_SATURATION_MIN_REQUESTS = 10_000;
const CRAWL_SATURATION_MIN_QUERY_VARIANTS = 1_000;
const CRAWL_SATURATION_MIN_QUERY_VARIANT_RATIO = 0.5;
const CRAWL_SATURATION_MIN_REPEATED_IPS = 20;
const CRAWL_SATURATION_MIN_REPEATED_REQUEST_SHARE = 0.8;
/**
 * When signal quality is very high (query-variant ratio ≥ 0.75 or many repeated IPs)
 * allow saturation at lower served-request volume. A URL receiving 1 000+ requests
 * where 75%+ are unique queries is clearly being exhaustively scraped regardless of
 * total volume.
 */
const CRAWL_SATURATION_HIGH_SIGNAL_MIN_REQUESTS = 1_000;
const CRAWL_SATURATION_HIGH_SIGNAL_QUERY_RATIO = 0.75;
const CRAWL_SATURATION_HIGH_SIGNAL_REPEATED_IPS = 30;
const CRAWL_SATURATION_MIN_PEAK_SERVED_PER_MINUTE = 120;
const CRAWL_SATURATION_LARGE_CHURN_MIN_REQUESTS = 20_000;
const CRAWL_SATURATION_LARGE_CHURN_MIN_PEAK_SERVED_PER_MINUTE = 60;
const CRAWL_SATURATION_SUSTAINED_QUERY_MIN_REQUESTS = 5_000;
const CRAWL_SATURATION_SUSTAINED_QUERY_MIN_VARIANTS = 1_000;
const CRAWL_SATURATION_SUSTAINED_QUERY_MIN_RATIO = 0.5;
const CRAWL_SATURATION_SUSTAINED_QUERY_MIN_DISTRIBUTED_IPS = 200;
const CRAWL_SATURATION_SUSTAINED_QUERY_MIN_CONCENTRATED_PEAK = 50;
const CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_REQUESTS = 5_000;
const CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_REPEATED_IPS = 10;
const CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_SHARE = 0.75;
const CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_PEAK = 20;
const CRAWL_SATURATION_MAX_BLOCKED_RATIO = 5;
const CRAWL_SATURATION_BLOCKED_QUERY_MIN_REQUESTS = 2_500;
const CRAWL_SATURATION_BLOCKED_QUERY_MIN_SERVED = 100;
const CRAWL_SATURATION_BLOCKED_QUERY_MIN_PEAK_REQUESTS_PER_MINUTE = 120;
const CRAWL_SATURATION_MIN_5XX_DISTRESS = 100;
const POST_HOTSPOT_MIN_REQUESTS = 200;
const QUERY_EXPLOSION_MIN_REQUESTS = 500;
const QUERY_EXPLOSION_MIN_VARIANTS = 150;
const QUERY_EXPLOSION_MIN_VARIANT_RATIO = 0.5;
const TOP_PATHS_LIMIT = 10;

/**
 * Cheap substring fast-path — if none match, skip all regex evaluation.
 *
 * IMPORTANT: every regex pattern in RULES must have at least one literal
 * substring listed here. Adding a pattern to RULES without a corresponding
 * entry here means the pattern is NEVER evaluated (the early-return fires first).
 */
const PAYLOAD_PREFIXES = [
  // SQLi — union/select family
  "select",
  "union",
  "information_schema",
  "sleep(",
  "benchmark(",
  "waitfor",
  "prepare",
  "execute",
  "0x",
  // SQLi — fingerprinting functions
  "pg_sleep(",
  "version()",
  "database()",
  "user()",
  "connection_id()",
  // SQLi — comment injection
  "/**/",
  "/*!",
  // XSS — script tags and execution
  "<script",
  "%3cscript",
  "onerror",
  "onload",
  "javascript:",
  "%3csvg",
  "alert(",
  "document.cookie",
  // XSS — HTML5 event handlers (no <script> needed)
  "onmouseover",
  "onfocus",
  "onfocusin",
  "onclick",
  "onpointerdown",
  "onanimationstart",
  "ontoggle",
  // LFI/RFI
  "../",
  "..%2f",
  "%252e",
  "/etc/",
  "/proc/",
  "php://",
  "file=http",
  "path=http",
  "template=http",
  // SSRF
  "169.254",
  "metadata.google",
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "url=http",
  "callback=http",
  "webhook=http",
  "redirect=http",
  // Command injection — metacharacters
  ";",
  "%3b",
  "|",
  "%7c",
  "`",
  "%60",
  "$(",
  "%24%28",
  "$IFS",
  "${IFS}",
  "%0a",
  "%0d%0a",
  "powershell",
  "cmd.exe",
  // Sensitive file probes
  ".env",
  ".git",
  "composer.json",
  "phpinfo",
  ".sql",
  ".bak",
  ".old"
];

const PAYLOAD_PREFIX_RE = new RegExp(PAYLOAD_PREFIXES.map(escapeRegex).join("|"), "i");
const COMMON_METHODS = new Set(["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"]);

export function detectRequestHits(entry: AccessLogEntry): RuleHit[] {
  // Fast path: skip expensive decode + regex if no known payload prefix present
  if (!PAYLOAD_PREFIX_RE.test(entry.target)) {
    // Still check rare method (PUT/DELETE/PATCH are standard REST and excluded).
    if (COMMON_METHODS.has(entry.method)) {
      return [];
    }
    return [buildRareMethodHit(entry)];
  }

  const target = normalizeForMatching(entry.target);
  const hits: RuleHit[] = [];

  for (const rule of RULES) {
    if (rule.patterns.some((pattern) => pattern.test(target))) {
      hits.push({
        ruleId: rule.id,
        category: rule.category,
        kind: rule.kind,
        severity: rule.severity,
        score: rule.score,
        title: rule.title,
        description: rule.description,
        sample: redactTarget(entry.target)
      });
    }
  }

  // PUT/DELETE/PATCH are standard REST methods. Truly rare = TRACE/CONNECT/DEBUG.
  if (!COMMON_METHODS.has(entry.method)) {
    hits.push(buildRareMethodHit(entry));
  }

  return hits;
}

function buildRareMethodHit(entry: AccessLogEntry): RuleHit {
  return {
    ruleId: "rare_method",
    category: "http_anomaly",
    kind: "noise" as IncidentKind,
    severity: "medium" as IncidentSeverity,
    score: 55,
    title: "Rare HTTP method",
    description: "Request uses an uncommon HTTP method for public web traffic.",
    sample: `${entry.method} ${redactTarget(entry.target)}`
  };
}

/** Static asset paths produce huge query/path counts naturally (cache-busters,
 *  imagemap variants). They're never the target of an actual attack.  */
const STATIC_ASSET_RE =
  /\.(?:js|mjs|css|map|png|jpe?g|gif|svg|webp|avif|woff2?|ttf|otf|eot|ico|bmp|tiff?|mp3|mp4|webm|ogg|m4a|m4v|pdf)(?:\?|$)/i;

/** Crawler-infra paths hammered by Googlebot/aggregators but never abuse targets. */
const CRAWLER_INFRA_RE =
  /^\/(?:sitemap[^?]*\.xml|robots\.txt|feed(?:\/|$|\?)|rss(?:\/|$|\?)|\.well-known(?:\/|$|\?)|favicon\.ico)(?:\?|$)/i;

/** Marketing / analytics click-tracking params that are unique per visitor/click.
 *  Stripped from query variant signatures to avoid false-positive saturation signals
 *  on popular social-shared or ad-targeted URLs. */
const TRACKING_PARAM_RE =
  /^(?:fbclid|gclid|gclsrc|dclid|msclkid|yclid|gbraid|wbraid|gad_\w+|srsltid|utm_\w+|_ga\w*|_gl|_gid|mc_eid|mc_cid|igshid|s_kwcid|ef_id|_|rand|random|cache|cachebuster|cb|ts|timestamp|time)$/i;

function isLowSignalAggregatePath(path: string): boolean {
  return STATIC_ASSET_RE.test(path) || CRAWLER_INFRA_RE.test(path);
}

export function buildAggregateIncidents(pathStats: Iterable<PathStats>): Incident[] {
  const incidents: Incident[] = [];

  for (const stats of pathStats) {
    // Skip static assets (cache-busters) and admin paths (legit high-volume).
    if (isLowSignalAggregatePath(stats.path)) {
      continue;
    }

    const crawlSignal = highVolumeCrawlSignal(stats);

    if (crawlSignal) {
      const saturationKind = materialPathSaturationSignal(stats, crawlSignal);

      // Rate per minute (null when timestamps not available).
      const durationMinutes =
        stats.firstSeen !== null && stats.lastSeen !== null
          ? Math.max(1, (stats.lastSeen - stats.firstSeen) / 60)
          : null;
      const ratePerMinute =
        durationMinutes !== null ? Math.round(stats.count / durationMinutes) : null;

      // Server distress: 5xx under load escalates severity.
      const hasServerDistress = stats.status5xx >= CRAWL_SATURATION_MIN_5XX_DISTRESS;

      let kind: "saturation" | "noise";
      let severity: "critical" | "high" | "medium";
      let score: number;
      let title: string;
      let description: string;

      if (saturationKind === "query_churn") {
        kind = "saturation";
        severity = hasServerDistress ? "critical" : "high";
        score = hasServerDistress ? 85 : 75;
        title = "Distributed URL saturation";
        description = "A non-entrypoint URL received material distributed request pressure.";
      } else if (saturationKind === "repeat_pressure") {
        kind = "saturation";
        severity = hasServerDistress ? "critical" : "high";
        score = hasServerDistress ? 80 : 70;
        title = "Concentrated URL pressure";
        description =
          "A non-entrypoint URL received concentrated repeated pressure from a small set of IPs.";
      } else {
        kind = "noise";
        severity = "medium";
        score = 55;
        title = "Distributed high-volume path crawling";
        description = "Many clients repeatedly requested a non-entrypoint path.";
      }

      const evidence: Incident["evidence"] = [
        { key: "path", value: stats.path },
        { key: "requests", value: stats.count },
        { key: "uniqueIps", value: stats.ipCounts.size },
        { key: "repeatedIps", value: crawlSignal.repeatedIps },
        { key: "repeatedRequestShare", value: crawlSignal.repeatedRequestShare },
        { key: "queryVariants", value: stats.queryVariants.size },
        { key: "queryVariantRatio", value: crawlSignal.queryVariantRatio },
        { key: "bytes", value: stats.bytes }
      ];

      if (stats.firstSeen !== null) {
        evidence.push({ key: "firstSeen", value: epochToIso(stats.firstSeen) });
      }
      if (stats.lastSeen !== null) {
        evidence.push({ key: "lastSeen", value: epochToIso(stats.lastSeen) });
      }
      if (ratePerMinute !== null) {
        evidence.push({ key: "ratePerMinute", value: ratePerMinute });
      }
      if (stats.maxRequestsPerMinute !== undefined) {
        evidence.push({ key: "maxRequestsPerMinute", value: stats.maxRequestsPerMinute });
      }
      if (stats.maxServedPerMinute !== undefined) {
        evidence.push({ key: "maxServedPerMinute", value: stats.maxServedPerMinute });
      }
      if (stats.status2xx > 0) evidence.push({ key: "status2xx", value: stats.status2xx });
      if (stats.status3xx > 0) evidence.push({ key: "status3xx", value: stats.status3xx });
      if (stats.status4xx > 0) evidence.push({ key: "status4xx", value: stats.status4xx });
      if (stats.status5xx > 0) evidence.push({ key: "status5xx", value: stats.status5xx });

      incidents.push({
        id: `abusive_crawl:${stats.path}`,
        category: "abusive_crawling",
        kind,
        severity,
        score,
        title,
        description,
        evidence,
        samples: stats.samples.slice(0, 5)
      });
    } else if (
      !isLowSignalEntryPath(stats.path) &&
      stats.queryVariants.size >= QUERY_EXPLOSION_MIN_VARIANTS &&
      stats.count >= QUERY_EXPLOSION_MIN_REQUESTS &&
      roundRatio(stats.queryVariants.size / stats.count) >= QUERY_EXPLOSION_MIN_VARIANT_RATIO
    ) {
      incidents.push({
        id: `query_explosion:${stats.path}`,
        category: "abusive_crawling",
        kind: "noise",
        severity: "low",
        score: 40,
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

    if (stats.postCount >= POST_HOTSPOT_MIN_REQUESTS) {
      incidents.push({
        id: `post_hotspot:${stats.path}`,
        category: "post_hotspot",
        kind: "noise",
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

function highVolumeCrawlSignal(stats: PathStats): {
  repeatedIps: number;
  repeatedRequestShare: number;
  queryVariantRatio: number;
} | null {
  if (
    isLowSignalEntryPath(stats.path) ||
    isIndexEntrypointWithoutAppSignal(stats) ||
    stats.count < CRAWL_MIN_REQUESTS
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
    stats.ipCounts.size >= CRAWL_MIN_UNIQUE_IPS &&
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

function materialPathSaturationSignal(
  stats: PathStats,
  crawlSignal: {
    repeatedIps: number;
    repeatedRequestShare: number;
    queryVariantRatio: number;
  }
): "query_churn" | "repeat_pressure" | null {
  // Saturation normally uses requests that hit real backend processing:
  //   2xx — content actually delivered.
  //   5xx — backend crashed under load (most extreme saturation signal).
  // 3xx (redirects) are resolved at the webserver/CDN level without app processing.
  // 4xx (WAF/auth blocks) usually do not count, except high-peak query churn with
  // some served responses: that still represents active pressure on a costly URL.
  const servedCount = stats.status2xx + stats.status5xx;
  const maxServedPerMinute = stats.maxServedPerMinute ?? 0;
  const maxRequestsPerMinute = stats.maxRequestsPerMinute ?? 0;

  // High signal quality (very high query-variant churn or many repeat IPs) allows
  // saturation at lower served volume — exhaustive scraping at 1 000+ hits is
  // actionable regardless of whether total volume reaches 10 000.
  const highQuerySignal = crawlSignal.queryVariantRatio >= CRAWL_SATURATION_HIGH_SIGNAL_QUERY_RATIO;
  const highRepeatSignal = crawlSignal.repeatedIps >= CRAWL_SATURATION_HIGH_SIGNAL_REPEATED_IPS;
  const minServed =
    highQuerySignal || highRepeatSignal
      ? CRAWL_SATURATION_HIGH_SIGNAL_MIN_REQUESTS
      : CRAWL_SATURATION_MIN_REQUESTS;

  if (hasBlockedQueryPressureSaturation(stats, crawlSignal, servedCount, maxRequestsPerMinute)) {
    return "query_churn";
  }

  if (servedCount < minServed) {
    return null;
  }

  if (blockedDominates(stats, servedCount)) {
    return null;
  }

  if (stats.status5xx >= CRAWL_SATURATION_MIN_5XX_DISTRESS) {
    return crawlSignal.queryVariantRatio >= CRAWL_SATURATION_MIN_QUERY_VARIANT_RATIO
      ? "query_churn"
      : "repeat_pressure";
  }

  if (hasSustainedQuerySaturation(stats, crawlSignal, servedCount, maxServedPerMinute)) {
    return "query_churn";
  }

  if (hasSustainedRepeatSaturation(stats, crawlSignal, servedCount, maxServedPerMinute)) {
    return "repeat_pressure";
  }

  const minPeakServedPerMinute =
    highQuerySignal && servedCount >= CRAWL_SATURATION_LARGE_CHURN_MIN_REQUESTS
      ? CRAWL_SATURATION_LARGE_CHURN_MIN_PEAK_SERVED_PER_MINUTE
      : CRAWL_SATURATION_MIN_PEAK_SERVED_PER_MINUTE;

  if (maxServedPerMinute < minPeakServedPerMinute) {
    return null;
  }

  // Distributed query churn: many unique non-tracking query variants from spread IPs.
  const hasMaterialQueryChurn =
    stats.queryVariants.size >= CRAWL_SATURATION_MIN_QUERY_VARIANTS &&
    crawlSignal.queryVariantRatio >= CRAWL_SATURATION_MIN_QUERY_VARIANT_RATIO;

  // Concentrated repeat pressure: small set of IPs accounts for the majority of load.
  // Labelled separately from distributed churn — the attack profile differs.
  const hasMaterialRepeatPressure =
    crawlSignal.repeatedIps >= CRAWL_SATURATION_MIN_REPEATED_IPS &&
    crawlSignal.repeatedRequestShare >= CRAWL_SATURATION_MIN_REPEATED_REQUEST_SHARE;

  if (hasMaterialQueryChurn) return "query_churn";
  if (hasMaterialRepeatPressure) return "repeat_pressure";
  return null;
}

function hasBlockedQueryPressureSaturation(
  stats: PathStats,
  crawlSignal: {
    repeatedIps: number;
    repeatedRequestShare: number;
    queryVariantRatio: number;
  },
  servedCount: number,
  maxRequestsPerMinute: number
): boolean {
  return (
    stats.count >= CRAWL_SATURATION_BLOCKED_QUERY_MIN_REQUESTS &&
    servedCount >= CRAWL_SATURATION_BLOCKED_QUERY_MIN_SERVED &&
    stats.queryVariants.size >= CRAWL_SATURATION_MIN_QUERY_VARIANTS &&
    crawlSignal.queryVariantRatio >= CRAWL_SATURATION_HIGH_SIGNAL_QUERY_RATIO &&
    maxRequestsPerMinute >= CRAWL_SATURATION_BLOCKED_QUERY_MIN_PEAK_REQUESTS_PER_MINUTE &&
    stats.status4xx > servedCount * CRAWL_SATURATION_MAX_BLOCKED_RATIO &&
    stats.status3xx <= servedCount
  );
}

function isLowSignalEntryPath(path: string): boolean {
  const normalized = path.toLowerCase().replace(/\/+$/, "") || "/";
  return ["/", "/index", "/index.html", "/index.htm", "/home"].includes(normalized);
}

function isIndexEntrypointWithoutAppSignal(stats: PathStats): boolean {
  const normalized = stats.path.toLowerCase().replace(/\/+$/, "");
  return normalized === "/index.php" && stats.queryVariants.size === 0 && stats.status5xx === 0;
}

function hasSustainedQuerySaturation(
  stats: PathStats,
  crawlSignal: {
    repeatedIps: number;
    repeatedRequestShare: number;
    queryVariantRatio: number;
  },
  servedCount: number,
  maxServedPerMinute: number
): boolean {
  if (
    servedCount < CRAWL_SATURATION_SUSTAINED_QUERY_MIN_REQUESTS ||
    stats.queryVariants.size < CRAWL_SATURATION_SUSTAINED_QUERY_MIN_VARIANTS ||
    crawlSignal.queryVariantRatio < CRAWL_SATURATION_SUSTAINED_QUERY_MIN_RATIO ||
    blockedDominates(stats, servedCount)
  ) {
    return false;
  }

  if (stats.ipCounts.size >= CRAWL_SATURATION_SUSTAINED_QUERY_MIN_DISTRIBUTED_IPS) {
    return true;
  }

  return maxServedPerMinute >= CRAWL_SATURATION_SUSTAINED_QUERY_MIN_CONCENTRATED_PEAK;
}

function hasSustainedRepeatSaturation(
  stats: PathStats,
  crawlSignal: {
    repeatedIps: number;
    repeatedRequestShare: number;
    queryVariantRatio: number;
  },
  servedCount: number,
  maxServedPerMinute: number
): boolean {
  return (
    servedCount >= CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_REQUESTS &&
    crawlSignal.repeatedIps >= CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_REPEATED_IPS &&
    crawlSignal.repeatedRequestShare >= CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_SHARE &&
    maxServedPerMinute >= CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_PEAK &&
    !blockedDominates(stats, servedCount)
  );
}

function blockedDominates(stats: PathStats, servedCount: number): boolean {
  return (
    stats.status4xx > servedCount * CRAWL_SATURATION_MAX_BLOCKED_RATIO ||
    stats.status3xx > servedCount * CRAWL_SATURATION_MAX_BLOCKED_RATIO
  );
}

function roundRatio(value: number): number {
  return Math.round(value * 1000) / 1000;
}

function epochToIso(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString();
}

export function mergeRuleHit(
  incidents: Map<string, Incident>,
  hit: RuleHit,
  entry: AccessLogEntry
): string {
  const ip = entry.ip;
  const id = `${hit.ruleId}:${ip}`;
  const existing = incidents.get(id);

  if (existing) {
    const stats = readOutcomeStats(existing.evidence);
    applyStatus(stats, entry.status);
    addTopPath(stats, entry.path);
    applyOutcomeScore(existing, hit, stats, ip);

    if (existing.samples.length < 5 && !existing.samples.includes(hit.sample)) {
      existing.samples.push(hit.sample);
    }

    return id;
  }

  const stats = createOutcomeStats();
  applyStatus(stats, entry.status);
  addTopPath(stats, entry.path);

  const incident: Incident = {
    id,
    category: hit.category,
    kind: hit.kind,
    severity: hit.severity,
    score: hit.score,
    title: hit.title,
    description: hit.description,
    evidence: [],
    samples: [hit.sample]
  };
  applyOutcomeScore(incident, hit, stats, ip);
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
    status404: 0,
    topPaths: new Set()
  };
}

function addTopPath(stats: RuleOutcomeStats, path: string): void {
  if (stats.topPaths.size < TOP_PATHS_LIMIT) {
    stats.topPaths.add(path);
  }
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
  const topPathsRaw = evidence.find((item) => item.key === "topPaths")?.value;
  const topPaths = new Set<string>(
    typeof topPathsRaw === "string" && topPathsRaw.length > 0 ? topPathsRaw.split(" | ") : []
  );

  return {
    count: numberEvidence(evidence, "count"),
    status2xx: numberEvidence(evidence, "status2xx"),
    status3xx: numberEvidence(evidence, "status3xx"),
    status4xx: numberEvidence(evidence, "status4xx"),
    status5xx: numberEvidence(evidence, "status5xx"),
    status404: numberEvidence(evidence, "status404"),
    topPaths
  };
}

function numberEvidence(evidence: Incident["evidence"], key: string): number {
  return Number(evidence.find((item) => item.key === key)?.value ?? 0);
}

function applyOutcomeScore(
  incident: Incident,
  hit: RuleHit,
  stats: RuleOutcomeStats,
  ip: string
): void {
  const outcome = outcomeFor(hit.ruleId, stats);
  incident.kind = actionableCompromiseKind(hit, outcome.label) ? "compromise" : "noise";
  incident.severity = outcome.severity ?? hit.severity;
  incident.score = outcome.score ?? hit.score;
  if (outcome.successful) {
    incident.successful = true;
  }
  incident.evidence = buildRuleEvidence(ip, stats, outcome.label);
}

function actionableCompromiseKind(hit: RuleHit, outcome: string): boolean {
  if (hit.kind !== "compromise") {
    return false;
  }

  if (isReconRule(hit.ruleId)) {
    return outcome === "file_served" || outcome === "server_error";
  }

  if (isPayloadRule(hit.ruleId)) {
    return outcome === "successful" || outcome === "server_error";
  }

  return false;
}

function outcomeFor(
  ruleId: string,
  stats: RuleOutcomeStats
): { label: string; severity?: IncidentSeverity; score?: number; successful?: boolean } {
  if (isReconRule(ruleId)) {
    // Recon is info-disclosure, not exploitation. Scale severity by outcome but never go critical/100.
    // Require ≥2 successes OR a non-trivial success ratio — a single 2xx out of
    // hundreds is almost always a fluke (robots.txt, security.txt, redirects to
    // a default page, etc.) and shouldn't escalate.
    const successRatio = stats.count > 0 ? stats.status2xx / stats.count : 0;
    const meaningfulSuccess = stats.status2xx >= 2 || successRatio >= 0.1;
    if (meaningfulSuccess) {
      return { label: "file_served", severity: "high", score: 80, successful: true };
    }
    if (stats.status5xx > 0) {
      return { label: "server_error", severity: "medium", score: 55 };
    }
    if (stats.status404 === stats.count) {
      return { label: "all_404", severity: "low", score: 20 };
    }
    if (stats.status4xx === stats.count) {
      return { label: "all_4xx", severity: "low", score: 30 };
    }
    return { label: "mixed", severity: "medium", score: 50 };
  }

  if (!isPayloadRule(ruleId)) {
    return { label: "mixed" };
  }

  // 2xx = possible successful exploit — highest priority
  if (stats.status2xx > 0) {
    return { label: "successful", severity: "critical", score: 100, successful: true };
  }

  // 5xx = application crash/error — likely vulnerable code path hit
  if (stats.status5xx > 0) {
    return { label: "server_error", severity: "critical", score: 90 };
  }

  // No 2xx, no 5xx → attack was blocked or redirected (WAF / auth / 404).
  // Score by how the blocks happened, but never escalate to critical.
  if (stats.status404 === stats.count) {
    return { label: "all_404", severity: "low", score: 30 };
  }
  if (stats.status4xx === stats.count) {
    return { label: "all_4xx", severity: "medium", score: 50 };
  }
  // Mixed 3xx + 4xx — still blocked (redirects to login/error pages).
  return { label: "blocked", severity: "medium", score: 55 };
}

function isPayloadRule(ruleId: string): boolean {
  return ["sqli", "xss", "lfi_rfi", "ssrf", "command_injection"].includes(ruleId);
}

function isReconRule(ruleId: string): boolean {
  return ruleId === "recon_sensitive_file";
}

function buildRuleEvidence(
  ip: string,
  stats: RuleOutcomeStats,
  outcome: string
): Incident["evidence"] {
  const evidence: Incident["evidence"] = [
    { key: "ip", value: ip },
    { key: "count", value: stats.count },
    { key: "outcome", value: outcome }
  ];

  if (stats.topPaths.size > 0) {
    evidence.push({ key: "topPaths", value: [...stats.topPaths].join(" | ") });
  }

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

/**
 * Drop low-signal rule incidents to reduce noise.
 * Keeps any incident with 2xx (possible success), 5xx (possible crash),
 * sustained activity (count >= 3) or fan-out (paths > 1).
 * Drops single 404 probes — these are constant on the internet and not actionable.
 */
export function pruneNoise(incidents: Map<string, Incident>): void {
  for (const [id, incident] of incidents) {
    const count = Number(incident.evidence.find((item) => item.key === "count")?.value ?? 0);
    const status2xx = Number(
      incident.evidence.find((item) => item.key === "status2xx")?.value ?? 0
    );
    const status5xx = Number(
      incident.evidence.find((item) => item.key === "status5xx")?.value ?? 0
    );
    const topPathsRaw = incident.evidence.find((item) => item.key === "topPaths")?.value;
    const pathCount =
      typeof topPathsRaw === "string" && topPathsRaw.length > 0
        ? topPathsRaw.split(" | ").length
        : 0;

    // Always keep any incident with a 2xx (possible success) or 5xx (possible vuln hit).
    if (status2xx > 0 || status5xx > 0) {
      continue;
    }

    // rare_method spam: needs ≥5 events from same IP to be interesting.
    if (incident.id.startsWith("rare_method:") && count < 5) {
      incidents.delete(id);
      continue;
    }

    // Single 404 probe on one path — extremely common, almost always noise.
    if (count < 2 && pathCount <= 1) {
      incidents.delete(id);
      continue;
    }

    // Recon all-404 with ≤2 paths and low count — still noise.
    if (incident.id.startsWith("recon_sensitive_file:") && count < 3 && pathCount <= 2) {
      incidents.delete(id);
      continue;
    }
  }
}

export function redactTarget(target: string): string {
  return truncateSample(redactSensitiveTarget(target));
}

export function querySignature(target: string): string {
  const queryStart = target.indexOf("?");
  if (queryStart === -1) return "";

  // Strip marketing/analytics tracking params before building the variant signature.
  // fbclid/gclid/utm_*/etc. are unique per click and inflate query-variant counts
  // for legitimate marketing traffic. We keep all real application params so genuine
  // query-explosion abuse is still detected.
  try {
    const url = new URL(target, "http://citrx.local");
    for (const key of [...url.searchParams.keys()]) {
      if (TRACKING_PARAM_RE.test(key)) {
        url.searchParams.delete(key);
      }
    }
    if (!url.search) return "";
    return redactSensitiveTarget(`/${url.search}`).slice(1);
  } catch {
    return redactSensitiveTarget(`/${target.slice(queryStart)}`).slice(1);
  }
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

/**
 * Iterative URL-decode up to 3 passes to catch double/triple encoding
 * (e.g. %2527 → %27 → ') without risking infinite loops on crafted input.
 * Stops as soon as a pass produces no change.
 */
function normalizeForMatching(target: string): string {
  let current = target;
  for (let i = 0; i < 3; i++) {
    try {
      const next = decodeURIComponent(current);
      if (next === current) break;
      current = next;
    } catch {
      break;
    }
  }
  return current.toLowerCase();
}

function truncateSample(value: string): string {
  return value.length <= MAX_SAMPLE_LENGTH ? value : `${value.slice(0, MAX_SAMPLE_LENGTH - 3)}...`;
}

function escapeRegex(value: string): string {
  return value.replace(/[|\\{}()[\]^$+*?.]/g, "\\$&");
}
