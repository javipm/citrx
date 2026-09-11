import type { AccessLogEntry } from "../parser/access-log.js";
import type { Incident, IncidentKind, IncidentSeverity } from "../analysis/types.js";
import { ipInPreparedRanges, prepareRanges } from "../analysis/ip-ranges.js";
import { redactSecretPairs } from "../utils/redact.js";
import { extractSubnetPrefix } from "../utils/subnet.js";
import { BINGBOT_RANGES } from "./data/bingbot-ranges.js";
import { GOOGLEBOT_RANGES } from "./data/googlebot-ranges.js";

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
  /** A high-value sensitive path that actually returned content, if any. */
  servedSensitivePath?: string;
  /** Response size of that hit, so an operator can rule out a soft-404 page. */
  servedSensitiveBytes?: number;
}

export interface PathStats {
  path: string;
  count: number;
  bytes: number;
  ipCounts: Map<string, number>;
  queryVariants: Set<string>;
  /**
   * Distinguished unique IPs: stored keys plus dropped keys still fingerprintable.
   * Never higher than true cardinality; never substituted with `count`.
   */
  uniqueIpCount?: number;
  /** True when at least one distinct IP could not be stored or fingerprinted. */
  uniqueIpsIsLowerBound?: boolean;
  /**
   * True when this path filled its own per-path IP cap. Distinct from
   * `uniqueIpsIsLowerBound`, which is also set when the shared global budget ran
   * out — that can happen to a path with only a handful of IPs, so it proves
   * nothing about this path's cardinality. Reaching the per-path cap does.
   */
  uniqueIpsAtOwnCap?: boolean;
  /**
   * Distinguished query variants: stored keys plus dropped keys still fingerprintable.
   * Never higher than true cardinality; never substituted with `count`.
   */
  queryVariantCount?: number;
  /** True when at least one distinct query variant could not be stored or fingerprinted. */
  queryVariantsIsLowerBound?: boolean;
  /**
   * True when this path filled its own per-path query-variant cap. See
   * `uniqueIpsAtOwnCap` for why this is tracked separately from the lower-bound
   * flag.
   */
  queryVariantsAtOwnCap?: boolean;
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
      /\/\*(?:\d+|\s*)\*\//,
      // SQL-context comment terminators: quote/close-paren followed by -- or #
      // (never bare -- or # — those are legitimate in slugs "foo--bar" and
      // fragments "#top").
      /(?:'|%27)\s*--/,
      /\)\s*--\s/,
      /\d\s*--\s/,
      /(?:'|%27)\s*#/,
      // UNION(SELECT — no-space variant used to dodge naive "union select" filters
      /\bunion\s*\(\s*select/i,
      // Exfiltration/fingerprinting functions — only when actually called
      /\b(?:substring|substr|mid|concat|group_concat|cast)\s*\(/i
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
      /\bon(?:mouseover|focus|focusin|click|pointerdown|animationstart|toggle|wheel|pointerover|beforeload|transitionend)\s*=/i,
      // JS execution sinks used to run injected script without a <script> tag
      /\beval\s*\(/i,
      /\bsetTimeout\s*\(/i,
      /\bsetInterval\s*\(/i,
      /\b(?:inner|outer)HTML\b/i,
      /\binsertAdjacentHTML\s*\(/i
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
      // Windows backslash traversal (literal and URL-encoded)
      /\.\.\\/,
      /\.\.%5c/i,
      /\/etc\/passwd/i,
      /\/etc\/shadow/i,
      /\/etc\/sudoers/i,
      /\/proc\/self\/environ/i,
      /\/proc\/self\/cmdline/i,
      /php:\/\/filter/i,
      /php:\/\/input/i,
      /php:\/\/fd/i,
      /phar:\/\//i,
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
      // Require an internal/loopback/link-local/metadata destination — a bare
      // url=https:// param is extremely common in legitimate OAuth/redirect
      // flows (accounts.google.com, api.stripe.com, etc.) and is not a signal
      // on its own.
      /(?:url|uri|callback|webhook|next|redirect|dest|target|feed|host|domain)=https?:\/\/(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|\[::1\]|metadata\.)/i
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
      // Require a command position and token boundary: HTML entities followed
      // by catalogue text such as ";.../Cat" are not shell execution.
      /(?:;|%3b|\||%7c|`|%60|\$\(|%24%28)\s*(?:\/(?:usr\/(?:local\/)?)?s?bin\/)?(?:id|whoami|cat|wget|curl|bash|nc|sh|python|perl|php|ping|nslookup|base64|xxd|openssl)(?=$|[\s;&|`$()<>])/i,
      // Windows/PowerShell variants
      /(?:;|%3b|\||%7c|`|%60|\$\(|%24%28)\s*(?:powershell|cmd\.exe|wscript|cscript)(?=$|[\s;&|`$()<>])/i,
      // $IFS and newline-based separator bypass.
      // normalizeForMatching() decodes %0a/%0d%0a to real \n/\r\n before RULES
      // run, so matching the literal "%0a" string here would be dead code —
      // match the decoded newline instead. Scoped to a shell metacharacter
      // right after the newline (not a bare letter) to avoid flagging benign
      // multi-line query values (e.g. a textarea field with embedded newlines).
      /\$IFS|\$\{IFS\}|\r?\n[;|`$]/
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
      /\/\.env\.local(?:$|\?)/i,
      /\/\.env\.production(?:$|\?)/i,
      /\/\.git(?:\/|$|\?)/i,
      /\/\.git\/head(?:$|\?)/i,
      /\/\.git\/config(?:$|\?)/i,
      /\/\.svn\//i,
      /\/\.hg\//i,
      /\/\.bzr\//i,
      /\/composer\.json(?:$|\?)/i,
      /\/vendor\/(?:autoload\.php|composer\/|phpunit\/|bin\/)/i,
      /\/phpinfo\.php(?:$|\?)/i,
      /\.(?:sql|bak|old|zip|tar\.gz|tar|7z|rar|orig|bkp)(?:$|\?)/i,
      /\/\.ssh\/id_rsa(?:$|\?)/i,
      /\/\.kube\/config(?:$|\?)/i,
      /\/wp-config\.php(?:$|\?)/i,
      /\/docker-compose\.yml(?:$|\?)/i,
      /\/\.ds_store(?:$|\?)/i
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
/**
 * Volume a path must reach before an abstained ratio counts, when the abstention
 * is due to the shared budget rather than the path's own cap.
 */
const CRAWL_BUDGET_STARVED_MIN_REQUESTS = 100_000;
const CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_REQUESTS = 5_000;
const CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_REPEATED_IPS = 10;
const CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_SHARE = 0.75;
const CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_PEAK = 20;
const CRAWL_SATURATION_MAX_BLOCKED_RATIO = 5;
const CRAWL_SATURATION_BLOCKED_QUERY_MIN_REQUESTS = 2_500;
const CRAWL_SATURATION_BLOCKED_QUERY_MIN_SERVED = 100;
const CRAWL_SATURATION_BLOCKED_QUERY_MIN_PEAK_REQUESTS_PER_MINUTE = 120;
const CRAWL_SATURATION_MIN_5XX_DISTRESS = 100;
/**
 * Server distress is a *rate*, not a tally. An absolute count alone is crossed
 * by any high-volume path — on a million-request URL a hundred errors is
 * background noise — so the busiest paths were the ones it mislabelled. Both
 * the floor above and this share must hold.
 */
const CRAWL_SATURATION_MIN_5XX_SHARE = 0.02;
/**
 * Authentication endpoints across the stacks citrx targets. Matching is on the
 * path only — an attacker controls the query string, not the route.
 */
const AUTH_PATH_RE =
  /(?:^|\/)(?:wp-login\.php|xmlrpc\.php|wp-json\/wp\/v2\/users|login|signin|sign-in|log-in|connexion|acceder|authenticate|auth|session|customer\/account\/login(?:post)?|administrator\/index\.php|user\/login|admin\/login|api\/login|api\/auth(?:\/[a-z-]+)?|oauth\/token)\/?$/i;

/** Times a body size must recur on ordinary paths before it reads as boilerplate. */
const GENERIC_BODY_MIN_OCCURRENCES = 3;

const AUTH_MIN_ATTEMPTS = 50;
/** Failure share expected of an attack; real logins are mostly 2xx/3xx. */
const AUTH_MIN_FAILURE_SHARE = 0.4;
/** Distinct sources that make a burst credential-stuffing rather than one user. */
const AUTH_DISTRIBUTED_MIN_IPS = 25;
/** Attempts per minute that separate an automated run from human logins. */
const AUTH_MIN_PEAK_PER_MINUTE = 20;
/** Share of attempts from one IP that makes it a single-source brute force. */
const AUTH_CONCENTRATED_MIN_SHARE = 0.5;

const POST_HOTSPOT_MIN_REQUESTS = 200;
const QUERY_EXPLOSION_MIN_REQUESTS = 500;
const QUERY_EXPLOSION_MIN_VARIANTS = 150;
const QUERY_EXPLOSION_MIN_VARIANT_RATIO = 0.5;
const TOP_PATHS_LIMIT = 10;
/** True when a served response on this path would itself be the disclosure. */
export function isHighValueSensitivePath(path: string): boolean {
  return HIGH_VALUE_SENSITIVE_RE.test(path);
}

/**
 * Recon targets where a single served response is already the disclosure. There
 * is no benign reason for any of these to return content: `phpinfo` dumps the
 * full environment, `.env` and `wp-config` backups carry credentials, `.git`
 * metadata exposes source, `server-status`/`actuator/env` expose internals, and
 * a database dump is the database. Success ratio is the wrong test here — one
 * hit out of hundreds of failures is still a leak.
 */
const HIGH_VALUE_SENSITIVE_RE =
  /(?:^|\/)(?:phpinfo\.php|info\.php|\.env(?:\.[a-z]+)?|\.git\/(?:config|HEAD|index)|wp-config\.php(?:\.[a-z]+)?|configuration\.php\.bak|\.aws\/credentials|\.ssh\/id_[a-z]+|server-status|server-info|actuator\/env|\.docker\/config\.json|sftp-config\.json|[^/]*\.(?:sql|sql\.gz|dump|bak)) *$/i;

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
  "--",
  "#",
  "union(",
  "substring(",
  "substr(",
  "mid(",
  "concat(",
  "group_concat(",
  "cast(",
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
  "onwheel",
  "onpointerover",
  "onbeforeload",
  "ontransitionend",
  // XSS — execution sinks
  "eval(",
  "settimeout(",
  "setinterval(",
  "innerhtml",
  "outerhtml",
  "insertadjacenthtml(",
  // LFI/RFI
  "../",
  "..%2f",
  "%252e",
  "..\\",
  "..%5c",
  "/etc/",
  "/proc/",
  "php://",
  "phar://",
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
  "dest=http",
  "target=http",
  "feed=http",
  "host=http",
  "domain=http",
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
  "base64",
  "xxd",
  "openssl",
  // Sensitive file probes
  ".env",
  ".git",
  "composer.json",
  "phpinfo",
  ".sql",
  ".bak",
  ".old",
  // Recon — additional sensitive files/dirs (Phase 2, D6)
  ".env.local",
  ".env.production",
  ".git/head",
  ".git/config",
  ".svn/",
  ".hg/",
  ".bzr/",
  ".tar",
  ".7z",
  ".rar",
  ".orig",
  ".bkp",
  ".ssh/id_rsa",
  ".kube/config",
  "wp-config.php",
  "docker-compose.yml",
  ".ds_store"
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

const TOP_PATH_IPS = 5;

/**
 * Heaviest IPs recorded for this path. `ipCounts` is capped, so this is the
 * heaviest of the *sampled* IPs — enough to attribute the load, not a proof of
 * global ranking.
 */
function topPathIps(stats: PathStats): [string, number][] {
  return [...stats.ipCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, TOP_PATH_IPS);
}

/**
 * Heaviest /24 (IPv4) or /48 (IPv6) among the sampled IPs. A single subnet
 * accounting for most of a path's load is the signature of one actor renting a
 * contiguous block, which reads very differently from genuinely spread traffic.
 */
function topPathSubnet(stats: PathStats): { prefix: string; ips: number; count: number } | null {
  const bySubnet = new Map<string, { ips: number; count: number }>();

  for (const [ip, count] of stats.ipCounts) {
    const prefix = extractSubnetPrefix(ip);
    if (!prefix) {
      continue;
    }
    const current = bySubnet.get(prefix) ?? { ips: 0, count: 0 };
    current.ips += 1;
    current.count += count;
    bySubnet.set(prefix, current);
  }

  let best: { prefix: string; ips: number; count: number } | null = null;
  for (const [prefix, value] of bySubnet) {
    if (!best || value.count > best.count) {
      best = { prefix, ips: value.ips, count: value.count };
    }
  }

  // A subnet holding a single IP says nothing beyond what topIps already shows.
  return best && best.ips > 1 ? best : null;
}

/** Distinct IPs observed for this path, including fingerprintable dropped keys. */
function observedUniqueIps(stats: PathStats): number {
  const stored = stats.ipCounts.size;
  const counted = stats.uniqueIpCount;
  const distinguished = typeof counted === "number" ? Math.max(counted, stored) : stored;
  return Math.min(stats.count, distinguished);
}

/** Distinct query variants observed for this path, including fingerprintable dropped keys. */
function observedQueryVariants(stats: PathStats): number {
  const stored = stats.queryVariants.size;
  const counted = stats.queryVariantCount;
  const distinguished = typeof counted === "number" ? Math.max(counted, stored) : stored;
  return Math.min(stats.count, distinguished);
}

function uniqueIpsAreLowerBound(stats: PathStats): boolean {
  return (
    stats.uniqueIpsIsLowerBound === true ||
    (typeof stats.uniqueIpCount === "number" && stats.uniqueIpCount > stats.ipCounts.size)
  );
}

function queryVariantsAreLowerBound(stats: PathStats): boolean {
  return (
    stats.queryVariantsIsLowerBound === true ||
    (typeof stats.queryVariantCount === "number" &&
      stats.queryVariantCount > stats.queryVariants.size)
  );
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
      const hasServerDistress = hasFiveXxDistress(stats);

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
        { key: "uniqueIps", value: observedUniqueIps(stats) },
        { key: "repeatedIps", value: crawlSignal.repeatedIps },
        { key: "repeatedRequestShare", value: crawlSignal.repeatedRequestShare },
        { key: "queryVariants", value: observedQueryVariants(stats) },
        { key: "queryVariantRatio", value: crawlSignal.queryVariantRatio },
        { key: "bytes", value: stats.bytes }
      ];

      // Without the offending IPs an operator cannot tell a genuine distributed
      // crawl from one client generating most of the load, and cannot act
      // (block/rate-limit) on the finding at all.
      const topIps = topPathIps(stats);
      if (topIps.length > 0) {
        evidence.push({
          key: "topIps",
          value: topIps.map(([ip, count]) => `${ip} (${count})`).join(" | ")
        });
        evidence.push({
          key: "topIpShare",
          value: roundRatio(topIps[0][1] / stats.count)
        });
      }

      const topSubnet = topPathSubnet(stats);
      if (topSubnet) {
        evidence.push({ key: "topSubnet", value: topSubnet.prefix });
        evidence.push({ key: "topSubnetIps", value: topSubnet.ips });
        evidence.push({ key: "topSubnetShare", value: roundRatio(topSubnet.count / stats.count) });
      }

      if (uniqueIpsAreLowerBound(stats)) {
        evidence.push({ key: "uniqueIpsLowerBound", value: true });
      }
      if (queryVariantsAreLowerBound(stats)) {
        evidence.push({ key: "queryVariantsLowerBound", value: true });
      }

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
      observedQueryVariants(stats) >= QUERY_EXPLOSION_MIN_VARIANTS &&
      stats.count >= QUERY_EXPLOSION_MIN_REQUESTS &&
      roundRatio(observedQueryVariants(stats) / stats.count) >= QUERY_EXPLOSION_MIN_VARIANT_RATIO
    ) {
      const explosionEvidence: Incident["evidence"] = [
        { key: "path", value: stats.path },
        { key: "requests", value: stats.count },
        { key: "queryVariants", value: observedQueryVariants(stats) }
      ];
      if (queryVariantsAreLowerBound(stats)) {
        explosionEvidence.push({ key: "queryVariantsLowerBound", value: true });
      }
      incidents.push({
        id: `query_explosion:${stats.path}`,
        category: "abusive_crawling",
        kind: "noise",
        severity: "low",
        score: 40,
        title: "Query explosion",
        description: "One path was requested with many query variants.",
        evidence: explosionEvidence,
        samples: []
      });
    }

    const authAbuse = authAbuseIncident(stats);
    if (authAbuse) {
      incidents.push(authAbuse);
    }

    // A plain POST count on a login endpoint is not actionable on its own, so
    // suppress it once the auth rule has described the same path in full.
    if (stats.postCount >= POST_HOTSPOT_MIN_REQUESTS && !authAbuse) {
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

/**
 * Crawl-pressure signal for one path. The `*IsUsable` flags say whether the
 * matching ratio was computed from a full sample: once a bounded-memory cap is
 * full the ratio understates reality and must not be used to reject a path.
 */
interface CrawlSignal {
  repeatedIps: number;
  repeatedRequestShare: number;
  queryVariantRatio: number;
  queryVariantRatioIsUsable: boolean;
  repeatedShareIsUsable: boolean;
  /** Corroborating pressure used when a truncated ratio cannot decide. */
  hasServedPeak: boolean;
}

/**
 * Credential stuffing and login brute force. Both shapes hit an auth endpoint
 * hard and fail most of the time; they differ only in whether the attempts come
 * from one source or are spread across many to dodge per-IP rate limits, so
 * they share a rule and are distinguished in the evidence.
 */
function authAbuseIncident(stats: PathStats): Incident | null {
  if (!AUTH_PATH_RE.test(stats.path)) {
    return null;
  }

  // POSTs are the attempts; a login page also serves GETs, which are not.
  const attempts = stats.postCount > 0 ? stats.postCount : stats.count;

  if (attempts < AUTH_MIN_ATTEMPTS) {
    return null;
  }

  const failures = stats.status4xx;
  const failureShare = roundRatio(failures / stats.count);
  const peakPerMinute = stats.maxRequestsPerMinute ?? 0;

  if (failureShare < AUTH_MIN_FAILURE_SHARE || peakPerMinute < AUTH_MIN_PEAK_PER_MINUTE) {
    return null;
  }

  const uniqueIps = observedUniqueIps(stats);
  const topIps = topPathIps(stats);
  const topIpShare = topIps.length > 0 ? roundRatio(topIps[0][1] / stats.count) : 0;
  const distributed = uniqueIps >= AUTH_DISTRIBUTED_MIN_IPS;
  const concentrated = topIpShare >= AUTH_CONCENTRATED_MIN_SHARE;

  if (!distributed && !concentrated) {
    return null;
  }

  const evidence: Incident["evidence"] = [
    { key: "path", value: stats.path },
    { key: "attempts", value: attempts },
    { key: "requests", value: stats.count },
    { key: "uniqueIps", value: uniqueIps },
    { key: "failureShare", value: failureShare },
    { key: "status4xx", value: failures },
    { key: "status2xx", value: stats.status2xx },
    { key: "maxRequestsPerMinute", value: peakPerMinute }
  ];

  if (topIps.length > 0) {
    evidence.push({
      key: "topIps",
      value: topIps.map(([ip, count]) => `${ip} (${count})`).join(" | ")
    });
    evidence.push({ key: "topIpShare", value: topIpShare });
  }

  const topSubnet = topPathSubnet(stats);
  if (topSubnet) {
    evidence.push({ key: "topSubnet", value: topSubnet.prefix });
    evidence.push({ key: "topSubnetIps", value: topSubnet.ips });
  }

  if (stats.firstSeen !== null) {
    evidence.push({ key: "firstSeen", value: epochToIso(stats.firstSeen) });
  }
  if (stats.lastSeen !== null) {
    evidence.push({ key: "lastSeen", value: epochToIso(stats.lastSeen) });
  }

  if (uniqueIpsAreLowerBound(stats)) {
    evidence.push({ key: "uniqueIpsLowerBound", value: true });
  }

  return {
    id: `auth_abuse:${stats.path}`,
    category: "auth_abuse",
    kind: "compromise",
    severity: "high",
    score: distributed ? 85 : 80,
    title: distributed ? "Distributed credential stuffing" : "Login brute force",
    description: distributed
      ? "An authentication endpoint received a burst of mostly failing attempts spread across many source IPs, the shape used to evade per-IP rate limits."
      : "An authentication endpoint received a burst of mostly failing attempts concentrated on one source IP.",
    evidence,
    samples: stats.samples.slice(0, 3)
    // Deliberately no `successful` flag: WordPress, PrestaShop and most
    // frameworks answer a *failed* login with 200 and the form again, so a 2xx
    // here is not evidence the credentials worked. The raw counts are in the
    // evidence for an operator to judge.
  };
}

function highVolumeCrawlSignal(stats: PathStats): CrawlSignal | null {
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

  const uniqueIps = observedUniqueIps(stats);
  const queryVariants = observedQueryVariants(stats);
  const repeatedRequestShare = roundRatio(repeatedRequests / stats.count);
  const queryVariantRatio = stats.count > 0 ? roundRatio(queryVariants / stats.count) : 0;
  // Both ratios divide a bounded-memory numerator by the full request count, so
  // they collapse toward zero exactly when a path is busy enough to fill its
  // caps. Once a cap is full the true ratio is unknowable and can only be
  // higher than observed, so the ratio must not veto — the absolute minimums
  // below still have to be met.
  // A ratio is only usable when its numerator was counted in full. That fails
  // both when the path fills its own cap and when the shared budget ran out
  // before this path was ever seen — the second case is how a path that starts
  // late in a long log ends up with a numerator of nearly zero.
  const queryVariantRatioIsUsable = !queryVariantsAreLowerBound(stats);
  const repeatedShareIsUsable = !uniqueIpsAreLowerBound(stats);
  // Abstaining is not the same as passing. A full variant cap only proves there
  // were at least `MAX_QUERY_VARIANTS` of them, which on a busy page is a low
  // bar, so the abstaining branch needs a corroborating pressure signal: a real
  // served-per-minute peak. Without it, an ordinary popular page with a wide
  // audience would read as churn purely because its counter filled.
  // When a path filled its own cap we know its cardinality is genuinely high, so
  // a served-rate peak is corroboration enough. When instead the shared budget
  // ran out before this path was seen, we know nothing about it at all — so it
  // must additionally be a heavy hitter before an abstained ratio is allowed to
  // pass, otherwise every busy-but-ordinary endpoint would qualify.
  const servedPeak =
    (stats.maxServedPerMinute ?? 0) >= CRAWL_SATURATION_SUSTAINED_QUERY_MIN_CONCENTRATED_PEAK;
  const filledOwnCaps = stats.queryVariantsAtOwnCap === true || stats.uniqueIpsAtOwnCap === true;
  const hasServedPeak =
    servedPeak && (filledOwnCaps || stats.count >= CRAWL_BUDGET_STARVED_MIN_REQUESTS);
  const hasQueryChurn =
    uniqueIps >= CRAWL_MIN_UNIQUE_IPS &&
    queryVariants >= CRAWL_MIN_QUERY_VARIANTS &&
    ratioMeets(
      queryVariantRatio,
      CRAWL_MIN_QUERY_VARIANT_RATIO,
      queryVariantRatioIsUsable,
      hasServedPeak
    );
  const hasRepeatPressure =
    repeatedIps >= CRAWL_MIN_REPEATED_IPS &&
    ratioMeets(
      repeatedRequestShare,
      CRAWL_MIN_REPEATED_REQUEST_SHARE,
      repeatedShareIsUsable,
      hasServedPeak
    );

  return hasQueryChurn || hasRepeatPressure
    ? {
        repeatedIps,
        repeatedRequestShare,
        queryVariantRatio,
        queryVariantRatioIsUsable,
        repeatedShareIsUsable,
        hasServedPeak
      }
    : null;
}

function materialPathSaturationSignal(
  stats: PathStats,
  crawlSignal: CrawlSignal
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
  const highQuerySignal = queryRatioAtLeast(crawlSignal, CRAWL_SATURATION_HIGH_SIGNAL_QUERY_RATIO);
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

  if (hasFiveXxDistress(stats)) {
    return queryRatioAtLeast(crawlSignal, CRAWL_SATURATION_MIN_QUERY_VARIANT_RATIO)
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
    observedQueryVariants(stats) >= CRAWL_SATURATION_MIN_QUERY_VARIANTS &&
    queryRatioAtLeast(crawlSignal, CRAWL_SATURATION_MIN_QUERY_VARIANT_RATIO);

  // Concentrated repeat pressure: small set of IPs accounts for the majority of load.
  // Labelled separately from distributed churn — the attack profile differs.
  const hasMaterialRepeatPressure =
    crawlSignal.repeatedIps >= CRAWL_SATURATION_MIN_REPEATED_IPS &&
    repeatShareAtLeast(crawlSignal, CRAWL_SATURATION_MIN_REPEATED_REQUEST_SHARE);

  if (hasMaterialQueryChurn) return "query_churn";
  if (hasMaterialRepeatPressure) return "repeat_pressure";
  return null;
}

/**
 * Ratio gate that accounts for bounded-memory truncation.
 *
 * These ratios divide a capped numerator by the full request count, and
 * truncation can only push the result *down*, never up. So:
 *
 * - at or above the minimum, the observation stands on its own — a capped
 *   counter could not have inflated it;
 * - below the minimum with a counter that never filled, the low ratio is real;
 * - below the minimum with a filled counter, the true ratio is unknowable, and
 *   a corroborating pressure signal decides instead of a number we know to be
 *   wrong.
 *
 * The third case is the one that mattered: it is exactly the busiest paths that
 * fill their caps, so comparing the collapsed ratio hid the largest events.
 */
function ratioMeets(
  observed: number,
  minimum: number,
  isUsable: boolean,
  corroborated: boolean
): boolean {
  if (observed >= minimum) {
    return true;
  }

  return !isUsable && corroborated;
}

function queryRatioAtLeast(signal: CrawlSignal, minimum: number): boolean {
  return ratioMeets(
    signal.queryVariantRatio,
    minimum,
    signal.queryVariantRatioIsUsable,
    signal.hasServedPeak
  );
}

function repeatShareAtLeast(signal: CrawlSignal, minimum: number): boolean {
  return ratioMeets(
    signal.repeatedRequestShare,
    minimum,
    signal.repeatedShareIsUsable,
    signal.hasServedPeak
  );
}

function hasBlockedQueryPressureSaturation(
  stats: PathStats,
  crawlSignal: CrawlSignal,
  servedCount: number,
  maxRequestsPerMinute: number
): boolean {
  return (
    stats.count >= CRAWL_SATURATION_BLOCKED_QUERY_MIN_REQUESTS &&
    servedCount >= CRAWL_SATURATION_BLOCKED_QUERY_MIN_SERVED &&
    observedQueryVariants(stats) >= CRAWL_SATURATION_MIN_QUERY_VARIANTS &&
    queryRatioAtLeast(crawlSignal, CRAWL_SATURATION_HIGH_SIGNAL_QUERY_RATIO) &&
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
  return normalized === "/index.php" && observedQueryVariants(stats) === 0 && stats.status5xx === 0;
}

function hasSustainedQuerySaturation(
  stats: PathStats,
  crawlSignal: CrawlSignal,
  servedCount: number,
  maxServedPerMinute: number
): boolean {
  if (
    servedCount < CRAWL_SATURATION_SUSTAINED_QUERY_MIN_REQUESTS ||
    observedQueryVariants(stats) < CRAWL_SATURATION_SUSTAINED_QUERY_MIN_VARIANTS ||
    !queryRatioAtLeast(crawlSignal, CRAWL_SATURATION_SUSTAINED_QUERY_MIN_RATIO) ||
    blockedDominates(stats, servedCount)
  ) {
    return false;
  }

  // Spread across many IPs normally stands in for the churn ratio. When the
  // ratio had to abstain because the variant cap filled, that shortcut would
  // admit any high-volume page with a wide audience, so a real served-rate peak
  // is required instead — otherwise ordinary faceted browsing spread over days
  // reads as saturation.
  if (
    (crawlSignal.queryVariantRatioIsUsable ||
      crawlSignal.queryVariantRatio >= CRAWL_SATURATION_SUSTAINED_QUERY_MIN_RATIO) &&
    observedUniqueIps(stats) >= CRAWL_SATURATION_SUSTAINED_QUERY_MIN_DISTRIBUTED_IPS
  ) {
    return true;
  }

  return maxServedPerMinute >= CRAWL_SATURATION_SUSTAINED_QUERY_MIN_CONCENTRATED_PEAK;
}

function hasSustainedRepeatSaturation(
  stats: PathStats,
  crawlSignal: CrawlSignal,
  servedCount: number,
  maxServedPerMinute: number
): boolean {
  return (
    servedCount >= CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_REQUESTS &&
    crawlSignal.repeatedIps >= CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_REPEATED_IPS &&
    repeatShareAtLeast(crawlSignal, CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_SHARE) &&
    maxServedPerMinute >= CRAWL_SATURATION_SUSTAINED_REPEAT_MIN_PEAK &&
    !blockedDominates(stats, servedCount)
  );
}

/**
 * True when errors are frequent enough on this path to mean the backend is
 * failing under the load, rather than the ordinary trickle of errors any busy
 * URL accumulates.
 */
function hasFiveXxDistress(stats: PathStats): boolean {
  return (
    stats.status5xx >= CRAWL_SATURATION_MIN_5XX_DISTRESS &&
    stats.count > 0 &&
    stats.status5xx / stats.count >= CRAWL_SATURATION_MIN_5XX_SHARE
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
    applyServedSensitivePath(stats, entry);
    applyOutcomeScore(existing, hit, stats, ip);

    if (existing.samples.length < 5 && !existing.samples.includes(hit.sample)) {
      existing.samples.push(hit.sample);
    }

    return id;
  }

  const stats = createOutcomeStats();
  applyStatus(stats, entry.status);
  addTopPath(stats, entry.path);
  applyServedSensitivePath(stats, entry);

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

/**
 * Remembers the first high-value path that was actually served. Kept as a
 * single path rather than a set: one is enough to escalate, and it keeps the
 * evidence round-trip cheap.
 */
function applyServedSensitivePath(stats: RuleOutcomeStats, entry: AccessLogEntry): void {
  if (stats.servedSensitivePath !== undefined) {
    return;
  }

  if (entry.status < 200 || entry.status >= 300) {
    return;
  }

  if (!HIGH_VALUE_SENSITIVE_RE.test(entry.path)) {
    return;
  }

  stats.servedSensitivePath = entry.path;
  stats.servedSensitiveBytes = entry.bytes ?? 0;
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

  const servedSensitivePath = evidence.find((item) => item.key === "servedSensitivePath")?.value;

  return {
    count: numberEvidence(evidence, "count"),
    status2xx: numberEvidence(evidence, "status2xx"),
    status3xx: numberEvidence(evidence, "status3xx"),
    status4xx: numberEvidence(evidence, "status4xx"),
    status5xx: numberEvidence(evidence, "status5xx"),
    status404: numberEvidence(evidence, "status404"),
    topPaths,
    servedSensitivePath: typeof servedSensitivePath === "string" ? servedSensitivePath : undefined,
    servedSensitiveBytes: numberEvidence(evidence, "servedSensitiveBytes")
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
    // A served high-value target escalates on its own. The ratio test below
    // exists to filter flukes on ordinary probes, but applying it here buries
    // the one response that matters under the hundreds that failed.
    const servedHighValueTarget =
      stats.servedSensitivePath !== undefined && (stats.servedSensitiveBytes ?? 0) > 0;
    const meaningfulSuccess = servedHighValueTarget || stats.status2xx >= 2 || successRatio >= 0.1;
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
  if (stats.servedSensitivePath !== undefined) {
    evidence.push({ key: "servedSensitivePath", value: stats.servedSensitivePath });
    evidence.push({ key: "servedSensitiveBytes", value: stats.servedSensitiveBytes ?? 0 });
  }

  return evidence;
}

/**
 * Drop low-signal rule incidents to reduce noise.
 * Keeps any incident with 2xx (possible success), 5xx (possible crash),
 * sustained activity (count >= 3) or fan-out (paths > 1).
 * Drops single 404 probes — these are constant on the internet and not actionable.
 */
const SEARCH_ENGINE_RANGES = [prepareRanges(GOOGLEBOT_RANGES), prepareRanges(BINGBOT_RANGES)];

function isVerifiedSearchEngineIp(ip: string): boolean {
  return SEARCH_ENGINE_RANGES.some((ranges) => ipInPreparedRanges(ip, ranges));
}

/**
 * Demotes payload and recon findings whose source is an IP that genuinely
 * belongs to Google or Microsoft. A crawler requesting an attack payload is
 * re-fetching a URL it found linked or previously indexed, so the log records a
 * poisoned URL rather than an attacker — reporting it as a critical, successful
 * compromise points the operator at the wrong problem entirely. The finding is
 * kept, because a poisoned indexed URL is worth cleaning up, but it moves to
 * noise and says why.
 */
export function demoteVerifiedCrawlerPayloads(incidents: Map<string, Incident>): void {
  for (const incident of incidents.values()) {
    // Incident ids are `<ruleId>:<ip>`; IPv6 addresses contain colons of their
    // own, so only the first segment is the rule.
    const ruleId = incident.id.split(":")[0] ?? "";

    if (!isPayloadRule(ruleId) && !isReconRule(ruleId)) {
      continue;
    }

    const ip = incident.evidence.find((item) => item.key === "ip")?.value;

    if (typeof ip !== "string" || !isVerifiedSearchEngineIp(ip)) {
      continue;
    }

    incident.kind = "noise";
    incident.severity = "low";
    incident.score = Math.min(incident.score, 30);
    incident.successful = false;
    incident.description =
      "Requested by a verified search-engine crawler, so this is an indexed or linked URL carrying the payload rather than an attack from this IP.";
    incident.evidence.push({ key: "verifiedCrawler", value: true });
  }
}

/**
 * Withdraws the high-value escalation when the "served" body is just the site's
 * generic page. Many sites answer an unknown path with 200 and the homepage or
 * a soft-404 template, so a sensitive path returning content is only a leak if
 * the content is distinctive — a real `phpinfo` dump does not weigh exactly
 * what the homepage weighs.
 *
 * The size table is capped, but truncation only ever omits a size, so a size
 * that IS present having been served repeatedly is sound evidence; a size that
 * is absent is simply left alone. Truncation can therefore cost a demotion,
 * never invent one.
 */
export function demoteSoftServedRecon(
  incidents: Map<string, Incident>,
  servedBodySizes: ReadonlyMap<number, number>
): void {
  for (const incident of incidents.values()) {
    if (!isReconRule(incident.id.split(":")[0] ?? "")) {
      continue;
    }

    const bytes = incident.evidence.find((item) => item.key === "servedSensitiveBytes")?.value;

    // One coincidental match is not a pattern; a generic page is served often.
    if (
      typeof bytes !== "number" ||
      (servedBodySizes.get(bytes) ?? 0) < GENERIC_BODY_MIN_OCCURRENCES
    ) {
      continue;
    }

    const stats = readOutcomeStats(incident.evidence);
    // Re-score as if the high-value hit had not been served. Anything that
    // still qualifies on its own (repeat successes, a real success ratio)
    // keeps its severity.
    stats.servedSensitivePath = undefined;
    stats.servedSensitiveBytes = undefined;
    const outcome = outcomeFor("recon_sensitive_file", stats);

    incident.severity = outcome.severity ?? incident.severity;
    incident.score = outcome.score ?? incident.score;
    incident.successful = outcome.successful ?? false;
    incident.kind = actionableCompromiseKind(
      { ruleId: "recon_sensitive_file" } as RuleHit,
      outcome.label
    )
      ? "compromise"
      : "noise";
    const outcomeEvidence = incident.evidence.find((item) => item.key === "outcome");
    if (outcomeEvidence) {
      outcomeEvidence.value = outcome.label;
    }
    incident.evidence.push({ key: "servedBodyMatchesGenericPage", value: true });
  }
}

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

/**
 * Parse a raw request target into a URL once, for reuse across redactTarget
 * and querySignature in the hot per-request path (see access-log.ts). Returns
 * null when the target cannot be parsed (callers fall back to the raw string,
 * matching prior try/catch behavior exactly).
 */
export function parseTargetUrl(target: string): URL | null {
  try {
    return new URL(target, "http://citrx.local");
  } catch {
    return null;
  }
}

export function redactTarget(target: string, parsed?: URL | null): string {
  return truncateSample(redactSensitiveTarget(target, parsed));
}

export function querySignature(target: string, parsed?: URL | null): string {
  const queryStart = target.indexOf("?");
  if (queryStart === -1) return "";

  // Strip marketing/analytics tracking params before building the variant signature.
  // fbclid/gclid/utm_*/etc. are unique per click and inflate query-variant counts
  // for legitimate marketing traffic. We keep all real application params so genuine
  // query-explosion abuse is still detected.
  const url = parsed !== undefined ? parsed : parseTargetUrl(target);
  if (url) {
    // Clone so we don't mutate a URL instance the caller may reuse elsewhere
    // (e.g. redactTarget's own parse of the same target).
    const cloned = new URL(url.toString());
    for (const key of [...cloned.searchParams.keys()]) {
      if (TRACKING_PARAM_RE.test(key)) {
        cloned.searchParams.delete(key);
      }
    }
    if (!cloned.search) return "";
    return redactSensitiveTarget(`/${cloned.search}`).slice(1);
  }
  return redactSensitiveTarget(`/${target.slice(queryStart)}`).slice(1);
}

function redactSensitiveTarget(target: string, parsed?: URL | null): string {
  const url = parsed !== undefined ? parsed : parseTargetUrl(target);
  if (url) {
    return redactSecretPairs(`${url.pathname}${url.search}`);
  }
  return redactSecretPairs(target);
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
  // Strip null bytes injected to break naive string matching / truncate paths
  // (classic PHP null-byte injection against legacy file-handling code).
  return current.replace(/\x00/g, "").toLowerCase();
}

function truncateSample(value: string): string {
  return value.length <= MAX_SAMPLE_LENGTH ? value : `${value.slice(0, MAX_SAMPLE_LENGTH - 3)}...`;
}

function escapeRegex(value: string): string {
  return value.replace(/[|\\{}()[\]^$+*?.]/g, "\\$&");
}
