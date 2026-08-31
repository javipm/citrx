import type { AccessLogEntry } from "../parser/access-log.js";
import { AI_BOT_RANGES } from "../rules/data/ai-bot-ranges.js";
import { AI_BOT_PATTERNS } from "../rules/data/ai-bots.js";
import { BINGBOT_RANGES } from "../rules/data/bingbot-ranges.js";
import { FINGERPRINT_PATHS } from "../rules/data/scanner-fingerprint-paths.js";
import { GOOGLEBOT_RANGES } from "../rules/data/googlebot-ranges.js";
import { SCANNER_UA_PATTERNS } from "../rules/data/scanner-uas.js";
import type { AiBotStats, Incident, IncidentKind, IpBehaviorStats, TimeStats } from "./types.js";
import { ipInPreparedRanges, isNonRoutableClientIp, prepareRanges } from "./ip-ranges.js";
import { extractSubnetPrefix } from "../utils/subnet.js";
import { accessLogTimestampToEpochSeconds } from "./timestamp.js";

export { extractSubnetPrefix };
import { MAX_GLOBAL_RPS_SECONDS, MAX_OVERFLOW_RPS_SECONDS } from "./capped-counter.js";

export const MAX_TRACKED_IPS = 100_000;
const STALE_IP_SECONDS = 900;
const STALE_IP_EVICTION_BATCH = 5_000;
const PATH_SENTINEL_LIMIT = 501;
const UA_SENTINEL_LIMIT = 9;
const TOP_IP_LIMIT = 100;
const SINGLE_IP_RPS_THRESHOLD = 50;
const SINGLE_IP_BURST_SECONDS = 3;
/**
 * Floods commonly pace below the per-second burst threshold. 600 requests in a
 * minute is 10 rps sustained for the whole minute — far above any single
 * browser session, but only when aimed at a handful of URLs.
 */
const SUSTAINED_FLOOD_MIN_PER_MINUTE = 600;
const SUSTAINED_FLOOD_MIN_REQUESTS_PER_PATH = 50;
const GLOBAL_SPIKE_ABSOLUTE_RPS = 100;
const GLOBAL_SPIKE_MULTIPLIER = 5;
const GLOBAL_SPIKE_SECONDS = 10;
const ERROR_PATH_LIMIT = 32;
const FOUR_XX_STORM_THRESHOLD = 200;
const FOUR_XX_BUCKET_SECONDS = 60;
const FIVE_XX_STORM_THRESHOLD = 200;
const FIVE_XX_BUCKET_SECONDS = 60;
const GOOGLEBOT_UA = /\bGooglebot\/\d/i;
const BINGBOT_UA = /\bbingbot\/\d/i;
const BOT_PATH_SENTINEL_LIMIT = 1001;
const BOT_IP_SENTINEL_LIMIT = 5001;
const AI_BOT_MEDIUM_REQUESTS = 500;
const AI_BOT_HIGH_PATH_MINUTES = 3;
const AI_BOT_MIN_PEAK_SERVED_PER_MINUTE = 120;
const AI_BOT_MIN_5XX_DISTRESS = 100;
/** Same reasoning as the path rules: distress is a rate, not a tally. */
const AI_BOT_MIN_5XX_SHARE = 0.02;
/**
 * A crawler taking this share of all traffic is a capacity problem regardless
 * of how it spreads across URLs. The absolute floor keeps tiny logs, where one
 * bot trivially dominates, out of the high band.
 */
const AI_BOT_DOMINANT_TRAFFIC_SHARE = 0.2;
const AI_BOT_DOMINANT_MIN_REQUESTS = 1_000;
/** Share is only meaningful once the log itself is big enough to have a shape. */
const AI_BOT_DOMINANT_MIN_TOTAL_REQUESTS = 10_000;
/** Some responses must actually be served; a bot blocked outright costs little. */
const AI_BOT_DOMINANT_MIN_SERVED = 200;
/**
 * 503 Service Unavailable, 507 Insufficient Storage, 508 Resource Limit
 * Reached and 504 Gateway Timeout are emitted when the server or its upstream
 * ran out of capacity, as opposed to 500, which is usually an application bug.
 */
const CAPACITY_ERROR_STATUSES = new Set([503, 504, 507, 508, 529]);
const SERVER_DISTRESS_MIN_ERRORS = 500;
const SERVER_DISTRESS_MIN_SHARE = 0.01;
const SERVER_DISTRESS_CRITICAL_SHARE = 0.05;
const FINGERPRINT_BUCKET_SECONDS = 60;
const FINGERPRINT_PATH_THRESHOLD = 20;
const SINGLE_IP_PATH_EXPLOSION_THRESHOLD = 500;
/** Minimum unique paths per minute for path explosion to be considered saturation.
 *  Normal users browsing for hours/days hit 500+ paths organically at low rates.
 *  Real path-explosion attacks/crawlers fan out fast: 10+ new paths every minute. */
const SINGLE_IP_PATH_EXPLOSION_MIN_RATE_PER_MIN = 10;
const UA_ROTATION_THRESHOLD = 8;
const UA_ROTATION_MIN_REQUESTS = 100;
/** UA rotation gate: real rotating bots burst hard. Shared NAT (AWS, mobile carriers,
 *  corporate proxies) generate many UAs slowly. Require peak RPS to be in attacker range. */
const UA_ROTATION_MIN_PEAK_RPS = 5;
const HEAD_FLOOD_MIN_REQUESTS = 500;
const HEAD_FLOOD_RATIO = 0.7;
const HEAD_FLOOD_PEAK_RPS = 25;
const SUBNET_RPS_THRESHOLD = 200;
const SUBNET_MIN_IPS = 10;
const SUBNET_BURST_SECONDS = 5;
const SUBNET_IPS_SENTINEL = 5001;
const MAX_TRACKED_SUBNETS = 50_000;
const STALE_SUBNET_SECONDS = 900;
const STALE_SUBNET_EVICTION_BATCH = 5_000;
/** Fake-bot threshold: 1-2 requests from a misconfigured bot or a typo'd UA aren't actionable.
 *  Real impersonation campaigns probe at scale. */
const FAKE_BOT_MIN_REQUESTS = 10;
/** Distinct forging IPs above which the per-IP incidents become one campaign. */
const FAKE_BOT_CAMPAIGN_MIN_IPS = 5;
/** Below this, an out-of-range hit is a stale snapshot or a one-off, not a campaign. */
const FAKE_AI_BOT_MIN_REQUESTS = 20;

interface BehaviorTrackerOptions {
  maxTrackedIps?: number;
  maxTrackedSubnets?: number;
  maxGlobalRpsSeconds?: number;
  maxOverflowRpsSeconds?: number;
}

interface IpBehaviorState {
  ip: string;
  totalRequests: number;
  /** Paths that produced 4xx/5xx, so an error storm can name what is failing. */
  status4xxPaths: Map<string, number>;
  status5xxPaths: Map<string, number>;
  /** Per-minute request counter; the peak separates a flood from a page load. */
  currentMinute: number | null;
  currentMinuteRequests: number;
  maxRequestsPerMinute: number;
  maxRequestsPerMinuteAt: number | null;
  firstSeen: number;
  lastSeen: number;
  currentSecond: number | null;
  currentCount: number;
  peakRps: number;
  peakRpsAt: number;
  burstRunLen: number;
  burstStart: number | null;
  longestBurstLen: number;
  longestBurstStart: number | null;
  longestBurstEnd: number | null;
  status4xxCount: number;
  status5xxCount: number;
  headCount: number;
  currentHeadSecond: number | null;
  currentHeadCount: number;
  peakHeadRps: number;
  peakHeadRpsAt: number;
  methods: Map<string, number>;
  paths: Set<string>;
  userAgents: Set<string>;
  requestedRobotsTxt: boolean;
  botMatch: string | null;
  scannerMatch: string | null;
  scannerUserAgent: string | null;
  currentFingerprintBucket: number | null;
  currentFingerprintPaths: Set<string>;
  previousFingerprintBucket: number | null;
  previousFingerprintPaths: Set<string>;
  maxFingerprintHits: number;
  maxFingerprintBucket: number | null;
  maxFingerprintSamplePaths: string[];
  current4xxBucket: number | null;
  current4xxCount: number;
  previous4xxBucket: number | null;
  previous4xxCount: number;
  max4xxTwoBucketCount: number;
  max4xxBucket: number | null;
  current5xxBucket: number | null;
  current5xxCount: number;
  previous5xxBucket: number | null;
  previous5xxCount: number;
  max5xxTwoBucketCount: number;
  max5xxBucket: number | null;
  claimedGooglebot: boolean;
  claimedBingbot: boolean;
  claimedBotUserAgent: string | null;
}

interface SubnetState {
  prefix: string;
  currentSecond: number | null;
  currentCount: number;
  currentIps: Set<string>;
  peakSubnetRps: number;
  peakSubnetRpsAt: number;
  peakIpCount: number;
  burstRunLen: number;
  burstStart: number | null;
  longestBurstLen: number;
  longestBurstStart: number | null;
  longestBurstEnd: number | null;
  lastSeen: number;
}

interface BotState {
  botName: string;
  requests: number;
  ips: Set<string>;
  paths: Set<string>;
  requestedRobotsTxt: boolean;
  firstSeen: number;
  lastSeen: number;
  pathMinuteBuckets: Map<number, Set<string>>;
  latestPathMinute: number;
  maxPathsPerMinute: number;
  highPathMinuteCount: number;
  status2xx: number;
  status3xx: number;
  status4xx: number;
  status5xx: number;
  currentMinute: number | null;
  currentMinuteServed: number;
  maxServedPerMinute: number;
  /** Requests from IPs outside the operator's published ranges, when published. */
  unverifiedRequests: number;
  unverifiedIps: Map<string, number>;
}

interface TopIpSnapshot {
  ip: string;
  totalRequests: number;
  firstSeen: number;
  lastSeen: number;
  peakRps: number;
  peakRpsAt: number;
  pathCount: number;
  uaCount: number;
  status4xxCount: number;
  status5xxCount: number;
}

export interface BehaviorAnalysis {
  timeStats: TimeStats;
  ipBehaviorStats: IpBehaviorStats[];
  aiBotStats: AiBotStats[];
  incidents: Incident[];
}

/**
 * p95 of per-second RPS over [firstSeen, lastSeen], counting missing seconds as
 * zeros without allocating or iterating the empty range.
 */
export function sparseRpsP95(
  occupied: Map<number, number>,
  firstSeen: number,
  lastSeen: number
): number {
  const duration = lastSeen - firstSeen + 1;
  if (duration <= 0) {
    return 0;
  }

  const values = [...occupied.values()].sort((a, b) => a - b);
  const zeros = Math.max(0, duration - occupied.size);
  const p95Index = Math.floor((duration - 1) * 0.95);

  if (p95Index < zeros) {
    return 0;
  }

  return values[p95Index - zeros] ?? 0;
}

export class BehaviorTracker {
  private readonly maxTrackedIps: number;
  private readonly maxTrackedSubnets: number;
  private readonly maxGlobalRpsSeconds: number;
  private readonly maxOverflowRpsSeconds: number;
  private readonly ips = new Map<string, IpBehaviorState>();
  private readonly subnets = new Map<string, SubnetState>();
  private readonly googlebotRanges = prepareRanges(GOOGLEBOT_RANGES);
  private readonly bingbotRanges = prepareRanges(BINGBOT_RANGES);
  private readonly aiBotRanges = new Map(
    [...AI_BOT_RANGES].map(([name, ranges]) => [name, prepareRanges(ranges)])
  );
  private readonly globalRpsBySecond = new Map<number, number>();
  private readonly topIps = new Map<string, TopIpSnapshot>();
  private readonly botRollup = new Map<string, BotState>();
  private firstSeen: number | null = null;
  private lastSeen: number | null = null;
  private streamNow: number | null = null;
  private observedRequests = 0;
  private globalStatus5xx = 0;
  private readonly capacityErrorCounts = new Map<number, number>();
  private capacityErrorFirstSeen: number | null = null;
  private capacityErrorLastSeen: number | null = null;
  private peakGlobalRps = 0;
  private peakGlobalRpsAt: number | null = null;
  private invalidTimestampLines = 0;
  private outOfOrderTimestamps = 0;
  private droppedIpCount = 0;
  private droppedSubnetCount = 0;
  private readonly overflowRpsBySecond = new Map<number, number>();
  droppedRpsSeconds = 0;

  constructor(options: BehaviorTrackerOptions = {}) {
    this.maxTrackedIps = options.maxTrackedIps ?? MAX_TRACKED_IPS;
    this.maxTrackedSubnets = options.maxTrackedSubnets ?? MAX_TRACKED_SUBNETS;
    this.maxGlobalRpsSeconds = options.maxGlobalRpsSeconds ?? MAX_GLOBAL_RPS_SECONDS;
    this.maxOverflowRpsSeconds = options.maxOverflowRpsSeconds ?? MAX_OVERFLOW_RPS_SECONDS;
  }

  observe(
    entry: AccessLogEntry,
    epochSecond = accessLogTimestampToEpochSeconds(entry.timestamp)
  ): void {
    if (epochSecond === null) {
      this.invalidTimestampLines += 1;
      return;
    }

    if (this.streamNow !== null && epochSecond < this.streamNow - 60) {
      this.outOfOrderTimestamps += 1;
    }

    this.streamNow = Math.max(this.streamNow ?? epochSecond, epochSecond);
    this.firstSeen = Math.min(this.firstSeen ?? epochSecond, epochSecond);
    this.lastSeen = Math.max(this.lastSeen ?? epochSecond, epochSecond);
    this.observeGlobalRps(epochSecond);
    this.observeSubnet(entry, epochSecond);

    const state = this.getOrCreateIp(entry.ip, epochSecond);

    if (!state) {
      return;
    }

    this.observeIp(state, entry, epochSecond);
    this.updateTopIps(state);
  }

  finalize(): BehaviorAnalysis {
    this.closeAllIpSeconds();
    this.closeAllHeadSeconds();
    this.closeAllSubnetSeconds();
    const timeStats = this.buildTimeStats();
    const incidents = [
      ...this.buildSingleIpBurstIncidents(),
      ...this.buildSustainedIpFloodIncidents(),
      ...this.buildGlobalSpikeIncidents(timeStats.globalRpsP95),
      ...this.build4xxStormIncidents(),
      ...this.buildAiScraperIncidents(),
      ...this.buildScannerUaIncidents(),
      ...this.buildScannerFingerprintIncidents(),
      ...this.buildSingleIpPathExplosionIncidents(),
      ...this.buildUaRotationIncidents(),
      ...this.buildHeadFloodIncidents(),
      ...this.buildSubnetDdosIncidents(),
      ...this.buildFakeBotIncidents(),
      ...this.buildFakeAiBotIncidents(),
      ...this.build5xxStormIncidents(),
      ...this.buildServerDistressIncidents()
    ].sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));

    return {
      timeStats,
      ipBehaviorStats: [...this.topIps.values()]
        .sort((a, b) => b.totalRequests - a.totalRequests || a.ip.localeCompare(b.ip))
        .map((snapshot) => ({
          ip: snapshot.ip,
          totalRequests: snapshot.totalRequests,
          firstSeen: formatEpoch(snapshot.firstSeen),
          lastSeen: formatEpoch(snapshot.lastSeen),
          peakRps: snapshot.peakRps,
          peakRpsAt: formatEpoch(snapshot.peakRpsAt),
          pathCount: snapshot.pathCount,
          uaCount: snapshot.uaCount,
          status4xxCount: snapshot.status4xxCount,
          status5xxCount: snapshot.status5xxCount
        })),
      aiBotStats: this.buildAiBotStats(),
      incidents
    };
  }

  private observeGlobalRps(epochSecond: number): void {
    const stored = this.globalRpsBySecond.get(epochSecond);
    if (stored !== undefined) {
      const count = stored + 1;
      this.globalRpsBySecond.set(epochSecond, count);
      this.notePeakRps(count, epochSecond);
      return;
    }

    if (this.globalRpsBySecond.size < this.maxGlobalRpsSeconds) {
      this.globalRpsBySecond.set(epochSecond, 1);
      this.notePeakRps(1, epochSecond);
      return;
    }

    const overflowStored = this.overflowRpsBySecond.get(epochSecond);
    if (overflowStored !== undefined) {
      const count = overflowStored + 1;
      this.overflowRpsBySecond.set(epochSecond, count);
      this.notePeakRps(count, epochSecond);
      return;
    }

    if (this.overflowRpsBySecond.size < this.maxOverflowRpsSeconds) {
      this.overflowRpsBySecond.set(epochSecond, 1);
      this.droppedRpsSeconds = this.overflowRpsBySecond.size;
      this.notePeakRps(1, epochSecond);
    }
  }

  private notePeakRps(count: number, epochSecond: number): void {
    if (count > this.peakGlobalRps) {
      this.peakGlobalRps = count;
      this.peakGlobalRpsAt = epochSecond;
    }
  }

  private getOrCreateIp(ip: string, epochSecond: number): IpBehaviorState | null {
    const existing = this.ips.get(ip);

    if (existing) {
      return existing;
    }

    if (this.ips.size >= this.maxTrackedIps && !this.evictStaleIp(epochSecond)) {
      this.droppedIpCount += 1;
      return null;
    }

    const state: IpBehaviorState = {
      ip,
      totalRequests: 0,
      status4xxPaths: new Map(),
      status5xxPaths: new Map(),
      currentMinute: null,
      currentMinuteRequests: 0,
      maxRequestsPerMinute: 0,
      maxRequestsPerMinuteAt: null,
      firstSeen: epochSecond,
      lastSeen: epochSecond,
      currentSecond: null,
      currentCount: 0,
      peakRps: 0,
      peakRpsAt: epochSecond,
      burstRunLen: 0,
      burstStart: null,
      longestBurstLen: 0,
      longestBurstStart: null,
      longestBurstEnd: null,
      status4xxCount: 0,
      status5xxCount: 0,
      headCount: 0,
      currentHeadSecond: null,
      currentHeadCount: 0,
      peakHeadRps: 0,
      peakHeadRpsAt: epochSecond,
      methods: new Map(),
      paths: new Set(),
      userAgents: new Set(),
      requestedRobotsTxt: false,
      botMatch: null,
      scannerMatch: null,
      scannerUserAgent: null,
      currentFingerprintBucket: null,
      currentFingerprintPaths: new Set(),
      previousFingerprintBucket: null,
      previousFingerprintPaths: new Set(),
      maxFingerprintHits: 0,
      maxFingerprintBucket: null,
      maxFingerprintSamplePaths: [],
      current4xxBucket: null,
      current4xxCount: 0,
      previous4xxBucket: null,
      previous4xxCount: 0,
      max4xxTwoBucketCount: 0,
      max4xxBucket: null,
      current5xxBucket: null,
      current5xxCount: 0,
      previous5xxBucket: null,
      previous5xxCount: 0,
      max5xxTwoBucketCount: 0,
      max5xxBucket: null,
      claimedGooglebot: false,
      claimedBingbot: false,
      claimedBotUserAgent: null
    };

    this.ips.set(ip, state);
    return state;
  }

  private evictStaleIp(epochSecond: number): boolean {
    const cutoff = epochSecond - STALE_IP_SECONDS;
    const candidates: IpBehaviorState[] = [];

    for (const state of this.ips.values()) {
      if (state.lastSeen < cutoff) {
        candidates.push(state);
      }
    }

    if (candidates.length === 0) {
      return false;
    }

    candidates.sort((a, b) => a.totalRequests - b.totalRequests || a.lastSeen - b.lastSeen);

    const count = Math.min(STALE_IP_EVICTION_BATCH, candidates.length);
    for (let index = 0; index < count; index += 1) {
      this.ips.delete(candidates[index]!.ip);
    }

    return true;
  }

  private getOrCreateSubnet(prefix: string, epochSecond: number): SubnetState | null {
    const existing = this.subnets.get(prefix);

    if (existing) {
      return existing;
    }

    if (this.subnets.size >= this.maxTrackedSubnets && !this.evictStaleSubnet(epochSecond)) {
      this.droppedSubnetCount += 1;
      return null;
    }

    const state: SubnetState = {
      prefix,
      currentSecond: null,
      currentCount: 0,
      currentIps: new Set(),
      peakSubnetRps: 0,
      peakSubnetRpsAt: epochSecond,
      peakIpCount: 0,
      burstRunLen: 0,
      burstStart: null,
      longestBurstLen: 0,
      longestBurstStart: null,
      longestBurstEnd: null,
      lastSeen: epochSecond
    };

    this.subnets.set(prefix, state);
    return state;
  }

  private evictStaleSubnet(epochSecond: number): boolean {
    const cutoff = epochSecond - STALE_SUBNET_SECONDS;
    const candidates: SubnetState[] = [];

    for (const subnet of this.subnets.values()) {
      if (subnet.lastSeen < cutoff) {
        candidates.push(subnet);
      }
    }

    if (candidates.length === 0) {
      return false;
    }

    candidates.sort((a, b) => a.peakSubnetRps - b.peakSubnetRps || a.lastSeen - b.lastSeen);

    const count = Math.min(STALE_SUBNET_EVICTION_BATCH, candidates.length);
    for (let index = 0; index < count; index += 1) {
      this.subnets.delete(candidates[index]!.prefix);
    }

    return true;
  }

  private observeIp(state: IpBehaviorState, entry: AccessLogEntry, epochSecond: number): void {
    state.totalRequests += 1;
    this.observedRequests += 1;
    this.observeIpMinute(state, epochSecond);
    state.firstSeen = Math.min(state.firstSeen, epochSecond);
    state.lastSeen = Math.max(state.lastSeen, epochSecond);
    incrementMap(state.methods, entry.method);

    // Threshold + 1 sentinel: enough to know path explosion crossed threshold without unbounded sets.
    if (state.paths.size < PATH_SENTINEL_LIMIT) {
      state.paths.add(entry.path);
    }

    // Threshold + 1 sentinel: enough to know UA rotation crossed threshold without unbounded sets.
    if (entry.userAgent && state.userAgents.size < UA_SENTINEL_LIMIT) {
      state.userAgents.add(entry.userAgent);
    }

    if (entry.status >= 400 && entry.status <= 499) {
      state.status4xxCount += 1;
      recordErrorPath(state.status4xxPaths, entry.path);
      this.observe4xx(state, epochSecond);
    } else if (entry.status >= 500 && entry.status <= 599) {
      state.status5xxCount += 1;
      this.globalStatus5xx += 1;
      recordErrorPath(state.status5xxPaths, entry.path);
      this.observe5xx(state, epochSecond);

      // Capacity-class errors say the server ran out of a resource rather than
      // hitting an application bug, so they are the clearest evidence that load
      // actually degraded the site.
      if (CAPACITY_ERROR_STATUSES.has(entry.status)) {
        this.capacityErrorCounts.set(
          entry.status,
          (this.capacityErrorCounts.get(entry.status) ?? 0) + 1
        );
        this.capacityErrorFirstSeen = this.capacityErrorFirstSeen ?? epochSecond;
        this.capacityErrorLastSeen = epochSecond;
      }
    }

    this.observeIpRps(state, epochSecond);
    this.observeHead(state, entry, epochSecond);
    this.observeKnownActors(state, entry, epochSecond);
  }

  private observeKnownActors(
    state: IpBehaviorState,
    entry: AccessLogEntry,
    epochSecond: number
  ): void {
    if (entry.path === "/robots.txt") {
      state.requestedRobotsTxt = true;
    }

    if (!state.botMatch && entry.userAgent) {
      state.botMatch = matchUserAgent(entry.userAgent, AI_BOT_PATTERNS);
    }

    if (state.botMatch) {
      this.observeBotRollup(state.botMatch, state.ip, entry, epochSecond);
    }

    if (!state.scannerMatch && entry.userAgent) {
      state.scannerMatch = matchUserAgent(entry.userAgent, SCANNER_UA_PATTERNS);
      state.scannerUserAgent = state.scannerMatch ? entry.userAgent : null;
    }

    if (FINGERPRINT_PATHS.has(entry.path)) {
      this.observeFingerprintPath(state, entry.path, epochSecond);
    }

    if (entry.userAgent && !state.claimedGooglebot && GOOGLEBOT_UA.test(entry.userAgent)) {
      state.claimedGooglebot = true;
      state.claimedBotUserAgent ??= entry.userAgent;
    }

    if (entry.userAgent && !state.claimedBingbot && BINGBOT_UA.test(entry.userAgent)) {
      state.claimedBingbot = true;
      state.claimedBotUserAgent ??= entry.userAgent;
    }
  }

  private observeHead(state: IpBehaviorState, entry: AccessLogEntry, epochSecond: number): void {
    if (entry.method !== "HEAD") {
      return;
    }

    state.headCount += 1;

    if (state.currentHeadSecond === null) {
      state.currentHeadSecond = epochSecond;
      state.currentHeadCount = 1;
      return;
    }

    if (state.currentHeadSecond === epochSecond) {
      state.currentHeadCount += 1;
      return;
    }

    this.closeHeadSecond(state);
    state.currentHeadSecond = epochSecond;
    state.currentHeadCount = 1;
  }

  private closeHeadSecond(state: IpBehaviorState): void {
    if (state.currentHeadSecond === null) {
      return;
    }

    if (state.currentHeadCount > state.peakHeadRps) {
      state.peakHeadRps = state.currentHeadCount;
      state.peakHeadRpsAt = state.currentHeadSecond;
    }
  }

  private observeSubnet(entry: AccessLogEntry, epochSecond: number): void {
    const prefix = extractSubnetPrefix(entry.ip);

    if (!prefix) {
      return;
    }

    const state = this.getOrCreateSubnet(prefix, epochSecond);

    if (!state) {
      return;
    }

    state.lastSeen = Math.max(state.lastSeen, epochSecond);

    if (state.currentSecond === null) {
      state.currentSecond = epochSecond;
      state.currentCount = 1;
      addSubnetIp(state, entry.ip);
      return;
    }

    if (state.currentSecond === epochSecond) {
      state.currentCount += 1;
      addSubnetIp(state, entry.ip);
      return;
    }

    const previousSecond = state.currentSecond;
    this.closeSubnetSecond(state);

    if (epochSecond !== previousSecond + 1) {
      state.burstRunLen = 0;
      state.burstStart = null;
    }

    state.currentSecond = epochSecond;
    state.currentCount = 1;
    state.currentIps = new Set([entry.ip]);
  }

  private closeSubnetSecond(state: SubnetState): void {
    if (state.currentSecond === null) {
      return;
    }

    if (state.currentCount > state.peakSubnetRps) {
      state.peakSubnetRps = state.currentCount;
      state.peakSubnetRpsAt = state.currentSecond;
      state.peakIpCount = state.currentIps.size;
    }

    if (state.currentCount >= SUBNET_RPS_THRESHOLD && state.currentIps.size >= SUBNET_MIN_IPS) {
      state.burstRunLen += 1;
      state.burstStart ??= state.currentSecond;

      if (state.burstRunLen > state.longestBurstLen) {
        state.longestBurstLen = state.burstRunLen;
        state.longestBurstStart = state.burstStart;
        state.longestBurstEnd = state.currentSecond;
      }
    } else {
      state.burstRunLen = 0;
      state.burstStart = null;
    }
  }

  private observeBotRollup(
    botName: string,
    ip: string,
    entry: AccessLogEntry,
    epochSecond: number
  ): void {
    const minute = Math.floor(epochSecond / 60);
    const bot = this.botRollup.get(botName) ?? {
      botName,
      requests: 0,
      ips: new Set<string>(),
      paths: new Set<string>(),
      requestedRobotsTxt: false,
      firstSeen: epochSecond,
      lastSeen: epochSecond,
      pathMinuteBuckets: new Map<number, Set<string>>(),
      latestPathMinute: minute,
      maxPathsPerMinute: 0,
      highPathMinuteCount: 0,
      status2xx: 0,
      status3xx: 0,
      status4xx: 0,
      status5xx: 0,
      currentMinute: null,
      currentMinuteServed: 0,
      maxServedPerMinute: 0,
      unverifiedRequests: 0,
      unverifiedIps: new Map<string, number>()
    };

    bot.requests += 1;
    this.observeBotVerification(bot, ip);
    bot.firstSeen = Math.min(bot.firstSeen, epochSecond);
    bot.lastSeen = Math.max(bot.lastSeen, epochSecond);
    bot.requestedRobotsTxt = bot.requestedRobotsTxt || entry.path === "/robots.txt";

    if (bot.ips.size < BOT_IP_SENTINEL_LIMIT) {
      bot.ips.add(ip);
    }

    if (bot.paths.size < BOT_PATH_SENTINEL_LIMIT) {
      bot.paths.add(entry.path);
    }

    this.observeBotStatus(bot, entry.status, minute);
    const paths = bot.pathMinuteBuckets.get(minute) ?? new Set<string>();
    const previousSize = paths.size;
    paths.add(entry.path);
    bot.pathMinuteBuckets.set(minute, paths);
    bot.maxPathsPerMinute = Math.max(bot.maxPathsPerMinute, paths.size);

    if (previousSize <= 10 && paths.size > 10) {
      bot.highPathMinuteCount += 1;
    }

    bot.latestPathMinute = Math.max(bot.latestPathMinute, minute);
    for (const bucket of bot.pathMinuteBuckets.keys()) {
      if (bucket < bot.latestPathMinute - 1) {
        bot.pathMinuteBuckets.delete(bucket);
      }
    }

    this.botRollup.set(botName, bot);
  }

  private observeBotStatus(bot: BotState, status: number, minute: number): void {
    const served = (status >= 200 && status < 300) || (status >= 500 && status < 600);

    if (status >= 200 && status < 300) {
      bot.status2xx += 1;
    } else if (status >= 300 && status < 400) {
      bot.status3xx += 1;
    } else if (status >= 400 && status < 500) {
      bot.status4xx += 1;
    } else if (status >= 500 && status < 600) {
      bot.status5xx += 1;
    }

    if (bot.currentMinute !== minute) {
      bot.currentMinute = minute;
      bot.currentMinuteServed = 0;
    }

    if (served) {
      bot.currentMinuteServed += 1;
      bot.maxServedPerMinute = Math.max(bot.maxServedPerMinute, bot.currentMinuteServed);
    }
  }

  private observeFingerprintPath(state: IpBehaviorState, path: string, epochSecond: number): void {
    const bucket = Math.floor(epochSecond / FINGERPRINT_BUCKET_SECONDS);

    if (state.currentFingerprintBucket === null) {
      state.currentFingerprintBucket = bucket;
      state.currentFingerprintPaths.add(path);
      this.updateFingerprintMax(state, bucket);
      return;
    }

    if (bucket === state.currentFingerprintBucket) {
      state.currentFingerprintPaths.add(path);
      this.updateFingerprintMax(state, bucket);
      return;
    }

    if (bucket === state.currentFingerprintBucket + 1) {
      state.previousFingerprintBucket = state.currentFingerprintBucket;
      state.previousFingerprintPaths = state.currentFingerprintPaths;
    } else {
      state.previousFingerprintBucket = null;
      state.previousFingerprintPaths = new Set();
    }

    state.currentFingerprintBucket = bucket;
    state.currentFingerprintPaths = new Set([path]);
    this.updateFingerprintMax(state, bucket);
  }

  private updateFingerprintMax(state: IpBehaviorState, bucket: number): void {
    const paths = new Set(state.currentFingerprintPaths);

    if (state.previousFingerprintBucket === bucket - 1) {
      for (const path of state.previousFingerprintPaths) {
        paths.add(path);
      }
    }

    if (paths.size > state.maxFingerprintHits) {
      state.maxFingerprintHits = paths.size;
      state.maxFingerprintBucket = bucket;
      state.maxFingerprintSamplePaths = [...paths].slice(0, 10);
    }
  }

  private observeIpRps(state: IpBehaviorState, epochSecond: number): void {
    if (state.currentSecond === null) {
      state.currentSecond = epochSecond;
      state.currentCount = 1;
      return;
    }

    if (state.currentSecond === epochSecond) {
      state.currentCount += 1;
      return;
    }

    this.closeIpSecond(state);

    if (epochSecond !== state.currentSecond + 1) {
      state.burstRunLen = 0;
      state.burstStart = null;
    }

    state.currentSecond = epochSecond;
    state.currentCount = 1;
  }

  private closeIpSecond(state: IpBehaviorState): void {
    if (state.currentSecond === null) {
      return;
    }

    if (state.currentCount > state.peakRps) {
      state.peakRps = state.currentCount;
      state.peakRpsAt = state.currentSecond;
    }

    if (state.currentCount >= SINGLE_IP_RPS_THRESHOLD) {
      state.burstRunLen += 1;
      state.burstStart ??= state.currentSecond;

      if (state.burstRunLen > state.longestBurstLen) {
        state.longestBurstLen = state.burstRunLen;
        state.longestBurstStart = state.burstStart;
        state.longestBurstEnd = state.currentSecond;
      }
    } else {
      state.burstRunLen = 0;
      state.burstStart = null;
    }
  }

  private observe4xx(state: IpBehaviorState, epochSecond: number): void {
    const bucket = Math.floor(epochSecond / FOUR_XX_BUCKET_SECONDS);

    if (state.current4xxBucket === null) {
      state.current4xxBucket = bucket;
      state.current4xxCount = 1;
      this.update4xxMax(state, bucket);
      return;
    }

    if (bucket === state.current4xxBucket) {
      state.current4xxCount += 1;
      this.update4xxMax(state, bucket);
      return;
    }

    if (bucket === state.current4xxBucket + 1) {
      state.previous4xxBucket = state.current4xxBucket;
      state.previous4xxCount = state.current4xxCount;
    } else {
      state.previous4xxBucket = null;
      state.previous4xxCount = 0;
    }

    state.current4xxBucket = bucket;
    state.current4xxCount = 1;
    this.update4xxMax(state, bucket);
  }

  private update4xxMax(state: IpBehaviorState, bucket: number): void {
    const previousIsAdjacent = state.previous4xxBucket === bucket - 1;
    const total = state.current4xxCount + (previousIsAdjacent ? state.previous4xxCount : 0);

    if (total > state.max4xxTwoBucketCount) {
      state.max4xxTwoBucketCount = total;
      state.max4xxBucket = bucket;
    }
  }

  private observe5xx(state: IpBehaviorState, epochSecond: number): void {
    const bucket = Math.floor(epochSecond / FIVE_XX_BUCKET_SECONDS);

    if (state.current5xxBucket === null) {
      state.current5xxBucket = bucket;
      state.current5xxCount = 1;
      this.update5xxMax(state, bucket);
      return;
    }

    if (bucket === state.current5xxBucket) {
      state.current5xxCount += 1;
      this.update5xxMax(state, bucket);
      return;
    }

    if (bucket === state.current5xxBucket + 1) {
      state.previous5xxBucket = state.current5xxBucket;
      state.previous5xxCount = state.current5xxCount;
    } else {
      state.previous5xxBucket = null;
      state.previous5xxCount = 0;
    }

    state.current5xxBucket = bucket;
    state.current5xxCount = 1;
    this.update5xxMax(state, bucket);
  }

  private update5xxMax(state: IpBehaviorState, bucket: number): void {
    const previousIsAdjacent = state.previous5xxBucket === bucket - 1;
    const total = state.current5xxCount + (previousIsAdjacent ? state.previous5xxCount : 0);

    if (total > state.max5xxTwoBucketCount) {
      state.max5xxTwoBucketCount = total;
      state.max5xxBucket = bucket;
    }
  }

  private updateTopIps(state: IpBehaviorState): void {
    const snapshot = this.snapshotIp(state);

    const existing = this.topIps.get(state.ip);

    if (existing) {
      if (snapshot.totalRequests >= existing.totalRequests) {
        this.topIps.set(state.ip, snapshot);
      }
      return;
    }

    if (this.topIps.size < TOP_IP_LIMIT) {
      this.topIps.set(state.ip, snapshot);
      return;
    }

    let min: TopIpSnapshot | undefined;

    for (const candidate of this.topIps.values()) {
      if (!min || candidate.totalRequests < min.totalRequests) {
        min = candidate;
      }
    }

    if (min && snapshot.totalRequests > min.totalRequests) {
      this.topIps.delete(min.ip);
      this.topIps.set(state.ip, snapshot);
    }
  }

  private snapshotIp(state: IpBehaviorState): TopIpSnapshot {
    const currentPeakRps = Math.max(state.peakRps, state.currentCount);
    const currentPeakRpsAt =
      currentPeakRps > state.peakRps && state.currentSecond !== null
        ? state.currentSecond
        : state.peakRpsAt;

    return {
      ip: state.ip,
      totalRequests: state.totalRequests,
      firstSeen: state.firstSeen,
      lastSeen: state.lastSeen,
      peakRps: currentPeakRps,
      peakRpsAt: currentPeakRpsAt,
      pathCount: state.paths.size,
      uaCount: state.userAgents.size,
      status4xxCount: state.status4xxCount,
      status5xxCount: state.status5xxCount
    };
  }

  private buildTimeStats(): TimeStats {
    const globalRpsP95 = this.globalRpsP95();

    return {
      firstSeen: this.firstSeen === null ? null : formatEpoch(this.firstSeen),
      lastSeen: this.lastSeen === null ? null : formatEpoch(this.lastSeen),
      peakGlobalRps: this.peakGlobalRps,
      peakGlobalRpsAt: this.peakGlobalRpsAt === null ? null : formatEpoch(this.peakGlobalRpsAt),
      globalRpsP95,
      invalidTimestampLines: this.invalidTimestampLines,
      outOfOrderTimestamps: this.outOfOrderTimestamps,
      droppedIpCount: this.droppedIpCount,
      droppedSubnetCount: this.droppedSubnetCount
    };
  }

  private globalRpsP95(): number {
    if (this.firstSeen === null || this.lastSeen === null) {
      return 0;
    }

    return sparseRpsP95(this.globalRpsBySecond, this.firstSeen, this.lastSeen);
  }

  private observeIpMinute(state: IpBehaviorState, epochSecond: number): void {
    const minute = Math.floor(epochSecond / 60);

    if (state.currentMinute !== minute) {
      state.currentMinute = minute;
      state.currentMinuteRequests = 0;
    }

    state.currentMinuteRequests += 1;

    if (state.currentMinuteRequests > state.maxRequestsPerMinute) {
      state.maxRequestsPerMinute = state.currentMinuteRequests;
      state.maxRequestsPerMinuteAt = minute * 60;
    }
  }

  /**
   * Sustained flood from one IP. The per-second burst rule only fires above
   * `SINGLE_IP_RPS_THRESHOLD`, which a real L7 flood often stays just under —
   * pacing at 30-45 rps for tens of seconds is both effective and invisible to
   * it. The discriminator against a browser is repetition: a page load fans out
   * across many distinct URLs, a flood hammers a handful, so a high per-minute
   * rate only counts when requests far outnumber the paths touched.
   */
  private buildSustainedIpFloodIncidents(): Incident[] {
    const incidents: Incident[] = [];

    for (const state of this.ips.values()) {
      if (state.maxRequestsPerMinute < SUSTAINED_FLOOD_MIN_PER_MINUTE) {
        continue;
      }

      if (this.skipPerIpBehavior(state.ip)) continue;

      const pathsTouched = Math.max(1, state.paths.size);
      const requestsPerPath = state.totalRequests / pathsTouched;

      if (requestsPerPath < SUSTAINED_FLOOD_MIN_REQUESTS_PER_PATH) {
        continue;
      }

      // Already reported at higher severity by the per-second burst rule.
      if (state.longestBurstLen >= SINGLE_IP_BURST_SECONDS) {
        continue;
      }

      incidents.push({
        id: `ddos_sustained_ip_flood:${state.ip}`,
        category: "ddos",
        kind: "saturation",
        severity: "high",
        score: 85,
        title: "Sustained single IP flood",
        description:
          "One IP sustained a high request rate against very few URLs, the shape of an application-layer flood rather than page loads.",
        evidence: [
          { key: "ip", value: state.ip },
          { key: "requests", value: state.totalRequests },
          { key: "maxRequestsPerMinute", value: state.maxRequestsPerMinute },
          {
            key: "maxRequestsPerMinuteAt",
            value:
              state.maxRequestsPerMinuteAt === null ? "" : formatEpoch(state.maxRequestsPerMinuteAt)
          },
          { key: "peakRps", value: state.peakRps },
          { key: "pathsTouched", value: state.paths.size },
          { key: "requestsPerPath", value: roundRatio(requestsPerPath) },
          { key: "firstSeen", value: formatEpoch(state.firstSeen) },
          { key: "lastSeen", value: formatEpoch(state.lastSeen) }
        ],
        samples: [...state.paths].slice(0, 3)
      });
    }

    return incidents;
  }

  private buildSingleIpBurstIncidents(): Incident[] {
    const incidents: Incident[] = [];

    for (const state of this.ips.values()) {
      if (state.longestBurstLen < SINGLE_IP_BURST_SECONDS) {
        continue;
      }

      if (this.skipPerIpBehavior(state.ip)) continue;

      incidents.push({
        id: `ddos_rps_burst_single_ip:${state.ip}`,
        category: "ddos",
        kind: "saturation",
        severity: "critical",
        score: 95,
        title: "Single IP RPS burst",
        description: "One IP exceeded the per-second request threshold for consecutive seconds.",
        evidence: [
          { key: "ip", value: state.ip },
          { key: "peakRps", value: state.peakRps },
          { key: "peakRpsAt", value: formatEpoch(state.peakRpsAt) },
          { key: "burstSeconds", value: state.longestBurstLen },
          { key: "burstStart", value: formatEpoch(state.longestBurstStart ?? state.peakRpsAt) },
          { key: "burstEnd", value: formatEpoch(state.longestBurstEnd ?? state.peakRpsAt) },
          { key: "requests", value: state.totalRequests },
          { key: "pathCount", value: state.paths.size }
        ],
        samples: []
      });
    }

    return incidents;
  }

  private buildGlobalSpikeIncidents(globalRpsP95: number): Incident[] {
    const threshold = Math.max(GLOBAL_SPIKE_ABSOLUTE_RPS, globalRpsP95 * GLOBAL_SPIKE_MULTIPLIER);
    let runStart: number | null = null;
    let runEnd: number | null = null;
    let runLength = 0;
    let bestStart: number | null = null;
    let bestEnd: number | null = null;
    let bestLength = 0;

    if (this.firstSeen === null || this.lastSeen === null) {
      return [];
    }

    const occupied = [...this.globalRpsBySecond.keys()].sort((a, b) => a - b);

    for (const second of occupied) {
      const rps = this.globalRpsBySecond.get(second) ?? 0;

      if (rps >= threshold) {
        if (runEnd !== null && second === runEnd + 1) {
          runLength += 1;
          runEnd = second;
        } else {
          runStart = second;
          runEnd = second;
          runLength = 1;
        }

        if (runLength > bestLength) {
          bestStart = runStart;
          bestEnd = runEnd;
          bestLength = runLength;
        }
      } else {
        runStart = null;
        runEnd = null;
        runLength = 0;
      }
    }

    if (bestLength < GLOBAL_SPIKE_SECONDS || bestStart === null || bestEnd === null) {
      return [];
    }

    return [
      {
        id: "ddos_global_rps_spike",
        category: "ddos",
        kind: "saturation",
        severity: "high",
        score: 75,
        title: "Global RPS spike",
        description: "Overall request rate exceeded the traffic baseline for consecutive seconds.",
        evidence: [
          { key: "peakGlobalRps", value: this.peakGlobalRps },
          { key: "peakGlobalRpsAt", value: formatEpoch(this.peakGlobalRpsAt ?? bestStart) },
          { key: "globalRpsP95", value: globalRpsP95 },
          { key: "threshold", value: threshold },
          { key: "spikeSeconds", value: bestLength },
          { key: "spikeStart", value: formatEpoch(bestStart) },
          { key: "spikeEnd", value: formatEpoch(bestEnd) }
        ],
        samples: []
      }
    ];
  }

  private build4xxStormIncidents(): Incident[] {
    const incidents: Incident[] = [];

    for (const state of this.ips.values()) {
      if (state.max4xxTwoBucketCount < FOUR_XX_STORM_THRESHOLD || state.max4xxBucket === null) {
        continue;
      }

      if (this.skipPerIpBehavior(state.ip)) continue;

      incidents.push({
        id: `http_4xx_storm:${state.ip}`,
        category: "http_anomaly",
        kind: "noise",
        severity: "low",
        score: 35,
        title: "4xx response storm",
        description:
          "One IP generated many blocked/error responses; this is useful context but not backend saturation.",
        evidence: [
          { key: "ip", value: state.ip },
          { key: "status4xx", value: state.max4xxTwoBucketCount },
          { key: "window", value: "two adjacent 60s buckets" },
          { key: "windowApproxSeconds", value: 120 },
          {
            key: "windowEnd",
            value: formatEpoch((state.max4xxBucket + 1) * FOUR_XX_BUCKET_SECONDS - 1)
          },
          { key: "topErrorPaths", value: formatTopErrorPaths(state.status4xxPaths) }
        ],
        samples: []
      });
    }

    return incidents;
  }

  /**
   * Site-wide capacity failure. The per-IP 5xx storm rule needs one client to
   * produce a burst of errors, so a site collapsing under load spread across
   * thousands of clients — the common shape when a crawler saturates it —
   * produced no incident at all despite being the clearest distress signal in
   * the log.
   */
  private buildServerDistressIncidents(): Incident[] {
    const capacityErrors = [...this.capacityErrorCounts.values()].reduce(
      (total, count) => total + count,
      0
    );

    if (capacityErrors < SERVER_DISTRESS_MIN_ERRORS || this.observedRequests === 0) {
      return [];
    }

    const share = capacityErrors / this.observedRequests;

    if (share < SERVER_DISTRESS_MIN_SHARE) {
      return [];
    }

    const critical = share >= SERVER_DISTRESS_CRITICAL_SHARE;
    const breakdown = [...this.capacityErrorCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([status, count]) => `${status}=${count}`)
      .join(" | ");

    return [
      {
        id: "server_capacity_distress",
        category: "http_anomaly",
        kind: "saturation",
        severity: critical ? "critical" : "high",
        score: critical ? 90 : 75,
        title: "Server capacity errors under load",
        description:
          "The server returned resource-limit or gateway-timeout responses, meaning requests were refused because capacity ran out rather than because of an application bug.",
        evidence: [
          { key: "capacityErrors", value: capacityErrors },
          { key: "statusBreakdown", value: breakdown },
          { key: "totalRequests", value: this.observedRequests },
          { key: "errorShare", value: roundRatio(share) },
          { key: "status5xxTotal", value: this.globalStatus5xx },
          {
            key: "firstSeen",
            value:
              this.capacityErrorFirstSeen === null ? "" : formatEpoch(this.capacityErrorFirstSeen)
          },
          {
            key: "lastSeen",
            value:
              this.capacityErrorLastSeen === null ? "" : formatEpoch(this.capacityErrorLastSeen)
          }
        ],
        samples: []
      }
    ];
  }

  private build5xxStormIncidents(): Incident[] {
    const incidents: Incident[] = [];

    for (const state of this.ips.values()) {
      if (state.max5xxTwoBucketCount < FIVE_XX_STORM_THRESHOLD || state.max5xxBucket === null) {
        continue;
      }

      if (this.skipPerIpBehavior(state.ip)) continue;

      incidents.push({
        id: `http_5xx_storm:${state.ip}`,
        category: "http_anomaly",
        kind: "saturation",
        severity: "medium",
        score: 60,
        title: "5xx response storm",
        description: "One IP generated many 5xx responses in adjacent minute buckets.",
        evidence: [
          { key: "ip", value: state.ip },
          { key: "status5xx", value: state.max5xxTwoBucketCount },
          { key: "window", value: "two adjacent 60s buckets" },
          { key: "windowApproxSeconds", value: 120 },
          {
            key: "windowEnd",
            value: formatEpoch((state.max5xxBucket + 1) * FIVE_XX_BUCKET_SECONDS - 1)
          },
          { key: "topErrorPaths", value: formatTopErrorPaths(state.status5xxPaths) }
        ],
        samples: []
      });
    }

    return incidents;
  }

  private buildFakeBotIncidents(): Incident[] {
    const incidents: Incident[] = [];
    const campaigns = new Map<
      "Googlebot" | "bingbot",
      { requests: number; sources: [string, number][]; userAgent: string }
    >();

    for (const state of this.ips.values()) {
      // Single-request impersonations are noise (misconfigured bots, tests, malformed UAs).
      if (state.totalRequests < FAKE_BOT_MIN_REQUESTS) {
        continue;
      }

      // A proxy hop carries whatever user-agent it forwarded, so "Googlebot
      // from 127.0.0.1" is the server relaying a request, not impersonation.
      if (isNonRoutableClientIp(state.ip)) {
        continue;
      }

      if (state.claimedGooglebot && !ipInPreparedRanges(state.ip, this.googlebotRanges)) {
        this.recordFakeBot(campaigns, "Googlebot", state);
        incidents.push(
          fakeBotIncident({
            id: `fake_bot_googlebot:${state.ip}`,
            ip: state.ip,
            claimedBot: "Googlebot",
            userAgent: state.claimedBotUserAgent ?? "",
            requests: state.totalRequests,
            pathsTouched: state.paths.size
          })
        );
      }

      if (state.claimedBingbot && !ipInPreparedRanges(state.ip, this.bingbotRanges)) {
        this.recordFakeBot(campaigns, "bingbot", state);
        incidents.push(
          fakeBotIncident({
            id: `fake_bot_bingbot:${state.ip}`,
            ip: state.ip,
            claimedBot: "bingbot",
            userAgent: state.claimedBotUserAgent ?? "",
            requests: state.totalRequests,
            pathsTouched: state.paths.size
          })
        );
      }
    }

    return this.rollUpFakeBotCampaigns(incidents, campaigns);
  }

  private recordFakeBot(
    campaigns: Map<
      "Googlebot" | "bingbot",
      { requests: number; sources: [string, number][]; userAgent: string }
    >,
    claimedBot: "Googlebot" | "bingbot",
    state: IpBehaviorState
  ): void {
    const campaign = campaigns.get(claimedBot) ?? {
      requests: 0,
      sources: [],
      userAgent: state.claimedBotUserAgent ?? ""
    };
    campaign.requests += state.totalRequests;
    campaign.sources.push([state.ip, state.totalRequests]);
    campaigns.set(claimedBot, campaign);
  }

  /**
   * Collapses a coordinated impersonation campaign into one incident. Dozens of
   * IPs sending the identical forged user-agent is a single actor, and listing
   * them one per incident buries every other finding in the report while
   * understating the campaign: each IP on its own looks like a minor probe.
   * Below the threshold the per-IP incidents are kept as they are.
   */
  private rollUpFakeBotCampaigns(
    incidents: Incident[],
    campaigns: Map<
      "Googlebot" | "bingbot",
      { requests: number; sources: [string, number][]; userAgent: string }
    >
  ): Incident[] {
    const rolledUp = new Set<"Googlebot" | "bingbot">();
    const campaignIncidents: Incident[] = [];

    for (const [claimedBot, campaign] of campaigns) {
      if (campaign.sources.length < FAKE_BOT_CAMPAIGN_MIN_IPS) {
        continue;
      }

      rolledUp.add(claimedBot);
      const sources = [...campaign.sources].sort((a, b) => b[1] - a[1]);
      const subnets = new Set<string>();
      for (const [ip] of sources) {
        const prefix = extractSubnetPrefix(ip);
        if (prefix) subnets.add(prefix);
      }

      campaignIncidents.push({
        id: `fake_bot_campaign:${claimedBot}`,
        category: "fake_bot",
        kind: "compromise",
        severity: "critical",
        score: 90,
        title: `Coordinated fake ${claimedBot} campaign`,
        description:
          "Many distinct IPs sent the same forged search-engine user-agent, which is one actor spreading a crawl across addresses rather than isolated misconfigured clients.",
        evidence: [
          { key: "claimedBot", value: claimedBot },
          { key: "sourceIps", value: sources.length },
          { key: "requests", value: campaign.requests },
          { key: "subnets", value: subnets.size },
          { key: "userAgent", value: campaign.userAgent },
          {
            key: "topIps",
            value: sources
              .slice(0, 5)
              .map(([ip, count]) => `${ip} (${count})`)
              .join(" | ")
          }
        ],
        samples: []
      });
    }

    if (rolledUp.size === 0) {
      return incidents;
    }

    const kept = incidents.filter((incident) => {
      if (rolledUp.has("Googlebot") && incident.id.startsWith("fake_bot_googlebot:")) return false;
      if (rolledUp.has("bingbot") && incident.id.startsWith("fake_bot_bingbot:")) return false;
      return true;
    });

    return [...kept, ...campaignIncidents];
  }

  private buildAiBotStats(): AiBotStats[] {
    return [...this.botRollup.values()]
      .sort((a, b) => b.requests - a.requests || a.botName.localeCompare(b.botName))
      .map((bot) => ({
        botName: bot.botName,
        requests: bot.requests,
        ipCount: bot.ips.size,
        pathCount: bot.paths.size,
        requestedRobotsTxt: bot.requestedRobotsTxt,
        firstSeen: formatEpoch(bot.firstSeen),
        lastSeen: formatEpoch(bot.lastSeen)
      }));
  }

  /**
   * Checks a declared AI crawler against its operator's published ranges. Only
   * some operators publish them; for the rest the user-agent is unprovable from
   * an access log and nothing is recorded, so absence of a finding never means
   * "verified".
   */
  private observeBotVerification(bot: BotState, ip: string): void {
    const ranges = this.aiBotRanges.get(bot.botName);

    if (!ranges || ipInPreparedRanges(ip, ranges)) {
      return;
    }

    bot.unverifiedRequests += 1;
    const current = bot.unverifiedIps.get(ip);

    if (current !== undefined) {
      bot.unverifiedIps.set(ip, current + 1);
      return;
    }

    if (bot.unverifiedIps.size < BOT_IP_SENTINEL_LIMIT) {
      bot.unverifiedIps.set(ip, 1);
    }
  }

  /**
   * Impersonation of an AI crawler whose operator publishes its ranges. Sending
   * a well-known crawler's user-agent from outside its network is a deliberate
   * attempt to inherit the allowances sites grant that crawler.
   */
  private buildFakeAiBotIncidents(): Incident[] {
    const incidents: Incident[] = [];

    for (const bot of this.botRollup.values()) {
      if (!this.aiBotRanges.has(bot.botName) || bot.unverifiedRequests < FAKE_AI_BOT_MIN_REQUESTS) {
        continue;
      }

      const sources = [...bot.unverifiedIps.entries()].sort((a, b) => b[1] - a[1]);

      incidents.push({
        id: `fake_ai_bot:${bot.botName}`,
        category: "fake_bot",
        kind: "compromise",
        severity: "high",
        score: 85,
        title: `Fake ${bot.botName} impersonation`,
        description:
          "Requests carried this AI crawler's user-agent from IPs outside the ranges its operator publishes, so the crawler identity is forged.",
        evidence: [
          { key: "botName", value: bot.botName },
          { key: "unverifiedRequests", value: bot.unverifiedRequests },
          { key: "totalRequests", value: bot.requests },
          { key: "unverifiedIps", value: sources.length },
          {
            key: "topIps",
            value: sources
              .slice(0, 5)
              .map(([ip, count]) => `${ip} (${count})`)
              .join(" | ")
          },
          { key: "firstSeen", value: formatEpoch(bot.firstSeen) },
          { key: "lastSeen", value: formatEpoch(bot.lastSeen) }
        ],
        samples: []
      });
    }

    return incidents;
  }

  private static botCausedDistress(bot: BotState): boolean {
    return (
      bot.status5xx >= AI_BOT_MIN_5XX_DISTRESS &&
      bot.requests > 0 &&
      bot.status5xx / bot.requests >= AI_BOT_MIN_5XX_SHARE
    );
  }

  private buildAiScraperIncidents(): Incident[] {
    const totalRequests = this.observedRequests;

    return [...this.botRollup.values()].map((bot) => {
      // Only sustained high-volume AI scraping counts as saturation. Low-volume
      // bot traffic is informational — kind: "noise" so it stays out of the
      // saturation panel.
      // Each of these is independently sufficient. Requiring path diversity on
      // top of the others used to veto the worst real cases: a crawler that
      // hammers one faceted URL with a fresh query string every request never
      // accrues "high path minutes", yet costs the backend the same per request
      // and can account for most of a site's traffic.
      const pathDiversityPressure =
        bot.highPathMinuteCount >= AI_BOT_HIGH_PATH_MINUTES &&
        (bot.maxServedPerMinute >= AI_BOT_MIN_PEAK_SERVED_PER_MINUTE ||
          BehaviorTracker.botCausedDistress(bot));
      const distressPressure = BehaviorTracker.botCausedDistress(bot);
      const trafficShare = totalRequests > 0 ? bot.requests / totalRequests : 0;
      const dominatesTraffic =
        totalRequests >= AI_BOT_DOMINANT_MIN_TOTAL_REQUESTS &&
        bot.requests >= AI_BOT_DOMINANT_MIN_REQUESTS &&
        bot.status2xx >= AI_BOT_DOMINANT_MIN_SERVED &&
        trafficShare >= AI_BOT_DOMINANT_TRAFFIC_SHARE;

      // A served-rate peak on its own is deliberately *not* enough: on a large
      // busy site any popular crawler touches it for a minute without that
      // being saturation. It counts only together with path fan-out.
      const high = pathDiversityPressure || distressPressure || dominatesTraffic;
      const medium = bot.requests >= AI_BOT_MEDIUM_REQUESTS;
      const kind: IncidentKind = high ? "saturation" : "noise";

      return {
        id: `ai_scraper_known:${bot.botName}`,
        category: "ai_scraper",
        kind,
        severity: high ? "high" : medium ? "low" : "info",
        score: high ? 70 : medium ? 35 : 15,
        title: "Known AI crawler",
        description: "Requests came from a known AI crawler or AI assistant user-agent.",
        evidence: [
          { key: "botName", value: bot.botName },
          { key: "requests", value: bot.requests },
          { key: "ipCount", value: bot.ips.size },
          { key: "pathsTouched", value: bot.paths.size },
          { key: "requestedRobotsTxt", value: bot.requestedRobotsTxt },
          { key: "maxPathsPerMinute", value: bot.maxPathsPerMinute },
          { key: "maxServedPerMinute", value: bot.maxServedPerMinute },
          { key: "highPathMinutes", value: bot.highPathMinuteCount },
          { key: "trafficShare", value: roundRatio(trafficShare) },
          { key: "ipVerifiable", value: this.aiBotRanges.has(bot.botName) },
          { key: "status2xx", value: bot.status2xx },
          { key: "status3xx", value: bot.status3xx },
          { key: "status4xx", value: bot.status4xx },
          { key: "status5xx", value: bot.status5xx },
          { key: "firstSeen", value: formatEpoch(bot.firstSeen) },
          { key: "lastSeen", value: formatEpoch(bot.lastSeen) }
        ],
        samples: []
      } satisfies Incident;
    });
  }

  private buildScannerUaIncidents(): Incident[] {
    const incidents: Incident[] = [];

    for (const state of this.ips.values()) {
      if (!state.scannerMatch) {
        continue;
      }

      if (this.skipPerIpBehavior(state.ip)) continue;

      incidents.push({
        id: `scanner_ua_known:${state.scannerMatch}:${state.ip}`,
        category: "scanner",
        kind: "compromise",
        severity: "high",
        score: 85,
        title: "Known scanner user-agent",
        description: "One IP used a known scanner or offensive tooling user-agent.",
        evidence: [
          { key: "scanner", value: state.scannerMatch },
          { key: "ip", value: state.ip },
          { key: "requests", value: state.totalRequests },
          { key: "pathsTouched", value: state.paths.size },
          { key: "userAgent", value: state.scannerUserAgent ?? state.scannerMatch }
        ],
        samples: []
      });
    }

    return incidents;
  }

  private buildScannerFingerprintIncidents(): Incident[] {
    const incidents: Incident[] = [];

    for (const state of this.ips.values()) {
      if (
        state.maxFingerprintHits < FINGERPRINT_PATH_THRESHOLD ||
        state.maxFingerprintBucket === null
      ) {
        continue;
      }

      if (this.skipPerIpBehavior(state.ip)) continue;

      incidents.push({
        id: `scanner_signature_paths:${state.ip}`,
        category: "scanner",
        kind: "compromise",
        severity: "high",
        score: 75,
        title: "Scanner fingerprint paths",
        description:
          "One IP touched many known scanner fingerprint paths in adjacent minute buckets.",
        evidence: [
          { key: "ip", value: state.ip },
          { key: "fingerprintHits", value: state.maxFingerprintHits },
          { key: "samplePaths", value: state.maxFingerprintSamplePaths.join(", ") },
          { key: "windowSeconds", value: 120 },
          {
            key: "windowEnd",
            value: formatEpoch((state.maxFingerprintBucket + 1) * FINGERPRINT_BUCKET_SECONDS - 1)
          }
        ],
        samples: state.maxFingerprintSamplePaths
      });
    }

    return incidents;
  }

  private isLegitimateBot(ip: string): boolean {
    return (
      ipInPreparedRanges(ip, this.googlebotRanges) || ipInPreparedRanges(ip, this.bingbotRanges)
    );
  }

  /**
   * Per-IP incidents are skipped for verified search-engine crawlers and for
   * addresses that cannot be a remote client. A loopback or RFC1918 source is
   * the server's own proxy hop: attributing behavior to it produces findings
   * about the server rather than about any attacker.
   */
  private skipPerIpBehavior(ip: string): boolean {
    return this.isLegitimateBot(ip) || isNonRoutableClientIp(ip);
  }

  private buildSingleIpPathExplosionIncidents(): Incident[] {
    const incidents: Incident[] = [];

    for (const state of this.ips.values()) {
      if (state.paths.size < SINGLE_IP_PATH_EXPLOSION_THRESHOLD) {
        continue;
      }

      // Skip verified Googlebot/Bingbot — legitimate crawlers touch many paths.
      if (this.skipPerIpBehavior(state.ip)) {
        continue;
      }

      // Rate-based gate: 500+ paths over hours/days at low rate is normal browsing,
      // not saturation. Require sustained high path-fan-out per minute.
      const durationSeconds = Math.max(1, state.lastSeen - state.firstSeen);
      const durationMinutes = durationSeconds / 60;
      const pathsPerMinute = state.paths.size / durationMinutes;

      if (pathsPerMinute < SINGLE_IP_PATH_EXPLOSION_MIN_RATE_PER_MIN) {
        continue;
      }

      incidents.push({
        id: `single_ip_path_explosion:${state.ip}`,
        category: "abusive_crawling",
        kind: "saturation",
        severity: "high",
        score: 75,
        title: "Single IP path explosion",
        description: "One IP touched hundreds of unique paths at a high rate.",
        evidence: [
          { key: "ip", value: state.ip },
          { key: "pathCount", value: state.paths.size },
          { key: "totalRequests", value: state.totalRequests },
          { key: "pathsPerMinute", value: Math.round(pathsPerMinute * 10) / 10 },
          { key: "peakRps", value: state.peakRps },
          { key: "firstSeen", value: formatEpoch(state.firstSeen) },
          { key: "lastSeen", value: formatEpoch(state.lastSeen) }
        ],
        samples: [...state.paths].slice(0, 5)
      });
    }

    return incidents;
  }

  private buildUaRotationIncidents(): Incident[] {
    const incidents: Incident[] = [];

    for (const state of this.ips.values()) {
      if (
        state.userAgents.size < UA_ROTATION_THRESHOLD ||
        state.totalRequests < UA_ROTATION_MIN_REQUESTS ||
        state.peakRps < UA_ROTATION_MIN_PEAK_RPS
      ) {
        continue;
      }

      if (this.skipPerIpBehavior(state.ip)) continue;

      incidents.push({
        id: `ua_rotation_same_ip:${state.ip}`,
        category: "http_anomaly",
        kind: "noise",
        severity: "low",
        score: 35,
        title: "User-agent rotation from one IP",
        description:
          "One IP used many different user-agents, but no attack payload was observed from this signal alone.",
        evidence: [
          { key: "ip", value: state.ip },
          { key: "uaCount", value: state.userAgents.size },
          { key: "totalRequests", value: state.totalRequests },
          { key: "sampleUserAgents", value: [...state.userAgents].slice(0, 3).join(" | ") }
        ],
        samples: [...state.userAgents].slice(0, 3)
      });
    }

    return incidents;
  }

  private buildHeadFloodIncidents(): Incident[] {
    const incidents: Incident[] = [];

    for (const state of this.ips.values()) {
      if (state.totalRequests < HEAD_FLOOD_MIN_REQUESTS) {
        continue;
      }

      if (this.skipPerIpBehavior(state.ip)) continue;

      const headRatio = state.headCount / state.totalRequests;

      if (headRatio < HEAD_FLOOD_RATIO || state.peakHeadRps < HEAD_FLOOD_PEAK_RPS) {
        continue;
      }

      incidents.push({
        id: `http_head_flood:${state.ip}`,
        category: "ddos",
        kind: "saturation",
        severity: "high",
        score: 70,
        title: "HEAD request flood",
        description: "One IP sent a high ratio of HEAD requests with a sustained peak rate.",
        evidence: [
          { key: "ip", value: state.ip },
          { key: "totalRequests", value: state.totalRequests },
          { key: "headCount", value: state.headCount },
          { key: "headRatio", value: roundRatio(headRatio) },
          { key: "peakHeadRps", value: state.peakHeadRps },
          { key: "peakHeadRpsAt", value: formatEpoch(state.peakHeadRpsAt) }
        ],
        samples: []
      });
    }

    return incidents;
  }

  private buildSubnetDdosIncidents(): Incident[] {
    const incidents: Incident[] = [];

    for (const subnet of this.subnets.values()) {
      if (subnet.longestBurstLen < SUBNET_BURST_SECONDS) {
        continue;
      }

      incidents.push({
        id: `ddos_distributed_subnet:${subnet.prefix}`,
        category: "ddos",
        kind: "saturation",
        severity: "critical",
        score: 90,
        title: "Distributed DDoS from subnet",
        description:
          "Subnet exceeded the per-second request threshold with many unique IPs for consecutive seconds.",
        evidence: [
          { key: "prefix", value: subnet.prefix },
          { key: "peakSubnetRps", value: subnet.peakSubnetRps },
          { key: "peakSubnetRpsAt", value: formatEpoch(subnet.peakSubnetRpsAt) },
          { key: "peakIpCount", value: subnet.peakIpCount },
          { key: "burstSeconds", value: subnet.longestBurstLen },
          {
            key: "burstStart",
            value: formatEpoch(subnet.longestBurstStart ?? subnet.peakSubnetRpsAt)
          },
          { key: "burstEnd", value: formatEpoch(subnet.longestBurstEnd ?? subnet.peakSubnetRpsAt) }
        ],
        samples: []
      });
    }

    return incidents;
  }

  private closeAllIpSeconds(): void {
    for (const state of this.ips.values()) {
      this.closeIpSecond(state);
    }
  }

  private closeAllHeadSeconds(): void {
    for (const state of this.ips.values()) {
      this.closeHeadSecond(state);
    }
  }

  private closeAllSubnetSeconds(): void {
    for (const state of this.subnets.values()) {
      this.closeSubnetSecond(state);
    }
  }
}

function incrementMap(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1);
}

function addSubnetIp(state: SubnetState, ip: string): void {
  if (state.currentIps.size < SUBNET_IPS_SENTINEL) {
    state.currentIps.add(ip);
  }
}

function roundRatio(value: number): number {
  return Math.round(value * 100) / 100;
}

function fakeBotIncident(input: {
  id: string;
  ip: string;
  claimedBot: "Googlebot" | "bingbot";
  userAgent: string;
  requests: number;
  pathsTouched: number;
}): Incident {
  return {
    id: input.id,
    category: "fake_bot",
    kind: "compromise",
    severity: "high",
    score: 80,
    title: `Fake ${input.claimedBot} impersonation`,
    description: `User-agent claims ${input.claimedBot} but IP is outside published crawler ranges.`,
    evidence: [
      { key: "ip", value: input.ip },
      { key: "claimedBot", value: input.claimedBot },
      { key: "userAgent", value: input.userAgent },
      { key: "requests", value: input.requests },
      { key: "pathsTouched", value: input.pathsTouched }
    ],
    samples: []
  };
}

function matchUserAgent(
  userAgent: string,
  patterns: Array<{ name: string; regex: RegExp }>
): string | null {
  return patterns.find((pattern) => pattern.regex.test(userAgent))?.name ?? null;
}

/**
 * Tracks which paths an IP is erroring on, bounded to a handful of entries. An
 * error storm without the failing URL says the server is unhappy but not what
 * broke, which is the one thing the operator needs to act.
 */
function recordErrorPath(paths: Map<string, number>, path: string): void {
  const current = paths.get(path);

  if (current !== undefined) {
    paths.set(path, current + 1);
    return;
  }

  if (paths.size < ERROR_PATH_LIMIT) {
    paths.set(path, 1);
  }
}

function formatTopErrorPaths(paths: Map<string, number>): string {
  return [...paths.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 3)
    .map(([path, count]) => `${path} (${count})`)
    .join(" | ");
}

function formatEpoch(epochSecond: number): string {
  return new Date(epochSecond * 1000).toISOString();
}
