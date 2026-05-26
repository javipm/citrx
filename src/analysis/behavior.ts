import type { AccessLogEntry } from "../parser/access-log.js";
import type { Incident, IpBehaviorStats, TimeStats } from "./types.js";
import { accessLogTimestampToEpochSeconds } from "./timestamp.js";

export const MAX_TRACKED_IPS = 100_000;
const STALE_IP_SECONDS = 900;
const PATH_SENTINEL_LIMIT = 501;
const UA_SENTINEL_LIMIT = 9;
const TOP_IP_LIMIT = 100;
const SINGLE_IP_RPS_THRESHOLD = 50;
const SINGLE_IP_BURST_SECONDS = 3;
const GLOBAL_SPIKE_ABSOLUTE_RPS = 100;
const GLOBAL_SPIKE_MULTIPLIER = 5;
const GLOBAL_SPIKE_SECONDS = 10;
const FOUR_XX_STORM_THRESHOLD = 200;
const FOUR_XX_BUCKET_SECONDS = 60;

interface BehaviorTrackerOptions {
  maxTrackedIps?: number;
}

interface IpBehaviorState {
  ip: string;
  totalRequests: number;
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
  methods: Map<string, number>;
  paths: Set<string>;
  userAgents: Set<string>;
  current4xxBucket: number | null;
  current4xxCount: number;
  previous4xxBucket: number | null;
  previous4xxCount: number;
  max4xxTwoBucketCount: number;
  max4xxBucket: number | null;
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
  incidents: Incident[];
}

export class BehaviorTracker {
  private readonly maxTrackedIps: number;
  private readonly ips = new Map<string, IpBehaviorState>();
  private readonly globalRpsBySecond = new Map<number, number>();
  private readonly topIps = new Map<string, TopIpSnapshot>();
  private firstSeen: number | null = null;
  private lastSeen: number | null = null;
  private streamNow: number | null = null;
  private peakGlobalRps = 0;
  private peakGlobalRpsAt: number | null = null;
  private invalidTimestampLines = 0;
  private outOfOrderTimestamps = 0;
  private droppedIpCount = 0;

  constructor(options: BehaviorTrackerOptions = {}) {
    this.maxTrackedIps = options.maxTrackedIps ?? MAX_TRACKED_IPS;
  }

  observe(entry: AccessLogEntry): void {
    const epochSecond = accessLogTimestampToEpochSeconds(entry.timestamp);

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

    const state = this.getOrCreateIp(entry.ip, epochSecond);

    if (!state) {
      return;
    }

    this.observeIp(state, entry, epochSecond);
    this.updateTopIps(state);
  }

  finalize(): BehaviorAnalysis {
    this.closeAllIpSeconds();
    const timeStats = this.buildTimeStats();
    const incidents = [
      ...this.buildSingleIpBurstIncidents(),
      ...this.buildGlobalSpikeIncidents(timeStats.globalRpsP95),
      ...this.build4xxStormIncidents()
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
      incidents
    };
  }

  private observeGlobalRps(epochSecond: number): void {
    const count = (this.globalRpsBySecond.get(epochSecond) ?? 0) + 1;
    this.globalRpsBySecond.set(epochSecond, count);

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
      methods: new Map(),
      paths: new Set(),
      userAgents: new Set(),
      current4xxBucket: null,
      current4xxCount: 0,
      previous4xxBucket: null,
      previous4xxCount: 0,
      max4xxTwoBucketCount: 0,
      max4xxBucket: null
    };

    this.ips.set(ip, state);
    return state;
  }

  private evictStaleIp(epochSecond: number): boolean {
    let candidate: IpBehaviorState | undefined;

    for (const state of this.ips.values()) {
      if (state.lastSeen >= epochSecond - STALE_IP_SECONDS) {
        continue;
      }

      if (
        !candidate ||
        state.totalRequests < candidate.totalRequests ||
        (state.totalRequests === candidate.totalRequests && state.lastSeen < candidate.lastSeen)
      ) {
        candidate = state;
      }
    }

    if (!candidate) {
      return false;
    }

    this.ips.delete(candidate.ip);
    return true;
  }

  private observeIp(state: IpBehaviorState, entry: AccessLogEntry, epochSecond: number): void {
    state.totalRequests += 1;
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
      this.observe4xx(state, epochSecond);
    } else if (entry.status >= 500 && entry.status <= 599) {
      state.status5xxCount += 1;
    }

    this.observeIpRps(state, epochSecond);
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
    const currentPeakRpsAt = currentPeakRps > state.peakRps && state.currentSecond !== null
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
      droppedIpCount: this.droppedIpCount
    };
  }

  private globalRpsP95(): number {
    if (this.firstSeen === null || this.lastSeen === null) {
      return 0;
    }

    const values: number[] = [];

    for (let second = this.firstSeen; second <= this.lastSeen; second += 1) {
      values.push(this.globalRpsBySecond.get(second) ?? 0);
    }

    values.sort((a, b) => a - b);
    return values[Math.floor((values.length - 1) * 0.95)] ?? 0;
  }

  private buildSingleIpBurstIncidents(): Incident[] {
    const incidents: Incident[] = [];

    for (const state of this.ips.values()) {
      if (state.longestBurstLen < SINGLE_IP_BURST_SECONDS) {
        continue;
      }

      incidents.push({
        id: `ddos_rps_burst_single_ip:${state.ip}`,
        category: "ddos",
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
    let runLength = 0;
    let bestStart: number | null = null;
    let bestEnd: number | null = null;
    let bestLength = 0;

    if (this.firstSeen === null || this.lastSeen === null) {
      return [];
    }

    for (let second = this.firstSeen; second <= this.lastSeen; second += 1) {
      const rps = this.globalRpsBySecond.get(second) ?? 0;

      if (rps >= threshold) {
        runStart ??= second;
        runLength += 1;

        if (runLength > bestLength) {
          bestStart = runStart;
          bestEnd = second;
          bestLength = runLength;
        }
      } else {
        runStart = null;
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

      incidents.push({
        id: `http_4xx_storm:${state.ip}`,
        category: "http_anomaly",
        severity: "medium",
        score: 60,
        title: "4xx response storm",
        description: "One IP generated many 4xx responses in adjacent minute buckets.",
        evidence: [
          { key: "ip", value: state.ip },
          { key: "status4xx", value: state.max4xxTwoBucketCount },
          { key: "window", value: "two adjacent 60s buckets" },
          { key: "windowApproxSeconds", value: 120 },
          { key: "windowEnd", value: formatEpoch((state.max4xxBucket + 1) * FOUR_XX_BUCKET_SECONDS - 1) }
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
}

function incrementMap(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1);
}

function formatEpoch(epochSecond: number): string {
  return new Date(epochSecond * 1000).toISOString();
}
