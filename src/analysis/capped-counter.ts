/**
 * Caps for the bounded-memory counters.
 *
 * Small per-record structures keep exact counts and simply stop admitting new
 * keys (`incrementCapped`). The global top-N counters instead use
 * `admitHeavyHitter`, because refusing new keys there silently reports the
 * wrong top-N: on a long log the busiest path is often one that only starts
 * appearing after the cap is already full.
 */
export const MAX_AGGREGATION_KEYS = 20_000;
export const MAX_PATH_STATS = 8_000;
export const MAX_PATH_UNIQUE_IPS = 64;
export const MAX_QUERY_VARIANTS = 256;
export const MAX_GLOBAL_PATH_IP_ENTRIES = 40_000;
export const MAX_GLOBAL_PATH_VARIANT_ENTRIES = 40_000;
/**
 * Floor every tracked path is entitled to even after the shared budget above is
 * spent. The budget is consumed in arrival order, so without a floor a path
 * that only starts being requested late in a long log records zero IPs and zero
 * query variants — and then reads as having no crawl signal at all, however
 * busy it actually is. The floors sit just above the thresholds the rules test,
 * so a late path still gets a sample big enough to be judged on.
 */
export const MIN_PATH_IPS_GUARANTEED = 32;
export const MIN_PATH_VARIANTS_GUARANTEED = 128;
export const MAX_GLOBAL_RPS_SECONDS = 100_000;
export const MAX_OVERFLOW_RPS_SECONDS = 8_192;
export const DROPPED_KEY_TRACK_LIMIT = 8_192;

export function incrementCapped(map: Map<string, number>, key: string, maxKeys: number): boolean {
  const current = map.get(key);

  if (current !== undefined) {
    map.set(key, current + 1);
    return true;
  }

  if (map.size >= maxKeys) {
    return false;
  }

  map.set(key, 1);
  return true;
}

export function addCappedSet(set: Set<string>, value: string, maxSize: number): boolean {
  if (set.has(value)) {
    return true;
  }

  if (set.size >= maxSize) {
    return false;
  }

  set.add(value);
  return true;
}

/** Records a distinct omitted key. Returns true only the first time it is seen. */
export function rememberDroppedKey(
  set: Set<string>,
  key: string,
  limit = DROPPED_KEY_TRACK_LIMIT
): boolean {
  if (set.has(key) || set.size >= limit) {
    return false;
  }

  set.add(key);
  return true;
}

/**
 * Evicts the least-seen entries and reports the count the freed slot was worth.
 * Long-tailed key distributions are dominated by singletons, so a sweep
 * normally reclaims most of the map and stays amortized cheap.
 */
function evictLowestCounts<K>(map: Map<K, number>): number {
  let lowest = Number.POSITIVE_INFINITY;

  for (const count of map.values()) {
    if (count < lowest) {
      lowest = count;
    }
  }

  if (!Number.isFinite(lowest)) {
    return 0;
  }

  for (const [key, count] of map) {
    if (count === lowest) {
      map.delete(key);
    }
  }

  return lowest;
}

/**
 * Space-saving admission for a top-N counter. A key already present is counted
 * exactly. A new key arriving once the map is full evicts the current
 * least-seen entries and is admitted just above that floor, so a key that
 * starts appearing late can still climb into the top-N.
 *
 * Counts for late-admitted keys are therefore upper bounds rather than exact.
 * That is the right trade for a top-N report: an approximate count for the
 * busiest path is far more useful than omitting it entirely.
 *
 * @returns `true` when the insert forced an eviction.
 */
export function admitHeavyHitter(map: Map<string, number>, key: string, maxKeys: number): boolean {
  const current = map.get(key);

  if (current !== undefined) {
    map.set(key, current + 1);
    return false;
  }

  if (map.size < maxKeys) {
    map.set(key, 1);
    return false;
  }

  const floor = evictLowestCounts(map);
  map.set(key, floor + 1);
  return true;
}
