/** Exact counts up to these caps. Further distinct keys are omitted, not estimated. */
export const MAX_AGGREGATION_KEYS = 20_000;
export const MAX_PATH_STATS = 8_000;
export const MAX_PATH_UNIQUE_IPS = 64;
export const MAX_QUERY_VARIANTS = 256;
export const MAX_GLOBAL_PATH_IP_ENTRIES = 40_000;
export const MAX_GLOBAL_PATH_VARIANT_ENTRIES = 40_000;
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
