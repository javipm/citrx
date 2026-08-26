export const INCIDENT_BUCKET_SIZE = 200;

/**
 * Tracks in-flight bucket fetches across viewport and origin changes.
 * A settled promise may delete itself from `inFlight` only if it is still the
 * mapped promise; stale promises never write the cache after origin reset.
 */
export class BucketLoadCoordinator<T> {
  generation = 0;
  cache = new Map<number, T>();
  inFlight = new Map<number, Promise<T>>();

  resetOrigin(): void {
    this.generation += 1;
    this.cache = new Map();
    this.inFlight = new Map();
  }

  begin(bucket: number, promise: Promise<T>): boolean {
    if (this.cache.has(bucket) || this.inFlight.has(bucket)) {
      return false;
    }
    this.inFlight.set(bucket, promise);
    return true;
  }

  /** Starts work only when the bucket is neither cached nor in flight. */
  start(bucket: number, create: () => Promise<T>): Promise<T> | undefined {
    if (this.cache.has(bucket) || this.inFlight.has(bucket)) {
      return undefined;
    }

    const promise = create();
    this.inFlight.set(bucket, promise);
    return promise;
  }

  settle(
    generation: number,
    bucket: number,
    promise: Promise<T>,
    value?: T,
    error?: unknown
  ): "applied" | "stale" | "error" {
    if (this.inFlight.get(bucket) === promise) {
      this.inFlight.delete(bucket);
    }

    if (generation !== this.generation) {
      return "stale";
    }

    if (error !== undefined) {
      return "error";
    }

    if (value !== undefined) {
      this.cache.set(bucket, value);
    }
    return "applied";
  }
}
