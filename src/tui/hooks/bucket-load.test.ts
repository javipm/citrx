import { describe, expect, it } from "vitest";

import { BucketLoadCoordinator } from "./bucket-load.js";

describe("BucketLoadCoordinator", () => {
  it("does not let a stale promise write the cache after origin reset", async () => {
    const loader = new BucketLoadCoordinator<string[]>();
    const generation = loader.generation;
    let resolveFirst!: (value: string[]) => void;
    const first = new Promise<string[]>((resolve) => {
      resolveFirst = resolve;
    });
    expect(loader.begin(0, first)).toBe(true);

    loader.resetOrigin();
    expect(loader.generation).toBe(generation + 1);
    expect(loader.cache.size).toBe(0);
    expect(loader.inFlight.size).toBe(0);

    const second = Promise.resolve(["new"]);
    expect(loader.begin(0, second)).toBe(true);
    await second;
    expect(loader.settle(loader.generation, 0, second, ["new"])).toBe("applied");
    expect(loader.cache.get(0)).toEqual(["new"]);

    resolveFirst(["old"]);
    await first;
    expect(loader.settle(generation, 0, first, ["old"])).toBe("stale");
    expect(loader.cache.get(0)).toEqual(["new"]);
    expect(loader.inFlight.has(0)).toBe(false);
  });

  it("does not start duplicate work for a cached or in-flight bucket", async () => {
    const loader = new BucketLoadCoordinator<string[]>();
    let created = 0;
    const create = () => {
      created += 1;
      return Promise.resolve(["x"]);
    };

    const first = loader.start(0, create);
    expect(first).toBeDefined();
    expect(created).toBe(1);

    const rejecting = () => {
      created += 1;
      return Promise.reject(new Error("orphan"));
    };
    expect(loader.start(0, rejecting)).toBeUndefined();
    expect(created).toBe(1);

    await first;
    expect(loader.settle(loader.generation, 0, first!, ["x"])).toBe("applied");
    expect(loader.start(0, rejecting)).toBeUndefined();
    expect(created).toBe(1);
  });

  it("unpins only its own in-flight promise when the viewport bucket changes", async () => {
    const loader = new BucketLoadCoordinator<string[]>();
    let resolveZero!: (value: string[]) => void;
    const zero = new Promise<string[]>((resolve) => {
      resolveZero = resolve;
    });
    expect(loader.begin(0, zero)).toBe(true);

    const one = Promise.resolve(["one"]);
    expect(loader.begin(1, one)).toBe(true);
    expect(loader.settle(loader.generation, 1, one, ["one"])).toBe("applied");

    resolveZero(["zero"]);
    await zero;
    expect(loader.settle(loader.generation, 0, zero, ["zero"])).toBe("applied");
    expect(loader.inFlight.size).toBe(0);
    expect(loader.cache.get(0)).toEqual(["zero"]);
    expect(loader.cache.get(1)).toEqual(["one"]);
  });
});
