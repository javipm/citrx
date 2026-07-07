import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import type { IncidentLogLine, IncidentMatchSet } from "../../analysis/types.js";
import { createAccessLogIndexWriter } from "../../run/access-index.js";
import {
  buildIncidentSubset,
  IncidentQueryCache,
  incidentQueryKey
} from "./useIncidentQuery.js";

describe("incidentQueryKey", () => {
  it("is stable for identical inputs", () => {
    expect(incidentQueryKey("sqli:1", "status:200", "timestamp", "asc")).toBe(
      incidentQueryKey("sqli:1", "status:200", "timestamp", "asc")
    );
  });

  it("differs when incidentId differs", () => {
    expect(incidentQueryKey("sqli:1", "", "timestamp", "asc")).not.toBe(
      incidentQueryKey("sqli:2", "", "timestamp", "asc")
    );
  });

  it("differs when filter differs", () => {
    expect(incidentQueryKey("sqli:1", "status:200", "timestamp", "asc")).not.toBe(
      incidentQueryKey("sqli:1", "status:500", "timestamp", "asc")
    );
  });

  it("differs when sortKey differs", () => {
    expect(incidentQueryKey("sqli:1", "", "timestamp", "asc")).not.toBe(
      incidentQueryKey("sqli:1", "", "ip", "asc")
    );
  });

  it("differs when sortDir differs", () => {
    expect(incidentQueryKey("sqli:1", "", "timestamp", "asc")).not.toBe(
      incidentQueryKey("sqli:1", "", "timestamp", "desc")
    );
  });
});

describe("IncidentQueryCache", () => {
  it("get returns undefined for an absent key", () => {
    const cache = new IncidentQueryCache();
    expect(cache.get("missing")).toBeUndefined();
  });

  it("set/get round-trips an entry", () => {
    const cache = new IncidentQueryCache();
    const entry = { promise: Promise.resolve({ orderedRowNumbers: emptyOrdered(), total: 0 }), resolved: true };
    cache.set("k1", entry);
    expect(cache.get("k1")).toBe(entry);
  });

  it("marks accessed entries as most-recently-used (MRU) for eviction order", () => {
    const cache = new IncidentQueryCache();
    // Fill to cap with resolved entries.
    for (let i = 0; i < 32; i++) {
      cache.set(`k${i}`, resolvedEntry());
    }
    // Touch k0 so it becomes MRU; the next insert should evict k1 (now oldest), not k0.
    cache.get("k0");
    cache.set("k32", resolvedEntry());

    expect(cache.get("k0")).toBeDefined();
    expect(cache.get("k1")).toBeUndefined();
  });

  it("evicts the oldest resolved entry once over the cap", () => {
    const cache = new IncidentQueryCache();
    for (let i = 0; i < 32; i++) {
      cache.set(`k${i}`, resolvedEntry());
    }

    cache.set("k32", resolvedEntry());

    // k0 was oldest and untouched -> evicted; k32 present.
    expect(cache.get("k0")).toBeUndefined();
    expect(cache.get("k32")).toBeDefined();
  });

  it("does not evict in-flight (unresolved) entries even when over cap", () => {
    const cache = new IncidentQueryCache();
    const inFlight = { promise: new Promise<never>(() => {}), resolved: false };
    cache.set("pinned", inFlight);
    for (let i = 0; i < 32; i++) {
      cache.set(`k${i}`, resolvedEntry());
    }
    // "pinned" should still be present; a resolved entry should have been evicted instead.
    expect(cache.get("pinned")).toBe(inFlight);
  });

  it("clearByIncidentId aborts controllers and purges by key prefix", () => {
    const cache = new IncidentQueryCache();
    const controllerA = new AbortController();
    const controllerB = new AbortController();
    cache.set(incidentQueryKey("inc-a", "", "timestamp", "asc"), {
      promise: Promise.resolve({ orderedRowNumbers: emptyOrdered(), total: 0 }),
      controller: controllerA,
      resolved: false
    });
    cache.set(incidentQueryKey("inc-a", "status:500", "ip", "desc"), {
      promise: Promise.resolve({ orderedRowNumbers: emptyOrdered(), total: 0 }),
      controller: controllerB,
      resolved: false
    });
    cache.set(incidentQueryKey("inc-b", "", "timestamp", "asc"), resolvedEntry());

    cache.clearByIncidentId("inc-a");

    expect(controllerA.signal.aborted).toBe(true);
    expect(controllerB.signal.aborted).toBe(true);
    expect(cache.get(incidentQueryKey("inc-a", "", "timestamp", "asc"))).toBeUndefined();
    expect(cache.get(incidentQueryKey("inc-a", "status:500", "ip", "desc"))).toBeUndefined();
    expect(cache.get(incidentQueryKey("inc-b", "", "timestamp", "asc"))).toBeDefined();
  });

  function resolvedEntry() {
    return { promise: Promise.resolve({ orderedRowNumbers: emptyOrdered(), total: 0 }), resolved: true };
  }

  function emptyOrdered() {
    return {
      length: 0,
      rowAt(i: number): number {
        throw new RangeError(`index ${i} out of range [0, 0)`);
      }
    };
  }
});

describe("buildIncidentSubset", () => {
  async function makeIndex(lines: IncidentLogLine[]) {
    const directory = await mkdtemp(join(tmpdir(), "citrx-incident-query-test-"));
    const writer = await createAccessLogIndexWriter(directory);
    for (const l of lines) writer.write(l);
    writer.close();
    return { index: writer.index, directory };
  }

  function line(row: number, overrides: Partial<IncidentLogLine> = {}): IncidentLogLine {
    return {
      row,
      source: "access.log",
      lineNumber: row + 1,
      raw: `${row}`,
      ip: `198.51.100.${row}`,
      timestamp: new Date(2026, 0, 1, 0, 0, row).toISOString(),
      method: "GET",
      path: `/path/${row}`,
      target: `/path/${row}`,
      status: 200,
      bytes: 100 + row,
      userAgent: "UA",
      ...overrides
    };
  }

  function matchSet(rowNumbers: number[]): IncidentMatchSet {
    return { incidentId: "inc-1", totalMatches: rowNumbers.length, rowNumbers, lines: [] };
  }

  it("filters rows by the filter expression", async () => {
    const ls = [
      line(0, { status: 200 }),
      line(1, { status: 500 }),
      line(2, { status: 200 }),
      line(3, { status: 500 })
    ];
    const { index, directory } = await makeIndex(ls);
    try {
      const result = await buildIncidentSubset(
        matchSet([0, 1, 2, 3]),
        index,
        "status:500",
        "timestamp",
        "asc",
        new AbortController().signal
      );

      const rows: number[] = [];
      for (let i = 0; i < result.orderedRowNumbers.length; i++) {
        rows.push(result.orderedRowNumbers.rowAt(i));
      }
      expect(rows).toEqual([1, 3]);
      expect(result.total).toBe(2);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("reverses order when sorting by timestamp desc", async () => {
    const ls = [line(0), line(1), line(2)];
    const { index, directory } = await makeIndex(ls);
    try {
      const result = await buildIncidentSubset(
        matchSet([0, 1, 2]),
        index,
        "status:200",
        "timestamp",
        "desc",
        new AbortController().signal
      );

      const rows: number[] = [];
      for (let i = 0; i < result.orderedRowNumbers.length; i++) {
        rows.push(result.orderedRowNumbers.rowAt(i));
      }
      expect(rows).toEqual([2, 1, 0]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("sorts by a non-timestamp field with row-number tie-break", async () => {
    const ls = [
      line(0, { status: 500 }),
      line(1, { status: 200 }),
      line(2, { status: 500 }),
      line(3, { status: 200 })
    ];
    const { index, directory } = await makeIndex(ls);
    try {
      const result = await buildIncidentSubset(
        matchSet([0, 1, 2, 3]),
        index,
        "",
        "status",
        "asc",
        new AbortController().signal
      );

      const rows: number[] = [];
      for (let i = 0; i < result.orderedRowNumbers.length; i++) {
        rows.push(result.orderedRowNumbers.rowAt(i));
      }
      // status 200 (rows 1,3) before 500 (rows 0,2); ties broken by row ascending.
      expect(rows).toEqual([1, 3, 0, 2]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects with an abort error when the signal is already aborted", async () => {
    const ls = [line(0), line(1)];
    const { index, directory } = await makeIndex(ls);
    try {
      const controller = new AbortController();
      controller.abort();

      await expect(
        buildIncidentSubset(matchSet([0, 1]), index, "", "status", "asc", controller.signal)
      ).rejects.toMatchObject({ name: "AbortError" });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("reports (total, total) progress on completion", async () => {
    const ls = [line(0), line(1), line(2)];
    const { index, directory } = await makeIndex(ls);
    try {
      const progress: Array<[number, number]> = [];
      await buildIncidentSubset(
        matchSet([0, 1, 2]),
        index,
        "",
        "status",
        "asc",
        new AbortController().signal,
        (done, total) => progress.push([done, total])
      );

      expect(progress[progress.length - 1]).toEqual([3, 3]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
