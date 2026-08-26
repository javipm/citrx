import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { discoverInputFiles } from "./files.js";

describe("discoverInputFiles", () => {
  it("filters discovered files with include and exclude globs", async () => {
    const directory = await mkdtemp(join(tmpdir(), "citrx-files-"));

    try {
      await writeFile(join(directory, "keep.log"), "a");
      await writeFile(join(directory, "drop.log"), "b");
      await writeFile(join(directory, "notes.txt"), "c");

      const files = await discoverInputFiles([directory], {
        include: "*.log",
        exclude: "drop.log"
      });

      expect(files).toEqual([join(directory, "keep.log")]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
