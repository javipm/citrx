import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const pkg = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8")
) as {
  name: string;
  bin: Record<string, string>;
  files: string[];
  engines: { node: string };
  license: string;
  repository: unknown;
  bugs: unknown;
  homepage: string;
};

describe("package metadata", () => {
  it("matches the published package contract", () => {
    expect(pkg.name).toBe("citrx");
    expect(pkg.bin).toEqual({ citrx: "dist/cli.js" });
    expect(pkg.files).toEqual(["dist", "README.md", "README_ES.md", "LICENSE"]);
    expect(pkg.engines.node).toBe(">=22.12");
    expect(pkg.license).toBe("MIT");
    expect(pkg.repository).toEqual({
      type: "git",
      url: "git+https://github.com/javipm/citrx.git"
    });
    expect(pkg.bugs).toEqual({ url: "https://github.com/javipm/citrx/issues" });
    expect(pkg.homepage).toBe("https://github.com/javipm/citrx#readme");
  });
});
