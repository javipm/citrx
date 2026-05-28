import { readFile, writeFile } from "node:fs/promises";

const packageJson = JSON.parse(await readFile("package.json", "utf8")) as {
  version?: unknown;
};

if (typeof packageJson.version !== "string" || packageJson.version.length === 0) {
  throw new Error("package.json must define a non-empty version string.");
}

const source =
  `export const APP_NAME = "citrx";\n` +
  `export const VERSION = ${JSON.stringify(packageJson.version)};\n`;

await writeFile("src/version.ts", source);
console.log(`Synced src/version.ts to ${packageJson.version}.`);
