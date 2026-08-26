import { opendir, stat } from "node:fs/promises";
import path from "node:path";

import { matchesGlob } from "../utils/glob.js";

export interface DiscoverFileOptions {
  include?: string;
  exclude?: string;
}

export async function discoverInputFiles(
  paths: string[],
  options: DiscoverFileOptions = {}
): Promise<string[]> {
  const files: string[] = [];

  for (const inputPath of paths) {
    const resolvedPath = path.resolve(inputPath);
    const stats = await stat(resolvedPath);

    if (stats.isFile()) {
      files.push(resolvedPath);
      continue;
    }

    if (stats.isDirectory()) {
      for await (const filePath of walkDirectory(resolvedPath)) {
        files.push(filePath);
      }
      continue;
    }

    throw new Error(`Unsupported input path: ${inputPath}`);
  }

  files.sort();
  return filterDiscoveredFiles(files, options);
}

export function filterDiscoveredFiles(files: string[], options: DiscoverFileOptions): string[] {
  const include = options.include?.trim();
  const exclude = options.exclude?.trim();

  if (include === "" || exclude === "") {
    throw new Error("--include and --exclude glob patterns must be non-empty.");
  }

  return files.filter((file) => {
    if (include && !matchesGlob(file, include)) {
      return false;
    }

    if (exclude && matchesGlob(file, exclude)) {
      return false;
    }

    return true;
  });
}

async function* walkDirectory(directory: string): AsyncGenerator<string> {
  const dir = await opendir(directory);

  for await (const entry of dir) {
    const entryPath = path.join(directory, entry.name);

    if (entry.isDirectory()) {
      yield* walkDirectory(entryPath);
    } else if (entry.isFile()) {
      yield entryPath;
    }
  }
}
