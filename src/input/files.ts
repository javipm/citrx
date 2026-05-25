import { opendir, stat } from "node:fs/promises";
import path from "node:path";

export async function discoverInputFiles(paths: string[]): Promise<string[]> {
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

  return files.sort();
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
