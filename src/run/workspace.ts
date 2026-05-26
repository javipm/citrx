import { randomUUID } from "node:crypto";
import { mkdtemp, readdir, rm, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const TEMP_PREFIX = "citrx-run-";
const STALE_TEMP_AGE_MS = 24 * 60 * 60 * 1000;

export async function createRunWorkspace(): Promise<{ id: string; directory: string }> {
  await cleanupStaleRunWorkspaces();
  const id = randomUUID();
  const directory = await mkdtemp(path.join(os.tmpdir(), `${TEMP_PREFIX}${id}-`));
  return { id, directory };
}

export async function removeRunWorkspace(directory: string): Promise<void> {
  await rm(directory, { recursive: true, force: true });
}

async function cleanupStaleRunWorkspaces(): Promise<void> {
  let entries: string[];

  try {
    entries = await readdir(os.tmpdir());
  } catch {
    return;
  }

  const now = Date.now();

  await Promise.all(
    entries
      .filter((entry) => entry.startsWith(TEMP_PREFIX))
      .map(async (entry) => {
        const directory = path.join(os.tmpdir(), entry);

        try {
          const details = await stat(directory);

          if (details.isDirectory() && now - details.mtimeMs > STALE_TEMP_AGE_MS) {
            await removeRunWorkspace(directory);
          }
        } catch {
          // Best-effort cleanup only.
        }
      })
  );
}
