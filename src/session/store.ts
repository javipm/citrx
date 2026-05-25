import { randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { z } from "zod";

import type { AnalyzeReport } from "../analysis/types.js";
import type { CitrxSession, SessionSummary } from "./types.js";

const sessionSchema = z.object({
  id: z.string().min(1),
  createdAt: z.string().min(1),
  updatedAt: z.string().min(1),
  sourcePaths: z.array(z.string()),
  report: z.record(z.string(), z.unknown())
});

export function resolveSessionDir(env: NodeJS.ProcessEnv = process.env): string {
  if (env.CITRX_SESSION_DIR) {
    return path.resolve(env.CITRX_SESSION_DIR);
  }

  if (env.XDG_STATE_HOME) {
    return path.join(env.XDG_STATE_HOME, "citrx", "sessions");
  }

  if (process.platform === "win32" && env.APPDATA) {
    return path.join(env.APPDATA, "citrx", "sessions");
  }

  if (process.platform === "darwin") {
    return path.join(os.homedir(), "Library", "Application Support", "citrx", "sessions");
  }

  return path.join(os.homedir(), ".local", "state", "citrx", "sessions");
}

export async function saveSession(
  report: AnalyzeReport,
  sourcePaths: string[],
  sessionDir = resolveSessionDir()
): Promise<CitrxSession> {
  await mkdir(sessionDir, { recursive: true });

  const now = new Date().toISOString();
  const id = randomUUID();
  const session: CitrxSession = {
    id,
    createdAt: now,
    updatedAt: now,
    sourcePaths,
    report: {
      ...report,
      sessionId: id
    }
  };

  await writeFile(sessionPath(sessionDir, id), `${JSON.stringify(session, null, 2)}\n`, "utf8");
  return session;
}

export async function listSessions(
  sessionDir = resolveSessionDir()
): Promise<SessionSummary[]> {
  let entries: string[];

  try {
    entries = await readdir(sessionDir);
  } catch (error) {
    if (isNotFound(error)) {
      return [];
    }

    throw error;
  }

  const sessions = await Promise.all(
    entries
      .filter((entry) => entry.endsWith(".json"))
      .map(async (entry) => readSession(entry.replace(/\.json$/, ""), sessionDir))
  );

  return sessions
    .map(toSummary)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function readSession(
  id: string,
  sessionDir = resolveSessionDir()
): Promise<CitrxSession> {
  const raw = await readFile(sessionPath(sessionDir, id), "utf8");
  const parsed = sessionSchema.parse(JSON.parse(raw));

  return parsed as unknown as CitrxSession;
}

export async function deleteSession(
  id: string,
  sessionDir = resolveSessionDir()
): Promise<void> {
  await rm(sessionPath(sessionDir, id));
}

function toSummary(session: CitrxSession): SessionSummary {
  return {
    id: session.id,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    files: session.report.summary.files,
    parsedLines: session.report.summary.parsedLines,
    invalidLines: session.report.summary.invalidLines,
    formats: [...new Set(session.report.inputFormats.map((input) => input.format))]
  };
}

function sessionPath(sessionDir: string, id: string): string {
  if (!/^[a-zA-Z0-9_-]+$/.test(id)) {
    throw new Error(`Invalid session id: ${id}`);
  }

  return path.join(sessionDir, `${id}.json`);
}

function isNotFound(error: unknown): boolean {
  return Boolean(
    error &&
      typeof error === "object" &&
      "code" in error &&
      (error as { code?: string }).code === "ENOENT"
  );
}
