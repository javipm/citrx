import { Command, CommanderError } from "commander";
import { writeFile } from "node:fs/promises";
import type { Readable, Writable } from "node:stream";

import { analyzeAccessLogSources } from "./analysis/access-log.js";
import type { AnalyzeInputSource } from "./analysis/types.js";
import { discoverInputFiles } from "./input/files.js";
import { isAccessLogFormatId } from "./parser/access-log.js";
import type { FormatChoice } from "./parser/access-log.js";
import { renderTerminalReport } from "./report/terminal.js";
import {
  deleteSession,
  listSessions,
  readSession,
  saveSession
} from "./session/store.js";
import { APP_NAME, VERSION } from "./version.js";

export interface CliRuntime {
  stdout: Writable;
  stderr: Writable;
  stdin: Readable;
  stdinIsTTY: boolean;
  env: NodeJS.ProcessEnv;
}

export function createProgram(runtime: CliRuntime): Command {
  const program = new Command();

  program
    .name(APP_NAME)
    .description("Local-first Apache/Nginx access log analysis CLI.")
    .version(VERSION, "-v, --version", "Display the current version.")
    .configureOutput({
      writeOut: (message) => runtime.stdout.write(message),
      writeErr: (message) => runtime.stderr.write(message)
    })
    .exitOverride();

  program
    .command("analyze")
    .description("Analyze access logs from files, folders, or stdin.")
    .argument("[paths...]", "Log files, folders, or '-' for stdin.")
    .option("--geo", "Enrich suspicious IPs with GeoIP/ASN data.")
    .option("--ai", "Offer OpenAI deep analysis after local analysis.")
    .option("--json", "Write machine-readable JSON output.")
    .option("--markdown", "Write Markdown output.")
    .option("--html", "Write a self-contained HTML report.")
    .option("--out <path>", "Write report output to a file.")
    .option("--no-session", "Do not persist this analysis session.")
    .option(
      "--format <format>",
      "Access-log format: auto, apache_common, apache_combined, nginx_combined, or custom:<name>.",
      "auto"
    )
    .option("--format-config <path>", "JSON file with custom access-log formats.")
    .option("--top <n>", "Limit top lists.", "20")
    .option("--since <date>", "Include entries at or after this date.")
    .option("--until <date>", "Include entries at or before this date.")
    .option("--include <glob>", "Include paths matching this glob.")
    .option("--exclude <glob>", "Exclude paths matching this glob.")
    .option("--no-color", "Disable colored terminal output.")
    .option("--debug", "Print debug details on failure.")
    .action(async (paths: string[], options: Record<string, unknown>) => {
      if (paths.length === 0) {
        if (runtime.stdinIsTTY) {
          throw new Error("No input paths provided. Interactive mode arrives in Phase 7.");
        }

        paths = ["-"];
      }

      const top = parseTopOption(options.top);
      const format = parseFormatOption(options.format);
      const sources = await buildInputSources(paths, runtime);
      let report = await analyzeAccessLogSources(sources, {
        top,
        format,
        formatConfig:
          typeof options.formatConfig === "string" ? options.formatConfig : undefined,
        since: parseDateOption(options.since, "--since"),
        until: parseDateOption(options.until, "--until")
      });
      const sessionDir = runtime.env.CITRX_SESSION_DIR;

      if (options.session !== false) {
        const session = await saveSession(report, report.inputs, sessionDir);
        report = session.report;
      }

      const output = options.json
        ? `${JSON.stringify(report, null, 2)}\n`
        : renderTerminalReport(report);

      if (typeof options.out === "string") {
        await writeFile(options.out, output, "utf8");
        return;
      }

      runtime.stdout.write(output);
    });

  const session = program
    .command("session")
    .description("Manage saved citrx analysis sessions.");

  session
    .command("list")
    .description("List saved sessions.")
    .option("--json", "Write machine-readable JSON output.")
    .action(async (options: Record<string, unknown>) => {
      const sessions = await listSessions(runtime.env.CITRX_SESSION_DIR);

      if (options.json) {
        runtime.stdout.write(`${JSON.stringify({ sessions }, null, 2)}\n`);
        return;
      }

      if (sessions.length === 0) {
        runtime.stdout.write("No sessions found.\n");
        return;
      }

      for (const item of sessions) {
        runtime.stdout.write(
          `${item.id}  ${item.createdAt}  files=${item.files} parsed=${item.parsedLines} formats=${item.formats.join(",")}\n`
        );
      }
    });

  session
    .command("show")
    .description("Show a saved session report.")
    .argument("<id>", "Session id.")
    .option("--json", "Write machine-readable JSON output.")
    .action(async (id: string, options: Record<string, unknown>) => {
      const saved = await readSession(id, runtime.env.CITRX_SESSION_DIR);

      if (options.json) {
        runtime.stdout.write(`${JSON.stringify(saved, null, 2)}\n`);
        return;
      }

      runtime.stdout.write(renderTerminalReport(saved.report));
    });

  session
    .command("export")
    .description("Export a saved session report.")
    .argument("<id>", "Session id.")
    .option("--json", "Write machine-readable JSON output.")
    .option("--out <path>", "Write export output to a file.")
    .action(async (id: string, options: Record<string, unknown>) => {
      const saved = await readSession(id, runtime.env.CITRX_SESSION_DIR);
      const output = options.json
        ? `${JSON.stringify(saved.report, null, 2)}\n`
        : renderTerminalReport(saved.report);

      if (typeof options.out === "string") {
        await writeFile(options.out, output, "utf8");
        return;
      }

      runtime.stdout.write(output);
    });

  session
    .command("delete")
    .description("Delete a saved session.")
    .argument("<id>", "Session id.")
    .action(async (id: string) => {
      await deleteSession(id, runtime.env.CITRX_SESSION_DIR);
      runtime.stdout.write(`Deleted session ${id}\n`);
    });

  return program;
}

async function buildInputSources(
  paths: string[],
  runtime: CliRuntime
): Promise<AnalyzeInputSource[]> {
  const filePaths = paths.filter((inputPath) => inputPath !== "-");
  const sources: AnalyzeInputSource[] = [];

  if (filePaths.length > 0) {
    sources.push(
      ...(await discoverInputFiles(filePaths)).map((filePath) => ({
        kind: "file" as const,
        path: filePath
      }))
    );
  }

  if (paths.includes("-")) {
    if (runtime.stdinIsTTY) {
      throw new Error("Stdin was requested with '-', but no piped input was detected.");
    }

    sources.push({
      kind: "stream",
      label: "-",
      stream: runtime.stdin
    });
  }

  return sources;
}

function parseFormatOption(value: unknown): FormatChoice {
  const format = String(value ?? "auto");

  if (format === "auto" || isAccessLogFormatId(format)) {
    return format;
  }

  throw new Error(
    "--format must be auto, apache_common, apache_combined, nginx_combined, or custom:<name>."
  );
}

function parseTopOption(value: unknown): number {
  const parsed = Number.parseInt(String(value ?? "20"), 10);

  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error("--top must be a positive integer.");
  }

  return parsed;
}

function parseDateOption(value: unknown, flag: string): Date | undefined {
  if (value === undefined) {
    return undefined;
  }

  const date = new Date(String(value));

  if (Number.isNaN(date.getTime())) {
    throw new Error(`${flag} must be a valid date.`);
  }

  return date;
}

export async function runCli(
  argv: string[],
  runtime: Partial<CliRuntime> = {}
): Promise<number> {
  const cliRuntime: CliRuntime = {
    stdout: runtime.stdout ?? process.stdout,
    stderr: runtime.stderr ?? process.stderr,
    stdin: runtime.stdin ?? process.stdin,
    stdinIsTTY: runtime.stdinIsTTY ?? Boolean(process.stdin.isTTY),
    env: runtime.env ?? process.env
  };

  try {
    await createProgram(cliRuntime).parseAsync(argv);
    return 0;
  } catch (error) {
    if (error instanceof CommanderError) {
      return error.exitCode;
    }

    const message = error instanceof Error ? error.message : String(error);
    cliRuntime.stderr.write(`${APP_NAME}: ${message}\n`);
    return 1;
  }
}
