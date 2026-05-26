import { Command, CommanderError } from "commander";
import { writeFile } from "node:fs/promises";
import type { Readable, Writable } from "node:stream";

import { analyzeAccessLogSources } from "./analysis/access-log.js";
import type { AnalyzeInputSource } from "./analysis/types.js";
import { discoverInputFiles } from "./input/files.js";
import { isAccessLogFormatId } from "./parser/access-log.js";
import type { FormatChoice } from "./parser/access-log.js";
import { renderHtmlReport } from "./report/html.js";
import { renderMarkdownReport } from "./report/markdown.js";
import { renderTerminalReport } from "./report/terminal.js";
import { createAccessLogIndexWriter } from "./run/access-index.js";
import type { CitrxRun } from "./run/types.js";
import { createRunWorkspace, removeRunWorkspace } from "./run/workspace.js";
import { APP_NAME, VERSION } from "./version.js";

type OutputFormat = "terminal" | "json" | "markdown" | "html";

export type InteractiveLauncher = (run: CitrxRun) => Promise<void>;

export interface CliRuntime {
  stdout: Writable;
  stderr: Writable;
  stdin: Readable;
  stdinIsTTY: boolean;
  env: NodeJS.ProcessEnv;
  openInteractive?: InteractiveLauncher;
}

export function createProgram(runtime: CliRuntime): Command {
  const program = new Command();

  program
    .name(APP_NAME)
    .usage("[options] <paths...>")
    .description("Local-first Apache/Nginx access log analysis CLI.")
    .allowExcessArguments(true)
    .option("--json", "Write machine-readable JSON output.")
    .option("--markdown", "Write Markdown output.")
    .option("--html", "Write a self-contained HTML report.")
    .option("--out <path>", "Write report output to a file.")
    .option("--no-interactive", "Print the terminal report instead of opening the TUI.")
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
    .version(VERSION, "-v, --version", "Display the current version.")
    .configureOutput({
      writeOut: (message) => runtime.stdout.write(message),
      writeErr: (message) => runtime.stderr.write(message)
    })
    .exitOverride();

  program.action(async (options: Record<string, unknown>, command: Command) => {
    await runRootAnalysis(command.args, options, runtime);
  });

  return program;
}

async function runRootAnalysis(
  initialPaths: string[],
  options: Record<string, unknown>,
  runtime: CliRuntime
): Promise<void> {
  let paths = initialPaths;
  let top = parseTopOption(options.top);
  let outputFormat = parseOutputFormat(options);

  if (paths[0] === "analyze") {
    throw new Error("The analyze subcommand was removed. Use `citrx <paths...>` instead.");
  }

  if (paths.length === 0) {
    if (runtime.stdinIsTTY) {
      throw new Error("No input paths provided. Usage: citrx <access-log-paths...>");
    } else {
      paths = ["-"];
    }
  }

  const format = parseFormatOption(options.format);
  const sources = await buildInputSources(paths, runtime);
  const workspace = await createRunWorkspace();
  const accessLogWriter = await createAccessLogIndexWriter(workspace.directory);

  try {
    const report = await analyzeAccessLogSources(sources, {
      top,
      format,
      formatConfig:
        typeof options.formatConfig === "string" ? options.formatConfig : undefined,
      since: parseDateOption(options.since, "--since"),
      until: parseDateOption(options.until, "--until"),
      accessLogWriter
    });
    accessLogWriter.close();

    const run: CitrxRun = {
      id: workspace.id,
      createdAt: report.generatedAt,
      sourcePaths: report.inputs,
      tempDir: workspace.directory,
      report,
      accessIndex: accessLogWriter.index
    };

    if (shouldOpenTui(options, outputFormat, runtime)) {
      await openInteractiveRun(run, runtime);
      return;
    }

    const output = renderReport(report, outputFormat, options, runtime);

    if (typeof options.out === "string") {
      await writeFile(options.out, output, "utf8");
      return;
    }

    runtime.stdout.write(output);
  } finally {
    accessLogWriter.close();
    await removeRunWorkspace(workspace.directory);
  }
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

function parseOutputFormat(options: Record<string, unknown>): OutputFormat {
  const requested = [
    options.json ? "json" : null,
    options.markdown ? "markdown" : null,
    options.html ? "html" : null
  ].filter(Boolean);

  if (requested.length > 1) {
    throw new Error("Choose only one output format: --json, --markdown, or --html.");
  }

  return (requested[0] as OutputFormat | undefined) ?? "terminal";
}

function shouldOpenTui(
  options: Record<string, unknown>,
  outputFormat: OutputFormat,
  runtime: CliRuntime
): boolean {
  return (
    runtime.stdinIsTTY &&
    options.interactive !== false &&
    outputFormat === "terminal" &&
    typeof options.out !== "string"
  );
}

async function openInteractiveRun(
  run: CitrxRun,
  runtime: CliRuntime
): Promise<void> {
  if (runtime.openInteractive) {
    await runtime.openInteractive(run);
    return;
  }

  const { openRunTui } = await import("./tui/app.js");
  await openRunTui(run, {
    env: runtime.env,
    stdout: runtime.stdout,
    stderr: runtime.stderr,
    stdin: runtime.stdin
  });
}

function renderReport(
  report: Parameters<typeof renderTerminalReport>[0],
  format: OutputFormat,
  options: Record<string, unknown>,
  runtime: CliRuntime
): string {
  switch (format) {
    case "json":
      return `${JSON.stringify(report, null, 2)}\n`;
    case "markdown":
      return renderMarkdownReport(report);
    case "html":
      return renderHtmlReport(report);
    case "terminal":
      return renderTerminalReport(report, {
        color: options.color !== false && runtime.env.NO_COLOR === undefined
      });
  }
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
    env: runtime.env ?? process.env,
    openInteractive: runtime.openInteractive
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
