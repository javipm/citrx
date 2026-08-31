import { Command, CommanderError } from "commander";
import { writeFile } from "node:fs/promises";
import type { Readable, Writable } from "node:stream";
import { setImmediate } from "node:timers/promises";

import { analyzeAccessLogSources } from "./analysis/access-log.js";
import type { AnalyzeInputSource } from "./analysis/types.js";
import { printBanner } from "./cli/banner.js";
import { createProgressReporter } from "./cli/progress.js";
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

/**
 * Callback that opens the interactive TUI for a completed analysis run.
 * Receives a fully-populated {@link CitrxRun} and resolves when the UI exits.
 */
export type InteractiveLauncher = (run: CitrxRun) => Promise<void>;

/**
 * I/O dependencies and environment context injected into the CLI.
 * Decouples the program from `process.*` globals, enabling testability
 * and custom embedding scenarios.
 */
export interface CliRuntime {
  /** Destination for normal program output. */
  stdout: Writable;
  /** Destination for progress messages, banners, and error text. */
  stderr: Writable;
  /** Source used when `-` is passed as an input path. */
  stdin: Readable;
  /** Whether stdin is a TTY; controls automatic stdin-as-source fallback. */
  stdinIsTTY: boolean;
  /** Process environment variables (e.g. `NO_COLOR`, `CITRX_QUIET`). */
  env: NodeJS.ProcessEnv;
  /**
   * Optional override for launching the interactive TUI.
   * When omitted, the default `openRunTui` implementation is used.
   */
  openInteractive?: InteractiveLauncher;
  /**
   * Success-path exit code set by the root action (`0` or `2`).
   * Commander usage/version events still throw {@link CommanderError}.
   */
  exitCode?: number;
}

/**
 * Builds and returns a configured Commander.js {@link Command} instance.
 *
 * Registers all CLI options and flags, wires output streams to `runtime`,
 * and attaches the root action that delegates to `runRootAnalysis`.
 * The program uses `exitOverride()` so Commander errors are thrown rather
 * than calling `process.exit`.
 *
 * @param runtime - I/O context and environment to bind to the program.
 * @returns Configured Commander program ready for `parseAsync`.
 */
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
      "Access-log format: auto, apache_common, apache_combined, nginx_combined (same combined regex as apache_combined), or custom:<name>.",
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
    runtime.exitCode = await runRootAnalysis(command.args, options, runtime);
  });

  return program;
}

async function runRootAnalysis(
  initialPaths: string[],
  options: Record<string, unknown>,
  runtime: CliRuntime
): Promise<number> {
  let paths = initialPaths;
  const top = parseTopOption(options.top);
  const outputFormat = parseOutputFormat(options);
  const color = isColorEnabled(options, runtime);
  const showUi = shouldShowStartupUi(outputFormat, runtime);
  const progress = createProgressReporter({
    stream: runtime.stderr,
    enabled: showUi,
    color,
    isTty: showUi && isStderrTty(runtime)
  });

  if (showUi) {
    printBanner(runtime.stderr, { color });
  }

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
  const sources = await progress.withStep("Discovering inputs", () =>
    buildInputSources(paths, runtime, options)
  );
  const workspace = await createRunWorkspace();
  const accessLogWriter = await createAccessLogIndexWriter(workspace.directory);

  try {
    const report = await progress.withStep("Reading and analyzing access logs", () =>
      analyzeAccessLogSources(sources, {
        top,
        format,
        formatConfig: typeof options.formatConfig === "string" ? options.formatConfig : undefined,
        since: parseDateOption(options.since, "--since"),
        until: parseDateOption(options.until, "--until"),
        accessLogWriter,
        onProgress: ({ phase, totalLines, parsedLines }) => {
          const counts = `${formatCount(totalLines)} lines read, ${formatCount(
            parsedLines
          )} parsed`;
          progress.update(
            phase === "finalizing"
              ? `Finalizing analysis (${counts})`
              : `Reading and analyzing access logs (${counts})`
          );
        }
      })
    );

    if (report.skippedInputs.length > 0 && runtime.env.CITRX_QUIET !== "1") {
      for (const skipped of report.skippedInputs) {
        runtime.stderr.write(
          `${APP_NAME}: skipped non-access-log input ${skipped.file} (${skipped.reason})\n`
        );
      }
    }

    const run: CitrxRun = {
      id: workspace.id,
      createdAt: report.generatedAt,
      sourcePaths: report.inputs,
      tempDir: workspace.directory,
      report,
      accessIndex: accessLogWriter.index
    };

    if (shouldOpenTui(options, outputFormat, runtime)) {
      await progress.withStep("Preparing interactive view", async () => {
        accessLogWriter.close();
        await setImmediate();
      });
      await openInteractiveRun(run, runtime);
      return exitCodeForReport(report);
    }

    if (typeof options.out === "string") {
      const output = await progress.withStep(`Writing report to ${options.out}`, async () =>
        renderReport(report, outputFormat, options, runtime)
      );
      await writeFile(options.out, output, "utf8");
      return exitCodeForReport(report);
    }

    const output = renderReport(report, outputFormat, options, runtime);
    runtime.stdout.write(output);
    return exitCodeForReport(report);
  } finally {
    accessLogWriter.close();
    await removeRunWorkspace(workspace.directory);
  }
}

function shouldShowStartupUi(format: OutputFormat, runtime: CliRuntime): boolean {
  if (format === "json" || format === "markdown" || format === "html") {
    return false;
  }

  if (runtime.env.CITRX_QUIET === "1") {
    return false;
  }

  return isStderrTty(runtime);
}

function isStderrTty(runtime: CliRuntime): boolean {
  const stderr = runtime.stderr as Writable & { isTTY?: boolean };
  return Boolean(stderr.isTTY);
}

function isColorEnabled(options: Record<string, unknown>, runtime: CliRuntime): boolean {
  return options.color !== false && runtime.env.NO_COLOR === undefined;
}

function exitCodeForReport(report: { incidents: Array<{ severity: string }> }): number {
  return report.incidents.some(
    (incident) => incident.severity === "high" || incident.severity === "critical"
  )
    ? 2
    : 0;
}

async function buildInputSources(
  paths: string[],
  runtime: CliRuntime,
  options: Record<string, unknown>
): Promise<AnalyzeInputSource[]> {
  const filePaths = paths.filter((inputPath) => inputPath !== "-");
  const sources: AnalyzeInputSource[] = [];
  const include = typeof options.include === "string" ? options.include : undefined;
  const exclude = typeof options.exclude === "string" ? options.exclude : undefined;

  const usingStdin = paths.includes("-") && !runtime.stdinIsTTY;

  if (filePaths.length > 0) {
    const discovered = await discoverInputFiles(filePaths, { include, exclude });
    if (discovered.length === 0 && !usingStdin) {
      throw new Error(emptyDiscoveryError(filePaths, include, exclude));
    }

    sources.push(
      ...discovered.map((filePath) => ({
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

function emptyDiscoveryError(
  filePaths: string[],
  include: string | undefined,
  exclude: string | undefined
): string {
  if (include?.trim() || exclude?.trim()) {
    return "No input files matched --include/--exclude.";
  }

  if (filePaths.length === 1) {
    return `No input files found in ${filePaths[0]}.`;
  }

  return "No input files found.";
}

function parseFormatOption(value: unknown): FormatChoice {
  const format = String(value ?? "auto");

  if (format === "auto" || isAccessLogFormatId(format)) {
    return format;
  }

  throw new Error(
    "--format must be auto, apache_common, apache_combined, nginx_combined (alias of the same combined regex), or custom:<name>."
  );
}

/**
 * Parses the `--top <n>` option value into a positive integer.
 *
 * @param value - Raw option value from Commander (string or undefined).
 * @returns Parsed positive integer to use as the top-N list limit.
 * @throws {Error} If the value is not a valid positive integer.
 */
function parseTopOption(value: unknown): number {
  const parsed = Number.parseInt(String(value ?? "20"), 10);

  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error("--top must be a positive integer.");
  }

  return parsed;
}

/**
 * Parses a `--since` or `--until` option value into a `Date`.
 *
 * @param value - Raw option value from Commander (string or undefined).
 * @param flag - Flag name used in the error message (e.g. `"--since"`).
 * @returns Parsed `Date`, or `undefined` when the option was not provided.
 * @throws {Error} If the value is present but cannot be parsed as a valid date.
 */
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

function formatCount(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
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

async function openInteractiveRun(run: CitrxRun, runtime: CliRuntime): Promise<void> {
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

/**
 * Main async entry point for the CLI.
 *
 * Creates a fully-resolved {@link CliRuntime} (falling back to `process.*`
 * globals for any omitted fields), builds the Commander program, and runs it
 * against `argv`. Commander and analysis errors are caught and written to
 * stderr rather than propagating.
 *
 * @param argv - Argument vector, typically `process.argv`.
 * @param runtime - Optional partial runtime overrides; unset fields default to
 *   their `process.*` equivalents.
 * @returns Exit code: `0` on success without high/critical incidents, `1` on
 *   unhandled error, `2` when high/critical incidents were found, or the
 *   Commander-supplied exit code on a usage/version event.
 */
export async function runCli(argv: string[], runtime: Partial<CliRuntime> = {}): Promise<number> {
  const debug = argv.includes("--debug");
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
    return cliRuntime.exitCode ?? 0;
  } catch (error) {
    if (error instanceof CommanderError) {
      return error.exitCode;
    }

    const message = error instanceof Error ? error.message : String(error);
    cliRuntime.stderr.write(`${APP_NAME}: ${message}\n`);
    if (debug && error instanceof Error && error.stack) {
      cliRuntime.stderr.write(`${error.stack}\n`);
    }
    return 1;
  }
}
