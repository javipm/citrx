import { Command, CommanderError } from "commander";
import { writeFile } from "node:fs/promises";
import type { Readable, Writable } from "node:stream";

import { analyzeAccessLogs } from "./analysis/access-log.js";
import { discoverInputFiles } from "./input/files.js";
import { isAccessLogFormatId } from "./parser/access-log.js";
import type { FormatChoice } from "./parser/access-log.js";
import { renderTerminalReport } from "./report/terminal.js";
import { APP_NAME, VERSION } from "./version.js";

export interface CliRuntime {
  stdout: Writable;
  stderr: Writable;
  stdin: Readable;
  stdinIsTTY: boolean;
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
        throw new Error(
          runtime.stdinIsTTY
            ? "No input paths provided. Interactive mode arrives in Phase 7."
            : "Reading from stdin arrives in Phase 3. Pass a file path for now."
        );
      }

      const top = parseTopOption(options.top);
      const format = parseFormatOption(options.format);
      const files = await discoverInputFiles(paths);
      const report = await analyzeAccessLogs(files, {
        top,
        format,
        formatConfig:
          typeof options.formatConfig === "string" ? options.formatConfig : undefined
      });
      const output = options.json
        ? `${JSON.stringify(report, null, 2)}\n`
        : renderTerminalReport(report);

      if (typeof options.out === "string") {
        await writeFile(options.out, output, "utf8");
        return;
      }

      runtime.stdout.write(output);
    });

  return program;
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

export async function runCli(
  argv: string[],
  runtime: Partial<CliRuntime> = {}
): Promise<number> {
  const cliRuntime: CliRuntime = {
    stdout: runtime.stdout ?? process.stdout,
    stderr: runtime.stderr ?? process.stderr,
    stdin: runtime.stdin ?? process.stdin,
    stdinIsTTY: runtime.stdinIsTTY ?? Boolean(process.stdin.isTTY)
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
