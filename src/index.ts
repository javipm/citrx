import { Command, CommanderError } from "commander";
import pc from "picocolors";
import type { Readable, Writable } from "node:stream";

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
    .option("--top <n>", "Limit top lists.", "20")
    .option("--since <date>", "Include entries at or after this date.")
    .option("--until <date>", "Include entries at or before this date.")
    .option("--include <glob>", "Include paths matching this glob.")
    .option("--exclude <glob>", "Exclude paths matching this glob.")
    .option("--no-color", "Disable colored terminal output.")
    .option("--debug", "Print debug details on failure.")
    .action((paths: string[], options: Record<string, unknown>) => {
      const hasInput = paths.length > 0 || !runtime.stdinIsTTY;
      const summary = {
        app: APP_NAME,
        phase: 0,
        status: "scaffold-ready",
        message: hasInput
          ? "The analyze command is wired. Log parsing arrives in Phase 1."
          : "Interactive mode arrives in Phase 7.",
        paths,
        options: Object.keys(options).sort()
      };

      if (options.json) {
        runtime.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
        return;
      }

      runtime.stdout.write(`${pc.bold(APP_NAME)} ${pc.green("Phase 0 ready")}\n`);
      runtime.stdout.write(`${summary.message}\n`);
    });

  return program;
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
