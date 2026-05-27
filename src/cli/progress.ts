import type { Writable } from "node:stream";

import pc from "picocolors";

const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_INTERVAL_MS = 80;
const CLEAR_LINE = "\r[2K";

/** Options accepted by {@link createProgressReporter}. */
export interface ProgressReporterOptions {
  /** Output stream to write progress text to (e.g. `process.stderr`). */
  stream: Writable;
  /** When `false`, a no-op reporter is returned and nothing is written to `stream`. */
  enabled: boolean;
  /** When `true`, ANSI colour codes are applied to output. */
  color: boolean;
  /** When `true`, a spinning TTY reporter is used; otherwise a plain line-per-event reporter. */
  isTty: boolean;
}

/** Public API returned by {@link createProgressReporter}. */
export interface ProgressReporter {
  /** Starts a new progress indicator with the given label, replacing any active one. */
  start(label: string): void;
  /** Updates the label of the currently active progress indicator. */
  update(label: string): void;
  /**
   * Marks the current step as succeeded.
   * @param label Override label; defaults to the label passed to {@link start}.
   */
  succeed(label?: string): void;
  /**
   * Marks the current step as failed.
   * @param label Override label; defaults to the label passed to {@link start}.
   */
  fail(label?: string): void;
  /**
   * Convenience wrapper: calls {@link start}, awaits `work()`, then calls
   * {@link succeed} on resolution or {@link fail} on rejection before re-throwing.
   *
   * @param label Label shown during and after execution.
   * @param work Async function to execute.
   * @returns The resolved value of `work`.
   */
  withStep<T>(label: string, work: () => Promise<T>): Promise<T>;
}

/** Internal state for the currently running TTY spinner. */
interface ActiveSpinner {
  /** Currently displayed label text. */
  label: string;
  /** `Date.now()` timestamp when the spinner was started. */
  startedAt: number;
  /** Interval handle returned by `setInterval`. */
  timer: NodeJS.Timeout;
  /** Current frame index into {@link SPINNER_FRAMES}. */
  frame: number;
}

/**
 * Creates a {@link ProgressReporter} appropriate for the runtime environment.
 *
 * - `enabled: false` → no-op reporter (silent).
 * - `isTty: true`    → animated spinner that redraws on the same line every 80 ms.
 * - `isTty: false`   → plain reporter that emits one line per event with elapsed time.
 *
 * @param options Configuration for the reporter.
 * @returns A {@link ProgressReporter} instance.
 */
export function createProgressReporter(
  options: ProgressReporterOptions
): ProgressReporter {
  if (!options.enabled) {
    return noopReporter();
  }

  if (options.isTty) {
    return ttyReporter(options);
  }

  return plainReporter(options);
}

/** Returns a {@link ProgressReporter} whose every method is a no-op. Used when `enabled` is `false`. */
function noopReporter(): ProgressReporter {
  return {
    start() {},
    update() {},
    succeed() {},
    fail() {},
    async withStep(_label, work) {
      return work();
    }
  };
}

/**
 * Plain-text reporter for non-TTY outputs (e.g. CI logs, piped streams).
 * Writes one line per event prefixed with `…`, `✓`, or `✗`, including elapsed
 * time on completion.
 */
function plainReporter(options: ProgressReporterOptions): ProgressReporter {
  const dim = options.color ? pc.dim : (text: string) => text;
  const green = options.color ? pc.green : (text: string) => text;
  const red = options.color ? pc.red : (text: string) => text;

  let currentLabel: string | null = null;
  let currentStart = 0;

  function emit(prefix: string, color: (text: string) => string, label: string): void {
    options.stream.write(`${color(prefix)} ${label}\n`);
  }

  return {
    start(label) {
      currentLabel = label;
      currentStart = Date.now();
      emit("…", dim, label);
    },
    update(label) {
      currentLabel = label;
      emit("…", dim, label);
    },
    succeed(label) {
      const text = label ?? currentLabel ?? "done";
      const elapsed = Date.now() - currentStart;
      emit("✓", green, `${text} ${dim(`(${formatElapsed(elapsed)})`)}`);
      currentLabel = null;
    },
    fail(label) {
      const text = label ?? currentLabel ?? "failed";
      emit("✗", red, text);
      currentLabel = null;
    },
    async withStep(label, work) {
      this.start(label);
      try {
        const result = await work();
        this.succeed(label);
        return result;
      } catch (error) {
        this.fail(label);
        throw error;
      }
    }
  };
}

/**
 * Animated spinner reporter for interactive TTY sessions.
 * Uses `\r\x1b[2K` to overwrite the current line at {@link SPINNER_INTERVAL_MS} ms intervals.
 * Finalises each step with a `✓` or `✗` line including elapsed time.
 */
function ttyReporter(options: ProgressReporterOptions): ProgressReporter {
  const dim = options.color ? pc.dim : (text: string) => text;
  const yellow = options.color ? pc.yellow : (text: string) => text;
  const green = options.color ? pc.green : (text: string) => text;
  const red = options.color ? pc.red : (text: string) => text;

  let active: ActiveSpinner | null = null;

  function clearLine(): void {
    options.stream.write(CLEAR_LINE);
  }

  function drawFrame(spinner: ActiveSpinner): void {
    const frame = SPINNER_FRAMES[spinner.frame % SPINNER_FRAMES.length];
    options.stream.write(`${CLEAR_LINE}${yellow(frame ?? "•")} ${spinner.label}`);
  }

  function stop(): void {
    if (!active) {
      return;
    }

    clearInterval(active.timer);
    clearLine();
    active = null;
  }

  function startSpinner(label: string): void {
    stop();
    const spinner: ActiveSpinner = {
      label,
      startedAt: Date.now(),
      frame: 0,
      timer: setInterval(() => {
        if (!active) {
          return;
        }
        active.frame += 1;
        drawFrame(active);
      }, SPINNER_INTERVAL_MS)
    };
    active = spinner;
    drawFrame(spinner);
  }

  return {
    start(label) {
      startSpinner(label);
    },
    update(label) {
      if (!active) {
        startSpinner(label);
        return;
      }

      active.label = label;
      drawFrame(active);
    },
    succeed(label) {
      const text = label ?? active?.label ?? "done";
      const elapsed = active ? Date.now() - active.startedAt : 0;
      stop();
      options.stream.write(
        `${green("✓")} ${text} ${dim(`(${formatElapsed(elapsed)})`)}\n`
      );
    },
    fail(label) {
      const text = label ?? active?.label ?? "failed";
      stop();
      options.stream.write(`${red("✗")} ${text}\n`);
    },
    async withStep(label, work) {
      this.start(label);
      try {
        const result = await work();
        this.succeed(label);
        return result;
      } catch (error) {
        this.fail(label);
        throw error;
      }
    }
  };
}

/**
 * Formats a millisecond duration as a human-readable string.
 * - `< 1 000 ms` → `"NNNms"`
 * - `< 60 s`     → `"N.Ns"`
 * - `≥ 60 s`     → `"NmNs"`
 *
 * @param ms Duration in milliseconds.
 * @returns Formatted string, e.g. `"450ms"`, `"3.2s"`, `"1m5s"`.
 */
function formatElapsed(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  }

  const seconds = ms / 1000;

  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`;
  }

  const minutes = Math.floor(seconds / 60);
  const remaining = (seconds - minutes * 60).toFixed(0);
  return `${minutes}m${remaining}s`;
}
