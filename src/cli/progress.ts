import type { Writable } from "node:stream";

import pc from "picocolors";

const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_INTERVAL_MS = 80;
const CLEAR_LINE = "\r[2K";

export interface ProgressReporterOptions {
  stream: Writable;
  enabled: boolean;
  color: boolean;
  isTty: boolean;
}

export interface ProgressReporter {
  start(label: string): void;
  update(label: string): void;
  succeed(label?: string): void;
  fail(label?: string): void;
  withStep<T>(label: string, work: () => Promise<T>): Promise<T>;
}

interface ActiveSpinner {
  label: string;
  startedAt: number;
  timer: NodeJS.Timeout;
  frame: number;
}

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
