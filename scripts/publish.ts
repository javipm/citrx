import { readFile, writeFile } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { spawn } from "node:child_process";

type PackageJson = {
  version?: unknown;
  [key: string]: unknown;
};

const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});

async function main(): Promise<void> {
  const packageJson = JSON.parse(await readFile("package.json", "utf8")) as PackageJson;
  if (typeof packageJson.version !== "string" || !SEMVER_RE.test(packageJson.version)) {
    throw new Error("package.json must define a valid semver version.");
  }

  const currentVersion = packageJson.version;
  await assertCleanWorktree();

  const rl = createInterface({ input, output });
  try {
    const nextVersion = (await rl.question(`Next version (current ${currentVersion}): `)).trim();

    if (!SEMVER_RE.test(nextVersion)) {
      throw new Error(`Invalid semver version: ${nextVersion}`);
    }
    if (nextVersion === currentVersion) {
      throw new Error("Next version must differ from current version.");
    }
    if (!isVersionGreater(nextVersion, currentVersion)) {
      throw new Error(`Next version must be greater than current version (${currentVersion}).`);
    }

    const tag = `v${nextVersion}`;
    const confirmed = (
      await rl.question(
        `Release ${tag}, push to origin, create GitHub release, and npm publish? [y/N] `
      )
    ).trim();
    if (!["y", "yes"].includes(confirmed.toLowerCase())) {
      console.log("Release cancelled.");
      return;
    }

    await assertTagAvailable(tag);
    await assertCommandAvailable("gh", ["--version"]);
    await assertCommandAvailable("npm", ["--version"]);

    packageJson.version = nextVersion;
    await writeFile("package.json", `${JSON.stringify(packageJson, null, 2)}\n`);

    await run("pnpm", ["run", "sync-version"]);
    await run("pnpm", ["run", "typecheck"]);
    await run("pnpm", ["run", "lint"]);
    await run("pnpm", ["test"]);
    await run("pnpm", ["run", "build"]);

    await run("git", ["add", "package.json", "src/version.ts"]);
    await run("git", ["commit", "-m", `chore: release ${tag}`]);

    const branch = (await capture("git", ["branch", "--show-current"])).trim();
    if (!branch) {
      throw new Error("Cannot publish from a detached HEAD.");
    }

    await run("git", ["push", "origin", branch]);
    await run("git", ["tag", "-a", tag, "-m", tag]);
    await run("git", ["push", "origin", tag]);
    await run("gh", ["release", "create", tag, "--title", tag, "--generate-notes"]);
    await run("npm", ["publish", "--access", "public"]);

    console.log(`Published ${tag}.`);
  } finally {
    rl.close();
  }
}

async function assertCleanWorktree(): Promise<void> {
  const status = await capture("git", ["status", "--porcelain"]);
  if (status.trim()) {
    throw new Error("Working tree must be clean before publishing.");
  }
}

function isVersionGreater(nextVersion: string, currentVersion: string): boolean {
  const next = versionParts(nextVersion);
  const current = versionParts(currentVersion);

  return (
    next.major > current.major ||
    (next.major === current.major && next.minor > current.minor) ||
    (next.major === current.major && next.minor === current.minor && next.patch > current.patch)
  );
}

function versionParts(version: string): { major: number; minor: number; patch: number } {
  const [major = "0", minor = "0", patchAndSuffix = "0"] = version.split(".");
  const [patch = "0"] = patchAndSuffix.split("-");

  return {
    major: Number(major),
    minor: Number(minor),
    patch: Number(patch)
  };
}

async function assertTagAvailable(tag: string): Promise<void> {
  const localCode = await exitCode("git", ["rev-parse", "-q", "--verify", `refs/tags/${tag}`]);
  if (localCode === 0) {
    throw new Error(`Local tag already exists: ${tag}`);
  }

  const remote = await capture("git", ["ls-remote", "--tags", "origin", tag]);
  if (remote.trim()) {
    throw new Error(`Remote tag already exists: ${tag}`);
  }
}

async function assertCommandAvailable(command: string, args: string[]): Promise<void> {
  const code = await exitCode(command, args);
  if (code !== 0) {
    throw new Error(`Required command is not available: ${command}`);
  }
}

async function capture(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve(stdout);
        return;
      }
      reject(new Error(`${command} ${args.join(" ")} failed (${code ?? "signal"}): ${stderr}`));
    });
  });
}

async function exitCode(command: string, args: string[]): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: "ignore" });
    child.on("error", () => resolve(1));
    child.on("close", (code) => resolve(code ?? 1));
  });
}

async function run(command: string, args: string[]): Promise<void> {
  console.log(`$ ${command} ${args.join(" ")}`);
  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit" });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${command} ${args.join(" ")} failed with exit code ${code ?? "signal"}.`));
    });
  });
}
