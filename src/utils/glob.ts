/**
 * Portable glob matching for --include / --exclude.
 * Supports *, ? and double-star across directories. No brace expansion, no extglob.
 * Patterns without a slash also match the basename (gitignore-style).
 */

export function matchesGlob(filePath: string, pattern: string): boolean {
  const glob = pattern.replaceAll("\\", "/");
  const regex = globToRegExp(glob);
  const posix = filePath.replaceAll("\\", "/");
  const parts = posix.split("/");

  if (regex.test(posix) || regex.test(parts.at(-1) ?? posix)) {
    return true;
  }

  for (let index = 0; index < parts.length; index += 1) {
    if (regex.test(parts.slice(index).join("/"))) {
      return true;
    }
  }

  return false;
}

export function globToRegExp(glob: string): RegExp {
  let source = "";

  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index];

    if (char === "*" && glob[index + 1] === "*") {
      if (glob[index + 2] === "/") {
        source += "(?:.*/)?";
        index += 2;
      } else {
        source += ".*";
        index += 1;
      }
      continue;
    }

    if (char === "*") {
      source += "[^/]*";
      continue;
    }

    if (char === "?") {
      source += "[^/]";
      continue;
    }

    source += escapeRegex(char ?? "");
  }

  const flags = process.platform === "win32" ? "i" : "";
  return new RegExp("^" + source + "$", flags);
}

function escapeRegex(value: string): string {
  return value.replace(/[|\\{}()[\]^$+*?.]/g, "\\$&");
}
