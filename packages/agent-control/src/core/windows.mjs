/**
 * Windows first-class platform support for CIRVIX AgentControl.
 *
 * Provides cross-platform utilities designed to eliminate POSIX-only
 * assumptions without bringing in external dependencies:
 * - PATH and PATHEXT binary resolution (.exe, .cmd, .bat, etc.)
 * - Global and user-level npm/node binary location discovery
 * - Argument quoting and escaping for Windows shells
 * - Process tree termination (preventing orphaned background processes)
 * - Path canonicalization and case-folding
 */

import { execFileSync, spawn } from "node:child_process";
import { accessSync, constants, statSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, isAbsolute, join, normalize, resolve } from "node:path";

export const IS_WINDOWS = process.platform === "win32";

/**
 * Standard executable extensions on Windows.
 */
export const DEFAULT_PATHEXT = IS_WINDOWS
  ? (process.env.PATHEXT || ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC")
      .split(";")
      .map((ext) => ext.toLowerCase())
  : [""];

/**
 * Normalizes a filesystem path across platforms.
 * Replaces backslashes with forward slashes for internal consistency
 * and normalizes drive letters to uppercase.
 */
export function normalizeFsPath(inputPath) {
  if (typeof inputPath !== "string" || !inputPath) return "";
  let p = inputPath.replace(/\\/g, "/");
  // Normalize drive letter: 'c:/...' -> 'C:/...'
  if (/^[a-zA-Z]:\//.test(p)) {
    p = p.charAt(0).toUpperCase() + p.slice(1);
  }
  return p;
}

/**
 * Checks if two filesystem paths refer to the same target (case-insensitive on Windows).
 */
export function arePathsEqual(pathA, pathB) {
  const a = normalizeFsPath(resolve(pathA));
  const b = normalizeFsPath(resolve(pathB));
  return IS_WINDOWS ? a.toLowerCase() === b.toLowerCase() : a === b;
}

/**
 * Checks if a file exists and is executable.
 */
function isFileExecutable(filePath) {
  try {
    const st = statSync(filePath);
    if (!st.isFile()) return false;
    accessSync(filePath, constants.X_OK | constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Discovers common npm and global tool binary directories.
 */
export function getGlobalBinaryDirectories() {
  const dirs = [];
  const home = homedir();

  if (IS_WINDOWS) {
    if (process.env.APPDATA) {
      dirs.push(join(process.env.APPDATA, "npm"));
    }
    if (process.env.LOCALAPPDATA) {
      dirs.push(join(process.env.LOCALAPPDATA, "Programs"));
      dirs.push(join(process.env.LOCALAPPDATA, "pnpm"));
    }
    if (process.env.ProgramFiles) {
      dirs.push(join(process.env.ProgramFiles, "nodejs"));
    }
    if (process.env["ProgramFiles(x86)"]) {
      dirs.push(join(process.env["ProgramFiles(x86)"], "nodejs"));
    }
    dirs.push(join(home, "AppData", "Roaming", "npm"));
    dirs.push(join(home, ".cargo", "bin"));
  } else {
    dirs.push("/usr/local/bin");
    dirs.push("/usr/bin");
    dirs.push(join(home, ".nvm", "versions", "node", process.version, "bin"));
    dirs.push(join(home, ".local", "bin"));
    dirs.push(join(home, ".cargo", "bin"));
  }

  return dirs.filter((d) => {
    try {
      return statSync(d).isDirectory();
    } catch {
      return false;
    }
  });
}

/**
 * Resolves an executable command name to an absolute file path.
 * On Windows, handles PATHEXT extensions (.exe, .cmd, .bat) and npm globals.
 *
 * @param {string} command - e.g. "npx", "node", "cirvix", "git"
 * @param {object} [options]
 * @param {string} [options.cwd]
 * @param {string[]} [options.searchPaths]
 * @returns {string|null} Absolute path or null if not found
 */
export function resolveExecutable(command, { cwd = process.cwd(), searchPaths } = {}) {
  if (typeof command !== "string" || !command) return null;

  const raw = command.trim();
  const pathext = DEFAULT_PATHEXT;

  // If path is already absolute or explicitly relative (./ or ../)
  if (isAbsolute(raw) || raw.startsWith("./") || raw.startsWith("../") || (IS_WINDOWS && /^[a-zA-Z]:[\\/]/.test(raw))) {
    const candidate = resolve(cwd, raw);
    if (isFileExecutable(candidate)) return candidate;
    if (IS_WINDOWS) {
      for (const ext of pathext) {
        const withExt = candidate + ext;
        if (isFileExecutable(withExt)) return withExt;
      }
    }
    return null;
  }

  // Search in PATH and standard directories
  const pathEnv = (process.env.PATH || "").split(delimiter).filter(Boolean);
  const allSearchPaths = [
    cwd,
    ...(searchPaths ?? []),
    ...pathEnv,
    ...getGlobalBinaryDirectories(),
  ];

  for (const dir of allSearchPaths) {
    const candidate = join(dir, raw);
    if (isFileExecutable(candidate)) return candidate;

    if (IS_WINDOWS) {
      // Check if command already has an extension
      const hasExt = pathext.some((ext) => raw.toLowerCase().endsWith(ext));
      if (!hasExt) {
        for (const ext of pathext) {
          const withExt = candidate + ext;
          if (isFileExecutable(withExt)) return withExt;
        }
      }
    }
  }

  return null;
}

/**
 * Prepares process spawn options for Windows to ensure batch scripts (.cmd, .bat)
 * and executables with spaces run cleanly.
 *
 * @param {string} command
 * @param {string[]} args
 * @param {import("node:child_process").SpawnOptions} options
 * @returns {{ command: string, args: string[], options: import("node:child_process").SpawnOptions }}
 */
export function prepareSpawn(command, args = [], options = {}) {
  const resolved = resolveExecutable(command, { cwd: options.cwd ? String(options.cwd) : process.cwd() });
  const targetCommand = resolved || command;

  if (IS_WINDOWS) {
    const lower = targetCommand.toLowerCase();
    const isBatch = lower.endsWith(".cmd") || lower.endsWith(".bat");

    if (isBatch) {
      const comspec = process.env.ComSpec || "cmd.exe";
      return {
        command: comspec,
        args: ["/d", "/s", "/c", `"${quoteArg(targetCommand)}"`, ...args.map(quoteArg)],
        options: {
          ...options,
          windowsVerbatimArguments: true,
        },
      };
    }
  }

  return {
    command: targetCommand,
    args,
    options,
  };
}

/**
 * Escapes and quotes an argument for Windows cmd.exe / PowerShell.
 */
export function quoteArg(arg) {
  const s = String(arg ?? "");
  if (!s) return '""';
  if (!/[\s"&|<>()^%!=]/.test(s)) return s;
  return `"${s.replace(/"/g, '\\"')}"`;
}

/**
 * Terminate a process and all of its spawned child processes cleanly.
 * Uses taskkill /T /F on Windows; process group kill or fallback on POSIX.
 *
 * @param {import("node:child_process").ChildProcess|number} procOrPid
 * @param {string} [signal="SIGTERM"]
 */
export function killProcessTree(procOrPid, signal = "SIGTERM") {
  const pid = typeof procOrPid === "number" ? procOrPid : procOrPid?.pid;
  if (!pid) return;

  if (IS_WINDOWS) {
    try {
      if (typeof procOrPid === "object" && typeof procOrPid.kill === "function") {
        procOrPid.kill();
      }
      execFileSync("taskkill.exe", ["/PID", String(pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
        timeout: 2000,
      });
    } catch {
      // Process may already have terminated
    }
  } else {
    try {
      process.kill(-pid, signal);
    } catch {
      try {
        if (typeof procOrPid === "object" && typeof procOrPid.kill === "function") {
          procOrPid.kill(signal);
        } else {
          process.kill(pid, signal);
        }
      } catch {}
    }
  }
}

export const isWindows = IS_WINDOWS;

export function getPathext() {
  return [...DEFAULT_PATHEXT];
}

export function quoteCmdArg(arg) {
  return quoteArg(arg);
}

export function quotePowerShellArg(arg) {
  const s = String(arg ?? "");
  if (!s) return "''";
  if (!/[\s"&|<>()^%!=']/.test(s)) return s;
  return `'${s.replace(/'/g, "''")}'`;
}

export function getNamedPipePath(identifier) {
  const slug = String(identifier).replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(-64);
  return `\\\\.\\pipe\\cirvix-${slug || "default"}`;
}
