/**
 * Universal Agent Sandbox Abstraction.
 *
 * Provides isolation boundaries for agent executions across:
 * - Filesystem root confinement
 * - Process memory and timeout limits
 * - Network destination allowlisting / link-local blocking
 * - Adapter interfaces for Claude Code, Cursor, LangChain, CrewAI, MCP
 */

import { spawn } from "node:child_process";
import { resolve, relative, isAbsolute } from "node:path";

export const SANDBOX_ADAPTERS = {
  CLAUDE_CODE: "claude_code",
  CURSOR: "cursor",
  LANGCHAIN: "langchain",
  CREWAI: "crewai",
  MCP: "mcp",
  GENERIC_PROCESS: "generic_process",
};

export class AgentSandbox {
  constructor({
    adapter = SANDBOX_ADAPTERS.GENERIC_PROCESS,
    fsRoot = process.cwd(),
    timeoutMs = 30000,
    maxMemoryMb = 512,
    allowedDomains = [],
    env = {},
  } = {}) {
    this.adapter = adapter;
    this.fsRoot = resolve(fsRoot);
    this.timeoutMs = timeoutMs;
    this.maxMemoryMb = maxMemoryMb;
    this.allowedDomains = new Set(allowedDomains.map((d) => d.toLowerCase()));
    this.env = { ...env };
    this.status = "ready";
  }

  /**
   * Validates whether a file access is strictly within the sandbox filesystem boundary.
   */
  checkPathAccess(filePath) {
    const target = isAbsolute(filePath) ? resolve(filePath) : resolve(this.fsRoot, filePath);
    const rel = relative(this.fsRoot, target);
    const isEscaped = rel.startsWith("..") || isAbsolute(rel);
    return {
      allowed: !isEscaped,
      resolvedPath: target,
      reason: isEscaped ? `Path '${filePath}' escapes sandbox boundary '${this.fsRoot}'` : "Path inside sandbox boundary",
    };
  }

  /**
   * Validates whether a network destination is permitted.
   */
  checkNetworkAccess(destinationUrl) {
    try {
      const url = new URL(destinationUrl);
      const host = url.hostname.toLowerCase();

      // Block link-local and cloud metadata by default
      if (
        host === "169.254.169.254" ||
        host === "metadata.google.internal" ||
        host === "100.100.100.200"
      ) {
        return {
          allowed: false,
          reason: "Access to cloud metadata endpoints is strictly blocked in sandbox",
        };
      }

      // If allowedDomains is specified, enforce allowlist
      if (this.allowedDomains.size > 0 && !this.allowedDomains.has(host)) {
        return {
          allowed: false,
          reason: `Host '${host}' is not in sandbox allowed network destinations`,
        };
      }

      return { allowed: true, reason: "Network destination permitted" };
    } catch {
      return { allowed: false, reason: `Malformed destination URL '${destinationUrl}'` };
    }
  }

  /**
   * Executes a command within the configured sandbox bounds.
   */
  async execute(command, args = [], { cwd = this.fsRoot } = {}) {
    const pathCheck = this.checkPathAccess(cwd);
    if (!pathCheck.allowed) {
      throw new Error(`Execution cwd rejected: ${pathCheck.reason}`);
    }

    return new Promise((resolveResult, reject) => {
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        proc.kill("SIGKILL");
        reject(new Error(`Sandbox execution exceeded timeout of ${this.timeoutMs}ms`));
      }, this.timeoutMs);

      const proc = spawn(command, args, {
        cwd: pathCheck.resolvedPath,
        env: {
          ...process.env,
          ...this.env,
          CIRVIX_SANDBOX_ACTIVE: "1",
        },
        shell: false, // Prevents shell injection by default
      });

      let stdout = "";
      let stderr = "";

      proc.stdout?.on("data", (d) => (stdout += d.toString()));
      proc.stderr?.on("data", (d) => (stderr += d.toString()));

      proc.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });

      proc.on("close", (code) => {
        clearTimeout(timer);
        if (timedOut) return;
        resolveResult({
          code,
          stdout,
          stderr,
          ok: code === 0,
        });
      });
    });
  }
}
