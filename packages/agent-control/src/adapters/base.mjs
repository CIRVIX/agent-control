/**
 * Base Agent Adapter interface and definitions for CIRVIX AgentControl.
 *
 * Provides the unified foundation for runtime/editor/framework-agnostic
 * governance. Each adapter implements detection, configuration lifecycle,
 * and request/response normalization for a specific agent environment.
 */

import { access, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseConfigJson } from "../core/config-store.mjs";
import { normalizeFsPath, arePathsEqual } from "../core/windows.mjs";

/**
 * Strict Compatibility Levels.
 * Never claim "supported" or "enforced" without empirical verification.
 */
export const COMPATIBILITY_LEVEL = {
  /** Config file or executable exists on disk. */
  DISCOVERED: "DISCOVERED",
  /** Valid configuration found; CIRVIX adapter can generate an integration plan. */
  CONFIGURABLE: "CONFIGURABLE",
  /** Configuration routes agent tool traffic to CIRVIX. */
  INTEGRATED: "INTEGRATED",
  /** Gateway or runtime has received protocol handshake/initialize from this agent. */
  ROUTED: "ROUTED",
  /** Policy engine has evaluated at least one tool call from this agent. */
  ENFORCED: "ENFORCED",
  /** Full end-to-end tool invocation passed through CIRVIX with verified audit entry. */
  VERIFIED: "VERIFIED",
};

export class BaseAgentAdapter {
  /**
   * @param {object} spec
   * @param {string} spec.id - Unique ID, e.g. "claude-code", "cursor", "codex"
   * @param {string} spec.label - Human readable name, e.g. "Claude Code"
   * @param {string} spec.type - "cli" | "editor" | "extension" | "framework" | "generic"
   * @param {string} [spec.mcpKey="mcpServers"] - Property holding MCP server definitions
   */
  constructor({ id, label, type, mcpKey = "mcpServers" }) {
    this.id = id;
    this.label = label;
    this.type = type;
    this.mcpKey = mcpKey;
  }

  /**
   * Discovers presence of this runtime on the host and in the workspace.
   *
   * @param {string} cwd
   * @returns {Promise<{ detected: boolean, paths: string[], config: object|null, executable: string|null, version: string|null, metadata: object }>}
   */
  async detect(cwd) {
    throw new Error(`detect() not implemented on ${this.id}`);
  }

  /**
   * Determines the strict compatibility level of this agent.
   *
   * @param {object} detectedInfo
   * @param {string} [stateDir]
   * @returns {Promise<string>} One of COMPATIBILITY_LEVEL values
   */
  async getCompatibilityLevel(detectedInfo, stateDir) {
    if (!detectedInfo || !detectedInfo.detected) {
      return null;
    }

    const { isIntegrated, hasConfig, hasAuditLogs, hasVerifiedCall } = detectedInfo;

    if (hasVerifiedCall) return COMPATIBILITY_LEVEL.VERIFIED;
    if (hasAuditLogs) return COMPATIBILITY_LEVEL.ENFORCED;
    if (detectedInfo.isRouted) return COMPATIBILITY_LEVEL.ROUTED;
    if (isIntegrated) return COMPATIBILITY_LEVEL.INTEGRATED;
    if (hasConfig) return COMPATIBILITY_LEVEL.CONFIGURABLE;
    return COMPATIBILITY_LEVEL.DISCOVERED;
  }

  /**
   * Helper to check if a file path exists and is readable.
   */
  async fileExists(filePath) {
    try {
      await access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Reads and parses a JSON/JSONC configuration file.
   */
  async readJson(filePath) {
    try {
      const raw = await readFile(filePath, "utf8");
      return parseConfigJson(raw);
    } catch {
      return null;
    }
  }

  /**
   * Checks if an MCP server definition belongs to CIRVIX.
   */
  isCirvixServer(name, def) {
    if (name === "cirvix") return true;
    if (typeof def?.command === "string" && def.command.includes("cirvix")) return true;
    if (Array.isArray(def?.args) && def.args.some((a) => typeof a === "string" && a.includes("cirvix"))) return true;
    return false;
  }

  /**
   * Generates a non-destructive integration plan.
   *
   * @param {string} cwd
   * @param {object} options
   * @returns {Promise<{ adapterId: string, label: string, targetFile: string, canIntegrate: boolean, currentServers: Record<string, any>, plan: object, reason: string }>}
   */
  async generateIntegrationPlan(cwd, options = {}) {
    throw new Error(`generateIntegrationPlan() not implemented on ${this.id}`);
  }

  /**
   * Normalizes a tool call into the universal CIRVIX format.
   */
  normalizeRequest(rawRequest, ctx = {}) {
    const rawArgs = rawRequest.args ?? rawRequest.arguments ?? rawRequest.tool_input ?? rawRequest.toolInput ?? {};
    return {
      agent: this.id,
      runtime: this.label,
      ...rawRequest,
      args: rawArgs,
      arguments: rawArgs,
    };
  }

  /**
   * Formats a CIRVIX decision into the response expected by this runtime.
   */
  formatResponse(decision, rawResult) {
    return {
      decision: decision.decision,
      verdict: decision.verdict,
      reason: decision.reason,
      rawResult,
    };
  }
}
