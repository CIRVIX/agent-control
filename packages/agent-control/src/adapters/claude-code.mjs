/**
 * Claude Code Adapter for CIRVIX AgentControl.
 *
 * Supports:
 * - ~/.claude/settings.json, ~/.claude.json, workspace .claude/settings.json
 * - PreToolUse hook bridging for non-MCP built-in tools (Bash, Read, Write, Edit, WebFetch)
 * - CLAUDE.md instruction integration
 * - Executable detection (claude / claude.cmd)
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { BaseAgentAdapter, COMPATIBILITY_LEVEL } from "./base.mjs";
import { resolveExecutable } from "../core/windows.mjs";

export class ClaudeCodeAdapter extends BaseAgentAdapter {
  constructor() {
    super({
      id: "claude-code",
      label: "Claude Code",
      type: "cli",
      mcpKey: "mcpServers",
    });
  }

  async detect(cwd) {
    const home = homedir();
    const candidatePaths = [
      join(cwd, ".claude", "settings.json"),
      join(cwd, ".claude.json"),
      join(home, ".claude", "settings.json"),
      join(home, ".claude.json"),
    ];

    const existingPaths = [];
    const servers = {};
    let configFound = null;

    for (const p of candidatePaths) {
      if (await this.fileExists(p)) {
        existingPaths.push(p);
        const data = await this.readJson(p);
        if (data) {
          if (!configFound) configFound = data;
          Object.assign(servers, data[this.mcpKey] ?? {});
        }
      }
    }

    const execPath = resolveExecutable("claude", { cwd });
    const hasInstructions = await this.fileExists(join(cwd, "CLAUDE.md"));
    const detected = existingPaths.length > 0 || Boolean(execPath) || hasInstructions;

    const isIntegrated = Object.entries(servers).some(([name, def]) => this.isCirvixServer(name, def));

    return {
      detected,
      paths: existingPaths,
      targetConfigPath: existingPaths[0] ?? join(home, ".claude", "settings.json"),
      config: configFound,
      servers,
      serverCount: Object.keys(servers).length,
      isIntegrated,
      hasConfig: existingPaths.length > 0,
      executable: execPath,
      metadata: {
        hasInstructions,
        hookSupported: true,
      },
    };
  }

  async generateIntegrationPlan(cwd, options = {}) {
    const info = await this.detect(cwd);
    const targetFile = info.targetConfigPath;
    const currentServers = { ...info.servers };

    // Upstream servers without cirvix itself
    const upstreams = {};
    for (const [k, v] of Object.entries(currentServers)) {
      if (!this.isCirvixServer(k, v)) upstreams[k] = v;
    }

    const cirvixServerDef = {
      command: "cirvix",
      args: ["gateway", "--servers", targetFile.replace(/\\/g, "/")],
    };

    const newConfig = {
      ...(info.config || {}),
      [this.mcpKey]: {
        ...currentServers,
        cirvix: cirvixServerDef,
      },
    };

    return {
      adapterId: this.id,
      label: this.label,
      targetFile,
      canIntegrate: true,
      currentServers,
      upstreams,
      plan: newConfig,
      snippet: JSON.stringify({ [this.mcpKey]: { cirvix: cirvixServerDef } }, null, 2),
      reason: "Routes Claude Code MCP tool invocations through the CIRVIX gateway.",
    };
  }

  normalizeRequest(rawRequest, ctx = {}) {
    // Built-in tools mapping if called from PreToolUse hook
    const name = rawRequest.tool_name ?? rawRequest.toolName ?? rawRequest.tool ?? "";
    const args = rawRequest.tool_input ?? rawRequest.toolInput ?? rawRequest.arguments ?? {};

    let tool = name;
    let normalizedArgs = { ...args };

    switch (name) {
      case "Bash":
        tool = "shell.exec";
        normalizedArgs = { command: args.command ?? "" };
        break;
      case "Read":
        tool = "filesystem.read";
        normalizedArgs = { path: args.file_path ?? args.path ?? "" };
        break;
      case "Write":
        tool = "filesystem.write";
        normalizedArgs = { path: args.file_path ?? args.path ?? "" };
        break;
      case "Edit":
      case "NotebookEdit":
        tool = "filesystem.write";
        normalizedArgs = { path: args.file_path ?? args.notebook_path ?? "" };
        break;
      case "Glob":
        tool = "filesystem.list";
        normalizedArgs = { path: args.path ?? args.pattern ?? "" };
        break;
      case "Grep":
        tool = "filesystem.search";
        normalizedArgs = { path: args.path ?? "" };
        break;
      case "WebFetch":
        tool = "network.request";
        normalizedArgs = { url: args.url ?? "" };
        break;
      default:
        break;
    }

    return {
      agent: this.id,
      runtime: this.label,
      tool,
      args: normalizedArgs,
      arguments: normalizedArgs,
      source: rawRequest.source ?? "claude-code",
    };
  }
}
