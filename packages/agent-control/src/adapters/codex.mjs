/**
 * OpenAI Codex CLI Adapter for CIRVIX AgentControl.
 *
 * Supports:
 * - ~/.codex/config.json, codex.json, .codex/mcp.json
 * - Executable detection (codex / codex.cmd)
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { BaseAgentAdapter } from "./base.mjs";
import { resolveExecutable } from "../core/windows.mjs";

export class CodexAdapter extends BaseAgentAdapter {
  constructor() {
    super({
      id: "codex",
      label: "OpenAI Codex CLI",
      type: "cli",
      mcpKey: "mcpServers",
    });
  }

  async detect(cwd) {
    const home = homedir();
    const candidatePaths = [
      join(cwd, "codex.json"),
      join(cwd, ".codex", "config.json"),
      join(cwd, ".codex", "mcp.json"),
      join(home, ".codex", "config.json"),
      join(home, ".codex", "mcp.json"),
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
          const map = data.mcpServers ?? data.mcp_servers ?? data.servers ?? {};
          Object.assign(servers, map);
        }
      }
    }

    const execPath = resolveExecutable("codex", { cwd });
    const detected = existingPaths.length > 0 || Boolean(execPath);

    const isIntegrated = Object.entries(servers).some(([name, def]) => this.isCirvixServer(name, def));

    return {
      detected,
      paths: existingPaths,
      targetConfigPath: existingPaths[0] ?? join(home, ".codex", "config.json"),
      config: configFound,
      servers,
      serverCount: Object.keys(servers).length,
      isIntegrated,
      hasConfig: existingPaths.length > 0,
      executable: execPath,
      metadata: {},
    };
  }

  async generateIntegrationPlan(cwd, options = {}) {
    const info = await this.detect(cwd);
    const targetFile = info.targetConfigPath;
    const currentServers = { ...info.servers };

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
      reason: "Places CIRVIX policy enforcement between Codex CLI and local execution tools.",
    };
  }
}
