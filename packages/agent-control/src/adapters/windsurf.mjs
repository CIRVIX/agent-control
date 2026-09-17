/**
 * Windsurf Adapter for CIRVIX AgentControl.
 *
 * Supports:
 * - ~/.codeium/windsurf/mcp_config.json
 * - Workspace .windsurf/mcp_config.json, .codeium/windsurf/mcp_config.json
 * - .windsurfrules
 * - Executable detection (windsurf / windsurf.cmd)
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { BaseAgentAdapter } from "./base.mjs";
import { resolveExecutable } from "../core/windows.mjs";

export class WindsurfAdapter extends BaseAgentAdapter {
  constructor() {
    super({
      id: "windsurf",
      label: "Windsurf",
      type: "editor",
      mcpKey: "mcpServers",
    });
  }

  async detect(cwd) {
    const home = homedir();
    const candidatePaths = [
      join(cwd, ".windsurf", "mcp_config.json"),
      join(cwd, ".codeium", "windsurf", "mcp_config.json"),
      join(home, ".codeium", "windsurf", "mcp_config.json"),
      join(home, ".windsurf", "mcp_config.json"),
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

    const execPath = resolveExecutable("windsurf", { cwd });
    const hasRules = await this.fileExists(join(cwd, ".windsurfrules"));
    const detected = existingPaths.length > 0 || Boolean(execPath) || hasRules;

    const isIntegrated = Object.entries(servers).some(([name, def]) => this.isCirvixServer(name, def));

    return {
      detected,
      paths: existingPaths,
      targetConfigPath: existingPaths[0] ?? join(home, ".codeium", "windsurf", "mcp_config.json"),
      config: configFound,
      servers,
      serverCount: Object.keys(servers).length,
      isIntegrated,
      hasConfig: existingPaths.length > 0,
      executable: execPath,
      metadata: {
        hasRules,
      },
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
      reason: "Integrates CIRVIX runtime policy and secret isolation into Windsurf Cascade.",
    };
  }
}
