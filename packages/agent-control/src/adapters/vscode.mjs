/**
 * VS Code Standard MCP Adapter for CIRVIX AgentControl.
 *
 * Supports:
 * - User mcp.json across Windows, macOS, Linux
 * - Workspace .vscode/mcp.json
 * - Uses the "servers" root key per VS Code MCP specification
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { BaseAgentAdapter } from "./base.mjs";

export class VSCodeAdapter extends BaseAgentAdapter {
  constructor() {
    super({
      id: "vscode",
      label: "VS Code (MCP)",
      type: "editor",
      mcpKey: "servers",
    });
  }

  async detect(cwd) {
    const home = homedir();
    const candidatePaths = [
      join(cwd, ".vscode", "mcp.json"),
      // Windows
      join(home, "AppData", "Roaming", "Code", "User", "mcp.json"),
      // macOS
      join(home, "Library", "Application Support", "Code", "User", "mcp.json"),
      // Linux
      join(home, ".config", "Code", "User", "mcp.json"),
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
          const map = data.servers ?? data.mcpServers ?? {};
          Object.assign(servers, map);
        }
      }
    }

    const detected = existingPaths.length > 0;
    const isIntegrated = Object.entries(servers).some(([name, def]) => this.isCirvixServer(name, def));

    return {
      detected,
      paths: existingPaths,
      targetConfigPath: existingPaths[0] ?? candidatePaths[1],
      config: configFound,
      servers,
      serverCount: Object.keys(servers).length,
      isIntegrated,
      hasConfig: existingPaths.length > 0,
      executable: null,
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
      reason: "Protects VS Code MCP tool execution across all configured servers.",
    };
  }
}
