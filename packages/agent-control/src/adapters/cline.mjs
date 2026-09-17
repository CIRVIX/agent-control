/**
 * Cline Adapter for CIRVIX AgentControl.
 *
 * Supports:
 * - VS Code globalStorage cline_mcp_settings.json across Windows, macOS, Linux
 * - Workspace .cline/mcp_settings.json
 * - .clinerules
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { BaseAgentAdapter } from "./base.mjs";

export class ClineAdapter extends BaseAgentAdapter {
  constructor() {
    super({
      id: "cline",
      label: "Cline",
      type: "extension",
      mcpKey: "mcpServers",
    });
  }

  async detect(cwd) {
    const home = homedir();
    const candidatePaths = [
      join(cwd, ".cline", "mcp_settings.json"),
      // Windows
      join(home, "AppData", "Roaming", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
      // macOS
      join(home, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
      // Linux
      join(home, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
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

    const hasRules = await this.fileExists(join(cwd, ".clinerules"));
    const detected = existingPaths.length > 0 || hasRules;

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
      reason: "Binds Cline MCP server actions to CIRVIX policy evaluation.",
    };
  }
}
