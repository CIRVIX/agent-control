/**
 * Cursor Adapter for CIRVIX AgentControl.
 *
 * Supports:
 * - ~/.cursor/mcp.json and project .cursor/mcp.json
 * - .cursorrules and .cursor/rules/
 * - Executable detection (cursor / cursor.cmd)
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { BaseAgentAdapter } from "./base.mjs";
import { resolveExecutable } from "../core/windows.mjs";

export class CursorAdapter extends BaseAgentAdapter {
  constructor() {
    super({
      id: "cursor",
      label: "Cursor",
      type: "editor",
      mcpKey: "mcpServers",
    });
  }

  async detect(cwd) {
    const home = homedir();
    const candidatePaths = [
      join(cwd, ".cursor", "mcp.json"),
      join(home, ".cursor", "mcp.json"),
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

    const execPath = resolveExecutable("cursor", { cwd });
    const hasRules = (await this.fileExists(join(cwd, ".cursorrules"))) || (await this.fileExists(join(cwd, ".cursor", "rules")));
    const detected = existingPaths.length > 0 || Boolean(execPath) || hasRules;

    const isIntegrated = Object.entries(servers).some(([name, def]) => this.isCirvixServer(name, def));

    return {
      detected,
      paths: existingPaths,
      targetConfigPath: existingPaths[0] ?? join(home, ".cursor", "mcp.json"),
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
      reason: "Routes Cursor MCP tool calls through the CIRVIX runtime governance gateway.",
    };
  }
}
