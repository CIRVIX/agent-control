/**
 * Gemini CLI Adapter for CIRVIX AgentControl.
 *
 * Supports:
 * - ~/.gemini/settings.json, gemini.json, .gemini/mcp.json
 * - Executable detection (gemini / gemini.cmd)
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { BaseAgentAdapter } from "./base.mjs";
import { resolveExecutable } from "../core/windows.mjs";

export class GeminiCliAdapter extends BaseAgentAdapter {
  constructor() {
    super({
      id: "gemini-cli",
      label: "Gemini CLI",
      type: "cli",
      mcpKey: "mcpServers",
    });
  }

  async detect(cwd) {
    const home = homedir();
    const candidatePaths = [
      join(cwd, "gemini.json"),
      join(cwd, ".gemini", "settings.json"),
      join(cwd, ".gemini", "mcp.json"),
      join(home, ".gemini", "settings.json"),
      join(home, ".gemini", "mcp.json"),
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
          const map = data.mcpServers ?? data.servers ?? {};
          Object.assign(servers, map);
        }
      }
    }

    const execPath = resolveExecutable("gemini", { cwd });
    const detected = existingPaths.length > 0 || Boolean(execPath);

    const isIntegrated = Object.entries(servers).some(([name, def]) => this.isCirvixServer(name, def));

    return {
      detected,
      paths: existingPaths,
      targetConfigPath: existingPaths[0] ?? join(home, ".gemini", "settings.json"),
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
      reason: "Brokers Gemini CLI tool execution through CIRVIX runtime policy.",
    };
  }
}
