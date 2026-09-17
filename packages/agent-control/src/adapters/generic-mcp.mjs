/**
 * Generic MCP Adapter for CIRVIX AgentControl.
 *
 * Supports:
 * - Arbitrary MCP configuration files (mcp.json, .mcp.json, servers.json)
 * - Environment variables specifying MCP server definitions
 * - Local and remote MCP servers over stdio or Streamable HTTP
 */

import { join } from "node:path";
import { BaseAgentAdapter } from "./base.mjs";

export class GenericMcpAdapter extends BaseAgentAdapter {
  constructor() {
    super({
      id: "generic-mcp",
      label: "Generic MCP Client",
      type: "generic",
      mcpKey: "mcpServers",
    });
  }

  async detect(cwd) {
    const candidatePaths = [
      join(cwd, "mcp.json"),
      join(cwd, ".mcp.json"),
      join(cwd, "servers.json"),
      join(cwd, "cirvix.servers.json"),
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
          const map = data.mcpServers ?? data.servers ?? data;
          if (typeof map === "object" && !Array.isArray(map)) {
            Object.assign(servers, map);
          }
        }
      }
    }

    const detected = existingPaths.length > 0;
    const isIntegrated = Object.entries(servers).some(([name, def]) => this.isCirvixServer(name, def));

    return {
      detected,
      paths: existingPaths,
      targetConfigPath: existingPaths[0] ?? join(cwd, "mcp.json"),
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
      mcpServers: {
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
      snippet: JSON.stringify({ mcpServers: { cirvix: cirvixServerDef } }, null, 2),
      reason: "Universal gateway configuration for generic MCP clients.",
    };
  }
}
