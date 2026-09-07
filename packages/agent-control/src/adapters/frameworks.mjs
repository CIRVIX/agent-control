/**
 * Autonomous Agent Frameworks Adapter for CIRVIX AgentControl.
 *
 * Inspects declared dependencies in package.json, requirements.txt, and pyproject.toml
 * for agent frameworks:
 * - LangChain / LangGraph
 * - CrewAI
 * - OpenAI Agents SDK
 * - Vercel AI SDK
 * - Anthropic SDK
 * - AutoGen
 * - Model Context Protocol SDK
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { BaseAgentAdapter } from "./base.mjs";

const FRAMEWORK_SPECS = [
  { id: "langchain", label: "LangChain / LangGraph", deps: ["langchain", "@langchain/core", "langgraph", "langchain-core"] },
  { id: "crewai", label: "CrewAI", deps: ["crewai"] },
  { id: "autogen", label: "AutoGen / AG2", deps: ["pyautogen", "autogen-agentchat", "autogen-core"] },
  { id: "openai-agents", label: "OpenAI Agents SDK", deps: ["@openai/agents", "openai-agents"] },
  { id: "vercel-ai", label: "Vercel AI SDK", deps: ["ai", "@ai-sdk/openai", "@ai-sdk/anthropic"] },
  { id: "anthropic", label: "Anthropic SDK", deps: ["@anthropic-ai/sdk", "anthropic"] },
  { id: "mcp-sdk", label: "MCP SDK", deps: ["@modelcontextprotocol/sdk", "mcp"] },
];

export class FrameworksAdapter extends BaseAgentAdapter {
  constructor() {
    super({
      id: "frameworks",
      label: "Autonomous Agent Frameworks",
      type: "framework",
      mcpKey: "servers",
    });
  }

  async detect(cwd) {
    const hits = [];

    // Check package.json
    const pkg = await this.readJson(join(cwd, "package.json"));
    if (pkg) {
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      for (const spec of FRAMEWORK_SPECS) {
        const found = spec.deps.find((d) => d in deps);
        if (found) {
          hits.push({
            id: spec.id,
            label: spec.label,
            via: `package.json -> ${found}`,
          });
        }
      }
    }

    // Check Python files
    for (const file of ["requirements.txt", "pyproject.toml"]) {
      const path = join(cwd, file);
      if (!(await this.fileExists(path))) continue;
      let text = "";
      try {
        text = await readFile(path, "utf8");
      } catch {
        continue;
      }

      for (const spec of FRAMEWORK_SPECS) {
        if (hits.some((h) => h.id === spec.id)) continue;
        const found = spec.deps.find((d) => new RegExp(`(^|[\\s"'=])${d.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "m").test(text));
        if (found) {
          hits.push({
            id: spec.id,
            label: spec.label,
            via: `${file} -> ${found}`,
          });
        }
      }
    }

    return {
      detected: hits.length > 0,
      frameworks: hits,
      paths: [],
      targetConfigPath: null,
      config: null,
      servers: {},
      serverCount: 0,
      isIntegrated: false,
      hasConfig: false,
      executable: null,
      metadata: { hits },
    };
  }

  async generateIntegrationPlan(cwd, options = {}) {
    return {
      adapterId: this.id,
      label: this.label,
      targetFile: null,
      canIntegrate: false,
      currentServers: {},
      upstreams: {},
      plan: null,
      snippet: `import { guard } from "@cirvix/agent-control/guard";\nconst governedTools = guard.wrap(myTools, { agent: "worker" });`,
      reason: "Agent frameworks in application code are instrumented via guard.wrap(tools, { agent, rules }).",
    };
  }
}
