/**
 * Universal Agent Adapter Registry & Fleet Coordinator for CIRVIX AgentControl.
 *
 * Coordinates detection, compatibility level verification, configuration
 * generation, and request routing across all supported AI agent environments.
 */

import { join } from "node:path";
import { BaseAgentAdapter, COMPATIBILITY_LEVEL } from "./base.mjs";
import { ClaudeCodeAdapter } from "./claude-code.mjs";
import { CursorAdapter } from "./cursor.mjs";
import { WindsurfAdapter } from "./windsurf.mjs";
import { ClineAdapter } from "./cline.mjs";
import { RooCodeAdapter } from "./roo-code.mjs";
import { CodexAdapter } from "./codex.mjs";
import { GeminiCliAdapter } from "./gemini-cli.mjs";
import { VSCodeAdapter } from "./vscode.mjs";
import { GenericMcpAdapter } from "./generic-mcp.mjs";
import { FrameworksAdapter } from "./frameworks.mjs";
import { read as readJournal } from "../core/journal.mjs";

export {
  BaseAgentAdapter,
  COMPATIBILITY_LEVEL,
  ClaudeCodeAdapter,
  CursorAdapter,
  WindsurfAdapter,
  ClineAdapter,
  RooCodeAdapter,
  CodexAdapter,
  GeminiCliAdapter,
  VSCodeAdapter,
  GenericMcpAdapter,
  FrameworksAdapter,
};

/**
 * Returns instantiated adapters for all known agent environments.
 */
export function getAllAdapters() {
  return [
    new ClaudeCodeAdapter(),
    new CursorAdapter(),
    new WindsurfAdapter(),
    new ClineAdapter(),
    new RooCodeAdapter(),
    new CodexAdapter(),
    new GeminiCliAdapter(),
    new VSCodeAdapter(),
    new GenericMcpAdapter(),
    new FrameworksAdapter(),
  ];
}

/**
 * Finds the adapter that handles a specific agent/runtime ID.
 */
export function getAdapter(id) {
  const adapters = getAllAdapters();
  return adapters.find((a) => a.id === id) ?? null;
}

/**
 * Scans the machine and workspace for all agent runtimes, assessing their
 * actual, measured compatibility and enforcement level.
 *
 * @param {string} cwd
 * @param {object} [options]
 * @param {string} [options.stateDir]
 * @returns {Promise<{ runtimes: object[], frameworks: object[], mcpServers: object[], summary: object }>}
 */
export async function detectFleet(cwd = process.cwd(), { stateDir = join(cwd, ".cirvix") } = {}) {
  const adapters = getAllAdapters();
  const detectionPromises = adapters.map(async (adapter) => {
    try {
      const info = await adapter.detect(cwd);
      return { adapter, info };
    } catch {
      return { adapter, info: { detected: false } };
    }
  });

  const results = await Promise.all(detectionPromises);

  // Read audit log to check for verified executions
  let auditRecords = [];
  try {
    auditRecords = await readJournal(join(stateDir, "audit.jsonl"));
  } catch {
    auditRecords = [];
  }

  const agentsWithAudits = new Set(auditRecords.map((r) => r.agent).filter(Boolean));
  const agentsWithVerifiedPermits = new Set();

  const detectedRuntimes = [];
  let detectedFrameworks = [];
  const serverMap = new Map();

  for (const { adapter, info } of results) {
    if (!info || !info.detected) continue;

    if (adapter.id === "frameworks") {
      detectedFrameworks = info.frameworks ?? [];
      continue;
    }

    const entries = Object.entries(info.servers ?? {});
    info.isIntegrated = entries.length > 0 && entries.every(([name, def]) => adapter.isCirvixServer(name, def));
    const hasAuditLogs = agentsWithAudits.has(adapter.id);
    const hasVerifiedCall = agentsWithVerifiedPermits.has(adapter.id);

    const level = await adapter.getCompatibilityLevel(
      {
        ...info,
        hasAuditLogs,
        hasVerifiedCall,
      },
      stateDir,
    );

    detectedRuntimes.push({
      id: adapter.id,
      label: adapter.label,
      type: adapter.type,
      path: info.paths?.[0] ?? info.targetConfigPath,
      paths: info.paths ?? [],
      targetConfigPath: info.targetConfigPath,
      governed: info.isIntegrated,
      isIntegrated: info.isIntegrated,
      compatibilityLevel: level,
      serverCount: info.serverCount ?? 0,
      servers: info.servers ?? {},
      executable: info.executable ?? null,
      metadata: info.metadata ?? {},
    });

    // Aggregate MCP servers across runtimes
    for (const [name, def] of Object.entries(info.servers ?? {})) {
      if (adapter.isCirvixServer(name, def)) continue;
      const transport = def?.url ? "http" : "stdio";
      const command = def?.command ?? def?.url ?? "";
      const key = `${name}::${command}`;
      const existing = serverMap.get(key);
      if (existing) {
        if (!existing.runtimes.includes(adapter.label)) {
          existing.runtimes.push(adapter.label);
        }
      } else {
        serverMap.set(key, {
          name,
          transport,
          command,
          args: def?.args ?? [],
          runtimes: [adapter.label],
          envKeys: Object.keys(def?.env ?? {}),
          scope: inferScope(def),
        });
      }
    }
  }

  const flattenedServers = [...serverMap.values()];

  const summary = {
    totalDetected: detectedRuntimes.length,
    integrated: detectedRuntimes.filter((r) => r.isIntegrated).length,
    enforced: detectedRuntimes.filter((r) => r.compatibilityLevel === COMPATIBILITY_LEVEL.ENFORCED || r.compatibilityLevel === COMPATIBILITY_LEVEL.VERIFIED).length,
    verified: detectedRuntimes.filter((r) => r.compatibilityLevel === COMPATIBILITY_LEVEL.VERIFIED).length,
    mcpServerCount: flattenedServers.length,
  };

  return {
    runtimes: detectedRuntimes,
    frameworks: detectedFrameworks,
    mcpServers: flattenedServers,
    summary,
  };
}

function inferScope(def) {
  const args = def?.args ?? [];
  const paths = args.filter((a) => typeof a === "string" && (a.startsWith("/") || /^[A-Za-z]:[\\/]/.test(a)));
  if (paths.length === 0) return null;
  const widest = paths.find((p) => p === "/" || /^[A-Za-z]:[\\/]?$/.test(p));
  return { paths, broad: Boolean(widest), widest: widest ?? null };
}

/**
 * Generates safe integration plans across all detected un-integrated agents.
 */
export async function generateFleetPlan(cwd = process.cwd(), options = {}) {
  const { runtimes } = await detectFleet(cwd, options);
  const plans = [];

  for (const rt of runtimes) {
    const adapter = getAdapter(rt.id);
    if (!adapter) continue;
    try {
      const plan = await adapter.generateIntegrationPlan(cwd, options);
      const map = plan.plan?.[adapter.mcpKey];
      if (!map || Object.entries(map).some(([name, def]) => !adapter.isCirvixServer(name, def))) {
        plan.canIntegrate = false;
        plan.reason = "Automatic integration would retain direct upstream access. Configure a separate upstream file and a gateway-only client map manually.";
      }
      if (!Object.keys(plan.upstreams ?? {}).length) {
        plan.canIntegrate = false;
        plan.reason = "No upstream servers available to govern.";
      }
      plans.push(plan);
    } catch {}
  }

  return plans;
}
