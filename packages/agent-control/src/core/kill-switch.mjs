/**
 * Unified Multi-Scope Emergency Kill Switch.
 *
 * Provides emergency freezing across scopes:
 * - single agent
 * - agent family
 * - organization
 * - environment
 * - MCP server
 * - credential
 * - session
 * - model
 * - tool
 */

import { DECISION } from "./decisions.mjs";

export const KILL_SCOPES = {
  AGENT: "agent",
  FAMILY: "family",
  ORG: "org",
  ENVIRONMENT: "environment",
  MCP: "mcp",
  CREDENTIAL: "credential",
  SESSION: "session",
  MODEL: "model",
  TOOL: "tool",
};

export class KillSwitchEngine {
  constructor() {
    this.activeRules = new Map(); // id -> rule
  }

  /**
   * Arms a kill switch.
   */
  arm({ scope, target, reason = "Emergency freeze activated", triggeredBy = "system" }) {
    if (typeof target !== "string" || !target.trim()) throw new TypeError("A kill switch needs a nonempty target.");
    if (!Object.values(KILL_SCOPES).includes(scope)) {
      throw new Error(`Invalid kill switch scope '${scope}'`);
    }
    const id = `ks_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const rule = {
      id,
      scope,
      target: String(target).toLowerCase(),
      reason,
      triggeredBy,
      armedAt: new Date().toISOString(),
      active: true,
    };
    Object.freeze(rule);
    this.activeRules.set(id, rule);
    return rule;
  }

  /**
   * Disarms a kill switch.
   */
  disarm(id) {
    return this.activeRules.delete(id);
  }

  /**
   * Checks whether a request matches any active kill rule.
   *
   * @param {Object} context
   * @returns {{ killed: boolean, decision: string, reason?: string, matchedRule?: Object }}
   */
  evaluate({
    agentId = null,
    family = null,
    orgId = null,
    environment = null,
    mcp = null,
    credential = null,
    session = null,
    model = null,
    tool = null,
  } = {}) {
    for (const rule of this.activeRules.values()) {
      if (!rule.active) continue;

      const target = rule.target;

      if (rule.scope === KILL_SCOPES.ORG && orgId && orgId.toLowerCase() === target) {
        return { killed: true, decision: DECISION.DENY, reason: `Organization under emergency freeze: ${rule.reason}`, matchedRule: rule };
      }
      if (rule.scope === KILL_SCOPES.AGENT && agentId && agentId.toLowerCase() === target) {
        return { killed: true, decision: DECISION.DENY, reason: `Agent '${agentId}' is frozen: ${rule.reason}`, matchedRule: rule };
      }
      if (rule.scope === KILL_SCOPES.FAMILY && family && family.toLowerCase() === target) {
        return { killed: true, decision: DECISION.DENY, reason: `Agent family '${family}' is frozen: ${rule.reason}`, matchedRule: rule };
      }
      if (rule.scope === KILL_SCOPES.ENVIRONMENT && environment && environment.toLowerCase() === target) {
        return { killed: true, decision: DECISION.DENY, reason: `Environment '${environment}' is frozen: ${rule.reason}`, matchedRule: rule };
      }
      if (rule.scope === KILL_SCOPES.MCP && mcp && mcp.toLowerCase() === target) {
        return { killed: true, decision: DECISION.DENY, reason: `MCP server '${mcp}' is disabled: ${rule.reason}`, matchedRule: rule };
      }
      if (rule.scope === KILL_SCOPES.TOOL && tool && tool.toLowerCase() === target) {
        return { killed: true, decision: DECISION.DENY, reason: `Tool '${tool}' is disabled: ${rule.reason}`, matchedRule: rule };
      }
      if (rule.scope === KILL_SCOPES.SESSION && session && session.toLowerCase() === target) {
        return { killed: true, decision: DECISION.DENY, reason: `Session '${session}' is terminated: ${rule.reason}`, matchedRule: rule };
      }
      if (rule.scope === KILL_SCOPES.MODEL && model && model.toLowerCase() === target) {
        return { killed: true, decision: DECISION.DENY, reason: `Model '${model}' is suspended: ${rule.reason}`, matchedRule: rule };
      }
      if (rule.scope === KILL_SCOPES.CREDENTIAL && credential && credential.toLowerCase() === target) {
        return { killed: true, decision: DECISION.DENY, reason: `Credential '${credential}' is revoked: ${rule.reason}`, matchedRule: rule };
      }
    }

    return { killed: false, decision: DECISION.ALLOW };
  }

  list() {
    return Array.from(this.activeRules.values());
  }
}

export const globalKillSwitch = new KillSwitchEngine();

export function enforceKillSwitch(decision, engine, context) {
  try {
    for (const tool of new Set([context.tool, context.rawTool].filter(Boolean))) {
      const result = (engine ?? globalKillSwitch).evaluate({ ...context, tool });
      if (!result || typeof result.killed !== "boolean") throw new Error("Invalid kill switch response.");
      if (result.killed) {
        return { ...decision, decision: DECISION.DENY, verdict: "deny", rule: "emergency-kill-switch", reason: result.reason, enforced: true, risk: "critical" };
      }
    }
    return decision;
  } catch {
    return { ...decision, decision: DECISION.DENY, verdict: "deny", rule: "kill-switch-unavailable", reason: "The emergency freeze state could not be verified.", enforced: true };
  }
}
