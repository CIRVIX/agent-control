/**
 * Intent-Aware Agent Firewall.
 *
 * Implements: CAPABILITY + AUTHORITY + INTENT + CONTEXT = AUTHORIZED ACTION
 *
 * Rather than evaluating tools in isolation (`tool == allowed`), an agent's
 * declared mission/purpose governs what it may reach for.
 *
 * Example:
 *   Mission: "Fix checkout test failures"
 *   Allowed: read source, run tests, modify checkout files
 *   Suspicious: read production credentials, drop database, upload code to external IP
 */

import { RISK } from "./risk.mjs";

/** Semantic categories of intent. */
export const INTENT_CATEGORIES = {
  TESTING: "testing",
  DEVELOPMENT: "development",
  MAINTENANCE: "maintenance",
  REPORTING: "reporting",
  DATABASE_ADMIN: "database_admin",
  DEPLOYMENT: "deployment",
  GENERAL: "general",
};

/** High-risk actions that require explicit intent alignment. */
const RESTRICTED_ACTIONS = {
  "secret:read": ["credential_management", "auth_setup"],
  "db:drop": ["database_admin", "migration_rollback"],
  "db:write": ["database_admin", "data_migration", "development"],
  "shell:destructive": ["system_admin"],
  "net:external_egress": ["data_sync", "api_integration", "deployment"],
  "iam:modify": ["cloud_admin", "iam_setup"],
};

/**
 * Classifies a declared intent string into dominant categories and allowed scopes.
 */
export function classifyIntent(intentText) {
  if (!intentText || typeof intentText !== "string") {
    return {
      category: INTENT_CATEGORIES.GENERAL,
      keywords: [],
      sensitivityFloor: RISK.LOW,
      allowedActions: ["*"],
    };
  }

  const text = intentText.toLowerCase();
  const keywords = text.match(/\b\w{3,}\b/g) ?? [];

  if (/\b(test|spec|assert|coverage|jest|mocha|pytest|unit)\b/.test(text)) {
    return {
      category: INTENT_CATEGORIES.TESTING,
      keywords,
      sensitivityFloor: RISK.LOW,
      disallowedActions: ["secret:read", "db:drop", "net:external_egress", "iam:modify"],
      allowedActions: ["fs:read", "fs:write", "exec:test", "exec:dev"],
    };
  }

  if (/\b(fix|bug|refactor|feature|implement|code|frontend|backend)\b/.test(text)) {
    return {
      category: INTENT_CATEGORIES.DEVELOPMENT,
      keywords,
      sensitivityFloor: RISK.LOW,
      disallowedActions: ["secret:read", "db:drop", "iam:modify"],
      allowedActions: ["fs:read", "fs:write", "exec:dev", "net:fetch"],
    };
  }

  if (/\b(deploy|release|ship|staging|production|publish)\b/.test(text)) {
    return {
      category: INTENT_CATEGORIES.DEPLOYMENT,
      keywords,
      sensitivityFloor: RISK.HIGH,
      disallowedActions: ["db:drop"],
      allowedActions: ["fs:read", "net:external_egress", "exec:deploy"],
    };
  }

  if (/\b(migrate|schema|table|sql|database|query|seed)\b/.test(text)) {
    return {
      category: INTENT_CATEGORIES.DATABASE_ADMIN,
      keywords,
      sensitivityFloor: RISK.HIGH,
      disallowedActions: ["iam:modify"],
      allowedActions: ["db:read", "db:write", "fs:read"],
    };
  }

  return {
    category: INTENT_CATEGORIES.GENERAL,
    keywords,
    sensitivityFloor: RISK.LOW,
    disallowedActions: ["db:drop", "iam:modify"],
    allowedActions: ["*"],
  };
}

/**
 * Evaluates whether a requested action aligns with the agent's declared intent.
 *
 * @param {Object} params
 * @param {string} params.intent - Declared mission or task description
 * @param {string} params.action - Canonical action identifier (e.g. "fs:read", "secret:read")
 * @param {string} params.resource - Resource target (e.g. "/etc/passwd", "src/auth.ts")
 * @param {string} params.tool - Tool name invoked
 * @param {Object} params.context - Execution context
 * @returns {{ aligned: boolean, intentScore: number, reason: string, category: string }}
 */
export function evaluateIntent({ intent, action, resource = "", tool = "", context = {} }) {
  const classification = classifyIntent(intent);

  // If action is explicitly restricted, verify if intent permits it
  const restrictedFor = RESTRICTED_ACTIONS[action];
  if (restrictedFor && !restrictedFor.includes(classification.category)) {
    return {
      aligned: false,
      intentScore: 0.1,
      reason: `Action '${action}' is restricted and outside declared mission '${intent}' (${classification.category})`,
      category: classification.category,
    };
  }

  // Check disallowed actions for this intent category
  if (classification.disallowedActions?.includes(action)) {
    return {
      aligned: false,
      intentScore: 0.2,
      reason: `Action '${action}' conflicts with declared mission scope (${classification.category})`,
      category: classification.category,
    };
  }

  // Resource sensitivity check against intent
  const isCredentialTarget = /(credential|\.env|id_rsa|secret|token|api[_-]?key|password)/i.test(resource);
  if (isCredentialTarget && classification.category === INTENT_CATEGORIES.TESTING) {
    return {
      aligned: false,
      intentScore: 0.15,
      reason: `Agent attempted to access credentials ('${resource}') while declared mission is testing only`,
      category: classification.category,
    };
  }

  // Production database deletion check
  const isDropTarget = /(drop\s+table|delete\s+from|truncate|rm\s+-rf\s+\/)/i.test(resource);
  if (isDropTarget && classification.category !== INTENT_CATEGORIES.DATABASE_ADMIN) {
    return {
      aligned: false,
      intentScore: 0.05,
      reason: `Destructive action against '${resource}' requires explicit administrative mission`,
      category: classification.category,
    };
  }

  return {
    aligned: true,
    intentScore: 0.95,
    reason: `Action '${action}' against '${resource || tool}' aligns with mission '${classification.category}'`,
    category: classification.category,
  };
}
