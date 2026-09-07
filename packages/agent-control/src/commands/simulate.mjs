/**
 * Policy Simulator CLI Command.
 *
 * Input: agent, user, intent, tool, resource, action, context
 * Output: decision, matched policies, risk, explanation
 */

import { evaluate } from "../core/policy.mjs";
import { classify } from "../core/risk.mjs";
import { evaluateIntent } from "../core/intent.mjs";
import { DECISION, toDecision } from "../core/decisions.mjs";
import { bold, dim, green, red, amber, cyan } from "../core/format.mjs";

export async function simulatePolicy({
  rules = [],
  action = "fs:read",
  resource = "",
  tool = "file_reader",
  intent = null,
  agent = "agent-simulator",
  json = false,
  cwd = process.cwd(),
} = {}) {
  const call = {
    agent,
    action,
    resource,
    tool,
    arguments: { resource, action },
    intent,
    cwd,
  };

  // 1. Risk
  const risk = classify(call);
  call.risk = risk.level;

  // 2. Policy Evaluation
  const evalResult = evaluate(call, rules, { cwd });
  let decision = toDecision(evalResult.verdict ?? "deny");
  let reason = evalResult.reason ?? "Matched policy evaluation";
  let matchedRule = evalResult.rule ?? "default-deny";

  // 3. Intent Check
  let intentCheck = null;
  if (intent) {
    intentCheck = evaluateIntent({ intent, action, resource, tool });
    if (!intentCheck.aligned && decision === DECISION.ALLOW) {
      decision = DECISION.DENY;
      matchedRule = "intent-firewall-boundary";
      reason = intentCheck.reason;
    }
  }

  const result = {
    decision,
    matchedRule,
    risk: risk.level,
    riskScore: risk.score ?? (risk.level === "CRITICAL" ? 90 : risk.level === "HIGH" ? 70 : 20),
    explanation: reason,
    intentAlignment: intentCheck ? intentCheck.aligned : null,
    call: { agent, action, resource, tool, intent },
  };

  if (json) {
    return { output: JSON.stringify(result, null, 2), code: decision === DECISION.ALLOW ? 0 : 1 };
  }

  const tone = decision === DECISION.ALLOW ? green : decision === DECISION.REQUIRE_APPROVAL ? amber : red;

  const lines = [
    "",
    `  ${bold("CIRVIX POLICY SIMULATOR")}`,
    "",
    `  ${bold("Input Request:")}`,
    `    ${dim("Agent:")}       ${cyan(agent)}`,
    `    ${dim("Action:")}      ${action}`,
    `    ${dim("Resource:")}    ${resource || "—"}`,
    `    ${dim("Tool:")}        ${tool || "—"}`,
    `    ${dim("Intent:")}      ${intent ? cyan(intent) : dim("(none declared)")}`,
    "",
    `  ${bold("Simulation Verdict:")}`,
    `    ${dim("Decision:")}    ${tone(bold(decision))}`,
    `    ${dim("Policy Rule:")} ${matchedRule}`,
    `    ${dim("Risk Level:")}  ${risk.level}`,
    `    ${dim("Explanation:")} ${reason}`,
  ];

  if (intentCheck) {
    lines.push(`    ${dim("Intent Check:")} ${intentCheck.aligned ? green("Aligned") : red("Misaligned")}`);
  }

  lines.push("");

  return { output: lines.join("\n"), code: decision === DECISION.ALLOW ? 0 : 1 };
}
