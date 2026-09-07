/**
 * Shadow Mode CLI Command.
 *
 * Runs policy evaluation in shadow mode (observe & log hypothetical counterfactuals).
 */

import { ShadowEngine } from "../core/shadow.mjs";
import { evaluate } from "../core/policy.mjs";
import { bold, dim, green, red, amber, cyan } from "../core/format.mjs";

export async function executeShadowCommand({
  rules = [],
  action = null,
  resource = null,
  json = false,
  cwd = process.cwd(),
} = {}) {
  const engine = new ShadowEngine();

  // Test sample candidate actions in shadow mode
  const candidates = [
    { action: "fs:read", resource: "src/index.ts", tool: "file_reader" },
    { action: "fs:read", resource: ".env.production", tool: "file_reader" },
    { action: "net:fetch", resource: "https://api.stripe.com/v1/charges", tool: "curl" },
    { action: "net:fetch", resource: "http://169.254.169.254/latest/meta-data/", tool: "curl" },
    { action: "exec:run", resource: "rm -rf /", tool: "bash" },
  ];

  if (action) {
    candidates.length = 0;
    candidates.push({ action, resource: resource ?? "", tool: "custom" });
  }

  for (const c of candidates) {
    engine.evaluateShadow(c, (call) => evaluate(call, rules, { cwd }));
  }

  const summary = engine.getSummary();
  if (json) return { output: JSON.stringify(summary, null, 2), code: 0 };

  const lines = [
    "",
    `  ${bold("CIRVIX SHADOW MODE EVALUATION")}`,
    `  ${dim("Non-blocking policy observation — live actions proceed without disruption")}`,
    "",
    `  ${bold("Summary:")}`,
    `    ${dim("Total Observed:")}           ${summary.totalEvaluated}`,
    `    ${green("●")} ${dim("Would Allow:")}              ${summary.wouldAllow}`,
    `    ${red("●")} ${dim("Would Block:")}              ${summary.wouldBlock}`,
    `    ${amber("●")} ${dim("Would Require Approval:")}   ${summary.wouldRequireApproval}`,
    `    ${red("●")} ${dim("Would Quarantine:")}         ${summary.wouldQuarantine}`,
    "",
    `  ${bold("Observed Counterfactuals:")}`,
    ...summary.logSnippet.map((s) => {
      const tone = s.hypotheticalDecision === "ALLOW" ? green : s.hypotheticalDecision === "REQUIRE_APPROVAL" ? amber : red;
      return `    ${tone(s.hypotheticalDecision.padEnd(16))} ${dim(s.call.action)} ${s.call.resource} ${dim(`[${s.ruleMatched ?? "default"}]`)}`;
    }),
    "",
  ];

  return { output: lines.join("\n"), code: 0 };
}
