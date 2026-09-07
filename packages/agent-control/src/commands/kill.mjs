/**
 * Emergency Kill Switch CLI Command.
 *
 * Scopes: agent, family, org, environment, mcp, tool, credential, session, model
 */

import { globalKillSwitch, KILL_SCOPES } from "../core/kill-switch.mjs";
import { bold, dim, green, red, amber, cyan } from "../core/format.mjs";

export async function executeKillCommand({
  scope = KILL_SCOPES.AGENT,
  target = null,
  reason = "Emergency freeze invoked via CLI",
  release = null,
  list = false,
  json = false,
} = {}) {
  if (list) {
    const rules = globalKillSwitch.list();
    if (json) return { output: JSON.stringify(rules, null, 2), code: 0 };
    if (rules.length === 0) {
      return { output: `\n  ${green("✓")} ${dim("No active emergency kill switches.")}\n`, code: 0 };
    }
    const lines = [
      "",
      `  ${bold("ACTIVE EMERGENCY KILL SWITCHES")}`,
      "",
      ...rules.map((r) => `  ${red("●")} [${r.scope.toUpperCase()}] ${bold(r.target)} — ${r.reason} ${dim(`(armed at ${r.armedAt})`)}`),
      "",
    ];
    return { output: lines.join("\n"), code: 0 };
  }

  if (release) {
    const ok = globalKillSwitch.disarm(release);
    if (json) return { output: JSON.stringify({ released: release, success: ok }), code: ok ? 0 : 1 };
    return {
      output: ok ? `\n  ${green("✓")} ${dim(`Kill switch ${release} disarmed.`)}\n` : `\n  ${red("✗")} ${dim(`Kill switch ${release} not found.`)}\n`,
      code: ok ? 0 : 1,
    };
  }

  if (!target) {
    return {
      output: `\n  ${red("Error:")} Specify target to kill, e.g. cirvix kill <agent-id> --scope agent --reason "Suspicious activity"\n`,
      code: 2,
    };
  }

  const rule = globalKillSwitch.arm({
    scope,
    target,
    reason,
    triggeredBy: process.env.USER || process.env.USERNAME || "cli",
  });

  if (json) return { output: JSON.stringify(rule, null, 2), code: 0 };

  const lines = [
    "",
    `  ${red(bold("EMERGENCY KILL SWITCH ACTIVATED"))}`,
    "",
    `    ${dim("Scope:")}        ${scope.toUpperCase()}`,
    `    ${dim("Target:")}       ${bold(target)}`,
    `    ${dim("Reason:")}       ${reason}`,
    `    ${dim("Rule ID:")}      ${rule.id}`,
    `    ${dim("Status:")}       ${red(bold("FROZEN"))}`,
    "",
    `  ${dim("All subsequent actions matching this target will be immediately quarantined or denied.")}`,
    "",
  ];

  return { output: lines.join("\n"), code: 0 };
}
