/**
 * DecisionRenderer — compact for ALLOW, expanded for DENY/CRITICAL/HOLD.
 *
 * Every label includes text (ALLOW/BLOCKED etc.) so color is never the only signal.
 */

import { bold, dim, blue, stripAnsi } from "../format.mjs";
import { toneForDecision, toneForRisk } from "./theme.mjs";
import { safeTarget } from "./primitives.mjs";

export function renderCompact(event) {
  const dt = toneForDecision(event.decision);
  const rt = toneForRisk(event.risk);
  const decisionLabel = String(event.decision ?? "unknown").toUpperCase().replace(/_/g, " ").padEnd(12);
  const riskLabel = String(event.risk ?? "—").toUpperCase().padEnd(8);
  const tool = String(event.tool ?? event.action ?? "—").padEnd(20);
  const target = safeTarget(event.resource ?? event.command ?? "", 38);
  const latency = `${event.latency_ms ?? "—"}ms`;
  const policy = event.policy ?? event.rule ?? "";

  // ALLOW: quiet, one line.
  // Icon per spec: ✓ ALLOW (green), ◈ SANITIZED (blue), etc.
  const icon = event.decision === "allow" ? "✓" : event.decision === "sanitize" ? "◈" : event.decision === "deny" ? "✕" : event.decision === "require_approval" ? "⏸" : "·";
  return `  ${dt(icon)} ${dt(decisionLabel)} ${rt(riskLabel)} ${tool} ${dim(target.padEnd(38))}  ${dim(latency.padEnd(8))} ${dim(policy)}`;
}

export function renderExpanded(event) {
  const dt = toneForDecision(event.decision);
  const rt = toneForRisk(event.risk);
  const lines = [];
  const icon = event.decision === "deny" ? "✕" : event.decision === "sanitize" ? "◈" : event.decision === "require_approval" ? "⏸" : "✓";
  const label = String(event.decision ?? "unknown").toUpperCase().replace(/_/g, " ");
  lines.push(`  ${dt(`${icon} ${label}`)} ${dim(String(event.tool ?? event.action ?? ""))}`);
  if (event.resource || event.command) {
    lines.push(`    ${dim(safeTarget(event.resource ?? event.command, 60))}`);
    lines.push("");
  }
  lines.push(`    ${dim("Risk".padEnd(10))} ${rt(String(event.risk ?? "—").toUpperCase())}`);
  lines.push(`    ${dim("Policy".padEnd(10))} ${event.policy ?? event.rule ?? dim("—")}`);
  if (event.latency_ms !== undefined) lines.push(`    ${dim("Latency".padEnd(10))} ${event.latency_ms}ms`);
  if (event.reason) lines.push(`    ${dim(event.reason)}`);
  return lines.join("\n");
}

/** Choose compact vs expanded per risk/decision. */
export function renderDecision(event) {
  const critical = String(event.risk ?? "").toLowerCase() === "critical";
  const denied = event.decision === "deny";
  const held = event.decision === "require_approval";
  const high = String(event.risk ?? "").toLowerCase() === "high";
  if (denied || held || critical || high) {
    return renderExpanded(event);
  }
  return renderCompact(event);
}
