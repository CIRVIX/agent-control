/**
 * Persistent status bar — always on screen, always honest.
 *
 * Wide terminal: full breakdown (mode, policy, counts, latency, audit).
 * Narrow terminal (<72 cols): compact one-liner. The bar adapts; it never
 * wraps into two unreadable lines.
 */

import { style, bold, dim } from "../core/theme.mjs";
import { latencyStats } from "../core/events.mjs";
import { clipText, wrapText, width as terminalWidth } from "./cards.mjs";

export function statusBar(state, { version = "", width = process.stdout.columns ?? 80, preview = false } = {}) {
  width = terminalWidth(width);
  const s = state.status;
  if (preview) {
    return dim("─".repeat(Math.max(0, width - 1))) + "\n" + wrapText([
      bold("AUTHORIZATION PREVIEW") + (version ? dim(`  v${version}`) : ""),
      `${s.requests} evaluations · Policy: ${s.policyName ?? "strict"}`,
      `Would allow: ${s.allowed} · Would sanitize: ${s.sanitized}`,
      `Would block: ${s.blocked} · Would require approval: ${s.held}`,
      dim("No action executed by preview."),
      dim("No audit records written. Latency not measured."),
    ].join("\n"), width);
  }
  const lat = latencyStats(s.latencies);
  const mode = s.mode === "audit"
    ? `${style("○", "warning")} ${style("AUDIT", "warning")}`
    : `${style("●", "allow")} ${bold("PROTECTED")}`;

  if (width < 72) {
    // Compact: [● PROTECTED] 148 req  21 blocked  P95 18ms
    return dim("─".repeat(Math.max(0, width - 1))) + "\n" +
      clipText(`${mode}  ${s.requests} req  ${blockedPart(s)}  ${dim(`P95 ${lat.p95}ms`)}`, width);
  }

  const line1 = dim("─".repeat(Math.max(0, width - 1)));
  const cells = [
    `${mode}   ${dim("│")}  ${dim("Policy:")} ${s.policyName ?? "strict"}   ${dim("│")}  ${dim("Requests:")} ${s.requests}`,
    `${dim("Allow:")} ${style(String(s.allowed), "allow")}   ${dim("│")}  ${dim("Sanitized:")} ${s.sanitized}   ${dim("│")}  ${dim("Blocked:")} ${blockedCount(s)}`,
    `${dim(`P50 ${lat.p50}ms`)}   ${dim("│")}  ${dim(`P95 ${lat.p95}ms`)}   ${dim("│")}  ${dim("Audit")} ${style("✓", "allow")}${version ? dim(`  │  v${version}`) : ""}`,
  ];
  return line1 + "\n" + wrapText(cells.join("\n"), width);
}

function blockedCount(s) {
  const n = `${s.blocked + s.held}`;
  return s.blocked + s.held > 0 ? style(n, "block") : n;
}

function blockedPart(s) {
  const n = s.blocked + s.held;
  return n > 0 ? style(`${n} blocked`, "block") : dim("0 blocked");
}
