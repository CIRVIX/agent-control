/**
 * Collapsible activity feed — the fix for the "wall of logs".
 *
 * 100 tool calls never dump as 100 lines. They collapse to:
 *
 *   ✓ Deployment completed
 *     14 actions  ├─ 8 allowed  ├─ 4 sanitized  └─ 2 blocked
 *     [Enter] inspect
 *
 * Expanding (Enter / click / `inspect`) shows the per-call rows with the
 * semantic badge (icon + color + WORD — never icon alone).
 */

import { style, bold, dim, badgeForDecision, roleForDecision } from "../core/theme.mjs";

export function activitySummary(activity) {
  const counts = { allow: 0, sanitize: 0, deny: 0, require_approval: 0, audit_only: 0 };
  for (const e of activity) {
    const d = e.decision ?? e.raw?.decision ?? "allow";
    if (d in counts) counts[d]++;
  }
  return { total: activity.length, ...counts };
}

export function collapsedFeed(activity, { expanded = false, maxRows = 8 } = {}) {
  const sum = activitySummary(activity);
  if (sum.total === 0) return dim("No activity yet. Ask Cirvix to evaluate something.");

  const head = `${style("✓", "allow")} ${bold(summaryTitle(sum))}\n\n` +
    `  ${dim(`${sum.total} actions`)}\n` +
    `  ${dim("├─")} ${sum.allow} allowed\n` +
    `  ${dim("├─")} ${sum.sanitize} sanitized\n` +
    `  ${dim("└─")} ${sum.deny + sum.require_approval} blocked/held\n\n` +
    `  ${dim("[Enter] inspect")}`;

  if (!expanded) return head;

  const rows = activity.slice(-maxRows).map((e) => activityRow(e)).join("\n");
  const more = sum.total > maxRows ? dim(`  … ${sum.total - maxRows} earlier (collapsed)`) + "\n" : "";
  return `▼ ${bold("Activity")}\n\n${more}${rows}`;
}

function summaryTitle(sum) {
  if (sum.deny > 0) return `Session activity — ${sum.deny} blocked`;
  if (sum.require_approval > 0) return `Session activity — ${sum.require_approval} held`;
  return `Session activity — all clear`;
}

export function activityRow(event) {
  const d = event.decision ?? event.raw?.decision ?? "allow";
  const badge = badgeForDecision(d);
  const role = roleForDecision(d);
  const when = clock(event.ts);
  const tool = event.tool ?? event.raw?.tool ?? "—";
  const target = truncate(event.resource ?? event.raw?.resource ?? "", 36);
  const suffix = d === "deny" ? style(" → blocked", "block")
    : d === "sanitize" ? style(" → sanitized", "sanitize")
    : d === "require_approval" ? style(" → held", "hold")
    : "";
  return `  ${dim(when)}  ${style(`${badge.icon} ${tool}`, role)}${target ? dim(`  ${target}`) : ""}${suffix}`;
}

function clock(ts) {
  const m = String(ts ?? "").match(/T(\d{2}:\d{2}:\d{2})/);
  return m ? m[1] : "--:--:--";
}

function truncate(s, n) {
  const v = String(s ?? "");
  return v.length <= n ? v : `…${v.slice(-(n - 1))}`;
}
