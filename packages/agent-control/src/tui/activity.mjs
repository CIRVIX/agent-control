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
import { clipText, wrapText, width as terminalWidth, previewDecision } from "./cards.mjs";

export function activitySummary(activity) {
  const counts = { allow: 0, sanitize: 0, deny: 0, require_approval: 0, audit_only: 0 };
  for (const e of activity) {
    const d = e.decision ?? e.raw?.decision ?? "allow";
    if (d in counts) counts[d]++;
  }
  return { total: activity.length, ...counts };
}

export function collapsedFeed(activity, { expanded = false, maxRows = 8, width, preview = false } = {}) {
  width = terminalWidth(width);
  const sum = activitySummary(activity);
  if (sum.total === 0) return wrapText(dim(preview ? "No previews yet. No action executed by preview." : "No activity yet. Ask Cirvix to evaluate something."), width);
  if (preview) {
    const rows = expanded
      ? activity.slice(-maxRows).map((event) => activityRow(event, { width, preview }))
      : [
        `${sum.total} evaluations`,
        `Would allow: ${sum.allow}`,
        `Would sanitize: ${sum.sanitize}`,
        `Would block: ${sum.deny}`,
        `Would require approval: ${sum.require_approval}`,
      ];
    return wrapText([
      bold("Authorization preview activity"),
      ...(expanded && sum.total > maxRows ? [dim(`${sum.total - maxRows} earlier (collapsed)`)] : []),
      ...rows,
      dim("No action executed by preview."),
    ].join("\n"), width);
  }

  const head = `${style("✓", "allow")} ${bold(summaryTitle(sum))}\n\n` +
    `  ${dim(`${sum.total} actions`)}\n` +
    `  ${dim("├─")} ${sum.allow} allowed\n` +
    `  ${dim("├─")} ${sum.sanitize} sanitized\n` +
    `  ${dim("└─")} ${sum.deny + sum.require_approval} blocked/held\n\n` +
    `  ${dim("[Enter] inspect")}`;

  if (!expanded) return wrapText(head, width);

  const rows = activity.slice(-maxRows).map((e) => activityRow(e, { width })).join("\n");
  const more = sum.total > maxRows ? dim(`  … ${sum.total - maxRows} earlier (collapsed)`) + "\n" : "";
  return wrapText(`▼ ${bold("Activity")}\n\n${more}${rows}`, width);
}

function summaryTitle(sum) {
  if (sum.deny > 0) return `Session activity — ${sum.deny} blocked`;
  if (sum.require_approval > 0) return `Session activity — ${sum.require_approval} held`;
  return `Session activity — all clear`;
}

export function activityRow(event, { width, preview = false } = {}) {
  width = terminalWidth(width);
  const d = event.decision ?? event.raw?.decision ?? "allow";
  const badge = badgeForDecision(d);
  const role = roleForDecision(d);
  const when = clock(event.ts);
  const tool = event.tool ?? event.raw?.tool ?? "—";
  const target = clipText(event.resource ?? event.raw?.resource ?? "", Math.max(0, Math.min(36, width - 2)), { tail: true });
  if (preview) return wrapText([
    style(previewDecision(d), role),
    `  ${tool}`,
    ...(target ? [dim(`  ${target}`)] : []),
  ].join("\n"), width);
  const suffix = d === "deny" ? style(" → blocked", "block")
    : d === "sanitize" ? style(" → sanitized", "sanitize")
    : d === "require_approval" ? style(" → held", "hold")
    : "";
  return wrapText(`  ${dim(when)}  ${style(`${badge.icon} ${tool}`, role)}${target ? dim(`  ${target}`) : ""}${suffix}`, width);
}

function clock(ts) {
  const m = String(ts ?? "").match(/T(\d{2}:\d{2}:\d{2})/);
  return m ? m[1] : "--:--:--";
}
