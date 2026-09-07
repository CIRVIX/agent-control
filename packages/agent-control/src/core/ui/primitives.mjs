/**
 * Primitives — Panel, Table, Badge, Logo, Status helpers.
 *
 * Zero deps, unicode with ASCII fallback, respects NO_COLOR via format.mjs.
 */

import { bold, dim, stripAnsi, supportsUnicode } from "../format.mjs";
import { boxChars, truncate, padVisible } from "./theme.mjs";

/** CIRVIX ASCII logo (5 lines). Compact, premium, not gamey. */
export const LOGO_LINES = [
  " ██████╗██╗██████╗ ██╗   ██╗██╗██╗  ██╗",
  "██╔════╝██║██╔══██╗██║   ██║██║╚██╗██╔╝",
  "██║     ██║██████╔╝██║   ██║██║ ╚███╔╝ ",
  "██║     ██║██╔══██╗╚██╗ ██╔╝██║ ██╔██╗ ",
  "╚██████╗██║██║  ██║ ╚████╔╝ ██║██╔╝ ██╗",
  " ╚═════╝╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚═╝  ╚═╝",
];

export const LOGO_SUBTITLE = "AI AGENT RUNTIME GOVERNANCE";

/**
 * Draw a rounded panel with optional title.
 *
 * @param {object} opts
 * @param {string} [opts.title]
 * @param {string[]} opts.lines — already formatted (may contain ANSI)
 * @param {number} [opts.width] — inner width, default 58
 * @param {boolean} [opts.heavy] — use heavy border for intercept
 */
export function panel({ title, lines = [], width = 58, heavy = false } = {}) {
  const ch = boxChars();
  const h = heavy ? ch.hHeavy : ch.h;
  const v = heavy ? ch.vHeavy : ch.v;

  // Compute actual inner width from content if not provided.
  let inner = width;
  if (!width) {
    inner = Math.max(...lines.map((l) => stripAnsi(l).length), title ? stripAnsi(title).length : 0) + 2;
    inner = Math.max(40, Math.min(72, inner));
  }

  const top = `╭${h.repeat(inner + 2)}╮`;
  const bottom = `╰${h.repeat(inner + 2)}╯`;
  // For ascii fallback, boxChars returns +/-, so above uses unicode literals.
  // Rebuild with actual chars for ascii.
  const useAscii = !supportsUnicode();
  const topLine = useAscii ? `${ch.tl}${ch.h.repeat(inner + 2)}${ch.tr}` : top;
  const bottomLine = useAscii ? `${ch.bl}${ch.h.repeat(inner + 2)}${ch.br}` : bottom;
  const vert = useAscii ? ch.v : v;

  const out = [];
  out.push(`  ${topLine}`);
  if (title) {
    const t = truncate(title, inner);
    out.push(`  ${vert} ${padVisible(t, inner)} ${vert}`);
    out.push(`  ${vert} ${" ".repeat(inner)} ${vert}`);
  } else {
    out.push(`  ${vert} ${" ".repeat(inner)} ${vert}`);
  }
  for (const line of lines) {
    const clean = truncate(stripAnsi(line), inner);
    // Preserve ANSI: pad based on visible length.
    const padded = padVisible(line, inner);
    // Ensure we truncate ANSI correctly — if original had ANSI, we need to re-truncate safely.
    // Simpler: use padded which already uses visibleWidth.
    out.push(`  ${vert} ${padded} ${vert}`);
  }
  out.push(`  ${vert} ${" ".repeat(inner)} ${vert}`);
  out.push(`  ${bottomLine}`);
  return out.join("\n");
}

/**
 * Render the full brand header — logo boxed.
 */
export function brandHeader({ width = 58 } = {}) {
  const ch = boxChars();
  const useAscii = !supportsUnicode();
  const h = ch.h;
  const top = useAscii ? `${ch.tl}${h.repeat(width + 2)}${ch.tr}` : `╭${h.repeat(width + 2)}╮`;
  const bottom = useAscii ? `${ch.bl}${h.repeat(width + 2)}${ch.br}` : `╰${h.repeat(width + 2)}╯`;
  const vert = useAscii ? ch.v : ch.v;

  const lines = [];
  lines.push(`  ${top}`);
  lines.push(`  ${vert} ${" ".repeat(width)} ${vert}`);
  for (const l of LOGO_LINES) {
    const padded = l.padStart(Math.floor((width + l.length) / 2)).padEnd(width);
    lines.push(`  ${vert} ${padded} ${vert}`);
  }
  lines.push(`  ${vert} ${" ".repeat(width)} ${vert}`);
  const sub = LOGO_SUBTITLE.padStart(Math.floor((width + LOGO_SUBTITLE.length) / 2)).padEnd(width);
  lines.push(`  ${vert} ${dim(sub)} ${vert}`);
  lines.push(`  ${vert} ${" ".repeat(width)} ${vert}`);
  lines.push(`  ${bottom}`);
  return lines.join("\n");
}

/** Simple key/value rows aligned. */
export function keyValueRows(rows, { keyWidth } = {}) {
  const w = keyWidth ?? Math.max(...rows.map(([k]) => stripAnsi(String(k)).length));
  return rows.map(([k, v]) => `  ${String(k).padEnd(w + 2)}${v}`);
}

/** Separator line. */
export function separator(width = 60, char = "─") {
  const ch = supportsUnicode() ? char : "-";
  return dim("  " + ch.repeat(width));
}

/** Badge: ● ONLINE / ● ENFORCING etc. with color. */
export function badge(label, state, tone) {
  const dot = "●";
  return `${tone(`${dot} ${state}`)} ${dim(label)}`;
}

/** Truncate path for display, never show secret values. */
export function safeTarget(value, max = 44) {
  const s = String(value ?? "");
  if (s.length <= max) return s;
  return "…" + s.slice(-(max - 1));
}
