/**
 * Primitives — Panel, Table, Badge, Logo, Status helpers.
 *
 * Zero deps, unicode with ASCII fallback, respects NO_COLOR via format.mjs.
 */

import { bold, dim, stripAnsi, supportsUnicode } from "../format.mjs";
import { gradient } from "../theme.mjs";
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
/**
 * The wordmark rows, centred and padded to the panel's inner width.
 *
 * Exported because the launch sequence animates the *same* geometry: if the
 * animation recomputed its own centring, the frame it lands on would drift from
 * the static header the rest of the CLI prints, and the brand would look like
 * two different brands depending on whether motion was enabled.
 */
export function logoRows(width = 58) {
  return LOGO_LINES.map((l) => l.padStart(Math.floor((width + l.length) / 2)).padEnd(width));
}

/** The subtitle row, centred the same way. */
export function subtitleRow(width = 58) {
  return LOGO_SUBTITLE.padStart(Math.floor((width + LOGO_SUBTITLE.length) / 2)).padEnd(width);
}

/**
 * The brand plate: the wordmark boxed.
 *
 * `accent` paints the wordmark with the brand ramp. It defaults to off so every
 * existing caller (`init`, `protect`, the interactive screen) keeps printing
 * exactly what it printed before; the launch sequence turns it on, because that
 * is the screen where the brand is the point.
 */
export function brandHeader({ width = 58, accent = false } = {}) {
  const ch = boxChars();
  const useAscii = !supportsUnicode();
  const h = ch.h;
  const top = useAscii ? `${ch.tl}${h.repeat(width + 2)}${ch.tr}` : `╭${h.repeat(width + 2)}╮`;
  const bottom = useAscii ? `${ch.bl}${h.repeat(width + 2)}${ch.br}` : `╰${h.repeat(width + 2)}╯`;
  const vert = useAscii ? ch.v : ch.v;

  const lines = [];
  lines.push(`  ${top}`);
  lines.push(`  ${vert} ${" ".repeat(width)} ${vert}`);
  for (const padded of logoRows(width)) {
    lines.push(`  ${vert} ${accent ? gradient(padded) : padded} ${vert}`);
  }
  lines.push(`  ${vert} ${" ".repeat(width)} ${vert}`);
  lines.push(`  ${vert} ${dim(subtitleRow(width))} ${vert}`);
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
