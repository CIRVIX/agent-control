/**
 * Theme — semantic palette + box characters, with NO_COLOR and ASCII fallbacks.
 *
 * Never rely on color alone; every semantic token also has a text label
 * (ALLOW/BLOCKED etc.) rendered elsewhere.
 */

import { bold, dim, green, red, amber, blue, cyan, gray, stripAnsi, supportsUnicode } from "../format.mjs";

export const palette = {
  success: green,
  critical: red,
  warning: amber,
  info: blue,
  muted: dim,
  subtle: gray,
  accent: cyan,
  strong: bold,
};

export const riskTone = {
  low: dim,
  medium: blue,
  high: amber,
  critical: red,
};

export const decisionTone = {
  allow: green,
  sanitize: blue,
  require_approval: amber,
  deny: red,
  audit_only: dim,
};

export function toneForDecision(decision) {
  return decisionTone[String(decision ?? "").toLowerCase()] ?? dim;
}

export function toneForRisk(risk) {
  return riskTone[String(risk ?? "").toLowerCase()] ?? dim;
}

/** Box characters, unicode primary, ascii fallback. */
export function boxChars() {
  if (supportsUnicode()) {
    return {
      tl: "╭",
      tr: "╮",
      bl: "╰",
      br: "╯",
      h: "─",
      v: "│",
      lt: "├",
      rt: "┤",
      mt: "┬",
      mb: "┴",
      cross: "┼",
      // heavy for intercept
      hHeavy: "━",
      vHeavy: "┃",
    };
  }
  return {
    tl: "+",
    tr: "+",
    bl: "+",
    br: "+",
    h: "-",
    v: "|",
    lt: "+",
    rt: "+",
    mt: "+",
    mb: "+",
    cross: "+",
    hHeavy: "=",
    vHeavy: "|",
  };
}

/** Safe width truncation with ANSI stripped. */
export function truncate(str, n) {
  const s = String(str ?? "");
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + "…";
}

export function padVisible(str, width) {
  const vis = stripAnsi(String(str)).length;
  if (vis >= width) return String(str);
  return String(str) + " ".repeat(width - vis);
}
