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

/** Standard semantic visual tokens. */
export const tokens = {
  ALLOW: green,
  DENY: red,
  APPROVAL_REQUIRED: amber,
  INFO: cyan,
  WARNING: amber,
  CRITICAL: red,
  MUTED: dim,
  HEADER: bold,
  BORDER: gray,
  ACCENT: cyan,
};

/** Unicode glyphs with ASCII fallbacks. */
export function glyphs() {
  if (supportsUnicode()) {
    return {
      check: "✓",
      cross: "✕",
      pause: "⏸",
      info: "ℹ",
      warning: "⚠",
      bullet: "●",
      diamond: "◆",
      arrow: "›",
      circle: "○",
      recycle: "↻",
      shield: "🛡",
      treeBranch: "├─",
      treeLast: "└─",
      treePipe: "│ ",
    };
  }
  return {
    check: "[OK]",
    cross: "[X]",
    pause: "[HOLD]",
    info: "[i]",
    warning: "[!]",
    bullet: "*",
    diamond: "*",
    arrow: ">",
    circle: "o",
    recycle: "[SAN]",
    shield: "[P]",
    treeBranch: "|-",
    treeLast: "`-",
    treePipe: "| ",
  };
}

/**
 * Format a decision badge with matching icon and semantic tone.
 */
export function formatDecisionBadge(decision, { human = false } = {}) {
  const g = glyphs();
  const d = String(decision ?? "").toLowerCase();
  if (d === "permit" || d === "allow") {
    return `${green(g.check)} ${green(bold("ALLOW"))}`;
  }
  if (d === "hold" || d === "require_approval") {
    return `${amber(g.pause)} ${amber(bold("APPROVAL REQUIRED"))}`;
  }
  if (d === "sanitize") {
    const label = human ? "CONTENT SANITIZED" : "SANITIZE";
    return `${blue(g.recycle ?? g.info)} ${blue(bold(label))}`;
  }
  const label = human ? "BLOCKED (DENY)" : "DENY";
  return `${red(g.cross)} ${red(bold(label))}`;
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
  const plain = stripAnsi(s);
  if (plain.length <= n) return s;
  return plain.slice(0, Math.max(1, n - 1)) + "…";
}

export function padVisible(str, width) {
  const s = String(str ?? "");
  const vis = stripAnsi(s).length;
  if (vis > width) return truncate(s, width);
  if (vis === width) return s;
  return s + " ".repeat(width - vis);
}

/** Word-wrap text into lines not exceeding maxWidth, preserving words. */
export function wordWrap(text, maxWidth) {
  const words = String(text ?? "").split(/\s+/).filter(Boolean);
  if (words.length === 0) return [];
  const lines = [];
  let current = words[0];
  for (let i = 1; i < words.length; i++) {
    const w = words[i];
    if (stripAnsi(current).length + 1 + stripAnsi(w).length <= maxWidth) {
      current += " " + w;
    } else {
      lines.push(current);
      current = w;
    }
  }
  if (current) lines.push(current);
  return lines;
}

/**
 * Render a content card container with rounded borders, title, and optional footer.
 */
export function renderCard({
  title = null,
  headerRight = null,
  lines = [],
  footer = null,
  width = 62,
  borderColor = gray,
} = {}) {
  const ch = boxChars();
  const W = Math.max(40, width);
  const inner = W - 4;

  const out = [];

  // Top border with title
  if (title) {
    const tVis = stripAnsi(title).length;
    const rVis = headerRight ? stripAnsi(headerRight).length : 0;
    if (headerRight && W >= tVis + rVis + 10) {
      const fill = W - 2 - (tVis + 3) - (rVis + 2);
      out.push(`  ${borderColor(ch.tl + ch.h)} ${title} ${borderColor(ch.h.repeat(Math.max(1, fill)))} ${headerRight} ${borderColor(ch.tr)}`);
    } else {
      const fill = W - 2 - (tVis + 3);
      out.push(`  ${borderColor(ch.tl + ch.h)} ${title} ${borderColor(ch.h.repeat(Math.max(1, fill)) + ch.tr)}`);
    }
  } else {
    out.push(`  ${borderColor(ch.tl + ch.h.repeat(W - 2) + ch.tr)}`);
  }

  out.push(`  ${borderColor(ch.v)} ${" ".repeat(inner)} ${borderColor(ch.v)}`);

  for (const rawLine of lines) {
    const lineStr = String(rawLine ?? "");
    const vis = stripAnsi(lineStr).length;
    if (vis <= inner) {
      out.push(`  ${borderColor(ch.v)} ${padVisible(lineStr, inner)} ${borderColor(ch.v)}`);
    } else {
      // Long lines wrapped safely
      const wrapped = wordWrap(lineStr, inner);
      for (const wl of wrapped) {
        out.push(`  ${borderColor(ch.v)} ${padVisible(wl, inner)} ${borderColor(ch.v)}`);
      }
    }
  }

  out.push(`  ${borderColor(ch.v)} ${" ".repeat(inner)} ${borderColor(ch.v)}`);

  if (footer) {
    out.push(`  ${borderColor(ch.lt + ch.h.repeat(W - 2) + ch.rt)}`);
    out.push(`  ${borderColor(ch.v)} ${padVisible(footer, inner)} ${borderColor(ch.v)}`);
  }

  out.push(`  ${borderColor(ch.bl + ch.h.repeat(W - 2) + ch.br)}`);
  return out.join("\n");
}
