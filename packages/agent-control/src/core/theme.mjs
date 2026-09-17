/**
 * Cirvix semantic theme system.
 *
 * Every color in the product goes through here. No file outside this one
 * (and its thin re-export in `format.mjs`) may hardcode an ANSI code or call
 * a raw color helper for a product meaning.
 *
 * Why semantic, not literal:
 * - `allow` always means "this proceeded". If it is green-on-dark today and
 *   bright-green-on-light tomorrow, every call site updates at once.
 * - Themes become data: `cirvix theme light` swaps one table, not 40 files.
 * - Accessibility (high-contrast, monochrome) is a theme, not a refactor.
 * - Tests can assert meaning ("blocked renders with the block role") without
 *   asserting escape bytes.
 *
 * Zero dependencies. Works with NO_COLOR / dumb terminals / pipes by
 * producing plain text (same contract `format.mjs` always had).
 */

const ANSI = {
  reset: "\x1b[0m",
  bold: ["\x1b[1m", "\x1b[22m"],
  dim: ["\x1b[2m", "\x1b[22m"],
};

/** Role names. Adding a role = adding a key here + every theme below. */
export const ROLES = [
  "text",
  "muted",
  "accent",
  "allow",
  "sanitize",
  "block",
  "hold",
  "info",
  "warning",
  "error",
  "border",
  "surface",
  "selection",
];

/**
 * Themes are { role: [open, close] } ANSI pairs, or null for "no styling".
 * Keep the numbers standard (30-37 / 90-97) so they survive SSH, tmux,
 * Windows Terminal, and CI log renderers.
 */
const THEMES = {
  dark: {
    text: [37, 39], // white
    muted: [90, 39], // bright black (grey)
    accent: [36, 39], // cyan
    allow: [32, 39], // green
    sanitize: [36, 39], // cyan
    block: [31, 39], // red
    hold: [33, 39], // yellow
    info: [34, 39], // blue
    warning: [33, 39], // yellow
    error: [31, 39], // red
    border: [90, 39],
    surface: null,
    selection: [36, 39],
  },
  light: {
    text: [30, 39], // black
    muted: [90, 39],
    accent: [36, 39],
    allow: [32, 39], // green reads on light bg; darker terminals vary but stay legible
    sanitize: [36, 39],
    block: [31, 39],
    hold: [33, 39],
    info: [34, 39],
    warning: [33, 39],
    error: [31, 39],
    border: [90, 39],
    surface: null,
    selection: [36, 39],
  },
  midnight: {
    text: [97, 39], // bright white
    muted: [34, 39], // dim blue-grey feel
    accent: [95, 39], // bright magenta
    allow: [92, 39], // bright green
    sanitize: [96, 39], // bright cyan
    block: [91, 39], // bright red
    hold: [93, 39], // bright yellow
    info: [94, 39], // bright blue
    warning: [93, 39],
    error: [91, 39],
    border: [35, 39], // magenta borders
    surface: null,
    selection: [95, 39],
  },
  "high-contrast": {
    text: [97, 39],
    muted: [37, 39], // no dim grey — everything legible
    accent: [93, 39],
    allow: [92, 39],
    sanitize: [96, 39],
    block: [91, 39],
    hold: [93, 39],
    info: [94, 39],
    warning: [93, 39],
    error: [91, 39],
    border: [97, 39],
    surface: null,
    selection: [93, 39],
  },
  monochrome: {
    text: null,
    muted: null,
    accent: null,
    allow: null,
    sanitize: null,
    block: null,
    hold: null,
    info: null,
    warning: null,
    error: null,
    border: null,
    surface: null,
    selection: null,
  },
};

export const THEME_NAMES = Object.keys(THEMES);

let current = process.env.CIRVIX_THEME && THEMES[process.env.CIRVIX_THEME]
  ? process.env.CIRVIX_THEME
  : "dark";

function colorEnabled() {
  if (process.env.FORCE_COLOR === "1" || process.env.FORCE_COLOR === "true") return true;
  if (process.env.NO_COLOR !== undefined) return false;
  if (process.env.TERM === "dumb") return false;
  if (process.env.CIRVIX_THEME === "monochrome") return false;
  // Non-TTY (pipes, CI logs) → plain text. Same rule format.mjs always had.
  if (!process.stdout.isTTY) return false;
  return true;
}

function wrapAnsi(open, close) {
  return (s) => (colorEnabled() ? `\x1b[${open}m${String(s)}\x1b[${close}m` : String(s));
}

/** Set the active theme. Returns the name set. Throws on unknown names. */
export function setTheme(name) {
  if (!THEMES[name]) throw new Error(`Unknown theme "${name}". Available: ${THEME_NAMES.join(", ")}`);
  current = name;
  return current;
}

/** Active theme name. */
export function themeName() {
  return current;
}

/** Raw role → ANSI pair for the active theme (or null). */
export function roleAnsi(role) {
  return THEMES[current]?.[role] ?? null;
}

/**
 * Style a string with a semantic role: `style("BLOCKED", "block")`.
 * Unknown roles pass through unstyled rather than throwing — a theme
 * must never break enforcement output.
 */
export function style(text, role) {
  const pair = THEMES[current]?.[role];
  if (!pair || !colorEnabled()) return String(text);
  return `\x1b[${pair[0]}m${String(text)}\x1b[${pair[1]}m`;
}

/** Bold / dim are emphasis, not color — they survive monochrome. */
export function bold(s) {
  if (!colorEnabled()) return String(s);
  return `${ANSI.bold[0]}${String(s)}${ANSI.bold[1]}`;
}

export function dim(s) {
  if (process.env.CIRVIX_THEME === "high-contrast") return String(s); // contrast: never dim
  if (!colorEnabled()) return String(s);
  return `${ANSI.dim[0]}${String(s)}${ANSI.dim[1]}`;
}

/**
 * The semantic palette. Prefer `colors.block("…")` over importing raw
 * helpers — call sites name the meaning, this file owns the rendering.
 */
export const colors = {
  get text() { return (s) => style(s, "text"); },
  get muted() { return (s) => style(s, "muted"); },
  get accent() { return (s) => style(s, "accent"); },
  get allow() { return (s) => style(s, "allow"); },
  get sanitize() { return (s) => style(s, "sanitize"); },
  get block() { return (s) => style(s, "block"); },
  get hold() { return (s) => style(s, "hold"); },
  get info() { return (s) => style(s, "info"); },
  get warning() { return (s) => style(s, "warning"); },
  get error() { return (s) => style(s, "error"); },
  get border() { return (s) => style(s, "border"); },
  get selection() { return (s) => style(s, "selection"); },
};

/** Decision → theme role. Single mapping, used by every renderer. */
export function roleForDecision(decision) {
  switch (String(decision ?? "").toLowerCase()) {
    case "allow": return "allow";
    case "sanitize": return "sanitize";
    case "deny": return "block";
    case "require_approval": return "hold";
    case "audit_only": return "muted";
    default: return "muted";
  }
}

/** Risk → theme role. */
export function roleForRisk(risk) {
  switch (String(risk ?? "").toLowerCase()) {
    case "critical": return "error";
    case "high": return "warning";
    case "medium": return "info";
    case "low": return "muted";
    default: return "muted";
  }
}

/** Decision → icon + label. Icon is never the only signal (a11y). */
export function badgeForDecision(decision) {
  switch (String(decision ?? "").toLowerCase()) {
    case "allow": return { icon: "✓", label: "ALLOWED" };
    case "sanitize": return { icon: "◇", label: "SANITIZED" };
    case "deny": return { icon: "✕", label: "BLOCKED" };
    case "require_approval": return { icon: "◷", label: "HELD FOR APPROVAL" };
    case "audit_only": return { icon: "○", label: "AUDIT ONLY" };
    default: return { icon: "?", label: String(decision ?? "UNKNOWN").toUpperCase() };
  }
}

export { wrapAnsi };
