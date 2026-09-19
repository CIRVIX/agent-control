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

/* -------------------------------------------------------------------------- */
/* Brand chroma                                                                */
/* -------------------------------------------------------------------------- */

/**
 * The one non-state colour, as a ramp.
 *
 * `DESIGN.md` is explicit: the four saturated colours are runtime verdicts
 * (permit / deny / hold / route) and "nothing decorative may use them". The
 * launch sequence is decoration, so it draws its entire palette from here —
 * deep → brand (#6f9bff) → highlight — and can never borrow green, red, or
 * amber by accident.
 *
 * Keeping the ramp in this file is the same rule as the semantic roles above:
 * no module outside `theme.mjs` hardcodes an ANSI sequence.
 */
export const BRAND = {
  deep: [26, 68, 168],
  base: [111, 155, 255],
  highlight: [216, 230, 255],
};

/**
 * The same ramp for a **light** background.
 *
 * The highlight end is nearly white: on a white terminal it is invisible, so a
 * "landed" flash or a scan head drawn with it looks like a glitch rather than
 * emphasis. On light backgrounds emphasis runs the other way — deeper is
 * brighter — so the ramp is inverted and the highlight becomes the deep blue.
 */
const BRAND_ON_LIGHT = {
  deep: [111, 155, 255],
  base: [26, 68, 168],
  highlight: [14, 44, 112],
};

/**
 * The ramp to draw with, given the active theme.
 *
 * Callers that draw gradients, scan heads, or emphasis must take the ramp from
 * here rather than reaching for `BRAND`, or the animation is only correct on the
 * half of terminals the author happened to be using.
 */
export function brandRamp() {
  return themeName() === "light" ? BRAND_ON_LIGHT : BRAND;
}

/**
 * What the terminal can actually render: `"truecolor"`, `"256"`, `"16"`, or
 * `"none"`. A degraded answer is a correct answer — an animated brand that
 * emits an unsupported SGR sequence renders as literal `[38;2;…` garbage in the
 * logs of the people this tool is sold to.
 */
export function colorDepth() {
  if (!colorEnabled()) return "none";
  const forced = String(process.env.CIRVIX_TRUECOLOR ?? "");
  // Explicit override, both directions: `1` for truecolor, `0`/`256` for the
  // 256-colour cube, `16` for the accent role. Support needs an escape hatch —
  // a terminal that claims a depth it cannot render is the case worth being
  // able to work around without a release.
  if (forced === "1" || forced === "truecolor" || forced === "24bit") return "truecolor";
  if (forced === "16") return "16";
  if (forced === "0" || forced === "256") return "256";
  const colorterm = String(process.env.COLORTERM ?? "").toLowerCase();
  if (colorterm.includes("truecolor") || colorterm.includes("24bit")) return "truecolor";
  const term = String(process.env.TERM ?? "");
  if (/\b(direct|truecolor)\b/.test(term)) return "truecolor";
  // Windows Terminal, VS Code, and most modern emulators set COLORTERM above;
  // anything that reaches here on Windows is a legacy console, which is 256-safe.
  if (/256color/.test(term) || process.platform === "win32") return "256";
  return "16";
}

function lerp(a, b, t) {
  return Math.round(a + (b - a) * t);
}

/**
 * RGB at position `t` (0..1) along the brand ramp.
 * The first half runs deep → brand, the second brand → highlight, so a plain
 * left-to-right gradient reads as lit from the right.
 */
export function brandAt(t, ramp = brandRamp()) {
  const clamped = Math.max(0, Math.min(1, Number(t) || 0));
  const [from, to, local] = clamped <= 0.5
    ? [ramp.deep, ramp.base, clamped * 2]
    : [ramp.base, ramp.highlight, (clamped - 0.5) * 2];
  return [
    lerp(from[0], to[0], local),
    lerp(from[1], to[1], local),
    lerp(from[2], to[2], local),
  ];
}

/** Nearest cell in the xterm 6×6×6 cube — the 256-colour fallback. */
function to256([r, g, b]) {
  const q = (v) => Math.max(0, Math.min(5, Math.round((v / 255) * 5)));
  return 16 + 36 * q(r) + 6 * q(g) + q(b);
}

/** Blend two rgb triplets. Used to light the wordmark under the launch sweep. */
export function mixRgb(from, to, t) {
  const k = Math.max(0, Math.min(1, Number(t) || 0));
  return [lerp(from[0], to[0], k), lerp(from[1], to[1], k), lerp(from[2], to[2], k)];
}

/**
 * Open/close sequences for one colour, at this terminal's depth — or null when
 * colour is off.
 *
 * Exposed because a run-based renderer needs to emit the *open* alone and reuse
 * it across runs: emitting `open + text + close` per run produces a stream where
 * half the escapes set a colour that is already active (`…Xm██` `…Xm██`), which
 * is wasted bytes on a slow link and a flicker source on some terminals.
 */
export function colourPair(rgb) {
  if (!colorEnabled() || !rgb) return null;
  const depth = colorDepth();
  if (depth === "truecolor") return [`\x1b[38;2;${rgb[0]};${rgb[1]};${rgb[2]}m`, "\x1b[39m"];
  if (depth === "256") return [`\x1b[38;5;${to256(rgb)}m`, "\x1b[39m"];
  const accent = roleAnsi("accent");
  return accent ? [`\x1b[${accent[0]}m`, `\x1b[${accent[1]}m`] : null;
}

/** True when two rgb triplets are the same colour. */
export function sameRgb(a, b) {
  return Boolean(a && b) && a[0] === b[0] && a[1] === b[1] && a[2] === b[2];
}

/**
 * Paint one colour with the best sequence this terminal understands.
 * On a 16-colour terminal the brand collapses to the `accent` role — still the
 * brand family, never a verdict colour.
 */
export function paint(text, rgb) {
  const s = String(text);
  const pair = colourPair(rgb);
  return pair ? pair[0] + s + pair[1] : s;
}

/**
 * Render `[{ text, rgb|null }]` as a minimal escape stream.
 *
 * One colour is emitted when it *changes* and reset once at the end, instead of
 * being set and reset around every run. The difference is not cosmetic: a plain
 * per-run emitter writes `…Xm██` `…39m` `…Xm██` for a gradient that happens to
 * revisit a colour, and on the previous animation that was 642 redundant
 * sequences out of 1,437 — the kind of thing that flickers on a real terminal
 * and reads as jank on a slow link.
 *
 * `rgb: null` means "carry the active colour" — spaces have no colour of their
 * own, and the escape after one is exactly what was being wasted.
 */
export function paintRuns(runs) {
  const visible = runs.filter((run) => run.text);
  if (!colorEnabled()) return visible.map((run) => run.text).join("");

  let out = "";
  let openedWith = null;
  let close = "";
  for (const run of visible) {
    if (run.rgb) {
      const pair = colourPair(run.rgb);
      // Compare sequences rather than colours: on a 16-colour terminal every
      // colour collapses to the same accent pair, and comparing rgb would
      // re-emit it once per run.
      if (pair && pair[0] !== openedWith) {
        out += pair[0];
        openedWith = pair[0];
        close = pair[1];
      }
    }
    out += run.text;
  }
  return close ? out + close : out;
}

/**
 * Paint a string as a brand gradient across its own length, skipping empty runs
 * so the result is the shortest escape stream that renders the same picture.
 */
export function gradient(text, { from = 0, to = 1, steps = 8, ramp = brandRamp() } = {}) {
  const s = String(text);
  if (!colorEnabled() || colorDepth() === "none") return s;

  const span = Math.max(1, s.length - 1);
  const runes = [];
  let buffered = "";
  let rgb = null;
  const same = (a, b) => (a === null && b === null) || sameRgb(a, b);

  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const next = ch.trim() === ""
      ? null
      : brandAt((Math.min(steps - 1, Math.max(0, Math.floor(steps * (from + ((to - from) * i) / span)))) + 0.5) / steps, ramp);
    if (!same(next, rgb)) {
      if (buffered) runes.push({ text: buffered, rgb });
      buffered = "";
      rgb = next;
    }
    buffered += ch;
  }
  if (buffered) runes.push({ text: buffered, rgb });
  return paintRuns(runes);
}

export { wrapAnsi };
