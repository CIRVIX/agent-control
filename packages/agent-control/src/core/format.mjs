/**
 * Terminal formatting — thin compatibility layer over the semantic theme.
 *
 * New code should import from `theme.mjs` and use `colors.*` / `style(text,
 * role)` so meaning stays in one place. This module keeps the historic names
 * (`green`, `red`, `amber`, `blue`, `cyan`, `gray`, `white`, `bold`, `dim`,
 * `plural`) working for the existing CLI, gateway logs, the `core/ui`
 * primitives, and every test that already asserts on them.
 *
 * Mapping (the product's chroma rule — green means permitted, red denied,
 * amber held, blue/cyan sanitized or informational, gray muted):
 *   green → allow · red → block · amber → hold/warning · blue/cyan → sanitize
 *   gray → muted · white → text
 */

export { bold, dim, colors, style, setTheme, themeName, THEME_NAMES } from "./theme.mjs";
import { style } from "./theme.mjs";

export const green = (s) => style(s, "allow");
export const red = (s) => style(s, "block");
export const amber = (s) => style(s, "hold");
export const blue = (s) => style(s, "sanitize");
export const cyan = (s) => style(s, "sanitize");
export const gray = (s) => style(s, "muted");
export const white = (s) => style(s, "text");

const forced = process.env.FORCE_COLOR === "1" || process.env.FORCE_COLOR === "true";
const disabled =
  !forced &&
  (process.env.NO_COLOR !== undefined ||
    process.env.TERM === "dumb" ||
    !process.stdout.isTTY);

/** Strip ANSI escape sequences for width calculation and secret checks. */
export function stripAnsi(s) {
  return String(s).replace(/\[[0-9;]*m/g, "");
}

/** Visible character width, ignoring ANSI. */
export function visibleWidth(s) {
  return stripAnsi(String(s)).length;
}

/** True when output should be decorated (TTY, not NO_COLOR, not dumb, not CI unless forced). */
export function isInteractive() {
  if (disabled) return false;
  if (process.env.CI !== undefined && !forced) return false;
  return Boolean(process.stdout.isTTY);
}

/** Whether unicode box-drawing is safe. ASCII fallback when TERM=dumb or CIRVIX_ASCII=1. */
export function supportsUnicode() {
  if (process.env.CIRVIX_ASCII === "1") return false;
  if (process.env.TERM === "dumb") return false;
  return true;
}

/** "1 server" / "3 servers" — avoids the "1 servers" that reads as a bug. */
export function plural(n, noun, pluralForm) {
  return `${n} ${n === 1 ? noun : (pluralForm ?? noun + "s")}`;
}
