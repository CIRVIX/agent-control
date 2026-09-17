/**
 * Terminal formatting — thin compatibility layer over the semantic theme.
 *
 * New code should import from `theme.mjs` and use `colors.*` / `style(text,
 * role)` so meaning stays in one place. This module keeps the historic names
 * (`green`, `red`, `amber`, `blue`, `bold`, `dim`, `plural`) working for the
 * existing CLI, gateway logs, and every test that already asserts on them.
 *
 * Mapping (the product's chroma rule — green means permitted, red denied,
 * amber held, blue sanitized/info):
 *   green → allow · red → block · amber → hold/warning · blue → sanitize/info
 */

export { bold, dim, colors, style, setTheme, themeName, THEME_NAMES } from "./theme.mjs";
import { style } from "./theme.mjs";

export const green = (s) => style(s, "allow");
export const red = (s) => style(s, "block");
export const amber = (s) => style(s, "hold");
export const blue = (s) => style(s, "sanitize");

/** "1 server" / "3 servers" — avoids the "1 servers" that reads as a bug. */
export function plural(n, noun, pluralForm) {
  return `${n} ${n === 1 ? noun : (pluralForm ?? noun + "s")}`;
}
