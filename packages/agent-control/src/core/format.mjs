/**
 * Terminal formatting.
 *
 * Colour is suppressed when stdout is not a TTY, when `NO_COLOR` is set, or
 * when `TERM=dumb` — so piping to a file or a CI log produces clean text
 * rather than escape sequences. `FORCE_COLOR` overrides for the cases where a
 * CI runner does support colour but does not present as a TTY.
 *
 * The palette mirrors the product's chroma rule: green means permitted, red
 * means denied, amber means held. Nothing decorative uses them.
 */

const forced = process.env.FORCE_COLOR === "1" || process.env.FORCE_COLOR === "true";
const disabled =
  !forced &&
  (process.env.NO_COLOR !== undefined ||
    process.env.TERM === "dumb" ||
    !process.stdout.isTTY);

const wrap = (open, close) => (s) =>
  disabled ? String(s) : `[${open}m${s}[${close}m`;

export const bold = wrap(1, 22);
export const dim = wrap(2, 22);
export const red = wrap(31, 39);
export const green = wrap(32, 39);
export const amber = wrap(33, 39);
export const blue = wrap(34, 39);
export const cyan = wrap(36, 39);
export const gray = wrap(90, 39);
export const white = wrap(97, 39);

/** Strip ANSI escape sequences for width calculation and secret checks. */
export function stripAnsi(s) {
  return String(s).replace(/\u001b\[[0-9;]*m/g, "");
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
