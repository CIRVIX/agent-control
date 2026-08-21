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

/** "1 server" / "3 servers" — avoids the "1 servers" that reads as a bug. */
export function plural(n, noun, pluralForm) {
  return `${n} ${n === 1 ? noun : (pluralForm ?? noun + "s")}`;
}
