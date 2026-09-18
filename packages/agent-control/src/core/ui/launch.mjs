/**
 * The launch sequence — what `cirvix` does in a terminal before it says
 * anything true.
 *
 * Design constraints this file inherits, and why they shape it:
 *
 * - `welcome.mjs` renders on *every* launch, so motion here is paid on every
 *   launch. The whole sequence is therefore bounded (~800ms), and every frame
 *   is generated up front as plain strings so the cost is drawing, not
 *   thinking. `--fast`, `NO_COLOR`, `TERM=dumb`, CI, a pipe, or a terminal too
 *   narrow all skip straight to the resting plate.
 * - `DESIGN.md`: chroma means state. Green, red, and amber are verdicts, so the
 *   entire animation draws from the brand ramp in `core/theme.mjs` — the
 *   wordmark and the scan head — and nothing else. Structure is neutrals.
 * - It must be skippable: any keypress, or `Ctrl+C`, lands on the resting plate
 *   immediately. A launch screen you cannot get past is a hostage situation,
 *   and this is a tool people run fifty times a day.
 * - The last frame is the *static* banner, from the same `brandHeader()` the
 *   rest of the CLI prints. Nothing is readable only while it is animating, and
 *   nothing drifts between the animated and the plain path.
 *
 * Zero dependencies. All ANSI encoding happens in `core/theme.mjs`.
 */

import { dim, supportsUnicode } from "../format.mjs";
import { BRAND, brandAt, mixRgb, paint } from "../theme.mjs";
import { boxChars, padVisible } from "./theme.mjs";
import { brandHeader, logoRows, subtitleRow } from "./primitives.mjs";
import { hideCursor, shouldAnimate, sleep } from "./controller.mjs";

export const LAUNCH_WIDTH = 58;
export const LAUNCH_HEIGHT = 12;
export const DEFAULT_PACE = 22;
/** Hard ceiling. Whatever happens, the user is looking at real output by now. */
export const DEFAULT_BUDGET_MS = 1600;

/**
 * Paint one wordmark row as a brand gradient, optionally lit by a travelling
 * sweep.
 *
 * Runs are grouped by quantised colour so a 58-cell row costs a handful of
 * escape sequences rather than one per character — this is on the critical path
 * of every `cirvix` on an SSH session.
 */
function paintRow(row, { sweep = null, steps = 8, glow = 7, uniform = null } = {}) {
  if (uniform) {
    let out = "";
    let run = "";
    for (const ch of row) {
      if (ch.trim() === "") {
        if (run) {
          out += paint(run, uniform);
          run = "";
        }
        out += ch;
      } else {
        run += ch;
      }
    }
    return out + (run ? paint(run, uniform) : "");
  }

  const span = Math.max(1, row.length - 1);
  const palette = new Map();
  const colour = (key) => {
    if (palette.has(key)) return palette.get(key);
    let rgb;
    if (key < steps) {
      rgb = brandAt((key + 0.5) / steps);
    } else {
      const rest = key - steps;
      const level = Math.floor(rest / steps) + 1;
      rgb = mixRgb(brandAt(((rest % steps) + 0.5) / steps), BRAND.highlight, Math.min(1, level / glow));
    }
    palette.set(key, rgb);
    return rgb;
  };

  let out = "";
  let run = "";
  let runKey = null;
  const flush = () => {
    if (!run) return;
    out += runKey === -1 ? run : paint(run, colour(runKey));
    run = "";
  };

  for (let i = 0; i < row.length; i++) {
    const ch = row[i];
    let key = -1;
    if (ch.trim() !== "") {
      key = Math.min(steps - 1, Math.floor((steps * i) / span));
      if (sweep !== null) {
        const distance = Math.abs(i - sweep);
        if (distance <= glow) {
          const level = Math.max(1, Math.round((1 - distance / (glow + 1)) * glow));
          key = steps + (level - 1) * steps + key;
        }
      }
    }
    if (key !== runKey) {
      flush();
      runKey = key;
    }
    run += ch;
  }
  flush();
  return out;
}

/**
 * Every frame of the launch, as finished strings, plus the frame it rests on.
 *
 * Pure and synchronous on purpose: the beats are data, so they can be asserted
 * (frame height, no verdict colours, the resting frame) without a terminal,
 * a clock, or a timer.
 */
export function launchFrames({ width = LAUNCH_WIDTH, steps = 8, glow = 7 } = {}) {
  const ch = boxChars();
  const h = ch.h;
  const v = ch.v;
  const rows = logoRows(width);
  const sub = subtitleRow(width);
  const span = width + 2;
  const head = paint(supportsUnicode() ? "▌" : "#", BRAND.highlight);
  const frames = [];

  const blank = () => new Array(LAUNCH_HEIGHT).fill("");
  const side = (inner) => `  ${v} ${inner} ${v}`;
  const gutter = () => side(" ".repeat(width));
  const rule = (fill, tail) => `  ${ch.tl}${h.repeat(fill)}${tail}`;
  const topDone = `  ${ch.tl}${h.repeat(span)}${ch.tr}`;
  const bottomDone = `  ${ch.bl}${h.repeat(span)}${ch.br}`;

  const plate = (canvas) => {
    canvas[0] = topDone;
    canvas[1] = gutter();
    rows.forEach((row, i) => {
      canvas[2 + i] = side(paintRow(row, { steps, glow }));
    });
    canvas[8] = gutter();
    canvas[10] = gutter();
    canvas[11] = bottomDone;
    return canvas;
  };

  // 1. The plate's top rule draws itself.
  const drawFrames = 7;
  for (let s = 1; s <= drawFrames; s++) {
    const fill = Math.round((span * s) / drawFrames);
    const canvas = blank();
    canvas[0] = rule(fill, fill < span ? head : ch.tr);
    frames.push(canvas.join("\n"));
  }

  // 2. The wordmark lands, row by row. The row that just landed is lit, so the
  //    eye is pulled down the letterforms instead of reading a finished plate.
  for (let r = 1; r <= rows.length; r++) {
    const canvas = blank();
    canvas[0] = topDone;
    for (let i = 0; i < r; i++) {
      canvas[2 + i] = side(i === r - 1 ? paintRow(rows[i], { uniform: BRAND.highlight }) : paintRow(rows[i], { steps, glow }));
    }
    frames.push(canvas.join("\n"));
  }

  // 3. The plate closes.
  const closeFrames = 4;
  for (let s = 1; s <= closeFrames; s++) {
    const fill = Math.round((span * s) / closeFrames);
    const canvas = plate(blank());
    canvas[11] = `  ${ch.bl}${h.repeat(fill)}${fill < span ? head : ch.br}`;
    frames.push(canvas.join("\n"));
  }

  // 4. A single light sweep crosses the wordmark — the one flourish, and it is
  //    brand chroma only.
  const sweepFrames = 9;
  for (let s = 0; s < sweepFrames; s++) {
    const position = Math.round(((span + 2 * glow) * s) / (sweepFrames - 1)) - glow;
    const canvas = blank();
    canvas[0] = topDone;
    canvas[1] = gutter();
    rows.forEach((row, i) => {
      canvas[2 + i] = side(paintRow(row, { sweep: position, steps, glow }));
    });
    canvas[8] = gutter();
    canvas[10] = gutter();
    canvas[11] = bottomDone;
    frames.push(canvas.join("\n"));
  }

  // 5. The tagline types in, in the neutral it will keep — no colour flash when
  //    it settles.
  const end = sub.trimEnd().length;
  const typeFrames = 9;
  for (let s = 1; s <= typeFrames; s++) {
    const upto = Math.max(1, Math.round((end * s) / typeFrames));
    const canvas = plate(blank());
    canvas[9] = side(padVisible(dim(sub.slice(0, upto)) + (upto < end ? head : ""), width));
    frames.push(canvas.join("\n"));
  }

  return {
    frames,
    settle: brandHeader({ width, accent: true }),
    plain: brandHeader({ width }),
    height: LAUNCH_HEIGHT,
    width,
  };
}

/** Redraw a fixed-height block in place. `prevHeight` 0 means "nothing drawn yet". */
function redraw(stream, text, prevHeight) {
  let out = "";
  if (prevHeight > 0) {
    out += `\u001b[${prevHeight - 1}A`;
    for (let i = 0; i < prevHeight; i++) {
      out += "\u001b[2K";
      if (i < prevHeight - 1) out += "\u001b[1B";
    }
    out += `\u001b[${prevHeight - 1}A`;
  }
  stream.write(out + text);
}

/**
 * Play the sequence.
 *
 * Resolves to `{ animated, frames }` so a caller can tell whether the brand
 * plate is already on screen and avoid printing it twice. Skipping is
 * best-effort: if stdin cannot be put into raw mode (piped, or a wrapper that
 * refuses), the sequence simply runs to its budget.
 */
export async function playLaunch({
  stdout = process.stdout,
  stdin = process.stdin,
  pace = DEFAULT_PACE,
  width = LAUNCH_WIDTH,
  enabled,
  budgetMs = DEFAULT_BUDGET_MS,
} = {}) {
  const resolved = enabled ?? shouldAnimate({ pace, stream: stdout });
  const { frames, settle, height } = launchFrames({ width });
  if (!resolved || !stdout.isTTY) return { animated: false, frames: 0 };

  const restoreCursor = hideCursor(stdout);
  let skipped = false;
  const onKey = () => {
    skipped = true;
  };

  let listening = false;
  try {
    if (typeof stdin.setRawMode === "function" && stdin.isTTY) {
      stdin.setRawMode(true);
      stdin.on("data", onKey);
      stdin.resume();
      listening = true;
    }
  } catch {
    listening = false;
  }

  const started = Date.now();
  let drawn = 0;
  try {
    for (const frame of frames) {
      if (skipped || Date.now() - started > budgetMs) break;
      redraw(stdout, frame, drawn > 0 ? height : 0);
      drawn++;
      await sleep(pace);
    }
    redraw(stdout, settle, drawn > 0 ? height : 0);
    stdout.write("\n");
  } finally {
    if (listening) {
      try {
        stdin.off("data", onKey);
      } catch {}
      try {
        stdin.setRawMode(false);
      } catch {}
      try {
        stdin.pause();
      } catch {}
      // A keystroke that skipped the animation is spent. Draining the buffer
      // stops it being replayed as a menu choice when the home screen asks for
      // one — "1" pressed to skip must not silently start `cirvix init`.
      try {
        stdin.read?.();
      } catch {}
    }
    restoreCursor();
  }

  return { animated: true, frames: drawn };
}

/**
 * The entry point the CLI uses: decide, then either animate or print nothing.
 *
 * Printing nothing when motion is off is deliberate. The plain home screen
 * already states the brand in its own first line, and CI logs should not grow a
 * twelve-line ASCII plate because a TTY happened to be attached. The animation
 * is a reward for running this by hand, not a new output contract.
 */
export async function launchBanner({
  stdout = process.stdout,
  stdin = process.stdin,
  json = false,
  pace,
  force,
  columns,
} = {}) {
  const cols = Number(columns ?? stdout.columns ?? 0);
  // The plate needs its own width plus margins, or the box wraps and breaks.
  // An unknown column count — a wrapper that does not report one — gets the
  // standard plate rather than a guessed narrower one.
  const tooNarrow = cols > 0 && cols < LAUNCH_WIDTH + 8;
  const width = LAUNCH_WIDTH;

  // A stream that cannot animate is never asked to — and an explicit
  // `force: true` there still gets the plate, as text. There is nothing to
  // animate in a log, but the brand still lands.
  const animatable = Boolean(stdout.isTTY) && !json && !tooNarrow;
  const enabled = animatable && shouldAnimate({ pace, json, force, stream: stdout });

  if (!enabled) {
    if (force === true && !json && !tooNarrow) stdout.write(brandHeader({ width }) + "\n");
    return { animated: false, frames: 0 };
  }

  return playLaunch({ stdout, stdin, pace, width, enabled: true });
}
