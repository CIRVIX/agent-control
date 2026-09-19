/**
 * The launch sequence — what `cirvix` does in a terminal before it says
 * anything true.
 *
 * Design constraints this file inherits, and why they shape it:
 *
 * - `welcome.mjs` renders on *every* launch, so motion here is paid on every
 *   launch. The whole sequence is bounded (~800ms), and every frame is generated
 *   up front as plain strings so the cost is drawing, not thinking. `--fast`,
 *   `NO_COLOR`, `TERM=dumb`, CI, a pipe, or a terminal too narrow all skip
 *   straight to the resting plate.
 * - `DESIGN.md`: chroma means state. Green, red, and amber are verdicts, so the
 *   plate draws only from the brand ramp in `core/theme.mjs` — the wordmark, the
 *   scan head, and nothing else. Structure and status are neutrals.
 * - It must be skippable: any keypress, or `Ctrl+C`, lands on the resting plate
 *   immediately. A launch screen you cannot get past is a hostage situation,
 *   and this is a tool people run fifty times a day.
 * - It must not damage the terminal. The plate is 12 rows redrawn in place, so
 *   it reserves those rows before its first frame; without that, starting near
 *   the bottom of the screen scrolls the buffer and every later `cursor-up-N`
 *   lands N rows too high, erasing output that was already there.
 * - The last frame is the *static* banner, from the same `brandHeader()` the
 *   rest of the CLI prints. The transient rows — live status, skip hint — are
 *   gone by then, so nothing is readable only while it is moving and nothing
 *   drifts between the animated and the plain path.
 * - It reports real work. The status row names the probe phase that is actually
 *   in flight and, once it lands, what it found. Decoration that lies about
 *   state would be worse than no decoration.
 *
 * Zero dependencies. All ANSI encoding happens in `core/theme.mjs`.
 */

import { dim, supportsUnicode } from "../format.mjs";
import { brandAt, brandRamp, mixRgb, paint, paintRuns, sameRgb } from "../theme.mjs";
import { boxChars, padVisible } from "./theme.mjs";
import { brandHeader, logoRows, subtitleRow } from "./primitives.mjs";
import { hideCursor, shouldAnimate, sleep, SPINNER_ASCII, SPINNER_FRAMES } from "./controller.mjs";

export const LAUNCH_WIDTH = 58;
export const LAUNCH_HEIGHT = 12;
/**
 * Per-frame pace.
 *
 * 43 frames at 14ms is ~600ms for the plate. The sequence is longer than it was,
 * so it has to be faster: a home screen that takes over a second before it says
 * anything is a tax on every launch, and this is the screen people see fifty
 * times a day.
 */
export const DEFAULT_PACE = 14;
/** Hard ceiling. Whatever happens, the user is looking at real output by now. */
export const DEFAULT_BUDGET_MS = 1600;
/** Per-line pace for the home screen's staggered reveal. */
export const DEFAULT_STAGGER_MS = 7;

/**
 * Plate row indices. Named because three passes draw into this one canvas, and
 * an off-by-one between them shows up as a border drawn through the wordmark.
 */
export const ROW = {
  top: 0,
  eyebrow: 1,
  logo: 2,
  gap: 8,
  subtitle: 9,
  hint: 10,
  bottom: 11,
};

const headGlyph = () => (supportsUnicode() ? "▌" : "#");

/* -------------------------------------------------------------------------- */
/* Row painting                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Group a string into coloured runs.
 *
 * `rgbFor(i, ch)` returns an rgb triplet, or null to leave the active colour
 * alone — which is what a space does, since re-setting a colour after a space is
 * pure waste. The runs are handed to `paintRuns`, which emits one escape per
 * colour *change* instead of one per run.
 */
function runsFor(text, rgbFor) {
  const runs = [];
  let buffered = "";
  let rgb = null;
  const same = (a, b) => (a === null && b === null) || sameRgb(a, b);

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = rgbFor(i, ch);
    if (!same(next, rgb)) {
      if (buffered) runs.push({ text: buffered, rgb });
      buffered = "";
      rgb = next;
    }
    buffered += ch;
  }
  if (buffered) runs.push({ text: buffered, rgb });
  return runs;
}

/** The gradient colour at column `i` of a row spanning `span` columns. */
function gradientAt(i, span, steps, ramp) {
  const step = Math.min(steps - 1, Math.max(0, Math.floor((steps * i) / span)));
  return brandAt((step + 0.5) / steps, ramp);
}

/** Paint a wordmark row as a brand gradient, optionally lit by a sweep. */
function paintRow(row, { sweep = null, steps = 8, glow = 7, uniform = null, ramp = brandRamp() } = {}) {
  const span = Math.max(1, row.length - 1);
  return paintRuns(runsFor(row, (i, ch) => {
    if (ch.trim() === "") return null;
    if (uniform) return uniform;
    const gradient = gradientAt(i, span, steps, ramp);
    if (sweep === null) return gradient;
    const distance = Math.abs(i - sweep);
    if (distance > glow) return gradient;
    const level = Math.max(1, Math.round((1 - distance / (glow + 1)) * glow));
    return mixRgb(gradient, ramp.highlight, Math.min(1, level / glow));
  }));
}

/**
 * A wordmark row revealed up to `cut`, with a lit leading edge.
 *
 * `cut >= row.length` returns the finished row, so the last frame of a wipe and
 * the gradient under it are the same picture — the reveal cannot leave a trace.
 * A glyph at the cut position is *replaced* by the head rather than displaced by
 * it, so the row's visible width is unchanged and the box never shifts.
 */
function wipeRow(row, cut, { steps = 8, glow = 7, ramp = brandRamp() } = {}) {
  if (cut >= row.length) return paintRow(row, { steps, glow, ramp });
  const head = row[cut].trim() === "" ? " " : headGlyph();
  const shown = row.slice(0, cut) + head + " ".repeat(row.length - cut - 1);
  const span = Math.max(1, row.length - 1);
  return paintRuns(runsFor(shown, (i, ch) => {
    if (ch.trim() === "") return null;
    if (i === cut) return ramp.highlight;
    return gradientAt(i, span, steps, ramp);
  }));
}

/* -------------------------------------------------------------------------- */
/* Transient rows                                                              */
/* -------------------------------------------------------------------------- */

/** Centre a plain string in the plate's inner width. */
function centre(text, width) {
  return text.padStart(Math.floor((width + text.length) / 2)).padEnd(width);
}

/**
 * The live status row.
 *
 * A spinner while the probe is in flight, a filled dot once it lands, a cross if
 * it failed — so the glyph is a fact about the run, not decoration. Neutral in
 * colour on purpose: the plate carries the brand chroma, and this row is
 * structure.
 */
export function statusRow({ label = "", busy = true, failed = false, tick = 0, width = LAUNCH_WIDTH } = {}) {
  if (!label) return "";
  const unicode = supportsUnicode();
  const glyph = failed
    ? (unicode ? "✕" : "x")
    : busy
      ? (unicode ? SPINNER_FRAMES : SPINNER_ASCII)[tick % (unicode ? SPINNER_FRAMES : SPINNER_ASCII).length]
      : (unicode ? "●" : "*");
  return dim(centre(`${glyph} ${label}`, width));
}

/** The skip hint — shown only while there is still something left to skip. */
export function skipRow({ width = LAUNCH_WIDTH } = {}) {
  return dim(centre("press any key to skip", width));
}

/**
 * Draw the transient rows over a frame.
 *
 * Transient is the point: both are gone by the frame the sequence rests on, so
 * the resting plate stays byte-identical to the static header, and a test can
 * assert exactly that rather than trusting it.
 */
export function withOverlay(frame, { eyebrow = "", hint = "", width = LAUNCH_WIDTH } = {}) {
  if (!eyebrow && !hint) return frame;
  const v = boxChars().v;
  const lines = frame.split("\n");
  if (eyebrow) lines[ROW.eyebrow] = `  ${v} ${padVisible(eyebrow, width)} ${v}`;
  if (hint) lines[ROW.hint] = `  ${v} ${padVisible(hint, width)} ${v}`;
  return lines.join("\n");
}

/* -------------------------------------------------------------------------- */
/* Frames                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Every frame of the launch, as finished strings, plus the frame it rests on.
 *
 * Pure and synchronous on purpose: the beats are data, so they can be asserted
 * (frame height, no verdict colours, the resting frame, transient rows) with no
 * terminal, clock, or timer.
 *
 * `overlayFrom` is the first frame whose side gutters exist. The transient rows
 * are only drawn from there, so status text never appears floating on a plate
 * whose box has not been drawn yet.
 */
export function launchFrames({ width = LAUNCH_WIDTH, steps = 8, glow = 7 } = {}) {
  const ch = boxChars();
  const h = ch.h;
  const v = ch.v;
  const ramp = brandRamp();
  const rows = logoRows(width);
  const sub = subtitleRow(width);
  const span = width + 2;
  const head = paint(headGlyph(), ramp.highlight);
  const frames = [];

  const blank = () => new Array(LAUNCH_HEIGHT).fill("");
  const side = (inner) => `  ${v} ${inner} ${v}`;
  const gutter = () => side(" ".repeat(width));
  const topDone = `  ${ch.tl}${h.repeat(span)}${ch.tr}`;
  const bottomDone = `  ${ch.bl}${h.repeat(span)}${ch.br}`;

  /** The finished frame: both rules, every side gutter, gradient wordmark. */
  const plate = (canvas = blank()) => {
    canvas[ROW.top] = topDone;
    for (let row = ROW.eyebrow; row <= ROW.hint; row++) canvas[row] = gutter();
    rows.forEach((row, i) => {
      canvas[ROW.logo + i] = side(paintRow(row, { steps, glow, ramp }));
    });
    canvas[ROW.bottom] = bottomDone;
    return canvas;
  };

  // 1. The top rule draws itself, head first.
  const ruleFrames = 7;
  for (let s = 1; s <= ruleFrames; s++) {
    const fill = Math.round((span * s) / ruleFrames);
    const canvas = blank();
    canvas[ROW.top] = `  ${ch.tl}${h.repeat(fill)}${fill < span ? head : ch.tr}`;
    frames.push(canvas.join("\n"));
  }

  // 2. The frame draws itself downward. Drawing the outline *before* the wordmark
  //    means the wordmark is always inside a box, rather than floating between
  //    two rules for the first half of the sequence.
  const outlineRows = ROW.hint - ROW.eyebrow + 1;
  const outlineFrames = 4;
  for (let s = 1; s <= outlineFrames; s++) {
    const upto = Math.round((outlineRows * s) / outlineFrames);
    const canvas = blank();
    canvas[ROW.top] = topDone;
    for (let r = 0; r < upto; r++) canvas[ROW.eyebrow + r] = gutter();
    frames.push(canvas.join("\n"));
  }
  const overlayFrom = frames.length;

  // 3. The wordmark wipes in, row by row, left to right.
  const wipes = 2;
  for (let r = 0; r < rows.length; r++) {
    for (let s = 1; s <= wipes; s++) {
      const canvas = blank();
      canvas[ROW.top] = topDone;
      for (let row = ROW.eyebrow; row <= ROW.hint; row++) canvas[row] = gutter();
      for (let i = 0; i < r; i++) {
        canvas[ROW.logo + i] = side(paintRow(rows[i], { steps, glow, ramp }));
      }
      canvas[ROW.logo + r] = side(wipeRow(rows[r], Math.round((width * s) / wipes), { steps, glow, ramp }));
      frames.push(canvas.join("\n"));
    }
  }

  // 4. The bottom rule closes the frame.
  const closeFrames = 4;
  for (let s = 1; s <= closeFrames; s++) {
    const fill = Math.round((span * s) / closeFrames);
    const canvas = plate();
    canvas[ROW.bottom] = `  ${ch.bl}${h.repeat(fill)}${fill < span ? head : ch.br}`;
    frames.push(canvas.join("\n"));
  }

  // 5. One light sweep crosses the wordmark — the flourish, brand chroma only.
  const sweepFrames = 9;
  for (let s = 0; s < sweepFrames; s++) {
    const position = Math.round(((span + 2 * glow) * s) / (sweepFrames - 1)) - glow;
    const canvas = blank();
    canvas[ROW.top] = topDone;
    for (let row = ROW.eyebrow; row <= ROW.hint; row++) canvas[row] = gutter();
    rows.forEach((row, i) => {
      canvas[ROW.logo + i] = side(paintRow(row, { sweep: position, steps, glow, ramp }));
    });
    canvas[ROW.bottom] = bottomDone;
    frames.push(canvas.join("\n"));
  }

  // 6. The tagline types in, wearing the style it will keep — there is no colour
  //    flash when it settles because it is never painted in anything else.
  const end = sub.trimEnd().length;
  const typeFrames = 7;
  for (let s = 1; s <= typeFrames; s++) {
    const upto = Math.max(1, Math.round((end * s) / typeFrames));
    const canvas = plate();
    canvas[ROW.subtitle] = side(padVisible(dim(sub.slice(0, upto)) + (upto < end ? head : ""), width));
    frames.push(canvas.join("\n"));
  }

  return {
    frames,
    overlayFrom,
    settle: brandHeader({ width, accent: true }),
    plain: brandHeader({ width }),
    height: LAUNCH_HEIGHT,
    width,
  };
}

/* -------------------------------------------------------------------------- */
/* Playback                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Reserve the plate's rows before the first frame.
 *
 * The whole sequence assumes `cursor-up-N` lands on its own first row. That is
 * false when the cursor starts within N rows of the bottom of the screen: the
 * first frame's newlines scroll the buffer, and every subsequent redraw then
 * erases N rows of *previous* output instead of its own lines. Writing the
 * block's height in newlines first makes the space exist, after which the
 * arithmetic is true wherever the plate starts.
 */
function reserveRows(stream, height) {
  stream.write("\n".repeat(height - 1) + `\u001b[${height - 1}A`);
}

/** Redraw a fixed-height block in place. `prevHeight` 0 means "not drawn yet". */
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
 * Watch for a keypress so the caller can cut the animation short, and restore
 * the terminal exactly as it was.
 *
 * Restoring is best-effort by necessity — a stdin that refuses raw mode (piped,
 * or wrapped) simply means nothing can skip, and the sequence runs to its budget
 * instead.
 */
function watchForSkip(stdin) {
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

  return {
    get skipped() {
      return skipped;
    },
    restore() {
      if (!listening) return;
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
    },
  };
}

/**
 * Play the sequence.
 *
 * `pending`/`phase`/`summary` make the status row honest: while `pending` is
 * unresolved the row names the phase the caller is actually inside, and once it
 * resolves the row reports what it found. Pass nothing and the plate simply has
 * no status row.
 */
export async function playLaunch({
  stdout = process.stdout,
  stdin = process.stdin,
  pace = DEFAULT_PACE,
  width = LAUNCH_WIDTH,
  enabled,
  budgetMs = DEFAULT_BUDGET_MS,
  pending = null,
  phase = null,
  summary = null,
} = {}) {
  const resolved = enabled ?? shouldAnimate({ pace, stream: stdout });
  const { frames, settle, height, overlayFrom } = launchFrames({ width });
  if (!resolved || !stdout.isTTY) return { animated: false, frames: 0 };

  let probe = "pending";
  if (pending && typeof pending.then === "function") {
    pending.then(
      () => {
        probe = "done";
      },
      () => {
        probe = "failed";
      },
    );
  }

  const restoreCursor = hideCursor(stdout);
  const skip = watchForSkip(stdin);
  const started = Date.now();
  let drawn = 0;

  try {
    reserveRows(stdout, height);
    for (let i = 0; i < frames.length; i++) {
      if (skip.skipped || Date.now() - started > budgetMs) break;
      let frame = frames[i];
      if (i >= overlayFrom) {
        const label = probe === "pending"
          ? (typeof phase === "function" ? phase() : "")
          : probe === "done"
            ? (typeof summary === "function" ? summary() : "")
            : "probe unavailable";
        frame = withOverlay(frame, {
          eyebrow: statusRow({ label, busy: probe === "pending", failed: probe === "failed", tick: drawn, width }),
          hint: skipRow({ width }),
          width,
        });
      }
      redraw(stdout, frame, drawn > 0 ? height : 0);
      drawn++;
      await sleep(pace);
    }
    redraw(stdout, settle, drawn > 0 ? height : 0);
    stdout.write("\n");
  } finally {
    skip.restore();
    restoreCursor();
  }

  return { animated: true, frames: drawn };
}

/**
 * Paint lines one at a time.
 *
 * The home screen's digest assembles itself instead of appearing whole, which is
 * the difference between a command that prints and a console that comes up. A
 * keypress finishes it immediately — and finishes it *completely*: a skip must
 * never cost the user a line of output, so the remainder is written in one go
 * rather than dropped.
 */
export async function revealLines({
  stdout = process.stdout,
  stdin = process.stdin,
  lines = [],
  pace = DEFAULT_STAGGER_MS,
  enabled,
} = {}) {
  const animate = enabled ?? shouldAnimate({ pace, stream: stdout });
  if (!animate || lines.length === 0) {
    stdout.write(lines.join("\n"));
    return { staggered: false, lines: lines.length };
  }

  const restoreCursor = hideCursor(stdout);
  const skip = watchForSkip(stdin);
  try {
    for (let i = 0; i < lines.length; i++) {
      // No newline after the last line, so the staggered path writes exactly the
      // bytes `join("\n")` writes. A TTY run and a piped run must not differ.
      stdout.write(lines[i] + (i < lines.length - 1 ? "\n" : ""));
      if (skip.skipped) {
        const rest = lines.slice(i + 1).join("\n");
        if (rest) stdout.write(rest);
        break;
      }
      await sleep(pace);
    }
  } finally {
    skip.restore();
    restoreCursor();
  }

  return { staggered: true, lines: lines.length };
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
  pending,
  phase,
  summary,
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

  return playLaunch({ stdout, stdin, pace, width, enabled: true, pending, phase, summary });
}