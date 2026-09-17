/**
 * AnimationController — decides whether animation is allowed and manages timers/cursor.
 *
 * Respects: NO_COLOR, TERM=dumb, !isTTY, CI, --json, --fast/pace=0,
 * CIRVIX_NO_ANIM, CIRVIX_REDUCED_MOTION, FORCE_COLOR override.
 *
 * Every animation cleans up its own intervals/timeouts and restores cursor.
 */

import { isInteractive } from "../format.mjs";

export function shouldAnimate({ pace, json, force } = {}) {
  if (json) return false;
  if (pace === 0) return false;
  if (process.env.CIRVIX_NO_ANIM === "1") return false;
  if (process.env.CIRVIX_REDUCED_MOTION === "1") return false;
  if (force === false) return false;
  if (force === true) return true;
  // format.mjs already handles NO_COLOR / TERM=dumb / !isTTY / FORCE_COLOR
  // but CI gate is extra: CI without FORCE_COLOR should not animate
  if (process.env.CI !== undefined && process.env.FORCE_COLOR !== "1" && process.env.FORCE_COLOR !== "true") {
    return false;
  }
  return isInteractive();
}

/** Hide cursor, remember to show it on exit. */
export function hideCursor(stream = process.stdout) {
  if (!stream.isTTY) return () => {};
  try {
    stream.write("\u001b[?25l");
  } catch {}
  let shown = false;
  const show = () => {
    if (shown) return;
    shown = true;
    try {
      stream.write("\u001b[?25h");
    } catch {}
  };
  const onExit = () => show();
  // Ensure cleanup on ctrl+c or exit.
  process.once("SIGINT", onExit);
  process.once("SIGTERM", onExit);
  process.once("exit", onExit);
  return () => {
    show();
    process.off("SIGINT", onExit);
    process.off("SIGTERM", onExit);
    process.off("exit", onExit);
  };
}

/** Spinner frames — subtle, not gamey. */
export const SPINNER_FRAMES = ["◌", "◎", "◉", "◎"];
export const SPINNER_ASCII = ["-", "\\", "|", "/"];

export class Spinner {
  constructor(label, { stream = process.stdout, enabled = shouldAnimate({}) } = {}) {
    this.label = label;
    this.stream = stream;
    this.enabled = enabled;
    this.interval = null;
    this.frame = 0;
    this.restoreCursor = null;
  }

  start() {
    if (!this.enabled) {
      this.stream.write(`${this.label}\n`);
      return this;
    }
    this.restoreCursor = hideCursor(this.stream);
    this.interval = setInterval(() => {
      const ch = SPINNER_FRAMES[this.frame % SPINNER_FRAMES.length];
      this.frame++;
      // Rewrite same line.
      try {
        this.stream.write(`\r\x1b[2K  ${ch} ${this.label}`);
      } catch {}
    }, 80);
    // Initial draw.
    try {
      this.stream.write(`  ${SPINNER_FRAMES[0]} ${this.label}`);
    } catch {}
    return this;
  }

  succeed(text) {
    this.stop();
    try {
      this.stream.write(`  \u2713 ${text ?? this.label}\n`);
    } catch {}
    return this;
  }

  fail(text) {
    this.stop();
    try {
      this.stream.write(`  \u2715 ${text ?? this.label}\n`);
    } catch {}
    return this;
  }

  stop() {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
      // Clear spinner line.
      try {
        this.stream.write("\r\x1b[2K");
      } catch {}
    }
    if (this.restoreCursor) {
      this.restoreCursor();
      this.restoreCursor = null;
    }
    return this;
  }
}

/** Sequential step runner: shows spinner per step, ✓ on success, ✕ on fail. */
export class StepSequence {
  constructor({ stream = process.stdout, enabled = shouldAnimate({}) } = {}) {
    this.stream = stream;
    this.enabled = enabled;
    this.steps = [];
    this.timers = [];
  }

  add(label, fn) {
    this.steps.push({ label, fn });
    return this;
  }

  async run({ interval = 120 } = {}) {
    const results = [];
    for (const step of this.steps) {
      const spinner = new Spinner(step.label, { stream: this.stream, enabled: this.enabled });
      if (this.enabled) spinner.start();
      let ok = false;
      let error = null;
      try {
        const res = await step.fn();
        // fn may return {ok, detail} or boolean; truthy means success.
        if (res && typeof res === "object" && "ok" in res) ok = Boolean(res.ok);
        else if (typeof res === "boolean") ok = res;
        else ok = true;
      } catch (err) {
        ok = false;
        error = err;
      }
      if (this.enabled) {
        // Small delay so spinner is visible, but not blocking.
        await new Promise((r) => {
          const t = setTimeout(r, interval);
          this.timers.push(t);
        });
        spinner.stop();
        if (ok) {
          try {
            this.stream.write(`  \x1b[32m\u2713\x1b[39m ${step.label}\n`);
          } catch {}
        } else {
          try {
            this.stream.write(`  \x1b[31m\u2715\x1b[39m ${step.label}${error ? ` — ${error.message}` : ""}\n`);
          } catch {}
        }
      } else {
        const sym = ok ? "\u2713" : "\u2715";
        try {
          this.stream.write(`  ${sym} ${step.label}\n`);
        } catch {}
      }
      results.push({ label: step.label, ok, error });
    }
    return results;
  }

  cleanup() {
    for (const t of this.timers) clearTimeout(t);
    this.timers = [];
  }
}

/** Simple sleep that tracks timer for cleanup. */
export function sleep(ms, tracker) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    if (tracker) tracker.push(t);
  });
}
