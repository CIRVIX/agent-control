/**
 * The launch sequence.
 *
 * What is worth asserting here is not "the animation animates" — it is the
 * contract around it: that decoration can never wear a verdict colour, that the
 * plain path is untouched for CI and pipes, that the animated path lands on the
 * same plate the static one prints, and that a keystroke actually gets the user
 * out of it.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { stripAnsi } from "../src/core/format.mjs";
import { brandHeader, logoRows } from "../src/core/ui/primitives.mjs";
import {
  LAUNCH_HEIGHT,
  LAUNCH_WIDTH,
  launchBanner,
  launchFrames,
  playLaunch,
  revealLines,
  skipRow,
  statusRow,
  withOverlay,
} from "../src/core/ui/launch.mjs";
import { colorDepth, setTheme } from "../src/core/theme.mjs";

const exec = promisify(execFile);
const cli = fileURLToPath(new URL("../bin/cirvix.mjs", import.meta.url));

/** Verdict chroma. Green means permitted, red denied, amber held — never decoration. */
const VERDICT_SGR = /\u001b\[(3[123]|9[123])m/;

/**
 * Visible text: SGR *and* cursor control removed.
 *
 * `stripAnsi` only removes SGR sequences, and an animated path legitimately
 * interleaves `hide cursor` / `show cursor` around its content. Comparing
 * un-hidden output is how you prove a TTY run says the same thing as a piped one
 * without asserting the cursor choreography.
 */
const visible = (s) => stripAnsi(s).replace(/\u001b\[\?25[lh]/g, "");

/**
 * Wait until `predicate` holds, or give up.
 *
 * The alternative — sleeping for a fixed duration and hoping the animation got
 * there — encodes this machine's timing into the test and fails on a slower
 * runner. Waiting for the condition asserts what the code promises (the phase is
 * named *while the probe is pending*) instead of how fast it renders.
 */
async function waitFor(predicate, timeoutMs = 3000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return false;
}

/**
 * Run `fn` with the given environment, then put it back.
 *
 * Awaiting `fn` (rather than returning it) matters: an async body that restored
 * the environment at the moment the promise was *created* would leak the
 * override into whichever test ran next.
 */
async function withEnv(vars, fn) {
  const saved = {};
  for (const [key, value] of Object.entries(vars)) {
    saved[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    return await fn();
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

/**
 * The gates `shouldAnimate` consults beyond the stream it is handed.
 *
 * A CI runner sets `CI`, so a test asserting what an *interactive terminal* does
 * has to clear these first. Without this, the test encodes the environment it
 * happened to run in: green on a laptop, red on the runner. That is exactly how
 * two tests in this file first shipped.
 */
const INTERACTIVE_ENV = {
  CI: undefined,
  CIRVIX_NO_ANIM: undefined,
  CIRVIX_REDUCED_MOTION: undefined,
  NO_COLOR: undefined,
  TERM: undefined,
  FORCE_COLOR: undefined,
};

function ttyStream({ columns = 120, isTTY = true } = {}) {
  const chunks = [];
  return {
    isTTY,
    columns,
    chunks,
    write(chunk) {
      chunks.push(String(chunk));
      return true;
    },
    text() {
      return chunks.join("");
    },
  };
}

function fakeStdin() {
  const handlers = new Map();
  return {
    isTTY: true,
    rawMode: null,
    paused: false,
    setRawMode(value) {
      this.rawMode = value;
    },
    on(event, fn) {
      handlers.set(event, [...(handlers.get(event) ?? []), fn]);
    },
    off(event, fn) {
      handlers.set(event, (handlers.get(event) ?? []).filter((f) => f !== fn));
    },
    resume() {},
    pause() {
      this.paused = true;
    },
    read() {
      return null;
    },
    press(key) {
      for (const fn of handlers.get("data") ?? []) fn(Buffer.from(key));
    },
  };
}

async function workspace(t) {
  const cwd = await mkdtemp(join(tmpdir(), "cirvix-launch-test-"));
  t.after(() => rm(cwd, { recursive: true, force: true }));
  return cwd;
}

async function runCli(cwd, args, extraEnv = {}) {
  const env = { ...process.env, HOME: cwd, USERPROFILE: cwd, CI: "1", ...extraEnv };
  delete env.CIRVIX_API_URL;
  delete env.CIRVIX_API_KEY;
  try {
    return { ...(await exec(process.execPath, [cli, ...args], { cwd, env, timeout: 20000 })), code: 0 };
  } catch (error) {
    if (typeof error.code !== "number") throw error;
    return { stdout: error.stdout, stderr: error.stderr, code: error.code };
  }
}

test("launch: the sequence rests on the static plate, so nothing is readable only while it moves", () => {
  const { frames, settle, plain } = launchFrames();

  assert.ok(frames.length > 0);
  // The resting frame is the same *text* the plain header prints — the animated
  // path may add brand colour, but it may never add, drop, or move a character.
  assert.equal(stripAnsi(settle), stripAnsi(plain));
  assert.equal(stripAnsi(settle), stripAnsi(brandHeader({ width: LAUNCH_WIDTH })));
  assert.match(stripAnsi(settle), /AI AGENT RUNTIME GOVERNANCE/);
});

test("launch: every frame is the same height, so redrawing in place cannot smear", () => {
  const { frames } = launchFrames();
  for (const [i, frame] of frames.entries()) {
    assert.equal(frame.split("\n").length, LAUNCH_HEIGHT, `frame ${i + 1} changed the block height`);
  }
});

test("launch: the whole wordmark is on screen before the sequence ends", () => {
  const { frames } = launchFrames();
  const seen = frames.map((frame) => stripAnsi(frame));
  for (const [i, row] of logoRows(LAUNCH_WIDTH).entries()) {
    const glyphs = row.trim();
    if (!glyphs) continue;
    assert.ok(
      seen.some((frame) => frame.includes(glyphs)),
      `wordmark row ${i + 1} never appeared in full`,
    );
  }
});

test("launch: decoration never wears a verdict colour", async () => {
  await withEnv({ FORCE_COLOR: "1", CIRVIX_TRUECOLOR: "1", NO_COLOR: undefined, TERM: "xterm-256color" }, () => {
    const { frames, settle } = launchFrames();
    const all = frames.join("\n") + settle;

    // It is colourful — this is a brand plate, not a monochrome one.
    assert.ok(all.includes("\u001b[38;2;"), "expected truecolor brand sequences");
    // And none of that colour is a decision.
    assert.equal(all.match(VERDICT_SGR), null, "animation used permit/deny/hold chroma");
    assert.equal(all.match(/\u001b\[(4[123456]|10[123456])m/), null, "animation used a verdict background");
  });
});

test("launch: NO_COLOR degrades to plain text rather than escape garbage", async () => {
  await withEnv({ NO_COLOR: "1", FORCE_COLOR: undefined, CIRVIX_TRUECOLOR: undefined }, () => {
    const { frames, settle } = launchFrames();
    for (const frame of frames) {
      assert.equal(frame, stripAnsi(frame), "escapes survived NO_COLOR");
    }
    assert.equal(settle, stripAnsi(settle));
  });
});

test("launch: a 16-colour terminal gets the accent role, never a 24-bit sequence", async () => {
  await withEnv({ FORCE_COLOR: "1", CIRVIX_TRUECOLOR: "16", NO_COLOR: undefined, COLORTERM: undefined }, () => {
    assert.equal(colorDepth(), "16");
    const all = launchFrames().frames.join("\n");
    assert.ok(all.includes("\u001b[36m"), "expected the accent role as the 16-colour fallback");
    assert.equal(all.match(/\u001b\[38;[25];/), null, "24-bit or 256-colour sequence on a 16-colour terminal");
    assert.equal(all.match(VERDICT_SGR), null);
  });
});

test("launch: with motion off nothing is written at all", async () => {
  const stdout = ttyStream();
  const result = await playLaunch({ stdout, stdin: fakeStdin(), enabled: false });

  assert.deepEqual(result, { animated: false, frames: 0 });
  assert.equal(stdout.text(), "", "a disabled launch must not touch stdout");
});

test("launch: an enabled run draws, then lands on the plate and gives the cursor back", async () => {
  const stdout = ttyStream();
  const stdin = fakeStdin();
  const result = await withEnv(INTERACTIVE_ENV, () => playLaunch({ stdout, stdin, pace: 1 }));
  const text = stdout.text();

  assert.equal(result.animated, true);
  assert.ok(result.frames > 0);
  assert.ok(text.includes("\u001b[?25l"), "cursor was never hidden");
  assert.ok(text.includes("\u001b[?25h"), "cursor was left hidden");
  assert.ok(text.indexOf("\u001b[?25h") > text.indexOf("\u001b[?25l"));
  assert.match(stripAnsi(text), /AI AGENT RUNTIME GOVERNANCE/);
  assert.equal(stdin.rawMode, false, "stdin was left in raw mode");
});

test("launch: a keypress ends it early and still lands on the plate", async () => {
  const stdout = ttyStream();
  const stdin = fakeStdin();
  const total = launchFrames().frames.length;

  const result = await withEnv(INTERACTIVE_ENV, async () => {
    const playing = playLaunch({ stdout, stdin, pace: 6, budgetMs: 60_000 });
    assert.ok(await waitFor(() => stdout.chunks.length >= 3), "the sequence never started");
    stdin.press("q");
    return playing;
  });

  assert.equal(result.animated, true);
  assert.ok(result.frames < total, `skip did not shorten the run (${result.frames}/${total})`);
  assert.match(stripAnsi(stdout.text()), /AI AGENT RUNTIME GOVERNANCE/);
  assert.equal(stdin.rawMode, false, "stdin was left in raw mode after a skip");
});

test("launch: a CI environment suppresses motion even on a TTY", async () => {
  // The runner's own environment is a contract worth pinning: `CI` beats a
  // terminal, which is why a build log never grows an animation.
  const stdout = ttyStream();
  const result = await withEnv({ ...INTERACTIVE_ENV, CI: "1" }, () =>
    playLaunch({ stdout, stdin: fakeStdin(), pace: 1 }),
  );

  assert.deepEqual(result, { animated: false, frames: 0 });
  assert.equal(stdout.text(), "", "a CI run animated");
});

test("launch: the banner is skipped for json, CI, a pipe, and a narrow terminal", async () => {
  const cases = [
    ["--json", { json: true }, ttyStream()],
    ["CI", {}, ttyStream(), { CI: "1" }],
    ["a pipe", {}, ttyStream({ isTTY: false })],
    ["a narrow terminal", {}, ttyStream({ columns: LAUNCH_WIDTH })],
  ];

  for (const [label, options, stdout, gates] of cases) {
    // Each case starts from a clean interactive environment, so the banner is
    // skipped for the reason named in the label — not because the runner
    // happens to set `CI` for the whole file.
    await withEnv({ ...INTERACTIVE_ENV, ...(gates ?? {}) }, async () => {
      const result = await launchBanner({ stdout, stdin: fakeStdin(), ...options });
      assert.deepEqual(result, { animated: false, frames: 0 }, `${label} animated`);
      assert.equal(stdout.text(), "", `${label} wrote to stdout`);
    });
  }
});

test("launch: forcing the plate on a non-TTY prints it as plain text", async () => {
  const stdout = ttyStream({ isTTY: false });
  const result = await launchBanner({ stdout, stdin: fakeStdin(), force: true });

  assert.equal(result.animated, false);
  assert.equal(stripAnsi(stdout.text()).trimEnd(), stripAnsi(brandHeader({ width: LAUNCH_WIDTH })));
});

test("launch: existing callers of brandHeader still get the unaccented plate", () => {
  const plain = brandHeader({ width: LAUNCH_WIDTH });
  const accented = brandHeader({ width: LAUNCH_WIDTH, accent: true });

  // init / protect / interactive must not change because the launch screen exists.
  assert.equal(plain, stripAnsi(plain), "brandHeader gained colour by default");
  assert.equal(stripAnsi(accented), plain, "accent changed the plate's text");
});

test("launch: a piped run prints no escapes and no plate", async (t) => {
  const cwd = await workspace(t);
  const result = await runCli(cwd, []);

  assert.equal(result.code, 0);
  assert.equal(stripAnsi(result.stdout), result.stdout, "ANSI escapes reached a piped run");
  assert.match(result.stdout, /GET STARTED/, "the home screen did not render");
  assert.equal(result.stdout.match(/█████/), null, "the brand plate was drawn into a pipe");
});

test("launch: the plate reserves its rows before drawing, so it cannot scroll the buffer", async () => {
  // Without the reservation, starting `cirvix` near the bottom of the terminal
  // scrolls the buffer and every redraw then erases the user's earlier output.
  const stdout = ttyStream();
  await withEnv(INTERACTIVE_ENV, () => playLaunch({ stdout, stdin: fakeStdin(), pace: 1 }));

  const reservation = "\n".repeat(LAUNCH_HEIGHT - 1) + `\u001b[${LAUNCH_HEIGHT - 1}A`;
  const reservedAt = stdout.chunks.findIndex((chunk) => chunk === reservation);
  const firstFrameAt = stdout.chunks.findIndex((chunk) => chunk.includes("╭"));

  assert.notEqual(reservedAt, -1, "the block's rows were never reserved");
  assert.notEqual(firstFrameAt, -1, "no frame was drawn");
  assert.ok(firstFrameAt > reservedAt, "a frame was drawn before the rows were reserved");
});

test("launch: once the outline exists, every frame is a closed box", () => {
  // The wordmark must land *inside* a frame. Frames before `overlayFrom` are the
  // outline being drawn; every frame after it has both side borders on all ten
  // inner rows, so nothing floats outside the box.
  const { frames, overlayFrom } = launchFrames();
  assert.ok(overlayFrom > 0, "the outline has to be drawn before the wordmark");

  for (let i = overlayFrom; i < frames.length; i++) {
    const bordered = frames[i].split("\n").filter((line) => (line.match(/│/g) ?? []).length === 2).length;
    assert.equal(bordered, 10, `frame ${i + 1} left the box open`);
  }
});

test("launch: no frame re-sets a colour that is already active", async () => {
  await withEnv({ FORCE_COLOR: "1", CIRVIX_TRUECOLOR: "0", NO_COLOR: undefined }, () => {
    const { frames } = launchFrames();
    const COLOUR = /\u001b\[(?:38;5;\d+|38;2;\d+;\d+;\d+)m/g;

    let seen = 0;
    for (const [i, frame] of frames.entries()) {
      for (const line of frame.split("\n")) {
        const codes = [...line.matchAll(COLOUR)].map((m) => m[0]);
        seen += codes.length;
        for (let k = 1; k < codes.length; k++) {
          assert.notEqual(codes[k], codes[k - 1], `frame ${i + 1} re-set ${codes[k]} already active`);
        }
      }
    }
    assert.ok(seen > 100, `expected coloured frames, saw ${seen} colour sequences`);
  });
});

test("launch: the skip hint and status row are overlay-only, never part of the plate", () => {
  const { frames, overlayFrom, settle } = launchFrames();
  const overlaid = withOverlay(frames[overlayFrom], {
    eyebrow: statusRow({ label: "probing the runtime" }),
    hint: skipRow(),
  });

  assert.match(stripAnsi(overlaid), /probing the runtime/);
  assert.match(stripAnsi(overlaid), /press any key to skip/);
  assert.equal(overlaid.split("\n").length, LAUNCH_HEIGHT, "the overlay changed the block height");

  // The resting plate is the static header, so nothing transient survives into it.
  assert.doesNotMatch(stripAnsi(settle), /press any key to skip/);
  assert.doesNotMatch(stripAnsi(settle), /probing the runtime/);
});

test("launch: the status row follows the probe — phase, then findings, then gone", async () => {
  const stdout = ttyStream();
  const stdin = fakeStdin();
  let resolveProbe;
  const pending = new Promise((resolve) => {
    resolveProbe = resolve;
  });
  let findings = "";

  const playing = withEnv(INTERACTIVE_ENV, () =>
    playLaunch({
      stdout,
      stdin,
      pace: 20,
      pending,
      phase: () => "probing the runtime",
      summary: () => findings,
    }));

  assert.ok(
    await waitFor(() => visible(stdout.text()).includes("probing the runtime")),
    "the phase was never named while the probe was pending",
  );

  findings = "3 agents  ·  no policy  ·  runtime down";
  resolveProbe();
  assert.ok(
    await waitFor(() => visible(stdout.text()).includes("3 agents")),
    "the findings never replaced the phase",
  );

  const result = await playing;
  assert.equal(result.animated, true);

  // Whatever the resting frame is, it carries neither transient row.
  const resting = stdout.chunks
    .filter((chunk) => stripAnsi(chunk).includes("AI AGENT RUNTIME GOVERNANCE"))
    .pop() ?? "";
  assert.doesNotMatch(stripAnsi(resting), /press any key to skip/);
  assert.doesNotMatch(stripAnsi(resting), /probing the runtime|3 agents/);
});

test("launch: a light background never gets the near-white highlight", async () => {
  // #d8e6ff is invisible on white, so on the light theme the ramp inverts rather
  // than flashing rows that look blank.
  await withEnv({ FORCE_COLOR: "1", CIRVIX_TRUECOLOR: "1", NO_COLOR: undefined }, () => {
    const dark = launchFrames().frames.join("");
    assert.ok(dark.includes("216;230;255"), "the dark ramp should reach the highlight");

    setTheme("light");
    try {
      const light = launchFrames();
      const all = light.frames.join("") + light.settle;
      assert.equal(all.includes("216;230;255"), false, "near-white on a light background is invisible");
      assert.ok(all.includes("\u001b[38;2;"), "the light ramp still draws a gradient");
    } finally {
      setTheme("dark");
    }
  });
});

test("launch: the staggered digest writes exactly what the single write writes", async () => {
  const lines = ["", "  ◆ CIRVIX v0.2.4", "", "  GET STARTED", ""];

  const plain = ttyStream({ isTTY: false });
  await revealLines({ stdout: plain, stdin: fakeStdin(), lines, pace: 1 });
  assert.equal(plain.text(), lines.join("\n"));

  const staggered = ttyStream();
  const result = await withEnv(INTERACTIVE_ENV, () =>
    revealLines({ stdout: staggered, stdin: fakeStdin(), lines, pace: 1 }));

  assert.equal(result.staggered, true);
  assert.ok(staggered.chunks.length > 1, "the digest was written in one chunk");
  assert.equal(visible(staggered.text()), lines.join("\n"), "a TTY run and a piped run diverged");
  assert.ok(staggered.text().includes("\u001b[?25l") && staggered.text().includes("\u001b[?25h"));
});

test("launch: skipping the digest still prints every line", async () => {
  const lines = Array.from({ length: 12 }, (_, i) => `line ${i}`);
  const stdout = ttyStream();
  const stdin = fakeStdin();

  const running = withEnv(INTERACTIVE_ENV, () => revealLines({ stdout, stdin, lines, pace: 20 }));
  assert.ok(await waitFor(() => stdout.chunks.length >= 3), "the digest never started");
  stdin.press("q");
  await running;

  assert.equal(visible(stdout.text()), lines.join("\n"), "a skip cost the user output");
});

test("launch: --fast and --no-animation are the same home screen as the plain run", async (t) => {
  const cwd = await workspace(t);
  const plain = await runCli(cwd, []);
  const fast = await runCli(cwd, ["--fast"]);
  const off = await runCli(cwd, ["--no-animation"]);

  assert.equal(fast.code, 0);
  assert.equal(off.code, 0);
  assert.equal(fast.stdout, plain.stdout);
  assert.equal(off.stdout, plain.stdout);
});
