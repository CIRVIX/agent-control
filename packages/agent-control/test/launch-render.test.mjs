/**
 * Regression tests for the launch banner renderer.
 *
 * The bug these guard against: `redraw()` moved the cursor up rows but never
 * back to column 0, so after any frame that ended mid-line the next frame was
 * written at that column, wrapped, and every later frame landed one row further
 * down — the terminal filled with repeated box-drawing fragments and the banner
 * disintegrated (most visibly on Windows Terminal at 80/100/120 columns).
 *
 * The simulator below interprets exactly the escape vocabulary the renderer
 * uses (cursor up/down, erase line, SGR colours) plus autowrap, so the tests
 * assert on what a real terminal would show, not on the bytes emitted.
 */

import { describe, it } from "node:test";
import * as assert from "node:assert/strict";

import { launchBanner, launchFrames, LAUNCH_HEIGHT, LAUNCH_WIDTH } from "../src/core/ui/launch.mjs";
import { brandHeader, separator, logoRows, subtitleRow, panel } from "../src/core/ui/primitives.mjs";
import { stripAnsi } from "../src/core/format.mjs";

/** Minimal terminal screen: autowrap, cursor-up/down, erase-line, colours skipped. */
class Screen {
  constructor(cols, rows = 60) {
    this.cols = cols;
    this.rows = rows;
    this.isTTY = true;
    this.lines = [];
    this.y = 0;
    this.x = 0;
  }
  write(s) {
    let i = 0;
    while (i < s.length) {
      const rest = s.slice(i);
      const esc = /^\u001b\[([0-9]*)([AaBbKJ])/.exec(rest);
      if (esc) {
        const n = esc[1] === "" ? 1 : parseInt(esc[1], 10);
        if (esc[2] === "A") this.y = Math.max(0, this.y - n);
        else if (esc[2] === "B") this.y = Math.min(this.rows - 1, this.y + n);
        else if (esc[2] === "K") this.set(this.y, "");
        i += esc[0].length;
        continue;
      }
      const color = /^\u001b\[[0-9;?]*[a-zA-Z]/.exec(rest);
      if (color) { i += color[0].length; continue; }
      const ch = s[i];
      if (ch === "\n") { this.x = 0; this.y++; this.line(this.y); i++; continue; }
      if (ch === "\r") { this.x = 0; i++; continue; }
      this.put(ch);
      i++;
    }
  }
  line(y) { while (this.lines.length <= y) this.lines.push(""); return this.lines[y]; }
  set(y, v) { this.line(y); this.lines[y] = v; }
  put(ch) {
    const line = this.line(this.y).padEnd(this.x);
    this.lines[this.y] = line.slice(0, this.x) + ch + line.slice(this.x + 1);
    this.x++;
    if (this.x >= this.cols) { this.x = 0; this.y++; this.line(this.y); }
  }
  dump() { return this.lines; }
}

const visible = (s) => stripAnsi(s);

describe("launch frames geometry", () => {
  it("every frame is exactly LAUNCH_HEIGHT rows and within the plate width", () => {
    const { frames } = launchFrames({ width: LAUNCH_WIDTH });
    for (const frame of frames) {
      const rows = frame.split("\n");
      assert.equal(rows.length, LAUNCH_HEIGHT);
      for (const row of rows) {
        assert.ok(visible(row).length <= LAUNCH_WIDTH + 6,
          `frame row too wide: ${visible(row).length}`);
      }
    }
  });

  it("the resting frame is byte-identical to the static brandHeader", () => {
    const { settle } = launchFrames({ width: LAUNCH_WIDTH });
    assert.equal(settle, brandHeader({ width: LAUNCH_WIDTH, accent: true }));
  });
});

describe("redraw column discipline (regression: repeated border fragments)", () => {
  for (const cols of [80, 100, 120, 160, 200]) {
    it(`renders a clean 12-row plate at ${cols} columns`, async () => {
      const screen = new Screen(cols);
      await launchBanner({
        stdout: screen,
        stdin: { isTTY: false },
        force: true,
        pace: 0,
        pending: Promise.resolve(null),
        phase: () => "scanning",
        summary: () => "done",
      });
      const dump = screen.dump();
      const ruleRows = dump.filter((l) => (l.match(/╭|╰/g) || []).length > 0).length;
      // Exactly one top and one bottom rule may survive on screen.
      assert.ok(ruleRows <= 2, `expected <=2 border rows, got ${ruleRows} at cols=${cols}:\n${dump.join("\n")}`);
      const used = dump.filter((l) => l.trim().length > 0).length;
      assert.ok(used <= LAUNCH_HEIGHT, `plate overflowed its ${LAUNCH_HEIGHT} rows at cols=${cols}`);
      // The wordmark and the subtitle must both be intact.
      assert.ok(dump.some((l) => l.includes("█")), "wordmark missing");
      assert.ok(dump.some((l) => visible(l).includes("AI AGENT RUNTIME GOVERNANCE")), "subtitle missing");
      // No wrapped garbage: every visible line fits the terminal.
      for (const l of dump) assert.ok(visible(l).length <= cols, "line wider than terminal");
    });
  }

  it("missing stdout.columns still renders within the 80-column fallback", async () => {
    const screen = new Screen(80);
    await launchBanner({ stdout: screen, stdin: { isTTY: false }, force: true, pace: 0 });
    for (const l of screen.dump()) {
      assert.ok(visible(l).length <= 80, "fallback width not respected");
    }
  });

  it("non-TTY output is never animated and emits nothing", async () => {
    const out = { isTTY: false, write(s) { this.buf += s; }, buf: "" };
    const res = await launchBanner({ stdout: out, stdin: { isTTY: false } });
    assert.equal(res.animated, false);
    assert.equal(out.buf, "");
  });
});

describe("dimension validation", () => {
  it("brandHeader tolerates NaN, negative, zero, and infinite widths", () => {
    for (const bad of [NaN, -5, 0, Infinity, undefined, "not-a-number"]) {
      const header = brandHeader({ width: bad });
      const rows = header.split("\n");
      assert.equal(rows.length, 12);
      for (const r of rows) assert.equal(visible(r).length, 64); // 58 plate + margins/glyphs
    }
  });

  it("logoRows and subtitleRow clamp invalid widths to the default", () => {
    for (const rows of [logoRows(NaN), logoRows(-3), logoRows(Infinity)]) {
      assert.equal(rows.length, 6);
      for (const r of rows) assert.equal(r.length, 58);
    }
    assert.equal(subtitleRow(NaN).length, 58);
  });

  it("separator never receives an invalid repeat count", () => {
    assert.equal(visible(separator(NaN)).length, 62);
    assert.equal(visible(separator(-10)).length, 62);
    assert.doesNotThrow(() => separator(0));
  });

  it("panel with a zero/negative width falls back to content-derived width", () => {
    const p = panel({ lines: ["hello"], width: -1 });
    assert.ok(p.includes("hello"));
  });

  it("output is deterministic for identical inputs", () => {
    assert.equal(brandHeader({ width: 58 }), brandHeader({ width: 58 }));
    assert.equal(brandHeader({ width: 58, accent: true }), brandHeader({ width: 58, accent: true }));
  });
});

