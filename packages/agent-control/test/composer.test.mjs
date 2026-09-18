import { it } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { startComposer } from "../src/tui/composer.mjs";
import { ConsoleApp } from "../src/tui/app.mjs";

const tick = () => new Promise((resolve) => setImmediate(resolve));
function tty() {
  const input = new PassThrough();
  const output = new PassThrough();
  input.isTTY = output.isTTY = true;
  output.columns = 80;
  input.setRawMode = (value) => { input.isRaw = value; };
  let text = "";
  output.on("data", (chunk) => { text += chunk; });
  return { input, output, text: () => text };
}
function fixture(t, options = {}) {
  const streams = tty();
  const lines = [];
  const rl = startComposer({ ...streams, onLine: (line) => { lines.push(line); }, ...options });
  t.after(() => { rl.close(); streams.input.destroy(); streams.output.destroy(); });
  return { ...streams, rl, lines, send: async (text) => { streams.input.write(text); await tick(); } };
}

it("imports and renders the console with an injected writer", () => {
  const app = new ConsoleApp({ write: () => {} });
  assert.match(app.renderTranscript(), /CIRVIX/);
});

it("submits once and preserves readline history", async (t) => {
  const f = fixture(t);
  await f.send("hello\r");
  assert.deepEqual(f.lines, ["hello"]);
  await f.send("\x1b[A");
  assert.equal(f.rl.line, "hello");
});

it("cancels draft and continuation without exiting, including empty Ctrl+C", async (t) => {
  const f = fixture(t);
  await f.send("first\\\rsecond\x03");
  assert.equal(f.rl.line, "");
  assert.equal(f.rl.snapshot().pending, "");
  await f.send("\x03next\r");
  assert.deepEqual(f.lines, ["next"]);
});

it("bracketed paste is a single draft until explicit Enter, even with split delimiters", async (t) => {
  const f = fixture(t);
  await f.send("before ");
  for (const chunk of ["\x1b[20", "0~a\r\nb\nc", "\x1b[201", "~"]) await f.send(chunk);
  assert.deepEqual(f.lines, []);
  assert.equal(f.rl.snapshot().draft, "before a\nb\nc");
  await f.send("\r");
  assert.deepEqual(f.lines, ["before a\nb\nc"]);
});

it("filters palette, navigates and submits only the highlighted command", async (t) => {
  const f = fixture(t);
  await f.send("/pol");
  assert.equal(f.rl.snapshot().palette.query, "/pol");
  await f.send("\x1b[B\r");
  assert.deepEqual(f.lines, ["/policy test"]);
  assert.equal(f.rl.snapshot().palette, null);
});

it("Escape preserves the exact draft and cursor without redraw reopening", async (t) => {
  const f = fixture(t);
  await f.send("/pol  \x1b[D\x1b[D");
  const before = { draft: f.rl.line, cursor: f.rl.cursor };
  f.input.emit("keypress", "\x1b", { name: "escape" });
  f.rl.refresh();
  assert.equal(f.rl.snapshot().palette, null);
  assert.deepEqual({ draft: f.rl.line, cursor: f.rl.cursor }, before);
  await f.send("i");
  assert.equal(f.rl.snapshot().palette, null);
});

it("serializes newline submissions and exposes errors", async (t) => {
  const seen = [];
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const f = fixture(t, { onLine: async (line) => {
    seen.push(line);
    if (line === "one") await gate;
    if (line === "two") throw new Error("visible failure");
  } });
  await f.send("one\ntwo\nthree\n");
  assert.deepEqual(seen, ["one"]);
  release();
  await tick();
  assert.deepEqual(seen, ["one", "two", "three"]);
  assert.match(f.text(), /visible failure/);
});
