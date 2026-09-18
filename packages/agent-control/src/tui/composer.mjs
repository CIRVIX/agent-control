/**
 * Composer — console input adapter with explicit session semantics.
 *
 * - Ctrl+C cancels the current draft, the trailing-backslash continuation
 *   buffer, queued lines and any in-flight submission. It NEVER exits the
 *   console, including when the draft is empty; deliberate exit is `/quit`
 *   (or Ctrl+D).
 * - Bracketed paste (mode 2004) is intercepted before readline: the whole
 *   paste becomes draft text and newlines inside a paste never submit.
 * - Submissions are serialized: one line is evaluated at a time, later
 *   lines queue without duplicates, and errors surface via `onError`.
 * - Only public readline primitives are used; tests inject fake TTY
 *   streams through `input`/`output`.
 */
import readline from "node:readline";
import { PassThrough } from "node:stream";
import { filterCommands } from "./palette.mjs";
import { dim } from "../core/theme.mjs";

export const KEY_HINT = dim("Enter send · trailing \\ continues · ↑↓ history · Tab commands · / or Ctrl+K palette · Esc close · Ctrl+C cancel · /quit exit");

export function composerBox() {
  return `CIRVIX\n${KEY_HINT}`;
}

function completer(line) {
  if (!line.startsWith("/")) return [[], line];
  return [filterCommands(line).map((c) => c.name), line];
}

export function startComposer({ prompt = "> ", history = [], onLine, onKey, onChange, onError, input = process.stdin, output = process.stdout, transient = { palette: null } }) {
  const terminal = Boolean(input.isTTY && output.isTTY);
  const adapter = new PassThrough();
  adapter.isTTY = terminal;
  adapter.setRawMode = (value) => input.setRawMode?.(value);
  const rl = readline.createInterface({ input: adapter, output, prompt, completer, history, terminal });
  let draft = "";
  const savedDrafts = new Map();
  const display = (text) => text.replace(/\n/g, "⏎");
  let pending = "";
  let paste = null;
  let closed = false;
  let running = false;
  let active = null;
  const queue = [];

  const notify = () => onChange?.(snapshot());
  const snapshot = () => ({ draft, cursor: rl.cursor, pending, palette: transient.palette, busy: running, queued: queue.length });
  const refresh = () => { if (!closed) rl.prompt(true); };
  const clearDraft = () => {
    rl.write(null, { ctrl: true, name: "e" });
    rl.write(null, { ctrl: true, name: "u" });
    draft = "";
  };
  const report = (error) => {
    if (onError) onError(error);
    else output.write(`\nError: ${error?.message ?? error}\n`);
  };
  const drain = async () => {
    if (running || closed) return;
    running = true;
    while (queue.length && !closed) {
      const line = queue.shift();
      active = new AbortController();
      try {
        const verdict = await onLine?.(line, { signal: active.signal });
        if (verdict === "quit" && !active.signal.aborted) rl.close();
      } catch (error) {
        report(error);
      }
      active = null;
    }
    running = false;
    refresh();
  };
  const submit = (line) => {
    if (line.endsWith("\\")) {
      pending += line.slice(0, -1) + "\n";
      rl.setPrompt("… ");
      refresh();
      return;
    }
    const full = pending + line;
    pending = "";
    rl.setPrompt(prompt);
    if (full.trim()) queue.push(full);
    void drain();
  };
  const cancel = () => {
    pending = "";
    paste = null;
    queue.length = 0;
    active?.abort();
    transient.palette = null;
    clearDraft();
    rl.setPrompt(prompt);
    notify();
    refresh();
  };
  rl.on("SIGINT", cancel);
  rl.on("line", (line) => {
    const full = terminal ? draft : line;
    if (terminal) savedDrafts.set(line, full);
    draft = "";
    submit(full);
  });

  const keypress = (str, key = {}) => {
    if (closed) return;
    if (key.name === "paste-start") { paste = ""; return; }
    if (key.name === "paste-end") {
      if (paste !== null) {
        const text = paste.replace(/\r\n?/g, "\n");
        draft = draft.slice(0, rl.cursor) + text + draft.slice(rl.cursor);
        rl.write(display(text));
        paste = null;
        if (transient.palette) transient.palette = { query: rl.line, selected: 0 };
        notify();
      }
      return;
    }
    if (paste !== null) { paste += str ?? key.sequence ?? ""; return; }
    if (key.ctrl && key.name === "c") { cancel(); return; }
    if (key.name === "escape") {
      transient.palette = null;
      onKey?.("escape");
      notify();
      return;
    }
    if (key.ctrl && key.name === "k") {
      transient.palette = { query: rl.line.startsWith("/") ? rl.line : "/", selected: 0 };
      notify();
      return;
    }
    const shortcuts = { o: "toggle-activity", p: "policies", a: "audit", s: "session", l: "clear" };
    if (key.ctrl && shortcuts[key.name]) { onKey?.(shortcuts[key.name]); return; }
    const palette = transient.palette;
    if (palette && (key.name === "up" || key.name === "down")) {
      const count = filterCommands(palette.query).length;
      palette.selected = count ? (palette.selected + (key.name === "up" ? -1 : 1) + count) % count : 0;
      notify();
      return;
    }
    if (key.name === "return" || key.name === "enter") {
      const selected = palette && filterCommands(palette.query)[palette.selected];
      transient.palette = null;
      if (selected) { clearDraft(); draft = selected.name; rl.write(selected.name); }
      if (palette) notify();
      adapter.emit("keypress", str, key);
      return;
    }
    const before = rl.line;
    const previous = draft;
    adapter.emit("keypress", str, key);
    if (rl.line !== before) {
      if (key.name === "up" || key.name === "down") draft = savedDrafts.get(rl.line) ?? rl.line;
      else {
        let start = 0;
        while (start < before.length && start < rl.line.length && before[start] === rl.line[start]) start++;
        let end = 0;
        while (end < before.length - start && end < rl.line.length - start && before[before.length - 1 - end] === rl.line[rl.line.length - 1 - end]) end++;
        draft = previous.slice(0, start) + rl.line.slice(start, rl.line.length - end) + (end ? previous.slice(-end) : "");
      }
      if (transient.palette || (!before.startsWith("/") && rl.line.startsWith("/"))) {
        transient.palette = rl.line.startsWith("/") ? { query: rl.line, selected: 0 } : null;
      }
      notify();
    }
  };
  const end = () => { adapter.end(); };
  if (terminal) {
    readline.emitKeypressEvents(input);
    input.on("keypress", keypress);
    input.on("end", end);
    output.write("\x1b[?2004h");
  } else input.pipe(adapter);
  rl.on("close", () => {
    closed = true;
    queue.length = 0;
    active?.abort();
    input.removeListener("keypress", keypress);
    input.removeListener("end", end);
    input.unpipe(adapter);
    if (terminal) { output.write("\x1b[?2004l"); input.pause(); }
    adapter.destroy();
  });
  rl.snapshot = snapshot;
  rl.refresh = refresh;
  rl.cancel = cancel;
  refresh();
  return rl;
}

export { completer };
