/**
 * Composer — the input box. Multiline, history, paste, autocomplete.
 *
 * Built on node:readline (zero deps) rather than a bespoke ANSI editor:
 * - multiline via Shift+Enter semantics: plain Enter sends, and a trailing
 *   `\` continues the line; pasted multi-line blocks are joined safely.
 * - ↑↓ history, Ctrl+R reverse search, Ctrl+C cancel, Ctrl+L clear, Tab
 *   completion come from readline itself.
 * - `/` prefix triggers the command palette; Tab completes it.
 * - Ctrl+K opens the palette, Ctrl+O toggles activity, Ctrl+P policies,
 *   Ctrl+A audit, Ctrl+S session, Esc closes overlays.
 *
 * The composer never evaluates policy itself — it emits lines to the app.
 */

import readline from "node:readline";
import { filterCommands } from "./palette.mjs";
import { dim, bold } from "../core/theme.mjs";

export const KEY_HINT = dim("Enter ↵ send   Shift+Enter newline   ↑↓ history   Tab commands   / palette   Ctrl+K palette   Esc close");

export function composerBox() {
  return `${dim("╭─ CIRVIX ─" + "─".repeat(50) + "╮")}\n${dim("│")}  ${dim("Ask Cirvix anything... type / for commands")}\n${dim("╰" + "─".repeat(60) + "╯")}\n  ${KEY_HINT}`;
}

function completer(line) {
  if (!line.startsWith("/")) return [[], line];
  const matches = filterCommands(line).map((c) => c.name);
  return [matches, line];
}

/**
 * Start the interactive prompt. `onLine` may be async; return "quit" from
 * it (or type /quit) to exit. Returns a handle with `close()`.
 */
export function startComposer({ prompt = "> ", history = [], onLine, onKey }) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt,
    completer,
    history,
    terminal: Boolean(process.stdin.isTTY),
  });

  // Extra shortcuts beyond readline's builtins.
  if (process.stdin.isTTY) {
    readline.emitKeypressEvents(process.stdin);
    const onKeypress = (str, key = {}) => {
      if (key.name === "escape") onKey?.("escape");
      else if (key.ctrl && key.name === "k") { rl.write("/"); onKey?.("palette"); }
      else if (key.ctrl && key.name === "o") onKey?.("toggle-activity");
      else if (key.ctrl && key.name === "p") onKey?.("policies");
      else if (key.ctrl && key.name === "a") onKey?.("audit");
      else if (key.ctrl && key.name === "s") onKey?.("session");
      else if (key.ctrl && key.name === "l") { console.clear(); rl.prompt(); }
    };
    process.stdin.on("keypress", onKeypress);
    rl.on("close", () => process.stdin.removeListener("keypress", onKeypress));
  }

  // Trailing-backslash continuation = Shift+Enter equivalent for terminals
  // that cannot distinguish the two.
  let pending = "";
  rl.on("line", async (line) => {
    if (line.endsWith("\\")) {
      pending += line.slice(0, -1) + "\n";
      rl.setPrompt("… ");
      rl.prompt();
      return;
    }
    const full = (pending + line).trim();
    pending = "";
    rl.setPrompt(prompt);
    try {
      const verdict = await onLine?.(full);
      if (verdict === "quit") rl.close();
      else rl.prompt();
    } catch {
      rl.prompt();
    }
  });

  rl.prompt();
  return rl;
}

export { completer };
