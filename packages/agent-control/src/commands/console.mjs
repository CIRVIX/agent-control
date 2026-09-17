/**
 * `cirvix console` — the primary product interface.
 *
 * Interactive when attached to a TTY, one-shot when piped:
 *   cirvix console                        # full REPL
 *   echo "read ~/.aws/credentials" | cirvix console --once
 *   cirvix console --eval "deploy to production"
 *
 * `--once` / `--eval` exist so the product UI is scriptable and testable:
 * the same cards render in CI as in the terminal.
 */

import { ConsoleApp } from "../tui/app.mjs";

export async function consoleCmd({ cwd = process.cwd(), rules = [], mode = "enforce", evalText = null, once = false, write = (s) => process.stdout.write(s) } = {}) {
  const app = new ConsoleApp({ cwd, rules, mode, write });

  if (evalText) {
    const out = await app.runOnce(evalText);
    if (out && out !== "quit") write(out + "\n");
    return { app, output: out };
  }

  if (once || !process.stdin.isTTY) {
    // Piped: evaluate each line, print cards, exit. Never start readline
    // on a non-TTY — it would hang waiting for a terminal that is not there.
    const chunks = await readStdin();
    const lines = chunks.split("\n").map((l) => l.trim()).filter(Boolean);
    let output = "";
    for (const line of lines) {
      const out = await app.runOnce(line);
      if (out && out !== "quit") {
        write(out + "\n");
        output += out + "\n";
      }
    }
    if (!lines.length) {
      const help = app.renderTranscript();
      write(help + "\n");
      return { app, output: help };
    }
    return { app, output };
  }

  await app.start();
  return { app, output: "" };
}

function readStdin() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve("");
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (data += c));
    process.stdin.on("end", () => resolve(data));
    setTimeout(() => resolve(data), 1000);
  });
}
