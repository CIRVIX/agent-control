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

export async function consoleCmd({ cwd = process.cwd(), rules = [], policyFilePresent = null, mode = "enforce", evalText = null, once = false, write = (s) => process.stdout.write(s) } = {}) {
  const app = new ConsoleApp({ cwd, rules, policyFilePresent, mode, write });
  if (evalText || once || !process.stdin.isTTY) return oneShot(app, evalText, write);
  if (!process.stdout.isTTY) throw new Error("cirvix console requires a TTY on stdout for the interactive preview.");
  await app.start();
  return { app, output: "" };
}

async function oneShot(app, evalText, write) {
  const run = async (text) => {
    const out = await app.runOnce(text);
    if (out && out !== "quit") {
      write(out + "\n");
      return out + "\n";
    }
    return "";
  };
  if (evalText) return { app, output: await run(evalText) };
  const chunks = await readStdin();
  const lines = chunks.split("\n").map((l) => l.trim()).filter(Boolean);
  let output = "";
  for (const line of lines) output += await run(line);
  if (!lines.length) {
    const help = app.renderTranscript();
    write(help + "\n");
    return { app, output: help };
  }
  return { app, output };
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
