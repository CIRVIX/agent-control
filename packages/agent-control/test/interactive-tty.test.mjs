import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { interactive } from "../src/commands/interactive.mjs";
import { stripAnsi } from "../src/core/format.mjs";

function createMockTerminal({ columns = 80, rows = 24 } = {}) {
  const stdin = new EventEmitter();
  stdin.isTTY = true;
  stdin.setRawMode = () => {};
  stdin.resume = () => {};
  stdin.pause = () => {};
  stdin.setEncoding = () => {};
  stdin.send = (str) => stdin.emit("data", Buffer.from(str));

  const stdout = new EventEmitter();
  stdout.isTTY = true;
  stdout.columns = columns;
  stdout.rows = rows;
  const chunks = [];
  stdout.write = (chunk) => {
    chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    return true;
  };
  stdout.getOutput = () => chunks.join("");
  stdout.clearOutput = () => { chunks.length = 0; };
  stdout.resize = (cols, r) => {
    stdout.columns = cols;
    stdout.rows = r;
    stdout.emit("resize");
  };

  return { stdin, stdout };
}

async function createTempWorkspace(t) {
  const cwd = await mkdtemp(join(tmpdir(), "cirvix-tty-test-"));
  t.after(() => rm(cwd, { recursive: true, force: true }));
  return cwd;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(fn, timeout = 5000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (fn()) return;
    await sleep(20);
  }
  throw new Error("Timed out waiting for condition");
}

test("interactive TTY: clean exit on Ctrl+C (\\x03)", async (t) => {
  const cwd = await createTempWorkspace(t);
  const { stdin, stdout } = createMockTerminal();

  let exitedCode = null;
  const runner = interactive({
    cwd,
    flags: { fast: true },
    rules: [],
    stdin,
    stdout,
    onExit: (code) => { exitedCode = code; },
  });

  await waitFor(() => stdout.getOutput().includes("\x1b[?1049h"));
  await waitFor(() => stdout.getOutput().includes("$ "));

  // Send Ctrl+C
  stdin.send("\x03");
  const code = await runner;

  assert.equal(code, 0);
  assert.equal(exitedCode, 0);
  assert.match(stdout.getOutput(), /\x1b\[\?1049l/); // exited alt screen
});

test("interactive TTY: Escape closes help modal and clears input mode", async (t) => {
  const cwd = await createTempWorkspace(t);
  const { stdin, stdout } = createMockTerminal();

  let exitedCode = null;
  const runner = interactive({
    cwd,
    flags: { fast: true },
    rules: [],
    stdin,
    stdout,
    onExit: (code) => { exitedCode = code; },
  });

  await waitFor(() => stdout.getOutput().includes("$ "));
  stdout.clearOutput();

  // Press '?' to open help
  stdin.send("?");
  await waitFor(() => stdout.getOutput().includes("CIRVIX HELP"));

  // Press Escape to close help
  stdout.clearOutput();
  stdin.send("\x1b");
  await waitFor(() => stdout.getOutput().includes("ACTIVITY"));

  // Type characters into prompt
  stdin.send("s");
  stdin.send("t");
  await waitFor(() => stdout.getOutput().includes("$ st█"));

  // Press Escape to cancel input mode
  stdout.clearOutput();
  stdin.send("\x1b");
  await waitFor(() => stdout.getOutput().includes("$ _"));

  // Clean exit
  stdin.send("\x03");
  await runner;
});

test("interactive TTY: multiline paste executes commands sequentially", async (t) => {
  const cwd = await createTempWorkspace(t);
  const { stdin, stdout } = createMockTerminal();

  const runner = interactive({
    cwd,
    flags: { fast: true },
    rules: [],
    stdin,
    stdout,
    onExit: () => {},
  });

  await waitFor(() => stdout.getOutput().includes("$ "));
  stdout.clearOutput();

  // Paste multiple lines with newlines
  stdin.send("status\naudit\n");
  await waitFor(() => stdout.getOutput().includes("CIRVIX AUDIT"));

  // Clean exit
  stdin.send("\x03");
  await runner;
});

test("interactive TTY: bracketed paste executes command inside tags", async (t) => {
  const cwd = await createTempWorkspace(t);
  const { stdin, stdout } = createMockTerminal();

  const runner = interactive({
    cwd,
    flags: { fast: true },
    rules: [],
    stdin,
    stdout,
    onExit: () => {},
  });

  await waitFor(() => stdout.getOutput().includes("$ "));
  stdout.clearOutput();

  // Paste with ANSI bracketed paste sequence
  stdin.send("\x1b[200~status\n\x1b[201~");
  await waitFor(() => stdout.getOutput().includes("status — live"));

  // Clean exit
  stdin.send("\x03");
  await runner;
});

test("interactive TTY: terminal resize redraws dynamically without crash", async (t) => {
  const cwd = await createTempWorkspace(t);
  const { stdin, stdout } = createMockTerminal({ columns: 80, rows: 24 });

  const runner = interactive({
    cwd,
    flags: { fast: true },
    rules: [],
    stdin,
    stdout,
    onExit: () => {},
  });

  await waitFor(() => stdout.getOutput().includes("$ "));
  stdout.clearOutput();

  // Resize to narrow terminal
  stdout.resize(45, 18);
  await waitFor(() => stdout.getOutput().includes("CIRVIX"));

  // Resize to wide terminal
  stdout.clearOutput();
  stdout.resize(120, 40);
  await waitFor(() => stdout.getOutput().includes("CIRVIX"));

  // Clean exit
  stdin.send("\x03");
  await runner;
});

test("interactive TTY: backspace edits input buffer", async (t) => {
  const cwd = await createTempWorkspace(t);
  const { stdin, stdout } = createMockTerminal();

  const runner = interactive({
    cwd,
    flags: { fast: true },
    rules: [],
    stdin,
    stdout,
    onExit: () => {},
  });

  await waitFor(() => stdout.getOutput().includes("$ "));

  // Type "xyz"
  stdin.send("x");
  stdin.send("y");
  stdin.send("z");
  await waitFor(() => stdout.getOutput().includes("$ xyz█"));

  // Send backspace (\x7f)
  stdout.clearOutput();
  stdin.send("\x7f");
  await waitFor(() => stdout.getOutput().includes("$ xy█"));

  // Send backspace (\x08)
  stdout.clearOutput();
  stdin.send("\x08");
  await waitFor(() => stdout.getOutput().includes("$ x█"));

  // Clean exit
  stdin.send("\x03");
  await runner;
});

test("interactive TTY: empty state displays clear guidance when no decisions exist", async (t) => {
  const cwd = await createTempWorkspace(t);
  const { stdin, stdout } = createMockTerminal();

  const runner = interactive({
    cwd,
    flags: { fast: true },
    rules: [],
    stdin,
    stdout,
    onExit: () => {},
  });

  await waitFor(() => stdout.getOutput().includes("No security decisions yet"));
  const output = stdout.getOutput();
  assert.match(output, /No security decisions yet/);
  assert.match(output, /Cirvix is ready to inspect agent activity/);
  assert.match(output, /cirvix demo/);
  assert.match(output, /cirvix init/);

  stdin.send("\x03");
  await runner;
});

test("interactive TTY: Enter inspects decision details and Esc returns to list", async (t) => {
  const cwd = await createTempWorkspace(t);
  const { stdin, stdout } = createMockTerminal();

  // Create audit.jsonl with a demo decision
  const { mkdir, writeFile } = await import("node:fs/promises");
  const stateDir = join(cwd, ".cirvix");
  await mkdir(stateDir, { recursive: true });
  const sampleEvent = {
    request_id: "req_test_01",
    decision_id: "dec_test_01",
    run_id: "run_demo_123",
    timestamp: "2026-09-18T10:00:00.000Z",
    tool: "read_file",
    action: "filesystem.read",
    resource: "~/.aws/credentials",
    decision: "deny",
    verdict: "deny",
    risk: "critical",
    policy: "deny-credential-directories",
    reason: "Credential directories are not readable outside an approved secrets flow.",
    latency_ms: 2.5,
  };
  await writeFile(join(stateDir, "audit.jsonl"), JSON.stringify(sampleEvent) + "\n", "utf8");

  const runner = interactive({
    cwd,
    flags: { fast: true },
    rules: [],
    stdin,
    stdout,
    onExit: () => {},
  });

  await waitFor(() => stripAnsi(stdout.getOutput()).includes("SECURITY DEMO"));
  const listOutput = stripAnsi(stdout.getOutput());
  assert.match(listOutput, /SECURITY DEMO/);
  assert.match(listOutput, /SIMULATED EVENTS/);
  assert.match(listOutput, /BLOCKED/);
  assert.match(listOutput, /read_file/);

  // Press Enter to inspect decision
  stdout.clearOutput();
  stdin.send("\r");
  await waitFor(() => stripAnsi(stdout.getOutput()).includes("DECISION DETAILS"));
  const detailOutput = stripAnsi(stdout.getOutput());
  assert.match(detailOutput, /DECISION DETAILS/);
  assert.match(detailOutput, /BLOCKED \(DENY\)/);
  assert.match(detailOutput, /No action was executed/);
  assert.match(detailOutput, /Credential directories are not readable/);
  assert.match(detailOutput, /FORENSICS/);
  assert.match(detailOutput, /req_test_01/);
  assert.match(detailOutput, /\[Esc\] Back to decisions/);

  // Press Escape to return to activity list
  stdout.clearOutput();
  stdin.send("\x1b");
  await waitFor(() => stripAnsi(stdout.getOutput()).includes("SECURITY DEMO"));

  stdin.send("\x03");
  await runner;
});
