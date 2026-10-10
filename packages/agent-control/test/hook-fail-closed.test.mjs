/**
 * EVERY FAILURE BRANCH OF THE CLAUDE CODE HOOK, run as the real process.
 *
 * The hook is the surface that governs Bash, so the question this file answers is
 * not "does the hook work" but "what happens when the hook cannot answer". Each
 * row is a way the hook can fail to reach a decision, crossed with the posture,
 * crossed with whether the tool is consequential:
 *
 *   branch (malformed payload, no runtime, unreachable runtime)
 *   × posture (enforcing default, explicit open, explicit dev profile, typo)
 *   × tool (Bash = consequential, Read = read-only)
 *
 * The invariant the whole file exists for: in the DEFAULT posture, an
 * unevaluated consequential call is DENIED, and an unevaluated read-only call is
 * allowed but RECORDED — never allowed silently, and never allowed because
 * somebody assumed the default was permissive.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const hook = fileURLToPath(new URL("../../../integrations/claude-code/hook.mjs", import.meta.url));

function invoke({ stdin, fail = undefined, state = undefined, identityMode = undefined }) {
  const env = { ...process.env, NO_COLOR: "1" };
  delete env.CIRVIX_HOOK_FAIL;
  delete env.CIRVIX_STATE;
  delete env.CIRVIX_IDENTITY_MODE;
  delete env.CIRVIX_AGENT;
  if (fail !== undefined) env.CIRVIX_HOOK_FAIL = fail;
  if (state !== undefined) env.CIRVIX_STATE = state;
  if (identityMode !== undefined) env.CIRVIX_IDENTITY_MODE = identityMode;
  let result;
  if (process.platform === "win32") {
    // Write stdin through the shell explicitly: PowerShell's spawnSync input
    // piping swallows the payload, so the hook sees EOF and answers for the
    // wrong scenario.
    const script = `$input | & ${JSON.stringify(process.execPath)} ${JSON.stringify(hook)}`;
    result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
      input: stdin, encoding: "utf8", env, timeout: 15000,
    });
  } else {
    result = spawnSync(process.execPath, [hook], {
      input: stdin, encoding: "utf8", env, timeout: 15000,
    });
  }
  assert.equal(result.error, undefined, String(result.error));
  assert.equal(result.status, 0, `hook exited ${result.status}: ${result.stderr}`);
  return { stdout: String(result.stdout ?? ""), stderr: String(result.stderr ?? "") };
}

function decision(stdout) {
  return JSON.parse(stdout).hookSpecificOutput.permissionDecision;
}

function reason(stdout) {
  return JSON.parse(stdout).hookSpecificOutput.permissionDecisionReason;
}

/* ------------------------------------------------------------------ */
/*  Branch 1 — the payload cannot be parsed                            */
/* ------------------------------------------------------------------ */

// A payload that never parsed cannot be evaluated *because* it looked safe. In
// the default posture that is a denial: an unreadable request is not a safe one.
for (const stdin of ["{not json", "[1,2,3]", "42"]) {
  test(`malformed payload (${stdin}) is DENIED by default`, async (t) => {
    const state = await mkdtemp(join(tmpdir(), "cirvix-hook-"));
    t.after(() => rm(state, { recursive: true, force: true }));
    const { stdout, stderr } = invoke({ stdin, state });
    assert.equal(decision(stdout), "deny");
    assert.match(reason(stdout), /could not be evaluated/);
    assert.match(reason(stdout), /CIRVIX_HOOK_FAIL=open only if you intend/);
    assert.match(stderr, /not evaluated/);
  });

  test(`malformed payload (${stdin}) is allowed only when compatibility was selected`, async (t) => {
    const state = await mkdtemp(join(tmpdir(), "cirvix-hook-"));
    t.after(() => rm(state, { recursive: true, force: true }));
    const opened = invoke({ stdin, fail: "open", state });
    assert.equal(decision(opened.stdout), "allow");
    assert.match(reason(opened.stdout), /Compatibility posture is in force/);
    assert.equal(decision(invoke({ stdin, identityMode: "dev-insecure", state }).stdout), "allow");
  });
}

test("an EMPTY payload is not malformed — it is an empty request, and an unclassified request is denied", async (t) => {
  /* An explicit state dir, always: without one the hook resolves the state
     directory from its cwd, and a test that writes into the checkout is a test
     that leaves artifacts behind for the next person. */
  const state = await mkdtemp(join(tmpdir(), "cirvix-hook-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  const { stdout } = invoke({ stdin: "", state });
  assert.equal(decision(stdout), "deny");
  assert.match(reason(stdout), /not evaluated|initialized/i);
});

test("a typo in CIRVIX_HOOK_FAIL does not open the boundary", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-hook-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  const { stdout } = invoke({ stdin: "{not json", fail: "opne", state });
  assert.equal(decision(stdout), "deny");
  /* And the typo is recorded as the REASON, so the operator can see that the
     setting they wrote is not the setting that took effect. */
  const recorded = JSON.parse(await readFile(join(state, "claude-code-hook.json"), "utf8"));
  assert.match(recorded.source, /opne/);
  assert.equal(recorded.posture, "enforcing");
});

/* ------------------------------------------------------------------ */
/*  Branch 2 — the runtime was never initialized                       */
/* ------------------------------------------------------------------ */

const BASH = JSON.stringify({ tool_name: "Bash", tool_input: { command: "rm -rf /" } });
const READ = JSON.stringify({ tool_name: "Read", tool_input: { file_path: "notes.txt" } });

test("no runtime: a consequential call is DENIED by default, and the fix is in the message", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-hook-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  const { stdout } = invoke({ stdin: BASH, state });
  assert.equal(decision(stdout), "deny");
  assert.match(reason(stdout), /runtime is not initialized/);
  assert.match(reason(stdout), /cirvix init/);
});

test("no runtime: a read-only call is allowed, RECORDED, and marked as unevaluated", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-hook-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  const { stdout } = invoke({ stdin: READ, state });
  assert.equal(decision(stdout), "allow");
  assert.match(reason(stdout), /was NOT evaluated/);
  assert.match(reason(stdout), /read-only/);

  /* Not silent: the call is on the hook's chain and in the posture snapshot. */
  const state_ = JSON.parse(await readFile(join(state, "claude-code-hook.json"), "utf8"));
  assert.equal(state_.posture, "enforcing");
  assert.equal(state_.unevaluatedAllowed, 1);
  const chained = (await readFile(join(state, "claude-code-hook.jsonl"), "utf8")).trim().split("\n").filter(Boolean);
  assert.equal(chained.length, 1);
  assert.equal(JSON.parse(chained[0]).decision, "allow");
});

test("no runtime: compatibility allows the same consequential call, and SAYS it is compatibility", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-hook-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  const { stdout } = invoke({ stdin: BASH, state, fail: "open" });
  assert.equal(decision(stdout), "allow");
  assert.match(reason(stdout), /Compatibility posture is in force/);
  assert.match(reason(stdout), /ALLOWED/);
  const recorded = JSON.parse(await readFile(join(state, "claude-code-hook.json"), "utf8"));
  assert.equal(recorded.posture, "compatibility");
  assert.equal(recorded.unevaluatedAllowed, 1);
});

/* ------------------------------------------------------------------ */
/*  Branch 3 — the runtime exists but is not listening                 */
/* ------------------------------------------------------------------ */

test("unreachable runtime: consequential call denied by default, with no token file needed to be absent", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-hook-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  /* A token exists, so the hook gets past that branch and fails at connect. */
  await mkdir(state, { recursive: true });
  await writeFile(join(state, "runtime.token"), "not-a-real-token", "utf8");
  const { stdout } = invoke({ stdin: JSON.stringify({ tool_name: "Write", tool_input: { file_path: "x", content: "y" }, cwd: state }), state });
  assert.equal(decision(stdout), "deny");
  assert.match(reason(stdout), /could not be evaluated|unreachable/i);
});

test("an unknown tool is treated as consequential, because policy is what classifies unknown tools", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-hook-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  const { stdout } = invoke({ stdin: JSON.stringify({ tool_name: "SomeMcpTool", tool_input: {} }), state });
  assert.equal(decision(stdout), "deny");
});
