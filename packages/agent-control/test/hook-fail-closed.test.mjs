import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const hook = fileURLToPath(new URL("../../../integrations/claude-code/hook.mjs", import.meta.url));

function invoke({ stdin, fail = null, state = null }) {
  const env = { ...process.env, NO_COLOR: "1" };
  if (fail === null) delete env.CIRVIX_HOOK_FAIL;
  else env.CIRVIX_HOOK_FAIL = fail;
  if (state === null) delete env.CIRVIX_STATE;
  else env.CIRVIX_STATE = state;
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

// Malformed input can never be evaluated. The configured posture decides the
// exit, and the message must say the call was not evaluated — never that it
// looked safe.
for (const stdin of ["{not json", "[1,2,3]", "42"]) {
  test(`malformed hook input (${stdin}) warns and allows by default`, () => {
    const { stdout, stderr } = invoke({ stdin });
    assert.equal(decision(stdout), "allow");
    assert.match(stderr, /not evaluated/);
  });

  test(`malformed hook input (${stdin}) denies when fail-closed`, () => {
    const { stdout } = invoke({ stdin, fail: "closed" });
    assert.equal(decision(stdout), "deny");
  });
}

test("missing runtime warns and follows the configured posture", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-hook-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  const payload = JSON.stringify({ tool_name: "Bash", tool_input: { command: "ls" }, cwd: state });
  assert.equal(decision(invoke({ stdin: payload, state }).stdout), "allow");
  assert.equal(decision(invoke({ stdin: payload, state, fail: "closed" }).stdout), "deny");
});
