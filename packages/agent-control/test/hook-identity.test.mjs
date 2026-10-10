/**
 * The Claude Code hook is a TRANSPORT ADAPTER over the canonical core, and
 * these tests are the proof — not that it "sends something", but that the
 * identity it sends is the same identity the boundary verifies, through the
 * same stage, in the same mode.
 *
 * The hook governs Claude Code's built-in tools (Bash, Write, Read, …), which
 * never traverse the MCP gateway. If it speaks its own dialect, then "Cirvix
 * protects Claude Code" is true of one transport and false of the one that
 * runs shell commands.
 *
 * WHAT IS ASSERTED, AND WHY IT CANNOT BE FAKED
 *
 * `identityMode: production` on BOTH the server and the pipeline. In that mode
 * the core refuses any caller whose identity it cannot verify. So an `allow`
 * from this hook is only reachable by presenting an enrolled credential plus a
 * signature over the exact params sent: there is no code path from "claimed a
 * name" to "allowed" in production.
 *
 * The mirror row is the un-enrolled host: there, the same hook must be REFUSED.
 * A hook that allowed it would be a transport-specific hole in the identity
 * stage — the exact failure P0-D exists to remove.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Pipeline } from "../src/core/pipeline.mjs";
import { UdsServer, defaultEndpoint, writeToken } from "../src/core/uds.mjs";
import { AuditChain } from "../src/core/audit.mjs";
import { compile } from "../src/core/policy-dsl.mjs";
import { createCallerVerifier, enrollAgent, loadCallerIdentity } from "../src/core/identity.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK = fileURLToPath(new URL("../../../integrations/claude-code/hook.mjs", import.meta.url));

const POLICY = `
allow:
  name = allow-workspace-read
  tool = filesystem.read
  workspace = true
`;

/** Runs the real hook as a child process and returns its stdout JSON. */
function runHook({ stdin, env }) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [HOOK], { stdio: ["pipe", "pipe", "pipe"], env });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(stdin);
  });
}

/**
 * A REAL socket runtime — the same Pipeline and the same UdsServer the
 * `cirvix runtime` command builds — with a real MCP-free policy, over a real
 * endpoint. `enroll` decides whether this host has an identity at all.
 */
async function withRuntime(fn, { enroll = true, identityMode = "production" } = {}) {
  const root = await mkdtemp(join(tmpdir(), "cirvix-hook-identity-"));
  const workspace = join(root, "workspace");
  const stateDir = join(root, "state");
  await mkdir(join(workspace, "src"), { recursive: true });
  await mkdir(stateDir, { recursive: true });
  const target = join(workspace, "src", "app.ts");
  await writeFile(target, "export const answer = 42;\n", "utf8");

  const enrollment = enroll ? await enrollAgent({ stateDir, agentId: "claude-code", runtime: "claude-code" }) : null;
  const identity = await createCallerVerifier({ stateDir });
  const rules = compile(POLICY, { cwd: workspace, origin: "hook-identity" }).rules;
  const chain = await new AuditChain(join(root, "audit.jsonl")).open();
  const token = await writeToken(stateDir);

  const server = new UdsServer({
    pipeline: new Pipeline({ rules, cwd: workspace, agent: "host", identity, identityMode, audit: chain }),
    endpoint: defaultEndpoint(stateDir),
    token,
    identity,
    identityMode,
    status: () => ({}),
    recent: async () => [],
  });
  await server.start();

  try {
    return await fn({ root, workspace, stateDir, target, chain, enrollment });
  } finally {
    await server.stop();
    await rm(root, { recursive: true, force: true });
  }
}

const payload = (workspace, file) =>
  JSON.stringify({
    hook_event_name: "PreToolUse",
    tool_name: "Read",
    tool_input: { file_path: file },
    cwd: workspace,
  });

test("hook/enrolled: the hook's proof is verified by the boundary, and the call is allowed as the ENROLLED agent", async () => {
  await withRuntime(async ({ workspace, stateDir, target, chain }) => {
    const { code, stdout, stderr } = await runHook({
      stdin: payload(workspace, target),
      env: { ...process.env, NO_COLOR: "1", CIRVIX_STATE: stateDir, CIRVIX_HOOK_FAIL: "closed" },
    });

    assert.equal(code, 0, stderr);
    const answer = JSON.parse(stdout);
    const decision = answer.hookSpecificOutput.permissionDecision;
    assert.equal(decision, "allow", `in production an allow requires a verified identity: ${stdout}`);

    /* The record is the second half of the claim: the decision was taken for
       the ENROLLED agent, and the identity block says verifiedBy transport. */
    const records = await chain.read();
    const rec = records.at(-1);
    assert.ok(rec, "the hook's call was recorded");
    assert.equal(rec.identity?.verified, true, JSON.stringify(rec.identity));
    assert.equal(rec.identity?.agentId, "claude-code");
    assert.equal(rec.agent, "claude-code", "the principal is the verified agent, not the host default");
    assert.equal(rec.claimed_agent, undefined, "an identity that verified is not a claim");
  });
});

test("hook/un-enrolled: production refuses, because a name the hook invented is not an identity", async () => {
  await withRuntime(async ({ workspace, target, stateDir, chain }) => {
    const { code, stdout } = await runHook({
      stdin: payload(workspace, target),
      env: { ...process.env, NO_COLOR: "1", CIRVIX_STATE: stateDir, CIRVIX_HOOK_FAIL: "closed" },
    });

    assert.equal(code, 0);
    const answer = JSON.parse(stdout);
    assert.equal(answer.hookSpecificOutput.permissionDecision, "deny");
    assert.match(answer.hookSpecificOutput.permissionDecisionReason, /identity|verifier|enrol/i);

    const rec = (await chain.read()).at(-1);
    assert.equal(rec.identity?.verified, false);
    assert.notEqual(rec.agent, "claude-code", "the self-declared name never became the principal");
    // Nothing was authorized, so there is no substituted argument set either.
    assert.equal(rec.decision, "deny");
  }, { enroll: false });
});

test("hook/compat-unverified: the hook transmits no claim it cannot back, and the record says so", async () => {
  await withRuntime(async ({ workspace, target, stateDir, chain }) => {
    const { stdout } = await runHook({
      stdin: payload(workspace, target),
      env: { ...process.env, NO_COLOR: "1", CIRVIX_STATE: stateDir },
    });
    const answer = JSON.parse(stdout);

    /* Compat accepts an unverified caller — that is what the profile is for —
       but the record must not be able to mistake it for a proven one. */
    assert.equal(answer.hookSpecificOutput.permissionDecision, "allow");
    const rec = (await chain.read()).at(-1);
    assert.equal(rec.identity?.verified, false);
    assert.equal(rec.identity?.mode, "compat");
    assert.equal(rec.claimed_agent, undefined, "the hook sent no agent name to be recorded as a claim");
  }, { enroll: false, identityMode: "compat" });
});

test("hook/identity-loader: an ambiguous host is not guessed at", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-hook-ambig-"));
  try {
    await enrollAgent({ stateDir, agentId: "agent-A", runtime: "claude-code" });
    await enrollAgent({ stateDir, agentId: "agent-B", runtime: "claude-code" });
    assert.equal(await loadCallerIdentity({ stateDir }), null, "two enrolments means the caller must say which one it is");
    const named = await loadCallerIdentity({ stateDir, agentId: "agent-B" });
    assert.equal(named.agentId, "agent-B");
    assert.equal(typeof named.credential, "string");
    assert.match(named.meta({ tool: "x" }).credential, /.+/);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

test("hook/identity-loader: a host with no enrolment yields no identity, not an empty one", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-hook-empty-"));
  try {
    assert.equal(await loadCallerIdentity({ stateDir }), null);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

/** The hook's own module must be readable as evidence: no stray `console.log`. */
test("hook: writes nothing to stdout except the decision object", async () => {
  const source = await readFile(HOOK, "utf8");
  assert.doesNotMatch(source, /console\.log\(/, "stdout is the hook protocol; diagnostics go to stderr");
});
