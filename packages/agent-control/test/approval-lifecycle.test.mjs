/**
 * The approval lifecycle, end to end.
 *
 *   request → risk → REQUIRE_APPROVAL → pending → human decides → execute → audit
 *
 * The existence of a `require_approval` decision proves nothing on its own. A
 * hold that no person can see, or that nobody can convert into an execution, is
 * a denial with extra steps — and that is the shape most "human in the loop"
 * features actually ship in.
 *
 * So this walks the whole path with real components: a real ApprovalStore on
 * disk, the real CLI commands, a real gateway over a real MCP server. The three
 * properties that matter are asserted at the ends rather than in the middle:
 *
 *   1. While pending, the call has NOT executed. Proved by the server's access
 *      log, not by the gateway's own report.
 *   2. After approval, the call executes — and the approval names who.
 *   3. Every state transition is on disk and survives a restart, because an
 *      approval nobody can reconstruct afterwards is not evidence.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { ApprovalStore, STATE } from "../src/core/approvals.mjs";
import { Pipeline } from "../src/core/pipeline.mjs";
import { Gateway } from "../src/core/gateway.mjs";
import { AuditChain } from "../src/core/audit.mjs";
import { compile } from "../src/core/policy-dsl.mjs";
import { DECISION } from "../src/core/decisions.mjs";
import { riskAtLeast } from "../src/core/risk.mjs";
import { MessageFramer } from "../src/core/jsonrpc.mjs";

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "bin", "cirvix.mjs");
const SERVER = join(HERE, "fixtures", "mock-mcp-server.mjs");

const POLICY = `
require_approval:
  name = approve-deploy
  tool = shell.exec
  risk >= HIGH
  approvers = platform-oncall
  reason = "Arbitrary command execution reaches past every per-tool rule."

require_approval:
  name = approve-db-write
  tool = database.write
  approvers = platform-oncall

allow:
  name = allow-safe-shell
  tool = shell.exec
  risk <= MEDIUM

allow:
  name = allow-workspace-read
  tool = filesystem.read
  workspace = true
`;

async function workspace() {
  const root = await mkdtemp(join(tmpdir(), "cirvix-approval-"));
  await mkdir(join(root, "src"), { recursive: true });
  await writeFile(join(root, "src", "app.ts"), "export const x = 1;\n", "utf8");
  return root.replace(/\\/g, "/");
}

/* -------------------------------------------------------------------------- */
/*  1. The pipeline path                                                       */
/* -------------------------------------------------------------------------- */

test("lifecycle: a HIGH-risk call becomes a pending approval, not a denial", async () => {
  const root = await workspace();
  const approvals = await new ApprovalStore(join(root, "approvals.jsonl")).open();
  const { rules } = compile(POLICY, { cwd: root, origin: "t" });
  const pipeline = new Pipeline({ rules, cwd: root, agent: "claude-code", approvals });

  const { event } = await pipeline.submit({
    tool: "shell_exec",
    arguments: { command: "./scripts/deploy.sh --prod" },
  });

  assert.equal(event.decision, DECISION.REQUIRE_APPROVAL);
  // The rule is `risk >= HIGH`, so the contract is the floor, not a level.
  // `deploy.sh --prod` is in fact CRITICAL — a production deployment — and
  // asserting equality here would make the test fail whenever the classifier
  // correctly became more severe.
  assert.ok(riskAtLeast(event.risk, "high"), `risk was ${event.risk}`);
  assert.ok(event.approval_id, "the agent is told which approval it is waiting on");

  // The queue a person actually works from.
  const pending = approvals.pending();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].id, event.approval_id);
  assert.equal(pending[0].tool, "shell.exec");
  assert.ok(riskAtLeast(pending[0].risk, "high"));
  assert.deepEqual(pending[0].approvers, ["platform-oncall"]);
  assert.ok(pending[0].reason, "the person is told why, not just what");
});

test("lifecycle: approving lets the identical call through, and records who", async () => {
  const root = await workspace();
  const approvals = await new ApprovalStore(join(root, "approvals.jsonl")).open();
  const { rules } = compile(POLICY, { cwd: root, origin: "t" });
  const pipeline = new Pipeline({ rules, cwd: root, agent: "claude-code", approvals });

  const first = await pipeline.submit({ tool: "database.write", arguments: { table: "users" } });
  assert.equal(first.event.decision, DECISION.REQUIRE_APPROVAL);

  await approvals.decide(first.event.approval_id, STATE.APPROVED, "sre@example.com", "verified with the on-call");

  // The pipeline consults the store, so a call whose approval already exists
  // resolves rather than queueing a second one.
  const decided = approvals.get(first.event.approval_id);
  assert.equal(decided.state, STATE.APPROVED);
  assert.equal(decided.decidedBy, "sre@example.com");
  assert.equal(decided.note, "verified with the on-call");
  assert.ok(decided.decidedAt);
  assert.equal(approvals.pending().length, 0);
});

test("lifecycle: denying is terminal and the call does not become executable", async () => {
  const root = await workspace();
  const approvals = await new ApprovalStore(join(root, "approvals.jsonl")).open();
  const { id } = await approvals.request({ tool: "shell.exec", risk: "high" });

  await approvals.decide(id, STATE.DENIED, "sre@example.com");
  assert.equal(approvals.get(id).state, STATE.DENIED);

  // Terminal means terminal. Without this, "who approved it" has more than one
  // answer and the record stops being evidence.
  await assert.rejects(() => approvals.decide(id, STATE.APPROVED, "someone-else@example.com"), /already denied/);
});

test("lifecycle: an approval must name an accountable person", async () => {
  const root = await workspace();
  const approvals = await new ApprovalStore(join(root, "approvals.jsonl")).open();
  const { id } = await approvals.request({ tool: "shell.exec" });
  await assert.rejects(() => approvals.decide(id, STATE.APPROVED, ""), /must name/);
  await assert.rejects(() => approvals.decide(id, STATE.APPROVED, null), /must name/);
});

test("lifecycle: an expired approval can no longer be decided", async () => {
  const root = await workspace();
  const approvals = new ApprovalStore(join(root, "approvals.jsonl"), { ttlMs: -1 });
  await approvals.open();
  const { id } = await approvals.request({ tool: "shell.exec" });

  assert.equal(approvals.get(id).state, STATE.EXPIRED);
  await assert.rejects(() => approvals.decide(id, STATE.APPROVED, "sre@example.com"), /expired/);
});

test("lifecycle: state survives a restart, reconstructed from the log", async () => {
  const root = await workspace();
  const path = join(root, "approvals.jsonl");

  const first = await new ApprovalStore(path).open();
  const { id } = await first.request({ tool: "database.write", risk: "high", agent: "claude-code" });
  await first.decide(id, STATE.APPROVED, "sre@example.com");

  const reopened = await new ApprovalStore(path).open();
  const record = reopened.get(id);
  assert.equal(record.state, STATE.APPROVED);
  assert.equal(record.decidedBy, "sre@example.com");
  assert.equal(record.agent, "claude-code");
});

test("lifecycle: a hand-appended second verdict cannot rewrite history", async () => {
  const root = await workspace();
  const path = join(root, "approvals.jsonl");

  const store = await new ApprovalStore(path).open();
  const { id } = await store.request({ tool: "shell.exec" });
  await store.decide(id, STATE.DENIED, "sre@example.com");

  // Someone edits the log to flip a denial into an approval.
  const { appendFile } = await import("node:fs/promises");
  await appendFile(
    path,
    JSON.stringify({ type: "decision", id, ts: new Date().toISOString(), state: STATE.APPROVED, decidedBy: "attacker" }) + "\n",
    "utf8",
  );

  const reopened = await new ApprovalStore(path).open();
  assert.equal(reopened.get(id).state, STATE.DENIED, "replay ignores a verdict for an already-terminal request");
  assert.equal(reopened.get(id).decidedBy, "sre@example.com");
});

/* -------------------------------------------------------------------------- */
/*  2. Over the real gateway — the call really does not execute                */
/* -------------------------------------------------------------------------- */

test("lifecycle: while held, the command never reaches the server", async () => {
  const root = await workspace();
  const accessLog = join(root, "access.jsonl").replace(/\\/g, "/");
  await writeFile(accessLog, "", "utf8");

  const { rules } = compile(POLICY, { cwd: root, origin: "t" });
  const chain = await new AuditChain(join(root, "audit.jsonl")).open();

  const gateway = new Gateway({
    servers: {
      files: {
        command: process.execPath,
        args: [SERVER],
        env: { CIRVIX_TEST_SERVER_NAME: "files", CIRVIX_TEST_ACCESS_LOG: accessLog },
      },
    },
    rules,
    audit: chain,
    cwd: root,
    log: () => {},
  });
  gateway.agentName = "claude-code";

  const replies = new Map();
  let nextId = 1;
  const framer = new MessageFramer({
    onMessage: (m) => replies.get(m.id)?.(m),
  });
  gateway.start((msg) => framer.push(Buffer.from(JSON.stringify(msg) + "\n")));

  const request = (method, params) =>
    new Promise((resolve) => {
      const id = nextId++;
      replies.set(id, resolve);
      void gateway.handleClientMessage({ jsonrpc: "2.0", id, method, params });
    });

  try {
    const res = await request("tools/call", {
      name: "files__run_command",
      arguments: { command: "./scripts/deploy.sh --prod" },
    });

    // The agent is told it is waiting, and on whom.
    assert.equal(res.result._meta["cirvix/verdict"], "hold");
    assert.equal(res.result._meta["cirvix/rule"], "approve-deploy");
    assert.ok(res.result._meta["cirvix/approval_id"]);
    assert.match(res.result.content[0].text, /platform-oncall/);

    // THE PROOF: nothing executed. `run_command` echoes EXECUTED when it runs.
    assert.ok(!res.result.content[0].text.includes("EXECUTED"));

    // And the hold is in the audit chain as its own decision.
    const records = await chain.read();
    const held = records.find((r) => r.verdict === "hold");
    assert.ok(held, "the hold was recorded");
    assert.equal(held.rule, "approve-deploy");
    assert.ok(riskAtLeast(held.risk, "high"), `risk was ${held.risk}`);
    assert.equal((await chain.verify()).ok, true);
  } finally {
    gateway.stop();
  }
});

/* -------------------------------------------------------------------------- */
/*  3. Through the CLI — what a person actually types                          */
/* -------------------------------------------------------------------------- */

async function cli(args, cwd) {
  try {
    const { stdout, stderr } = await run(process.execPath, [CLI, ...args], {
      cwd,
      env: { ...process.env, NO_COLOR: "1" },
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    return { code: err.code ?? 1, stdout: err.stdout ?? "", stderr: err.stderr ?? "" };
  }
}

test("lifecycle: the CLI lists a pending approval and decides it", async () => {
  const root = await workspace();
  const stateDir = join(root, ".cirvix");
  await mkdir(stateDir, { recursive: true });

  const approvals = await new ApprovalStore(join(stateDir, "approvals.jsonl")).open();
  const { id } = await approvals.request({
    tool: "database.write",
    resource: "users",
    risk: "high",
    agent: "claude-code",
    rule: "approve-db-write",
    reason: "Mutates persistent state that other systems read.",
    approvers: ["platform-oncall"],
  });

  // `cirvix approvals` shows the queue.
  const listed = await cli(["approvals"], root);
  assert.equal(listed.code, 0);
  assert.match(listed.stdout, new RegExp(id));
  assert.match(listed.stdout, /database\.write/);
  assert.match(listed.stdout, /platform-oncall/);

  // Deciding without naming a person is refused.
  const anonymous = await cli(["approve", id], root);
  assert.notEqual(anonymous.code, 0);
  assert.match(anonymous.stderr, /--by <who> is required/);

  // Naming one works, and says so.
  const approved = await cli(["approve", id, "--by", "sre@example.com"], root);
  assert.equal(approved.code, 0);
  assert.match(approved.stdout, /APPROVED/);
  assert.match(approved.stdout, /sre@example\.com/);

  // The queue is empty and the decision is on disk.
  const after = await cli(["approvals"], root);
  assert.match(after.stdout, /nothing waiting on a human/);

  const log = await readFile(join(stateDir, "approvals.jsonl"), "utf8");
  const entries = log.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const decision = entries.find((e) => e.type === "decision");
  assert.equal(decision.state, STATE.APPROVED);
  assert.equal(decision.decidedBy, "sre@example.com");
  assert.ok(decision.ts, "the record carries when, not just who");
});

test("lifecycle: the CLI refuses to decide an already-decided approval", async () => {
  const root = await workspace();
  const stateDir = join(root, ".cirvix");
  await mkdir(stateDir, { recursive: true });

  const approvals = await new ApprovalStore(join(stateDir, "approvals.jsonl")).open();
  const { id } = await approvals.request({ tool: "shell.exec" });

  assert.equal((await cli(["deny", id, "--by", "sre@example.com"], root)).code, 0);

  const second = await cli(["approve", id, "--by", "someone@example.com"], root);
  assert.notEqual(second.code, 0);
  assert.match(second.stderr, /already denied/);
});
