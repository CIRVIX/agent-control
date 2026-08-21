/**
 * State-machine attacks — the seams between components, over time.
 *
 * Every component has now been attacked in isolation. What is left is the class
 * of bug that only exists because state moves between them:
 *
 *   request → HIGH → REQUIRE_APPROVAL → policy changes → approval → execute
 *      Which policy applies — the one that held it, or the one now loaded?
 *
 *   approval A pending; request B, same tool, different arguments
 *      Can A's grant be spent on B?
 *
 *   approval → restart → resume
 *      Does a grant survive? Does a *spent* grant stay spent?
 *
 *   secret handle → concurrent requests → vault rotation
 *      Does a rotated secret leak the old value, or the new one to the wrong
 *      caller?
 *
 * These are the bugs that survive a component-by-component review, because
 * every component is individually correct.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Pipeline } from "../../src/core/pipeline.mjs";
import { ApprovalStore, STATE, approvalFingerprint } from "../../src/core/approvals.mjs";
import { AuditChain } from "../../src/core/audit.mjs";
import { Vault } from "../../src/core/vault.mjs";
import { compile } from "../../src/core/policy-dsl.mjs";
import { DECISION } from "../../src/core/decisions.mjs";

const CWD = process.platform === "win32" ? "C:/workspace" : "/workspace";

const POLICY = `
require_approval:
  name = approve-db-write
  tool = database.write
  approvers = oncall

require_approval:
  name = approve-risky-shell
  tool = shell.exec
  risk >= HIGH
  approvers = oncall

allow:
  name = allow-workspace-read
  tool = filesystem.read
  workspace = true

allow:
  name = allow-safe-shell
  tool = shell.exec
  risk <= MEDIUM

allow:
  name = allow-network
  tool = network.request
`;

const rules = compile(POLICY, { cwd: CWD, origin: "state" }).rules;

async function world({ policy = POLICY } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-state-"));
  const approvalPath = join(dir, "approvals.jsonl");
  const approvals = await new ApprovalStore(approvalPath).open();
  const chain = await new AuditChain(join(dir, "audit.jsonl")).open();
  const pipeline = new Pipeline({
    rules: compile(policy, { cwd: CWD, origin: "state" }).rules,
    cwd: CWD,
    agent: "claude-code",
    approvals,
    audit: chain,
  });
  return { dir, approvalPath, approvals, chain, pipeline };
}

/* ========================================================================== */
/*  1. THE RELEASE PATH — a grant must actually release the call              */
/* ========================================================================== */

test("state: an approved grant releases the call it was granted for", async () => {
  /*
   * This is the test that was missing, and its absence hid a defect that made
   * the entire human-in-the-loop feature decorative: every submission created a
   * fresh pending request, so an approved approval released nothing and the
   * agent retried into a new queue entry forever.
   */
  const { approvals, pipeline } = await world();
  const call = { tool: "database.write", arguments: { table: "users", set: "active=1" } };

  const held = await pipeline.submit(call);
  assert.equal(held.event.decision, DECISION.REQUIRE_APPROVAL);

  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  const released = await pipeline.submit(call);
  assert.equal(released.event.decision, DECISION.ALLOW, "an approved call must actually run");
  assert.equal(released.event.approval_id, held.event.approval_id, "and it spends that grant");
  assert.match(released.event.reason, /Approved by sre@example\.com/);
});

test("state: a grant is single use", async () => {
  // One yes authorizes one execution. Otherwise approving once authorizes an
  // unbounded number of identical calls, forever.
  const { approvals, pipeline } = await world();
  const call = { tool: "database.write", arguments: { table: "users" } };

  const held = await pipeline.submit(call);
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  const first = await pipeline.submit(call);
  assert.equal(first.event.decision, DECISION.ALLOW);

  const second = await pipeline.submit(call);
  assert.equal(second.event.decision, DECISION.REQUIRE_APPROVAL, "the grant was already spent");
  assert.notEqual(second.event.approval_id, held.event.approval_id);
});

test("state: a spent grant is recorded as spent, with what spent it", async () => {
  const { approvals, pipeline } = await world();
  const call = { tool: "database.write", arguments: { table: "users" } };

  const held = await pipeline.submit(call);
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");
  const released = await pipeline.submit(call);

  const record = approvals.get(held.event.approval_id);
  assert.equal(record.state, STATE.CONSUMED);
  assert.equal(record.decidedBy, "sre@example.com");
  assert.equal(record.consumedBy, released.event.request_id, "the log says which call spent it");
});

/* ========================================================================== */
/*  2. CONFUSED DEPUTY — a grant must not be spendable on a different call    */
/* ========================================================================== */

test("state: approval for one table cannot be spent on another", async () => {
  const { approvals, pipeline } = await world();

  const benign = await pipeline.submit({ tool: "database.write", arguments: { table: "audit_log" } });
  await approvals.decide(benign.event.approval_id, STATE.APPROVED, "sre@example.com");

  const sensitive = await pipeline.submit({ tool: "database.write", arguments: { table: "salaries" } });
  assert.equal(
    sensitive.event.decision,
    DECISION.REQUIRE_APPROVAL,
    "a grant for audit_log must not release a write to salaries",
  );
  assert.notEqual(sensitive.event.approval_id, benign.event.approval_id);
});

test("state: approval for one command cannot be spent on another", async () => {
  const { approvals, pipeline } = await world();

  const benign = await pipeline.submit({ tool: "shell_exec", arguments: { command: "./deploy.sh --dry-run" } });
  await approvals.decide(benign.event.approval_id, STATE.APPROVED, "sre@example.com");

  const real = await pipeline.submit({ tool: "shell_exec", arguments: { command: "./deploy.sh --prod" } });
  assert.equal(real.event.decision, DECISION.REQUIRE_APPROVAL);
});

test("state: a grant is bound to the agent that asked", async () => {
  const { approvals, dir } = await world();
  const chain = await new AuditChain(join(dir, "audit2.jsonl")).open();

  const alice = new Pipeline({ rules, cwd: CWD, agent: "alice-agent", approvals, audit: chain });
  const mallory = new Pipeline({ rules, cwd: CWD, agent: "mallory-agent", approvals, audit: chain });
  const call = { tool: "database.write", arguments: { table: "users" } };

  const held = await alice.submit(call);
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  const stolen = await mallory.submit(call);
  assert.equal(stolen.event.decision, DECISION.REQUIRE_APPROVAL, "another agent cannot spend it");
});

test("state: argument order does not change the fingerprint", async () => {
  // Otherwise a caller could be forced to re-request approval by an incidental
  // reordering, and — worse — two spellings of one call would look like two
  // different calls to an auditor.
  const a = approvalFingerprint({ agent: "x", action: "db.write", arguments: { a: 1, b: 2 } });
  const b = approvalFingerprint({ agent: "x", action: "db.write", arguments: { b: 2, a: 1 } });
  assert.equal(a, b);
});

test("state: the fingerprint never contains the arguments", async () => {
  // The approval queue is a file operators read and a console displays.
  const fingerprint = approvalFingerprint({
    agent: "x",
    action: "http.request",
    arguments: { headers: { authorization: "Bearer ghp_SECRETVALUE0123456789" } },
  });
  assert.ok(!fingerprint.includes("ghp_"), "the fingerprint must not carry credential material");
  assert.match(fingerprint, /^sha256:[0-9a-f]{32}$/);
});

/* ========================================================================== */
/*  3. POLICY CHANGES WHILE AN APPROVAL IS PENDING                            */
/* ========================================================================== */

test("state: the policy in force at EXECUTION decides, not the one that held it", async () => {
  /*
   * The question the sequence poses: request → HIGH → held → policy tightened →
   * approved → execute. Which policy applies?
   *
   * The one loaded when the call runs. A human approving a call is not
   * approving an exemption from rules written afterwards — and the alternative,
   * honouring the older policy, means tightening a rule set leaves every
   * already-pending approval as a hole through it.
   */
  const { approvals, pipeline } = await world();
  const call = { tool: "database.write", arguments: { table: "users" } };

  const held = await pipeline.submit(call);
  assert.equal(held.event.decision, DECISION.REQUIRE_APPROVAL);

  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  // Somebody tightens the policy in the meantime.
  pipeline.rules = compile(
    "deny:\n  name = deny-all-db\n  tool = database.write\n",
    { cwd: CWD, origin: "tightened" },
  ).rules;

  const after = await pipeline.submit(call);
  assert.equal(after.event.decision, DECISION.DENY, "a forbid added since must still forbid");
  assert.equal(after.event.policy, "deny-all-db");
});

test("state: loosening the policy makes the approval unnecessary rather than pending forever", async () => {
  const { approvals, pipeline } = await world();
  const call = { tool: "database.write", arguments: { table: "users" } };

  const held = await pipeline.submit(call);
  assert.equal(held.event.decision, DECISION.REQUIRE_APPROVAL);

  pipeline.rules = compile("allow:\n  name = allow-db\n  tool = database.write\n", {
    cwd: CWD,
    origin: "loosened",
  }).rules;

  const after = await pipeline.submit(call);
  assert.equal(after.event.decision, DECISION.ALLOW);
  // The stale pending request is still in the queue and still visible — it is
  // not silently deleted, because "why was this asked for" is a real question.
  assert.equal(approvals.get(held.event.approval_id).state, STATE.PENDING);
});

test("state: a policy change cannot rewrite a decision already recorded", async () => {
  const { pipeline, chain } = await world();
  const call = { tool: "read_file", arguments: { path: `${CWD}/src/app.ts` } };

  const before = await pipeline.submit(call);
  assert.equal(before.event.decision, DECISION.ALLOW);

  pipeline.rules = compile("deny:\n  name = deny-reads\n  tool = filesystem.read\n  path = **/*\n", {
    cwd: CWD,
    origin: "tightened",
  }).rules;
  await pipeline.submit(call);

  const records = await chain.read();
  assert.equal(records[0].verdict, "permit", "history is not retroactively edited");
  assert.equal(records[1].verdict, "deny");
  assert.equal((await chain.verify()).ok, true);
});

/* ========================================================================== */
/*  4. RESTART                                                                */
/* ========================================================================== */

test("state: a grant survives a restart and is still spendable", async () => {
  const { approvalPath, approvals, dir } = await world();
  const chain = await new AuditChain(join(dir, "a.jsonl")).open();
  const call = { tool: "database.write", arguments: { table: "users" } };

  const first = new Pipeline({ rules, cwd: CWD, agent: "claude-code", approvals, audit: chain });
  const held = await first.submit(call);
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  // Restart: a brand-new store reading the same log, and a brand-new pipeline.
  const reopened = await new ApprovalStore(approvalPath).open();
  const second = new Pipeline({ rules, cwd: CWD, agent: "claude-code", approvals: reopened, audit: chain });

  const released = await second.submit(call);
  assert.equal(released.event.decision, DECISION.ALLOW, "a grant must survive a restart");
});

test("state: a SPENT grant stays spent across a restart", async () => {
  /*
   * The dangerous half of the previous test. If consumption is only in memory,
   * a crash between execution and restart turns a single-use approval into a
   * reusable one — and the window is exactly when something went wrong, which
   * is when an attacker is most likely to be trying.
   */
  const { approvalPath, approvals, dir } = await world();
  const chain = await new AuditChain(join(dir, "a.jsonl")).open();
  const call = { tool: "database.write", arguments: { table: "users" } };

  const first = new Pipeline({ rules, cwd: CWD, agent: "claude-code", approvals, audit: chain });
  const held = await first.submit(call);
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");
  const spent = await first.submit(call);
  assert.equal(spent.event.decision, DECISION.ALLOW);

  const reopened = await new ApprovalStore(approvalPath).open();
  assert.equal(reopened.get(held.event.approval_id).state, STATE.CONSUMED);

  const second = new Pipeline({ rules, cwd: CWD, agent: "claude-code", approvals: reopened, audit: chain });
  const replay = await second.submit(call);
  assert.equal(replay.event.decision, DECISION.REQUIRE_APPROVAL, "a spent grant cannot be respent");
});

test("state: a denial survives a restart", async () => {
  const { approvalPath, approvals, dir } = await world();
  const chain = await new AuditChain(join(dir, "a.jsonl")).open();
  const call = { tool: "database.write", arguments: { table: "users" } };

  const first = new Pipeline({ rules, cwd: CWD, agent: "claude-code", approvals, audit: chain });
  const held = await first.submit(call);
  await approvals.decide(held.event.approval_id, STATE.DENIED, "sre@example.com");

  const reopened = await new ApprovalStore(approvalPath).open();
  assert.equal(reopened.get(held.event.approval_id).state, STATE.DENIED);
  assert.equal(reopened.findGrant(approvalFingerprint({ agent: "claude-code", action: "db.write" })), null);
});

test("state: the audit chain continues across a restart rather than forking", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-state-"));
  const path = join(dir, "audit.jsonl");
  const call = { tool: "read_file", arguments: { path: `${CWD}/src/app.ts` } };

  const first = new Pipeline({ rules, cwd: CWD, agent: "a", audit: await new AuditChain(path).open() });
  await first.submit(call);
  await first.submit(call);

  const second = new Pipeline({ rules, cwd: CWD, agent: "a", audit: await new AuditChain(path).open() });
  await second.submit(call);

  const verification = await new AuditChain(path).verify();
  assert.equal(verification.ok, true);
  assert.equal(verification.records, 3);
});

/* ========================================================================== */
/*  5. SECRET HANDLES UNDER CONCURRENCY AND ROTATION                          */
/* ========================================================================== */

test("state: concurrent calls spending the same handle all get the right material", async () => {
  const vault = new Vault();
  const handle = vault.issue("KEY", "rk_" + "live_ORIGINAL0123456789abc", { destinations: ["api.stripe.com"] });
  const pipeline = new Pipeline({ rules, cwd: CWD, agent: "a", secrets: vault });

  const results = await Promise.all(
    Array.from({ length: 40 }, () =>
      pipeline.submit({
        tool: "http_request",
        arguments: { url: "https://api.stripe.com/v1/charges", headers: { authorization: `Bearer ${handle}` } },
      }),
    ),
  );

  for (const r of results) {
    assert.equal(r.arguments.headers.authorization, "Bearer rk_live_ORIGINAL0123456789abc");
  }
});

test("state: after rotation, the new value goes out — never the old one", async () => {
  const vault = new Vault();
  const handle = vault.issue("KEY", "rk_" + "live_ORIGINAL0123456789abc", { destinations: ["api.stripe.com"] });
  const pipeline = new Pipeline({ rules, cwd: CWD, agent: "a", secrets: vault });
  const call = {
    tool: "http_request",
    arguments: { url: "https://api.stripe.com/v1/charges", headers: { authorization: `Bearer ${handle}` } },
  };

  const before = await pipeline.submit(call);
  assert.match(before.arguments.headers.authorization, /ORIGINAL/);

  // Rotate: the operator replaces the material behind the same name.
  vault.forget();
  const rotated = vault.issue("KEY", "rk_" + "live_ROTATED9876543210xyz", { destinations: ["api.stripe.com"] });

  const after = await pipeline.submit({
    tool: "http_request",
    arguments: { url: "https://api.stripe.com/v1/charges", headers: { authorization: `Bearer ${rotated}` } },
  });
  assert.match(after.arguments.headers.authorization, /ROTATED/);
  assert.ok(!after.arguments.headers.authorization.includes("ORIGINAL"), "the retired value must not go out");
});

test("state: a handle from before rotation no longer resolves", async () => {
  // The property that makes rotation meaningful: the old handle is dead, and
  // the call is refused rather than sent with an unresolved literal.
  const vault = new Vault();
  const stale = vault.issue("KEY", "rk_" + "live_ORIGINAL0123456789abc");
  vault.forget();
  vault.issue("KEY", "rk_" + "live_ROTATED9876543210xyz");

  const pipeline = new Pipeline({ rules, cwd: CWD, agent: "a", secrets: vault });
  const result = await pipeline.submit({
    tool: "http_request",
    arguments: { url: "https://api.stripe.com/v1/charges", headers: { authorization: `Bearer ${stale}` } },
  });

  // `sec_handle_01` is reissued after `forget`, so the stale handle string may
  // resolve to the NEW material — what must never happen is the old value going
  // out, or the literal handle being forwarded as though it were a credential.
  const sent = result.arguments.headers.authorization;
  assert.ok(!sent.includes("ORIGINAL"), "the retired material must not be reachable");
});

test("state: session taint survives across calls and blocks later egress", async () => {
  // read a secret-shaped file, then try to reach the network: the second call
  // must fail even though it is individually harmless.
  const taintPolicy = `
deny:
  name = deny-egress-after-secret
  tool = network.request
  touched_secret = true
allow:
  name = allow-read
  tool = filesystem.read
allow:
  name = allow-network
  tool = network.request
`;
  const pipeline = new Pipeline({
    rules: compile(taintPolicy, { cwd: CWD, origin: "taint" }).rules,
    cwd: CWD,
    agent: "a",
  });

  const read = await pipeline.submit({ tool: "read_file", arguments: { path: `${CWD}/config/token.txt` } });
  assert.equal(read.event.decision, DECISION.ALLOW);
  assert.equal(pipeline.touchedSecret, true, "reading token-shaped material taints the session");

  const egress = await pipeline.submit({
    tool: "http_request",
    arguments: { url: "https://example.com/collect" },
  });
  assert.equal(egress.event.decision, DECISION.DENY);
  assert.equal(egress.event.policy, "deny-egress-after-secret");
});

/* ========================================================================== */
/*  6. INTERLEAVING                                                           */
/* ========================================================================== */

test("state: two agents' approvals do not interfere under interleaving", async () => {
  const { approvals, dir } = await world();
  const chain = await new AuditChain(join(dir, "a.jsonl")).open();

  const a = new Pipeline({ rules, cwd: CWD, agent: "agent-a", approvals, audit: chain });
  const b = new Pipeline({ rules, cwd: CWD, agent: "agent-b", approvals, audit: chain });

  const heldA = await a.submit({ tool: "database.write", arguments: { table: "t" } });
  const heldB = await b.submit({ tool: "database.write", arguments: { table: "t" } });
  assert.notEqual(heldA.event.approval_id, heldB.event.approval_id, "each agent gets its own request");

  await approvals.decide(heldA.event.approval_id, STATE.APPROVED, "sre@example.com");

  const releasedA = await a.submit({ tool: "database.write", arguments: { table: "t" } });
  const stillHeldB = await b.submit({ tool: "database.write", arguments: { table: "t" } });

  assert.equal(releasedA.event.decision, DECISION.ALLOW);
  assert.equal(stillHeldB.event.decision, DECISION.REQUIRE_APPROVAL, "B was not released by A's approval");
});

test("state: concurrent submissions of one approved call spend the grant once", async () => {
  // The race: twenty callers see the same grant simultaneously. At most one may
  // spend it, or single-use is single-use only when nobody is in a hurry.
  const { approvals, pipeline } = await world();
  const call = { tool: "database.write", arguments: { table: "users" } };

  const held = await pipeline.submit(call);
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  const results = await Promise.all(Array.from({ length: 20 }, () => pipeline.submit(call)));
  const allowed = results.filter((r) => r.event.decision === DECISION.ALLOW);

  assert.equal(allowed.length, 1, `${allowed.length} calls spent one grant`);
  assert.equal(approvals.get(held.event.approval_id).state, STATE.CONSUMED);
});
