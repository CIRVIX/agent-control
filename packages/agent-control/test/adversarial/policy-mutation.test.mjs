/**
 * Policy mutation while requests are in flight.
 *
 * The production scenario nobody designs for and everybody eventually hits:
 *
 *   Request ──▶ policy v1 ──▶ held for approval
 *                    POLICY CHANGES
 *               policy v2 ──▶ approval granted ──▶ execute
 *
 * Which policy governs?
 *
 * THE ANSWER, AND WHY
 *
 * The policy in force when the call EXECUTES. Not the one that held it.
 *
 * A human approving a call is approving *that call*, not an exemption from
 * rules written afterwards. The alternative — honouring the policy that was
 * loaded when the request was made — means every pending approval is a hole
 * through any tightening, and the way to defeat a new rule is to have asked
 * before it existed. That is a race an attacker can win on purpose.
 *
 * It also cuts the other way, and that half is not optional: if the policy
 * LOOSENS, the approval becomes unnecessary rather than staying stuck. A hold
 * that outlives the rule that created it is a queue that only grows.
 *
 * WHAT IS NEVER RE-DECIDED
 *
 * A decision already recorded. History is not retroactively edited by a policy
 * change — `cirvix replay` exists precisely so you can ask "what would today's
 * rules have done" without pretending they were yesterday's.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Pipeline } from "../../src/core/pipeline.mjs";
import { AuditChain } from "../../src/core/audit.mjs";
import { ApprovalStore, STATE } from "../../src/core/approvals.mjs";
import { compile } from "../../src/core/policy-dsl.mjs";
import { DECISION } from "../../src/core/decisions.mjs";
import { replay } from "../../src/core/journal.mjs";

const CWD = process.platform === "win32" ? "C:/workspace" : "/workspace";

const V1_HOLDS = `
require_approval:
  name = approve-db-write
  tool = database.write
  approvers = oncall

allow:
  name = allow-read
  tool = filesystem.read
`;

const V2_DENIES = `
deny:
  name = deny-db-write
  tool = database.write
  reason = "Database writes were prohibited outright after the incident."

allow:
  name = allow-read
  tool = filesystem.read
`;

const V2_ALLOWS = `
allow:
  name = allow-db-write
  tool = database.write

allow:
  name = allow-read
  tool = filesystem.read
`;

const rulesFor = (source) => compile(source, { cwd: CWD, origin: "mutation" }).rules;

const DB_WRITE = { tool: "database.write", arguments: { table: "users" } };
const READ = { tool: "read_file", arguments: { path: `${CWD}/src/app.ts` } };

async function world(source = V1_HOLDS) {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-mutate-"));
  const approvals = await new ApprovalStore(join(dir, "approvals.jsonl")).open();
  const chain = await new AuditChain(join(dir, "audit.jsonl")).open();
  const pipeline = new Pipeline({
    rules: rulesFor(source),
    cwd: CWD,
    agent: "claude-code",
    approvals,
    audit: chain,
  });
  return { dir, approvals, chain, pipeline };
}

/* ========================================================================== */
/*  1. HELD UNDER v1 → POLICY TIGHTENS → APPROVAL ARRIVES                     */
/* ========================================================================== */

test("mutation: a grant cannot outlive the rule that permitted the call", async () => {
  /*
   * The headline case. Held under v1, approved by a human, and by then the
   * policy forbids it outright. The approval must not be a way through.
   */
  const { approvals, pipeline } = await world(V1_HOLDS);

  const held = await pipeline.submit(DB_WRITE);
  assert.equal(held.event.decision, DECISION.REQUIRE_APPROVAL);

  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  // The rule set is tightened while the approval sits in the queue.
  pipeline.rules = rulesFor(V2_DENIES);

  const after = await pipeline.submit(DB_WRITE);
  assert.equal(after.event.decision, DECISION.DENY, "the policy in force at execution decides");
  assert.equal(after.event.policy, "deny-db-write");
});

test("mutation: the stale grant is not silently spent by the denied attempt", async () => {
  // A denial must not consume the approval. Otherwise tightening the policy
  // quietly destroys grants an operator may still want to see, and the queue
  // no longer explains itself.
  const { approvals, pipeline } = await world(V1_HOLDS);

  const held = await pipeline.submit(DB_WRITE);
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");
  pipeline.rules = rulesFor(V2_DENIES);
  await pipeline.submit(DB_WRITE);

  assert.equal(
    approvals.get(held.event.approval_id).state,
    STATE.APPROVED,
    "the grant is untouched — it was never reached",
  );
});

test("mutation: reverting the policy makes the untouched grant usable again", async () => {
  // Follows from the previous test, and is the reason it matters: the operator
  // rolls back the bad rule and the approval they already gave still works.
  const { approvals, pipeline } = await world(V1_HOLDS);

  const held = await pipeline.submit(DB_WRITE);
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  pipeline.rules = rulesFor(V2_DENIES);
  assert.equal((await pipeline.submit(DB_WRITE)).event.decision, DECISION.DENY);

  pipeline.rules = rulesFor(V1_HOLDS);
  const released = await pipeline.submit(DB_WRITE);
  assert.equal(released.event.decision, DECISION.ALLOW);
  assert.equal(released.event.approval_id, held.event.approval_id);
});

/* ========================================================================== */
/*  2. HELD UNDER v1 → POLICY LOOSENS                                         */
/* ========================================================================== */

test("mutation: loosening the policy makes the approval unnecessary, not stuck", async () => {
  const { approvals, pipeline } = await world(V1_HOLDS);

  const held = await pipeline.submit(DB_WRITE);
  assert.equal(held.event.decision, DECISION.REQUIRE_APPROVAL);

  pipeline.rules = rulesFor(V2_ALLOWS);

  const after = await pipeline.submit(DB_WRITE);
  assert.equal(after.event.decision, DECISION.ALLOW);
  assert.equal(after.event.policy, "allow-db-write");
});

test("mutation: a now-unnecessary approval stays in the queue rather than vanishing", async () => {
  // "Why was this ever asked for" is a real question, and deleting the record
  // to tidy up is how it becomes unanswerable.
  const { approvals, pipeline } = await world(V1_HOLDS);

  const held = await pipeline.submit(DB_WRITE);
  pipeline.rules = rulesFor(V2_ALLOWS);
  await pipeline.submit(DB_WRITE);

  assert.equal(approvals.get(held.event.approval_id).state, STATE.PENDING);
  assert.equal(approvals.pending().length, 1);
});

/* ========================================================================== */
/*  3. ALLOW → RELOAD → NEXT EXECUTION                                        */
/* ========================================================================== */

test("mutation: a reload applies to the next call, immediately", async () => {
  const { pipeline } = await world(V1_HOLDS);

  assert.equal((await pipeline.submit(READ)).event.decision, DECISION.ALLOW);

  pipeline.rules = rulesFor("deny:\n  name = deny-reads\n  tool = filesystem.read\n  path = **/*\n");

  const after = await pipeline.submit(READ);
  assert.equal(after.event.decision, DECISION.DENY);
  assert.equal(after.event.policy, "deny-reads");
});

test("mutation: a reload does not retroactively change a recorded decision", async () => {
  const { pipeline, chain } = await world(V1_HOLDS);

  await pipeline.submit(READ);
  pipeline.rules = rulesFor("deny:\n  name = deny-reads\n  tool = filesystem.read\n  path = **/*\n");
  await pipeline.submit(READ);

  const records = await chain.read();
  assert.equal(records[0].verdict, "permit", "the first call was permitted, and still says so");
  assert.equal(records[1].verdict, "deny");
  assert.equal((await chain.verify()).ok, true, "and rewriting nothing keeps the chain intact");
});

test("mutation: replay is how you ask what the new policy would have done", async () => {
  /*
   * The honest alternative to retroactive editing. History records what was
   * decided; `replay` answers what today's rules would decide about the same
   * calls, without pretending they were in force at the time.
   */
  const { pipeline, chain } = await world(V1_HOLDS);
  await pipeline.submit(READ);

  const records = await chain.read();
  const tightened = rulesFor("deny:\n  name = deny-reads\n  tool = filesystem.read\n  path = **/*\n");
  const result = replay(records, tightened, { cwd: CWD });

  assert.equal(result.changed, 1, "the new policy would have decided differently");
  assert.equal(result.steps[0].before.decision, DECISION.ALLOW);
  assert.equal(result.steps[0].after.decision, DECISION.DENY);
  assert.match(result.caveat, /does not re-execute/);
});

/* ========================================================================== */
/*  4. MUTATION DURING CONCURRENT EXECUTION                                   */
/* ========================================================================== */

test("mutation: a swap mid-burst gives every call one policy or the other, never half of each", async () => {
  /*
   * The property that matters is atomicity per call. A call evaluated against
   * half of v1 and half of v2 is a decision no rule set ever authorized, and it
   * would be unreproducible in replay.
   */
  const { pipeline, chain } = await world(V1_HOLDS);
  const denyReads = rulesFor("deny:\n  name = deny-reads\n  tool = filesystem.read\n  path = **/*\n");

  const inFlight = [];
  for (let i = 0; i < 100; i++) {
    if (i === 50) pipeline.rules = denyReads;
    inFlight.push(pipeline.submit(READ));
  }
  const results = await Promise.all(inFlight);

  for (const { event } of results) {
    const consistent =
      (event.decision === DECISION.ALLOW && event.policy === "allow-read") ||
      (event.decision === DECISION.DENY && event.policy === "deny-reads");
    assert.ok(consistent, `mixed decision: ${event.decision} by ${event.policy}`);
  }

  // Both rule sets were exercised, so the test really did race them.
  const allowed = results.filter((r) => r.event.decision === DECISION.ALLOW).length;
  assert.ok(allowed > 0 && allowed < 100, `${allowed} allowed — the swap did not overlap the burst`);

  assert.equal((await chain.verify()).ok, true);
});

test("mutation: every decision names the rule that produced it, under churn", async () => {
  // Without this, "which policy decided" is unanswerable exactly when the
  // question is hardest — during a rollout.
  const { pipeline } = await world(V1_HOLDS);
  const variants = [V1_HOLDS, V2_DENIES, V2_ALLOWS];

  for (let i = 0; i < 30; i++) {
    pipeline.rules = rulesFor(variants[i % variants.length]);
    const { event } = await pipeline.submit(DB_WRITE);
    if (event.decision === DECISION.DENY && event.policy === null) continue; // default-deny is a legitimate answer
    assert.ok(event.policy, `no rule named for a ${event.decision}`);
  }
});

/* ========================================================================== */
/*  5. THE DANGEROUS DIRECTION, STATED AS ONE TEST                            */
/* ========================================================================== */

test("mutation: no sequence of policy changes lets a forbidden call through", async () => {
  /*
   * The invariant, brute-forced. Whatever order the rule sets are applied in,
   * and whatever approvals exist, a call the current policy forbids does not
   * execute.
   */
  const { approvals, pipeline } = await world(V1_HOLDS);

  // Bank an approval under the permissive policy first.
  const held = await pipeline.submit(DB_WRITE);
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  const sequences = [
    [V1_HOLDS, V2_DENIES],
    [V2_ALLOWS, V2_DENIES],
    [V2_DENIES, V1_HOLDS, V2_DENIES],
    [V2_DENIES, V2_ALLOWS, V2_DENIES],
  ];

  for (const sequence of sequences) {
    for (const source of sequence) pipeline.rules = rulesFor(source);
    // The last rule set applied is always V2_DENIES.
    const { event } = await pipeline.submit(DB_WRITE);
    assert.equal(
      event.decision,
      DECISION.DENY,
      `sequence ${sequence.length} ended permissive: ${event.decision} by ${event.policy}`,
    );
  }
});
