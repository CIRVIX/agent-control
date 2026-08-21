/**
 * Agent-to-agent delegation attacks.
 *
 *   Agent A ──▶ Agent B ──▶ tool
 *   Agent A ──▶ Agent B ──▶ Agent C ──▶ tool
 *
 * ONE INVARIANT:
 *
 *   An agent cannot gain authority merely because another agent has it.
 *
 * Every test here is an attempt to violate it, and the shape recurs: the
 * confused deputy. A planner holds database authority; a summariser does not.
 * If the summariser's call is evaluated against the planner's authority — or
 * against a token the summariser merely *possesses* — the summariser has
 * database access, permanently and invisibly.
 *
 * The design that resists this is not "check the token". It is:
 *
 *   · scope only ever NARROWS along a chain
 *   · delegation is a CONSTRAINT ANDed with policy, never an alternative
 *     source of authority
 *   · identity is (issuer, subject) and signed — a name proves nothing
 *   · every link is verified, not just the presented one
 *
 * Each of those is attacked below.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Pipeline } from "../../src/core/pipeline.mjs";
import { AuditChain } from "../../src/core/audit.mjs";
import { ApprovalStore, STATE } from "../../src/core/approvals.mjs";
import {
  DELEGATION_ERROR,
  DelegationBroker,
  MAX_DEPTH,
  intersectScopes,
  isNarrowing,
  scopePermits,
} from "../../src/core/delegation.mjs";
import { compile } from "../../src/core/policy-dsl.mjs";
import { DECISION } from "../../src/core/decisions.mjs";

const CWD = process.platform === "win32" ? "C:/workspace" : "/workspace";

/**
 * A permissive policy on purpose.
 *
 * Delegation must do the narrowing on its own. If the policy did the work, a
 * passing test would prove nothing about delegation.
 */
const POLICY = `
allow:
  name = allow-reads
  tool = filesystem.read

allow:
  name = allow-writes
  tool = filesystem.write

allow:
  name = allow-db-read
  tool = database.query

allow:
  name = allow-db-write
  tool = database.write

allow:
  name = allow-network
  tool = network.request
`;

const rules = compile(POLICY, { cwd: CWD, origin: "delegation" }).rules;

function broker() {
  return new DelegationBroker();
}

function pipeline(delegation, extra = {}) {
  return new Pipeline({ rules, cwd: CWD, agent: "unused", delegation, ...extra });
}

/** Submits `call` as `agent`, presenting `grant`. */
async function actAs(p, agent, grant, call) {
  const { event } = await p.submit(call, { agent, delegation: grant });
  return event;
}

const READ_APP = { tool: "read_file", arguments: { path: `${CWD}/src/app.ts` } };
const DB_WRITE = { tool: "database.write", arguments: { table: "salaries" } };

/* ========================================================================== */
/*  1. AUTHORITY INHERITANCE — the core invariant                              */
/* ========================================================================== */

test("delegation: B does not inherit A's authority just because A has it", async () => {
  const b = broker();
  b.root("planner", { actions: ["*"], resources: ["*"] });
  b.root("summariser", { actions: ["fs.read"], resources: ["**"] });

  const p = pipeline(b);

  // The summariser, acting alone, cannot write to the database — even though
  // the planner can, and even though policy permits `database.write`.
  const own = await p.submit(DB_WRITE, { agent: "summariser" });
  assert.equal(own.event.decision, DECISION.ALLOW, "policy alone permits it; that is the point of the setup");

  // With its own root grant presented, the narrow scope binds.
  const rootGrant = b.inventory().find((g) => g.subject === "summariser");
  const constrained = await actAs(p, "summariser", b.get(rootGrant.id), DB_WRITE);
  assert.equal(constrained.decision, DECISION.DENY);
  assert.equal(constrained.policy, "delegation-out-of-scope");
});

test("delegation: a narrowed grant permits only what was granted", async () => {
  const b = broker();
  const planner = b.root("planner", { actions: ["*"], resources: ["*"] });
  const grant = b.delegate(planner, "summariser", { actions: ["fs.read"], resources: [`${CWD}/**`] });
  assert.ok(grant.ok);

  const p = pipeline(b);

  const permitted = await actAs(p, "summariser", grant.grant, READ_APP);
  assert.equal(permitted.decision, DECISION.ALLOW);

  const refused = await actAs(p, "summariser", grant.grant, DB_WRITE);
  assert.equal(refused.decision, DECISION.DENY);
  assert.equal(refused.policy, "delegation-out-of-scope");
});

test("delegation: the refusal names the chain, so the deputy is identifiable", async () => {
  const b = broker();
  const planner = b.root("planner", { actions: ["*"], resources: ["*"] });
  const grant = b.delegate(planner, "summariser", { actions: ["fs.read"], resources: ["**"] });

  const event = await actAs(pipeline(b), "summariser", grant.grant, DB_WRITE);
  assert.match(event.reason, /planner → summariser/);
});

/* ========================================================================== */
/*  2. PRIVILEGE ESCALATION — widening                                        */
/* ========================================================================== */

test("delegation: an agent cannot delegate more than it holds", () => {
  const b = broker();
  const planner = b.root("planner", { actions: ["fs.read"], resources: [`${CWD}/**`] });

  const widened = b.delegate(planner, "worker", { actions: ["*"], resources: ["*"] });
  assert.equal(widened.ok, false);
  assert.equal(widened.error, DELEGATION_ERROR.WIDENED);
  assert.match(widened.reason, /cannot give .* authority it does not have/);
});

test("delegation: widening is refused rather than silently clamped", () => {
  // Clamping hides the attempt. An agent trying to widen its authority is
  // exactly the event an operator wants in the log.
  const events = [];
  const b = new DelegationBroker({ onEvent: (e) => events.push(e) });
  const planner = b.root("planner", { actions: ["fs.read"], resources: ["**"] });

  b.delegate(planner, "worker", { actions: ["shell.exec"], resources: ["**"] });
  assert.ok(events.some((e) => e.kind === "delegation_widening_refused"));
});

test("delegation: escalation by adding a sibling action is refused", () => {
  const b = broker();
  const planner = b.root("planner", { actions: ["fs.read"], resources: ["**"] });
  const attempt = b.delegate(planner, "worker", { actions: ["fs.read", "fs.write"], resources: ["**"] });
  assert.equal(attempt.ok, false, "one extra action is still widening");
});

test("delegation: escalation by widening the resource glob is refused", () => {
  const b = broker();
  const planner = b.root("planner", { actions: ["fs.read"], resources: [`${CWD}/src/**`] });
  const attempt = b.delegate(planner, "worker", { actions: ["fs.read"], resources: ["**"] });
  assert.equal(attempt.ok, false);
});

test("delegation: a wildcard cannot be laundered through a deeper hop", () => {
  // A→B narrow, B→C wide. C must not end up with more than B had.
  const b = broker();
  const planner = b.root("planner", { actions: ["*"], resources: ["*"] });
  const toB = b.delegate(planner, "b", { actions: ["fs.read"], resources: ["**"] });
  const toC = b.delegate(toB.grant, "c", { actions: ["*"], resources: ["*"] });
  assert.equal(toC.ok, false, "B cannot give C more than B holds");
});

test("delegation: narrowing holds across a long chain", () => {
  const b = broker();
  let current = b.root("a0", { actions: ["*"], resources: ["*"] });
  for (let i = 1; i < 5; i++) {
    const next = b.delegate(current, `a${i}`, { actions: ["fs.read"], resources: [`${CWD}/**`] });
    assert.ok(next.ok, `hop ${i}`);
    current = next.grant;
  }
  const resolved = b.resolve(current, "a4");
  assert.ok(resolved.ok);
  assert.ok(!scopePermits(resolved.scope, { action: "fs.write", resource: `${CWD}/x` }));
  assert.ok(scopePermits(resolved.scope, { action: "fs.read", resource: `${CWD}/x` }));
});

/* ========================================================================== */
/*  3. IDENTITY SPOOFING AND IMPERSONATION                                    */
/* ========================================================================== */

test("delegation: a grant issued to B cannot be presented by C", async () => {
  const b = broker();
  const planner = b.root("planner", { actions: ["*"], resources: ["*"] });
  const toB = b.delegate(planner, "agent-b", { actions: ["db.write"], resources: ["**"] });

  const stolen = await actAs(pipeline(b), "agent-c", toB.grant, DB_WRITE);
  assert.equal(stolen.decision, DECISION.DENY);
  assert.equal(stolen.policy, `delegation-${DELEGATION_ERROR.SUBJECT_MISMATCH}`);
});

test("delegation: claiming another agent's name grants nothing", async () => {
  // Names are attacker-controlled strings. Only a verifying grant means
  // anything, and it means exactly what it says.
  const b = broker();
  b.root("planner", { actions: ["*"], resources: ["*"] });

  const p = pipeline(b);
  const impostor = await p.submit(DB_WRITE, { agent: "planner" });
  // Without a grant, policy alone governs — the name bought no extra authority.
  assert.equal(impostor.event.decision, DECISION.ALLOW);

  // And with the planner's own root grant, presented by an impostor:
  const rootId = b.inventory().find((g) => g.subject === "planner").id;
  const forged = await actAs(p, "mallory", b.get(rootId), DB_WRITE);
  assert.equal(forged.decision, DECISION.DENY);
});

test("delegation: a hand-built grant with no signature is refused", async () => {
  const b = broker();
  const fake = {
    id: "dlg_fake",
    issuer: "planner",
    subject: "mallory",
    parent: null,
    depth: 0,
    scope: { actions: ["*"], resources: ["*"] },
    issuedAt: Date.now(),
    expiresAt: null,
  };
  const event = await actAs(pipeline(b), "mallory", fake, DB_WRITE);
  assert.equal(event.decision, DECISION.DENY);
});

test("delegation: editing a grant's scope invalidates its signature", async () => {
  const b = broker();
  const planner = b.root("planner", { actions: ["*"], resources: ["*"] });
  const toB = b.delegate(planner, "agent-b", { actions: ["fs.read"], resources: ["**"] });

  const tampered = { ...toB.grant, scope: { actions: ["*"], resources: ["*"] } };
  const event = await actAs(pipeline(b), "agent-b", tampered, DB_WRITE);

  assert.equal(event.decision, DECISION.DENY);
  assert.equal(event.policy, `delegation-${DELEGATION_ERROR.BAD_SIGNATURE}`);
});

test("delegation: editing the subject invalidates the signature", async () => {
  const b = broker();
  const planner = b.root("planner", { actions: ["*"], resources: ["*"] });
  const toB = b.delegate(planner, "agent-b", { actions: ["db.write"], resources: ["**"] });

  const tampered = { ...toB.grant, subject: "mallory" };
  const event = await actAs(pipeline(b), "mallory", tampered, DB_WRITE);
  assert.equal(event.decision, DECISION.DENY);
});

test("delegation: editing the depth or parent invalidates the signature", async () => {
  const b = broker();
  const planner = b.root("planner", { actions: ["*"], resources: ["*"] });
  const toB = b.delegate(planner, "agent-b", { actions: ["fs.read"], resources: ["**"] });

  for (const tampered of [
    { ...toB.grant, depth: 0 },
    { ...toB.grant, parent: null },
    { ...toB.grant, expiresAt: Date.now() + 10 ** 12 },
  ]) {
    const event = await actAs(pipeline(b), "agent-b", tampered, READ_APP);
    assert.equal(event.decision, DECISION.DENY, JSON.stringify(Object.keys(tampered)));
  }
});

test("delegation: a grant from another broker does not verify", async () => {
  // Distinct runtimes hold distinct keys, so a grant minted elsewhere is not
  // authority here. This is also the honest limit of local-only A2A.
  const mine = broker();
  const theirs = broker();
  const planner = theirs.root("planner", { actions: ["*"], resources: ["*"] });
  const toB = theirs.delegate(planner, "agent-b", { actions: ["db.write"], resources: ["**"] });

  const event = await actAs(pipeline(mine), "agent-b", toB.grant, DB_WRITE);
  assert.equal(event.decision, DECISION.DENY);
});

/* ========================================================================== */
/*  4. CHAINS: CYCLES, DEPTH, BROKEN LINKS                                    */
/* ========================================================================== */

test("delegation: a cycle is refused", () => {
  const b = broker();
  const a = b.root("a", { actions: ["*"], resources: ["*"] });
  const toB = b.delegate(a, "b", { actions: ["fs.read"], resources: ["**"] });
  const toC = b.delegate(toB.grant, "c", { actions: ["fs.read"], resources: ["**"] });

  const back = b.delegate(toC.grant, "a", { actions: ["fs.read"], resources: ["**"] });
  assert.equal(back.ok, false);
  assert.equal(back.error, DELEGATION_ERROR.CYCLE);
});

test("delegation: an immediate self-delegation is a cycle", () => {
  const b = broker();
  const a = b.root("a", { actions: ["*"], resources: ["*"] });
  const self = b.delegate(a, "a", { actions: ["fs.read"], resources: ["**"] });
  assert.equal(self.ok, false);
  assert.equal(self.error, DELEGATION_ERROR.CYCLE);
});

test("delegation: chain depth is bounded", () => {
  const b = broker();
  let current = b.root("a0", { actions: ["*"], resources: ["*"] });
  for (let i = 1; i <= MAX_DEPTH; i++) {
    const next = b.delegate(current, `a${i}`, { actions: ["fs.read"], resources: ["**"] });
    assert.ok(next.ok, `hop ${i} should be allowed`);
    current = next.grant;
  }
  const overflow = b.delegate(current, "one-too-many", { actions: ["fs.read"], resources: ["**"] });
  assert.equal(overflow.ok, false);
  assert.equal(overflow.error, DELEGATION_ERROR.TOO_DEEP);
});

test("delegation: a chain that does not reach a root is refused", async () => {
  const b = broker();
  const orphan = {
    id: "dlg_orphan",
    issuer: "ghost",
    subject: "agent-b",
    parent: "dlg_nonexistent",
    depth: 1,
    scope: { actions: ["*"], resources: ["*"] },
    issuedAt: Date.now(),
    expiresAt: null,
    signature: "whatever",
  };
  const event = await actAs(pipeline(b), "agent-b", orphan, DB_WRITE);
  assert.equal(event.decision, DECISION.DENY);
});

/* ========================================================================== */
/*  5. REVOCATION                                                             */
/* ========================================================================== */

test("delegation: revoking a grant stops it immediately", async () => {
  const b = broker();
  const planner = b.root("planner", { actions: ["*"], resources: ["*"] });
  const toB = b.delegate(planner, "agent-b", { actions: ["fs.read"], resources: ["**"] });
  const p = pipeline(b);

  assert.equal((await actAs(p, "agent-b", toB.grant, READ_APP)).decision, DECISION.ALLOW);

  b.revoke(toB.grant.id);

  const after = await actAs(p, "agent-b", toB.grant, READ_APP);
  assert.equal(after.decision, DECISION.DENY);
  assert.equal(after.policy, `delegation-${DELEGATION_ERROR.REVOKED}`);
});

test("delegation: revocation cascades to everything derived from it", async () => {
  /*
   * Revoking a link and leaving its children usable revokes nothing — the
   * authority simply flows around the hole.
   */
  const b = broker();
  const a = b.root("a", { actions: ["*"], resources: ["*"] });
  const toB = b.delegate(a, "b", { actions: ["fs.read"], resources: ["**"] });
  const toC = b.delegate(toB.grant, "c", { actions: ["fs.read"], resources: ["**"] });
  const p = pipeline(b);

  assert.equal((await actAs(p, "c", toC.grant, READ_APP)).decision, DECISION.ALLOW);

  b.revoke(toB.grant.id);

  const after = await actAs(p, "c", toC.grant, READ_APP);
  assert.equal(after.decision, DECISION.DENY, "C's grant died with its parent");
});

test("delegation: a revoked grant cannot issue new delegations", () => {
  const b = broker();
  const a = b.root("a", { actions: ["*"], resources: ["*"] });
  const toB = b.delegate(a, "b", { actions: ["fs.read"], resources: ["**"] });
  b.revoke(toB.grant.id);

  const onward = b.delegate(toB.grant, "c", { actions: ["fs.read"], resources: ["**"] });
  assert.equal(onward.ok, false);
  assert.equal(onward.error, DELEGATION_ERROR.REVOKED);
});

test("delegation: revoking the root kills the whole tree", async () => {
  const b = broker();
  const a = b.root("a", { actions: ["*"], resources: ["*"] });
  const toB = b.delegate(a, "b", { actions: ["fs.read"], resources: ["**"] });
  const toC = b.delegate(toB.grant, "c", { actions: ["fs.read"], resources: ["**"] });

  b.revoke(a.id);

  const p = pipeline(b);
  assert.equal((await actAs(p, "b", toB.grant, READ_APP)).decision, DECISION.DENY);
  assert.equal((await actAs(p, "c", toC.grant, READ_APP)).decision, DECISION.DENY);
});

/* ========================================================================== */
/*  6. EXPIRY                                                                 */
/* ========================================================================== */

test("delegation: an expired grant is refused", async () => {
  const b = broker();
  const planner = b.root("planner", { actions: ["*"], resources: ["*"] });
  const toB = b.delegate(planner, "agent-b", { actions: ["fs.read"], resources: ["**"] }, { ttlMs: -1 });

  const event = await actAs(pipeline(b), "agent-b", toB.grant, READ_APP);
  assert.equal(event.decision, DECISION.DENY);
  assert.equal(event.policy, `delegation-${DELEGATION_ERROR.EXPIRED}`);
});

test("delegation: an expired PARENT expires its children", async () => {
  // Otherwise a short-lived grant can be made permanent by delegating onward
  // before it lapses.
  const b = broker();
  const a = b.root("a", { actions: ["*"], resources: ["*"] });
  const toB = b.delegate(a, "b", { actions: ["fs.read"], resources: ["**"] }, { ttlMs: 30 });
  const toC = b.delegate(toB.grant, "c", { actions: ["fs.read"], resources: ["**"] }, { ttlMs: 10 ** 7 });

  await new Promise((r) => setTimeout(r, 60));

  const event = await actAs(pipeline(b), "c", toC.grant, READ_APP);
  assert.equal(event.decision, DECISION.DENY, "a long-lived child cannot outlive its parent");
});

test("delegation: an expired grant cannot issue new delegations", () => {
  const b = broker();
  const a = b.root("a", { actions: ["*"], resources: ["*"] });
  const toB = b.delegate(a, "b", { actions: ["fs.read"], resources: ["**"] }, { ttlMs: -1 });
  const onward = b.delegate(toB.grant, "c", { actions: ["fs.read"], resources: ["**"] });
  assert.equal(onward.ok, false);
  assert.equal(onward.error, DELEGATION_ERROR.EXPIRED);
});

/* ========================================================================== */
/*  7. CROSS-TENANT                                                           */
/* ========================================================================== */

test("delegation: tenancy is inherited, never chosen", () => {
  const b = broker();
  const acme = b.root("acme-planner", { actions: ["*"], resources: ["*"] }, { tenant: "acme" });
  const child = b.delegate(acme, "acme-worker", { actions: ["fs.read"], resources: ["**"] });
  assert.equal(child.grant.tenant, "acme", "a child cannot pick its own tenant");
});

test("delegation: a grant does not cross tenants", async () => {
  /*
   * This test used to assert something weaker, and the weakness was the bug.
   *
   * It asserted that a cross-tenant delegation RESOLVED successfully and that
   * the audit record honestly showed acme's tenancy on a globex agent's call.
   * That is a description of a breach, not a control against one: globex's
   * agent really did end up acting inside acme's authority, correctly signed,
   * correctly narrowed, and correctly logged.
   *
   * `UNKNOWN_TENANT` had been declared in `DELEGATION_ERROR` from the start and
   * was never raised anywhere in the codebase — the error code for this existed
   * and the check did not. The cross-boundary suite raises it now, at both
   * issue and presentation.
   */
  const b = broker();
  const acme = b.root("acme-planner", { actions: ["*"], resources: ["*"] }, { tenant: "acme" });
  b.root("globex-worker", { actions: ["fs.read"], resources: ["**"] }, { tenant: "globex" });

  const toWorker = b.delegate(acme, "globex-worker", { actions: ["db.write"], resources: ["**"] });
  assert.equal(toWorker.ok, false, "a tenant boundary is not crossed by a correctly signed grant");
  assert.equal(toWorker.error, DELEGATION_ERROR.UNKNOWN_TENANT);
});

/* ========================================================================== */
/*  8. APPROVALS AND DELEGATION                                               */
/* ========================================================================== */

test("delegation: an approval granted to A cannot be spent by B", async () => {
  /*
   * The approval fingerprint includes the agent, so a grant is bound to who
   * asked. Without that, delegation would be a route to approval laundering:
   * A gets a human to approve something, B spends it.
   */
  const dir = await mkdtemp(join(tmpdir(), "cirvix-dlg-"));
  const approvals = await new ApprovalStore(join(dir, "approvals.jsonl")).open();
  const chain = await new AuditChain(join(dir, "audit.jsonl")).open();

  const holdPolicy = compile(
    "require_approval:\n  name = approve-db\n  tool = database.write\n  approvers = oncall\n",
    { cwd: CWD, origin: "d" },
  ).rules;

  const p = new Pipeline({ rules: holdPolicy, cwd: CWD, agent: "x", approvals, audit: chain });

  const heldA = await p.submit(DB_WRITE, { agent: "agent-a" });
  assert.equal(heldA.event.decision, DECISION.REQUIRE_APPROVAL);
  await approvals.decide(heldA.event.approval_id, STATE.APPROVED, "sre@example.com");

  const byB = await p.submit(DB_WRITE, { agent: "agent-b" });
  assert.equal(byB.event.decision, DECISION.REQUIRE_APPROVAL, "B cannot spend A's approval");
  assert.notEqual(byB.event.approval_id, heldA.event.approval_id);
});

test("delegation: an approval cannot be replayed across a delegation chain", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-dlg-"));
  const approvals = await new ApprovalStore(join(dir, "approvals.jsonl")).open();
  const b = broker();
  const planner = b.root("planner", { actions: ["*"], resources: ["*"] });
  const toWorker = b.delegate(planner, "worker", { actions: ["db.write"], resources: ["**"] });

  const holdPolicy = compile(
    "require_approval:\n  name = approve-db\n  tool = database.write\n  approvers = oncall\n",
    { cwd: CWD, origin: "d" },
  ).rules;
  const p = new Pipeline({ rules: holdPolicy, cwd: CWD, agent: "x", approvals, delegation: b });

  const held = await p.submit(DB_WRITE, { agent: "planner" });
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  const viaWorker = await p.submit(DB_WRITE, { agent: "worker", delegation: toWorker.grant });
  assert.notEqual(viaWorker.event.decision, DECISION.ALLOW, "the worker did not inherit the approval");
});

/* ========================================================================== */
/*  9. CREDENTIAL HANDLES ACROSS AGENTS                                       */
/* ========================================================================== */

test("delegation: a scope that excludes network stops a handle being spent outward", async () => {
  // The interesting compound attack: B holds a secret handle and is delegated
  // filesystem authority only. It must not be able to spend the handle on an
  // outbound call.
  const { Vault } = await import("../../src/core/vault.mjs");
  const vault = new Vault();
  const handle = vault.issue("KEY", "rk_live_MATERIAL0123456789abc");

  const b = broker();
  const planner = b.root("planner", { actions: ["*"], resources: ["*"] });
  const toWorker = b.delegate(planner, "worker", { actions: ["fs.read"], resources: ["**"] });

  const p = new Pipeline({ rules, cwd: CWD, agent: "x", delegation: b, secrets: vault });
  const { event, arguments: outgoing } = await p.submit(
    {
      tool: "http_request",
      arguments: { url: "https://api.stripe.com/v1/charges", headers: { authorization: `Bearer ${handle}` } },
    },
    { agent: "worker", delegation: toWorker.grant },
  );

  assert.equal(event.decision, DECISION.DENY);
  assert.equal(outgoing.headers.authorization, `Bearer ${handle}`, "nothing was substituted");
});

/* ========================================================================== */
/*  10. DELEGATION NEVER GRANTS                                               */
/* ========================================================================== */

test("delegation: a wide grant cannot make a policy-denied call succeed", async () => {
  /*
   * The property that makes delegation safe to have at all. If a token could
   * turn a denial into a permit, the token would be a capability — and a
   * capability that leaks is authority that leaks.
   */
  const denyPolicy = compile(
    "deny:\n  name = deny-credentials\n  tool = filesystem.read\n  path = **/.aws/**\n" +
      "allow:\n  name = allow-reads\n  tool = filesystem.read\n",
    { cwd: CWD, origin: "d" },
  ).rules;

  const b = broker();
  const god = b.root("root-agent", { actions: ["*"], resources: ["*"] });
  const toWorker = b.delegate(god, "worker", { actions: ["*"], resources: ["*"] });

  const p = new Pipeline({ rules: denyPolicy, cwd: CWD, agent: "x", delegation: b });
  const { event } = await p.submit(
    { tool: "read_file", arguments: { path: "~/.aws/credentials" } },
    { agent: "worker", delegation: toWorker.grant },
  );

  assert.equal(event.decision, DECISION.DENY);
  assert.equal(event.policy, "deny-credentials", "the policy rule decided, not the delegation");
});

test("delegation: presenting no grant leaves policy in sole charge", async () => {
  const b = broker();
  const p = pipeline(b);
  const event = await p.submit(READ_APP, { agent: "solo" });
  assert.equal(event.event.decision, DECISION.ALLOW);
});

/* ========================================================================== */
/*  11. POLICY RELOAD AND RESTART                                             */
/* ========================================================================== */

test("delegation: a policy reload does not widen an existing grant", async () => {
  const b = broker();
  const planner = b.root("planner", { actions: ["*"], resources: ["*"] });
  const toWorker = b.delegate(planner, "worker", { actions: ["fs.read"], resources: ["**"] });

  const p = pipeline(b);
  assert.equal((await actAs(p, "worker", toWorker.grant, DB_WRITE)).decision, DECISION.DENY);

  // Policy becomes maximally permissive. The delegation still binds.
  p.rules = compile("allow:\n  name = allow-all\n  tool = database.write\n", { cwd: CWD, origin: "d" }).rules;

  const after = await actAs(p, "worker", toWorker.grant, DB_WRITE);
  assert.equal(after.decision, DECISION.DENY, "loosening policy cannot widen a delegation");
  assert.equal(after.policy, "delegation-out-of-scope");
});

test("delegation: a policy reload can still tighten past a grant", async () => {
  // Narrowing works in both directions: the tighter of policy and delegation
  // always wins, whichever one it is.
  const b = broker();
  const planner = b.root("planner", { actions: ["*"], resources: ["*"] });
  const toWorker = b.delegate(planner, "worker", { actions: ["fs.read"], resources: ["**"] });

  const p = pipeline(b);
  assert.equal((await actAs(p, "worker", toWorker.grant, READ_APP)).decision, DECISION.ALLOW);

  p.rules = compile("deny:\n  name = deny-reads\n  tool = filesystem.read\n  path = **/*\n", {
    cwd: CWD,
    origin: "d",
  }).rules;

  const after = await actAs(p, "worker", toWorker.grant, READ_APP);
  assert.equal(after.decision, DECISION.DENY);
  assert.equal(after.policy, "deny-reads");
});

test("delegation: grants do not survive a broker restart", async () => {
  /*
   * Deliberate, and the safe direction. Grants live in memory with a
   * per-runtime key, so restarting the runtime invalidates every outstanding
   * delegation rather than resurrecting one whose issuer is gone. Persisting
   * them is a control-plane feature; doing it here would mean a grant
   * outliving the process that could revoke it.
   */
  const first = broker();
  const planner = first.root("planner", { actions: ["*"], resources: ["*"] });
  const toWorker = first.delegate(planner, "worker", { actions: ["fs.read"], resources: ["**"] });

  const restarted = broker();
  const event = await actAs(pipeline(restarted), "worker", toWorker.grant, READ_APP);
  assert.equal(event.decision, DECISION.DENY, "a grant from a previous runtime is not authority");
});

/* ========================================================================== */
/*  12. THE AUDIT RECORD                                                      */
/* ========================================================================== */

test("delegation: the audit record names the whole chain", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-dlg-"));
  const chain = await new AuditChain(join(dir, "audit.jsonl")).open();

  const b = broker();
  const a = b.root("planner", { actions: ["*"], resources: ["*"] });
  const toB = b.delegate(a, "researcher", { actions: ["fs.read"], resources: ["**"] });
  const toC = b.delegate(toB.grant, "summariser", { actions: ["fs.read"], resources: ["**"] });

  const p = new Pipeline({ rules, cwd: CWD, agent: "x", delegation: b, audit: chain });
  await p.submit(READ_APP, { agent: "summariser", delegation: toC.grant });

  const records = await chain.read();
  const record = records[records.length - 1];
  assert.deepEqual(
    record.delegation.principals,
    ["planner", "researcher", "summariser"],
    "who authorized this must be answerable after the fact",
  );
  assert.equal(record.delegation.depth, 2);
  assert.equal((await chain.verify()).ok, true);
});

/* ========================================================================== */
/*  13. SCOPE ALGEBRA                                                         */
/* ========================================================================== */

test("delegation: isNarrowing rejects every widening shape", () => {
  const parent = { actions: ["fs.read"], resources: [`${CWD}/src/**`] };
  assert.equal(isNarrowing(parent, { actions: ["fs.read"], resources: [`${CWD}/src/lib/**`] }), true);
  assert.equal(isNarrowing(parent, { actions: ["fs.read", "fs.write"], resources: [`${CWD}/src/**`] }), false);
  assert.equal(isNarrowing(parent, { actions: ["*"], resources: [`${CWD}/src/**`] }), false);
  assert.equal(isNarrowing(parent, { actions: ["fs.read"], resources: ["**"] }), false);
  assert.equal(isNarrowing({ actions: ["*"], resources: ["*"] }, { actions: ["**"], resources: ["**"] }), true);
});

test("delegation: intersecting scopes keeps only what both permit", () => {
  const merged = intersectScopes(
    { actions: ["fs.read", "fs.write"], resources: ["**"] },
    { actions: ["fs.read"], resources: [`${CWD}/**`] },
  );
  assert.ok(scopePermits(merged, { action: "fs.read", resource: `${CWD}/x` }));
  assert.ok(!scopePermits(merged, { action: "fs.write", resource: `${CWD}/x` }));
});

test("delegation: an empty scope permits nothing", () => {
  assert.equal(scopePermits({ actions: [], resources: [] }, { action: "fs.read", resource: "x" }), false);
});
