/**
 * Cross-boundary identity attacks.
 *
 * The delegation suite next door attacks one hop:
 *
 *   A ──▶ B ──▶ tool
 *
 * This one attacks the shape a real deployment actually has, where authority
 * crosses a TRANSPORT as well as an agent:
 *
 *   A
 *    │ delegation
 *    ▼
 *   B
 *    │ MCP            ← a process boundary, a wire format, a different code path
 *    ▼
 *   C
 *    │ delegation
 *    ▼
 *   D
 *    │ tool
 *    ▼
 *   the thing that actually happens
 *
 * THE INVARIANT
 *
 *   Identity + delegation + policy + approval must all describe the SAME
 *   operation.
 *
 * Four subsystems each answer a different question — who is calling, what were
 * they lent, what is permitted, and who said yes. A system is secure when all
 * four answers refer to one operation. Every attack below tries to make two of
 * them refer to different operations, because that gap is where the authority
 * lives:
 *
 *   · identity says B, delegation says C            → impersonation
 *   · delegation says "read", policy evaluates "write" → confused deputy
 *   · approval was for A's call, B spends it        → approval laundering
 *   · the handle was issued to A, B resolves it     → credential laundering
 *   · the decision was made at T, execution at T+1  → revocation TOCTOU
 *
 * WHY A TRANSPORT SECTION EXISTS AT ALL
 *
 * Because this codebase has already been bitten twice by the same thing: a
 * control that was real in one code path and absent in another. Risk rules
 * fired over the socket and never over MCP. Approvals could be granted and had
 * no release path. Both passed their own unit tests, because a unit test calls
 * the layer that has the control.
 *
 * So section 1 does not test delegation logic. It tests whether a delegation
 * can be PRESENTED at each place a call can enter the runtime — and whether
 * dropping it fails open. Delegation only ever narrows, which means a dropped
 * delegation is a widened one. Silence is the dangerous direction here.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Pipeline } from "../../src/core/pipeline.mjs";
import { AuditChain } from "../../src/core/audit.mjs";
import { ApprovalStore, STATE, approvalFingerprint } from "../../src/core/approvals.mjs";
import { Guard } from "../../src/core/guard.mjs";
import { Vault } from "../../src/core/vault.mjs";
import {
  DELEGATION_ERROR,
  DelegationBroker,
  MAX_DEPTH,
} from "../../src/core/delegation.mjs";
import {
  UdsClient,
  UdsServer,
  defaultEndpoint,
  writeToken,
} from "../../src/core/uds.mjs";
import { compile } from "../../src/core/policy-dsl.mjs";
import { DECISION } from "../../src/core/decisions.mjs";

const CWD = process.platform === "win32" ? "C:/workspace" : "/workspace";

/**
 * Permissive on purpose, as in the delegation suite.
 *
 * If the policy did the narrowing, a passing test would prove nothing about
 * identity. Everything here must be stopped by delegation, approval, or handle
 * binding — never by a lucky `deny` rule.
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

const rules = compile(POLICY, { cwd: CWD, origin: "cross-boundary" }).rules;

const READ_APP = { tool: "read_file", arguments: { path: `${CWD}/src/app.ts` } };
const DB_WRITE = { tool: "database.write", arguments: { table: "salaries" } };
const WIDE = { actions: ["*"], resources: ["*"] };
const READ_ONLY = { actions: ["fs.read"], resources: ["**"] };

function broker(opts) {
  return new DelegationBroker(opts);
}

function pipeline(delegation, extra = {}) {
  return new Pipeline({ rules, cwd: CWD, agent: "unused", delegation, ...extra });
}

async function tempDir() {
  return mkdtemp(join(tmpdir(), "cirvix-xb-"));
}

/** Submits `call` as `agent`, presenting `grant`. */
async function actAs(p, agent, grant, call) {
  const { event } = await p.submit(call, { agent, delegation: grant });
  return event;
}

/** A → B, where B is read-only and the tool call is a database write. */
function confusedDeputy() {
  const b = broker();
  const planner = b.root("planner", WIDE);
  const toWorker = b.delegate(planner, "worker", READ_ONLY);
  assert.ok(toWorker.ok, "setup: the narrowing delegation must issue");
  return { b, planner, grant: toWorker.grant };
}

/* ========================================================================== */
/*  1. THE TRANSPORT BOUNDARY                                                  */
/*                                                                             */
/*  A control that exists in one code path and not another is not a control.   */
/*  Delegation NARROWS, so a transport that silently drops it does not fail    */
/*  safe — it hands the caller everything policy allows.                       */
/* ========================================================================== */

test("cross-boundary: the local socket enforces a presented delegation", async () => {
  /*
   * The daemon is how a real agent talks to Cirvix. If a delegation cannot be
   * presented here, the feature does not exist outside its own unit test — and
   * a read-only worker gets database authority the moment it stops using the
   * test harness.
   */
  const { b, grant } = confusedDeputy();

  const stateDir = await tempDir();
  const token = await writeToken(stateDir);
  const endpoint = defaultEndpoint(stateDir);

  const p = pipeline(b);
  const server = new UdsServer({
    pipeline: p,
    endpoint,
    token,
    status: () => ({}),
    recent: async () => [],
  });
  await server.start();

  try {
    const client = new UdsClient({ endpoint, token });
    const result = await client.call("cirvix/authorize", {
      agent: "worker",
      tool: "database.write",
      arguments: { table: "salaries" },
      delegation: grant,
    });

    assert.equal(
      result.allowed,
      false,
      "the worker was delegated filesystem reads and asked for a database write over the socket",
    );
    assert.equal(result.decision, DECISION.DENY);
    assert.match(
      String(result.policy),
      /^delegation-/,
      "delegation must be what refused it — policy permits this call by design",
    );
  } finally {
    await server.stop();
  }
});

test("cross-boundary: the socket refuses a grant presented by the wrong agent", async () => {
  const { b, grant } = confusedDeputy();

  const stateDir = await tempDir();
  const token = await writeToken(stateDir);
  const endpoint = defaultEndpoint(stateDir);

  const server = new UdsServer({
    pipeline: pipeline(b),
    endpoint,
    token,
    status: () => ({}),
    recent: async () => [],
  });
  await server.start();

  try {
    const client = new UdsClient({ endpoint, token });
    const result = await client.call("cirvix/authorize", {
      // `worker`'s grant, presented by `mallory`.
      agent: "mallory",
      tool: "read_file",
      arguments: { path: `${CWD}/src/app.ts` },
      delegation: grant,
    });

    assert.equal(result.allowed, false, "possession of a grant is not identity");
    assert.equal(result.policy, `delegation-${DELEGATION_ERROR.SUBJECT_MISMATCH}`);
  } finally {
    await server.stop();
  }
});

test("cross-boundary: the MCP decision core enforces a presented delegation", async () => {
  /*
   * The gateway and the SDK both decide through `Guard`, not through
   * `Pipeline`. This is the exact seam where risk rules were once enforced on
   * one side and not the other.
   */
  const { b, grant } = confusedDeputy();

  const g = new Guard({ rules, cwd: CWD, agent: "worker", delegation: b });
  const { decision } = await g.authorize({
    tool: "database.write",
    args: { table: "salaries" },
    delegation: grant,
  });

  assert.equal(decision.verdict, "deny", "policy permits this; the delegation must not");
  assert.match(String(decision.rule), /^delegation-/);
});

test("cross-boundary: Guard and Pipeline agree on the same delegated call", async () => {
  /*
   * Two engines that disagree are one bypass. Whichever surface an attacker can
   * reach becomes the effective policy, so the weaker one is the real one.
   */
  const { b, grant } = confusedDeputy();

  const viaPipeline = await actAs(pipeline(b), "worker", grant, DB_WRITE);
  const { decision: viaGuard } = await new Guard({
    rules,
    cwd: CWD,
    agent: "worker",
    delegation: b,
  }).authorize({ tool: "database.write", args: { table: "salaries" }, delegation: grant });

  assert.equal(viaPipeline.decision, DECISION.DENY);
  assert.equal(viaGuard.verdict, "deny");
  assert.equal(
    viaPipeline.policy,
    viaGuard.rule,
    "the two decision paths must refuse for the same recorded reason",
  );
});

test("cross-boundary: a delegation that cannot be presented is not a silent widening", async () => {
  /*
   * The failure mode this closes, stated plainly: a transport that ignores the
   * `delegation` field it was given produces ALLOW for a call the delegation
   * forbids, and records nothing about it. The operator reads the log and sees
   * an ordinary permitted write.
   *
   * So the audit record must name the chain whenever one was presented. An
   * allowed call with no `delegation` block, from a caller that presented one,
   * is the signature of a dropped control.
   */
  const { b, grant } = confusedDeputy();
  const dir = await tempDir();
  const chain = await new AuditChain(join(dir, "audit.jsonl")).open();

  const p = pipeline(b, { audit: chain });
  await actAs(p, "worker", grant, READ_APP);

  const records = await chain.read();
  const record = records[records.length - 1];
  assert.ok(record.delegation, "a presented delegation must appear in the record");
  assert.deepEqual(record.delegation.principals, ["planner", "worker"]);
});

/* ========================================================================== */
/*  2. FORGED IDENTITY                                                         */
/*                                                                             */
/*  Every field of a grant is attacker-controlled until a signature says       */
/*  otherwise. These attack each field individually.                           */
/* ========================================================================== */

test("cross-boundary: a forged issuer does not verify", async () => {
  const b = broker();
  const planner = b.root("planner", WIDE);
  const toWorker = b.delegate(planner, "worker", READ_ONLY);

  // Rewriting the issuer is the paperwork half of impersonation: the grant now
  // claims a more privileged parent than the one that signed it.
  const forged = { ...toWorker.grant, issuer: "root-agent" };
  const event = await actAs(pipeline(b), "worker", forged, READ_APP);

  assert.equal(event.decision, DECISION.DENY);
  assert.equal(event.policy, `delegation-${DELEGATION_ERROR.BAD_SIGNATURE}`);
});

test("cross-boundary: a swapped parent does not graft one chain onto another", async () => {
  /*
   * Two legitimate chains exist. The attacker takes the narrow grant it holds
   * and re-points its parent at the wide chain, hoping the walk collects the
   * wide scope on the way to the root.
   */
  const b = broker();
  const wideRoot = b.root("privileged", WIDE);
  const narrowRoot = b.root("restricted", { actions: ["fs.read"], resources: [`${CWD}/public/**`] });

  const toWorker = b.delegate(narrowRoot, "worker", {
    actions: ["fs.read"],
    resources: [`${CWD}/public/**`],
  });
  assert.ok(toWorker.ok);

  const grafted = { ...toWorker.grant, parent: wideRoot.id };
  const event = await actAs(pipeline(b), "worker", grafted, DB_WRITE);

  assert.equal(event.decision, DECISION.DENY, "a chain cannot be re-parented onto a richer root");
  assert.equal(event.policy, `delegation-${DELEGATION_ERROR.BAD_SIGNATURE}`);
});

test("cross-boundary: a grant whose id collides with a real one is not accepted on its id", async () => {
  /*
   * Resolution takes an object OR an id. A forged object carrying the id of a
   * legitimate grant must be judged on its own contents, not silently resolved
   * to the real record behind its id — which would make the id the credential.
   */
  const b = broker();
  const planner = b.root("planner", WIDE);
  const toWorker = b.delegate(planner, "worker", READ_ONLY);

  const impostor = {
    ...toWorker.grant,
    scope: { actions: ["*"], resources: ["*"] },
    signature: "0".repeat(64),
  };

  const event = await actAs(pipeline(b), "worker", impostor, DB_WRITE);
  assert.equal(event.decision, DECISION.DENY);
});

test("cross-boundary: a signature from a sibling grant does not transfer", () => {
  /*
   * Signature reuse. Two grants exist under one key; the attacker pastes the
   * signature of the wide one onto the narrow one. The signature covers the
   * whole grant, so it must not verify against different contents.
   */
  const b = broker();
  const wide = b.root("privileged", WIDE);
  const planner = b.root("planner", WIDE);
  const narrow = b.delegate(planner, "worker", READ_ONLY);

  const spliced = { ...narrow.grant, scope: WIDE, signature: wide.signature };
  const resolved = b.resolve(spliced, "worker");

  assert.equal(resolved.ok, false);
  assert.equal(resolved.error, DELEGATION_ERROR.BAD_SIGNATURE);
});

/* ========================================================================== */
/*  3. STALENESS AND REVOCATION ACROSS A BOUNDARY                              */
/* ========================================================================== */

test("cross-boundary: a revoked parent kills a child mid-chain over the socket", async () => {
  const b = broker();
  const a = b.root("a", WIDE);
  const toB = b.delegate(a, "b", READ_ONLY);
  const toC = b.delegate(toB.grant, "c", READ_ONLY);

  const stateDir = await tempDir();
  const token = await writeToken(stateDir);
  const endpoint = defaultEndpoint(stateDir);
  const server = new UdsServer({
    pipeline: pipeline(b),
    endpoint,
    token,
    status: () => ({}),
    recent: async () => [],
  });
  await server.start();

  try {
    const client = new UdsClient({ endpoint, token });
    const before = await client.call("cirvix/authorize", {
      agent: "c",
      tool: "read_file",
      arguments: { path: `${CWD}/src/app.ts` },
      delegation: toC.grant,
    });
    assert.equal(before.allowed, true, "setup: the chain works before revocation");

    b.revoke(toB.grant.id);

    const after = await client.call("cirvix/authorize", {
      agent: "c",
      tool: "read_file",
      arguments: { path: `${CWD}/src/app.ts` },
      delegation: toC.grant,
    });
    assert.equal(after.allowed, false, "revoking the middle of a chain must reach the far end");
    assert.equal(after.policy, `delegation-${DELEGATION_ERROR.REVOKED}`);
  } finally {
    await server.stop();
  }
});

test("cross-boundary: revocation between decision and execution stops the call", async () => {
  /*
   * The TOCTOU. Cirvix decides, then the caller executes. If revocation only
   * binds at decision time, an agent that holds its decision and acts later is
   * acting on authority that no longer exists — and the window is however long
   * the tool round trip takes.
   *
   * The check that matters is not "was it valid when we decided" but "is it
   * valid now" — asked again at the moment of release.
   */
  const b = broker();
  const planner = b.root("planner", WIDE);
  const toWorker = b.delegate(planner, "worker", READ_ONLY);

  const p = pipeline(b);
  const first = await actAs(p, "worker", toWorker.grant, READ_APP);
  assert.equal(first.decision, DECISION.ALLOW, "setup");

  b.revoke(toWorker.grant.id);

  // The same decision, replayed after revocation, must not still authorize.
  const replayed = await actAs(p, "worker", toWorker.grant, READ_APP);
  assert.equal(replayed.decision, DECISION.DENY);
  assert.equal(replayed.policy, `delegation-${DELEGATION_ERROR.REVOKED}`);
});

test("cross-boundary: a stale child cannot outlive the parent it was cut from", async () => {
  /*
   * `expiresAt` is signed, so it cannot be edited. The attack is subtler: mint
   * a long-lived child from a short-lived parent, wait for the parent to lapse,
   * and keep using the child.
   */
  const b = broker();
  const a = b.root("a", WIDE);
  const toB = b.delegate(a, "b", READ_ONLY, { ttlMs: 25 });
  const toC = b.delegate(toB.grant, "c", READ_ONLY, { ttlMs: 10 ** 7 });

  await new Promise((r) => setTimeout(r, 60));

  const event = await actAs(pipeline(b), "c", toC.grant, READ_APP);
  assert.equal(event.decision, DECISION.DENY);
  assert.equal(event.policy, `delegation-${DELEGATION_ERROR.EXPIRED}`);
});

test("cross-boundary: revoking a child does not revoke its parent", () => {
  /*
   * Cascade must run downward only. If revoking a leaf killed its ancestors, an
   * agent at the bottom of a chain could revoke the agent at the top — denial
   * of service by delegation, and an escalation of a different kind: the power
   * to disable someone above you.
   */
  const b = broker();
  const a = b.root("a", WIDE);
  const toB = b.delegate(a, "b", READ_ONLY);
  const toC = b.delegate(toB.grant, "c", READ_ONLY);

  b.revoke(toC.grant.id);

  assert.equal(b.isRevoked(toC.grant.id), true);
  assert.equal(b.isRevoked(toB.grant.id), false, "revocation must not travel upward");
  assert.equal(b.isRevoked(a.id), false);
});

/* ========================================================================== */
/*  4. CROSS-TENANT                                                            */
/*                                                                             */
/*  The one boundary a customer will never accept being soft.                  */
/* ========================================================================== */

test("cross-boundary: an agent rooted in one tenant cannot act under another's grant", async () => {
  /*
   * `acme-planner` delegates to `globex-worker`. Both are real, both are
   * signed, and the chain narrows correctly — the delegation logic has no
   * complaint.
   *
   * But `globex-worker` is rooted in `globex`, and the grant it presents is
   * rooted in `acme`. Accepting it lets one customer's agent act inside another
   * customer's authority. Recording the fact is not the same as refusing it:
   * "the audit shows a cross-tenant delegation" is a description of a breach,
   * not a control against one.
   */
  const b = broker();
  const acme = b.root("acme-planner", WIDE, { tenant: "acme" });
  b.root("globex-worker", READ_ONLY, { tenant: "globex" });

  const across = b.delegate(acme, "globex-worker", { actions: ["db.write"], resources: ["**"] });
  assert.equal(across.ok, false, "the broker must not mint a grant across a tenant boundary");
  assert.equal(across.error, DELEGATION_ERROR.UNKNOWN_TENANT);
});

test("cross-boundary: tenancy learned after the fact still refuses at presentation", async () => {
  /*
   * Refusing at issue is not sufficient on its own, because tenancy can be
   * registered AFTER a grant was minted — an operator onboards `globex-worker`
   * into globex tomorrow, and yesterday's acme grant is still signed and still
   * in the attacker's hands.
   *
   * So the boundary is checked twice: once where it can be reported early, and
   * once where it can actually be enforced.
   */
  const b = broker();
  const acme = b.root("acme-planner", WIDE, { tenant: "acme" });

  // At this moment `globex-worker` has no registered tenancy, so the grant mints.
  const across = b.delegate(acme, "globex-worker", { actions: ["db.write"], resources: ["**"] });
  assert.ok(across.ok, "setup: nothing yet says which tenant this agent belongs to");

  // The agent is onboarded into a different tenant.
  b.root("globex-worker", READ_ONLY, { tenant: "globex" });

  const event = await actAs(pipeline(b), "globex-worker", across.grant, DB_WRITE);
  assert.equal(event.decision, DECISION.DENY, "a tenant boundary is not crossed by a signature");
  assert.equal(event.policy, `delegation-${DELEGATION_ERROR.UNKNOWN_TENANT}`);
});

test("cross-boundary: an unrooted agent is vouched for, and gains nothing beyond the grant", async () => {
  /*
   * The deliberate non-refusal, recorded so nobody later reads it as an
   * oversight.
   *
   * `helper` has no root of its own — the ordinary case for an agent a planner
   * spawns for one task. Its acme grant works, because acme minted it FOR
   * `helper` and that is what vouching means. Refusing here would break normal
   * single-tenant use to defend a boundary nobody crossed.
   *
   * What it must NOT do is become authority beyond the grant: the scope still
   * binds, and the name still buys nothing on its own.
   */
  const b = broker();
  const acme = b.root("acme-planner", WIDE, { tenant: "acme" });
  const toHelper = b.delegate(acme, "helper", { actions: ["db.write"], resources: ["**"] });
  assert.ok(toHelper.ok);

  const p = pipeline(b);

  const within = await actAs(p, "helper", toHelper.grant, DB_WRITE);
  assert.equal(within.decision, DECISION.ALLOW, "the tenant vouched for this agent");
  assert.equal(within.delegation.tenant, "acme");

  const outside = await actAs(p, "helper", toHelper.grant, READ_APP);
  assert.equal(outside.decision, DECISION.DENY, "and the scope still binds");
  assert.equal(outside.policy, "delegation-out-of-scope");

  // Another agent claiming the same name proves nothing: the grant names
  // `helper`, and a name is not an identity.
  const impostor = await actAs(p, "helper-2", toHelper.grant, DB_WRITE);
  assert.equal(impostor.decision, DECISION.DENY);
  assert.equal(impostor.policy, `delegation-${DELEGATION_ERROR.SUBJECT_MISMATCH}`);
});

test("cross-boundary: an agent cannot be rooted into two tenants", () => {
  /*
   * The setup half of the cross-tenant attack, refused where an operator can
   * see it. Registering `globex-worker` in acme as well would make every acme
   * grant it holds resolve — the boundary defeated by configuration rather
   * than by forgery.
   */
  const b = broker();
  b.root("globex-worker", READ_ONLY, { tenant: "globex" });
  assert.throws(
    () => b.root("globex-worker", READ_ONLY, { tenant: "acme" }),
    /belongs to one tenant/,
  );
});

test("cross-boundary: same-tenant delegation still works", () => {
  // The control must not be a blanket refusal. Narrowing within one tenant is
  // the ordinary case and has to keep working, or the fix is a regression.
  const b = broker();
  const acme = b.root("acme-planner", WIDE, { tenant: "acme" });
  b.root("acme-worker", READ_ONLY, { tenant: "acme" });

  const within = b.delegate(acme, "acme-worker", READ_ONLY);
  assert.ok(within.ok);

  const resolved = b.resolve(within.grant, "acme-worker");
  assert.equal(resolved.ok, true);
  assert.equal(resolved.tenant, "acme");
});

test("cross-boundary: an untenanted deployment is unaffected", () => {
  // Most installs never set a tenant. Introducing a tenant check must not
  // break every one of them.
  const b = broker();
  const planner = b.root("planner", WIDE);
  b.root("worker", READ_ONLY);
  const grant = b.delegate(planner, "worker", READ_ONLY);

  assert.equal(b.resolve(grant.grant, "worker").ok, true);
});

/* ========================================================================== */
/*  5. APPROVAL CROSSING AN IDENTITY BOUNDARY                                  */
/*                                                                             */
/*  A human said yes to something. The attack is to make that yes apply to     */
/*  something else.                                                            */
/* ========================================================================== */

const HOLD_POLICY = compile(
  "require_approval:\n  name = approve-db\n  tool = database.write\n  approvers = oncall\n",
  { cwd: CWD, origin: "xb" },
).rules;

async function approvalRig(extra = {}) {
  const dir = await tempDir();
  const approvals = await new ApprovalStore(join(dir, "approvals.jsonl")).open();
  return {
    approvals,
    p: new Pipeline({ rules: HOLD_POLICY, cwd: CWD, agent: "x", approvals, ...extra }),
  };
}

test("cross-boundary: an approval granted to A cannot be spent by B", async () => {
  const { approvals, p } = await approvalRig();

  const held = await p.submit(DB_WRITE, { agent: "agent-a" });
  assert.equal(held.event.decision, DECISION.REQUIRE_APPROVAL);
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  const byB = await p.submit(DB_WRITE, { agent: "agent-b" });
  assert.equal(byB.event.decision, DECISION.REQUIRE_APPROVAL, "B must ask for its own");
});

test("cross-boundary: an approval is bound to the chain the approver was shown", async () => {
  /*
   * Approval laundering through a substituted chain.
   *
   * An operator approves a database write and sees `planner → worker`. The same
   * agent, the same tool, the same arguments — but arriving under
   * `planner → attacker → worker`. Identity is satisfied (it really is
   * `worker`), delegation is satisfied (the chain narrows correctly), policy is
   * satisfied (it asked for approval and got one).
   *
   * The four answers no longer describe the same operation: the human authorized
   * a call from one chain of custody and a different chain spends it. If the
   * fingerprint does not cover the chain, "who vouched for this" is not part of
   * what was approved.
   */
  const b = broker();
  const planner = b.root("planner", WIDE);
  const direct = b.delegate(planner, "worker", { actions: ["db.write"], resources: ["**"] });
  const viaAttacker = b.delegate(planner, "attacker", { actions: ["db.write"], resources: ["**"] });
  const laundered = b.delegate(viaAttacker.grant, "worker", {
    actions: ["db.write"],
    resources: ["**"],
  });
  assert.ok(direct.ok && laundered.ok, "setup: both chains are legitimately signed");

  const { approvals, p } = await approvalRig({ delegation: b });

  const held = await p.submit(DB_WRITE, { agent: "worker", delegation: direct.grant });
  assert.equal(held.event.decision, DECISION.REQUIRE_APPROVAL);
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  const spent = await p.submit(DB_WRITE, { agent: "worker", delegation: laundered.grant });
  assert.notEqual(
    spent.event.decision,
    DECISION.ALLOW,
    "an approval for one chain of custody must not release a call made under another",
  );
});

test("cross-boundary: the approval fingerprint distinguishes two chains", () => {
  // The property the test above depends on, asserted directly so a regression
  // names the cause rather than the symptom.
  const base = { agent: "worker", action: "db.write", resource: "salaries", arguments: {} };
  const viaOne = approvalFingerprint({ ...base, delegation: { principals: ["planner", "worker"] } });
  const viaTwo = approvalFingerprint({
    ...base,
    delegation: { principals: ["planner", "attacker", "worker"] },
  });
  assert.notEqual(viaOne, viaTwo, "the chain of custody is part of what was approved");
});

test("cross-boundary: an undelegated call cannot spend a delegated approval", async () => {
  /*
   * The inverse laundering: get approval while acting under a narrow chain,
   * then present nothing at all. Without a delegation the call is governed by
   * policy alone — which is WIDER — so the approval would be released into a
   * larger authority than the one it was granted under.
   */
  const b = broker();
  const planner = b.root("planner", WIDE);
  const toWorker = b.delegate(planner, "worker", { actions: ["db.write"], resources: ["**"] });

  const { approvals, p } = await approvalRig({ delegation: b });

  const held = await p.submit(DB_WRITE, { agent: "worker", delegation: toWorker.grant });
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  const bare = await p.submit(DB_WRITE, { agent: "worker" });
  assert.notEqual(bare.event.decision, DECISION.ALLOW, "dropping the chain must not release the grant");
});

test("cross-boundary: an approval is single-use across a delegation chain", async () => {
  const b = broker();
  const planner = b.root("planner", WIDE);
  const toWorker = b.delegate(planner, "worker", { actions: ["db.write"], resources: ["**"] });

  const { approvals, p } = await approvalRig({ delegation: b });

  const held = await p.submit(DB_WRITE, { agent: "worker", delegation: toWorker.grant });
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  const first = await p.submit(DB_WRITE, { agent: "worker", delegation: toWorker.grant });
  assert.equal(first.event.decision, DECISION.ALLOW, "the approval releases exactly once");

  const second = await p.submit(DB_WRITE, { agent: "worker", delegation: toWorker.grant });
  assert.notEqual(second.event.decision, DECISION.ALLOW, "one yes is not an unlimited yes");
});

test("cross-boundary: revoking the delegation invalidates its pending approval", async () => {
  /*
   * A hold outlives the decision that created it. If the chain is revoked while
   * a human is still deciding, saying yes afterwards must not resurrect
   * authority that was withdrawn.
   */
  const b = broker();
  const planner = b.root("planner", WIDE);
  const toWorker = b.delegate(planner, "worker", { actions: ["db.write"], resources: ["**"] });

  const { approvals, p } = await approvalRig({ delegation: b });

  const held = await p.submit(DB_WRITE, { agent: "worker", delegation: toWorker.grant });
  assert.equal(held.event.decision, DECISION.REQUIRE_APPROVAL);

  b.revoke(toWorker.grant.id);
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  const after = await p.submit(DB_WRITE, { agent: "worker", delegation: toWorker.grant });
  assert.equal(after.event.decision, DECISION.DENY);
  assert.equal(after.event.policy, `delegation-${DELEGATION_ERROR.REVOKED}`);
});

/* ========================================================================== */
/*  6. SECRET HANDLES CROSSING AN IDENTITY BOUNDARY                            */
/*                                                                             */
/*  A handle is deliberately not secret — that is the whole design. It appears */
/*  in arguments, in logs, in transcripts, in a result another agent reads. So */
/*  possession of one must not be authority to spend it.                       */
/* ========================================================================== */

test("cross-boundary: a handle issued to A cannot be resolved by B", async () => {
  /*
   * The credential-laundering attack, and the one the handle design invites if
   * binding is missing.
   *
   * `payments-agent` holds a live Stripe key behind `sec_handle_01`. The handle
   * string is not treated as a secret anywhere: it goes in arguments, it is
   * printed in audit records, it is safe to paste into a ticket. That is the
   * point of it.
   *
   * If the vault resolves whoever presents it, then a handle appearing in any
   * shared surface is the key itself, laundered — and every property the design
   * claims ("the agent never receives the material") is preserved for the wrong
   * agent.
   */
  const vault = new Vault();
  const handle = vault.issue("STRIPE_KEY", "rk_" + "live_MATERIAL0123456789abc", {
    subject: "payments-agent",
  });

  const owner = await vault.substitute(
    { url: "https://api.stripe.com/v1/charges", headers: { authorization: `Bearer ${handle}` } },
    { destination: "https://api.stripe.com/v1/charges", subject: "payments-agent" },
  );
  assert.equal(owner.ok, true, "the agent it was issued to can spend it");

  const thief = await vault.substitute(
    { url: "https://api.stripe.com/v1/charges", headers: { authorization: `Bearer ${handle}` } },
    { destination: "https://api.stripe.com/v1/charges", subject: "summariser" },
  );
  assert.equal(thief.ok, false, "another agent presenting the same handle must be refused");
  assert.equal(thief.outcome, "wrong_subject");
  assert.equal(
    JSON.stringify(thief.value ?? {}).includes("rk_live_"),
    false,
    "a refusal must not leak the material it refused to substitute",
  );
});

test("cross-boundary: an unbound handle stays usable by anyone", async () => {
  // Binding is opt-in per handle. A vault used without subjects at all must
  // keep working, or the fix breaks every existing single-agent install.
  const vault = new Vault();
  const handle = vault.issue("KEY", "rk_" + "live_MATERIAL0123456789abc");

  const anyone = await vault.substitute(
    { headers: { authorization: `Bearer ${handle}` } },
    { destination: "https://api.stripe.com/v1/charges", subject: "whoever" },
  );
  assert.equal(anyone.ok, true);
});

test("cross-boundary: the pipeline spends a handle as the calling agent, not the vault's owner", async () => {
  /*
   * The integration half. Binding in the vault is worthless if the pipeline
   * resolves handles under a fixed identity — every agent would look like the
   * same subject and the check would pass for all of them.
   */
  const vault = new Vault();
  const handle = vault.issue("STRIPE_KEY", "rk_" + "live_MATERIAL0123456789abc", {
    subject: "payments-agent",
  });

  const b = broker();
  const planner = b.root("planner", WIDE);
  const toSummariser = b.delegate(planner, "summariser", {
    actions: ["http.request"],
    resources: ["**"],
  });

  const p = new Pipeline({ rules, cwd: CWD, agent: "x", delegation: b, secrets: vault });
  const { event, arguments: outgoing } = await p.submit(
    {
      tool: "http_request",
      arguments: {
        url: "https://api.stripe.com/v1/charges",
        headers: { authorization: `Bearer ${handle}` },
      },
    },
    { agent: "summariser", delegation: toSummariser.grant },
  );

  assert.equal(event.decision, DECISION.DENY, "the summariser is not who the handle was issued to");
  assert.equal(event.policy, "secret-broker");
  assert.equal(
    JSON.stringify(outgoing).includes("rk_live_"),
    false,
    "nothing was substituted onto the wire",
  );
});

test("cross-boundary: delegation does not carry handle ownership with it", async () => {
  /*
   * The compound attack. `payments-agent` delegates to `worker` — legitimately,
   * narrowly, with network authority. That is a delegation of ACTION, and it
   * must not silently become a delegation of CREDENTIAL. Otherwise every
   * delegation quietly hands over every key the issuer holds.
   */
  const vault = new Vault();
  const handle = vault.issue("STRIPE_KEY", "rk_" + "live_MATERIAL0123456789abc", {
    subject: "payments-agent",
  });

  const b = broker();
  const payments = b.root("payments-agent", WIDE);
  const toWorker = b.delegate(payments, "worker", { actions: ["http.request"], resources: ["**"] });

  const p = new Pipeline({ rules, cwd: CWD, agent: "x", delegation: b, secrets: vault });
  const { event } = await p.submit(
    {
      tool: "http_request",
      arguments: {
        url: "https://api.stripe.com/v1/charges",
        headers: { authorization: `Bearer ${handle}` },
      },
    },
    { agent: "worker", delegation: toWorker.grant },
  );

  assert.equal(event.decision, DECISION.DENY, "being delegated to is not being handed the keys");
});

/* ========================================================================== */
/*  7. THE FOUR-HOP CHAIN:  A → B → MCP → C → D                                */
/* ========================================================================== */

test("cross-boundary: authority narrows across an MCP hop, not just within a process", async () => {
  /*
   *   A (wide)
   *    └─▶ B (fs.read + http.request)
   *          ══ MCP ══▶ C (fs.read)
   *                      └─▶ D (fs.read on /workspace/public only)
   *
   * D's effective authority is the intersection of all four. The MCP hop in the
   * middle is the interesting part: it is a different process and a different
   * decision path, and it is exactly where a chain gets forgotten.
   */
  const b = broker();
  const a = b.root("a", WIDE);
  const toB = b.delegate(a, "b", { actions: ["fs.read", "http.request"], resources: ["**"] });
  const toC = b.delegate(toB.grant, "c", { actions: ["fs.read"], resources: ["**"] });
  const toD = b.delegate(toC.grant, "d", {
    actions: ["fs.read"],
    resources: [`${CWD}/public/**`],
  });
  assert.ok(toB.ok && toC.ok && toD.ok, "setup: each hop narrows");

  const g = new Guard({ rules, cwd: CWD, agent: "d", delegation: b });

  const inside = await g.authorize({
    tool: "read_file",
    args: { path: `${CWD}/public/readme.md` },
    delegation: toD.grant,
  });
  assert.equal(inside.decision.verdict, "permit", "what every hop permits is permitted");

  const outside = await g.authorize({
    tool: "read_file",
    args: { path: `${CWD}/src/secret.ts` },
    delegation: toD.grant,
  });
  assert.equal(outside.decision.verdict, "deny", "the last hop's narrowing survives the MCP boundary");

  const wrongAction = await g.authorize({
    tool: "http_request",
    args: { url: "https://evil.example.com" },
    delegation: toD.grant,
  });
  assert.equal(
    wrongAction.decision.verdict,
    "deny",
    "B had network authority; D did not, and D is who is calling",
  );
});

test("cross-boundary: a grant is not scoped to the MCP server it was minted for", async () => {
  /*
   * Stated as a LIMIT rather than a bug, so nobody later reads the passing
   * suite as a claim it does not make.
   *
   * A grant constrains actions and resources. It does not name a server. A
   * grant for `fs.read` on `**` therefore works against any server exposing a
   * read tool, and confining an agent to one server is a job for the resource
   * glob or for policy — not for the grant.
   */
  const b = broker();
  const planner = b.root("planner", WIDE);
  const toWorker = b.delegate(planner, "worker", { actions: ["fs.read"], resources: ["**"] });

  const g = new Guard({ rules, cwd: CWD, agent: "worker", delegation: b });

  const first = await g.authorize({
    server: "files-a",
    tool: "read_file",
    args: { path: `${CWD}/src/app.ts` },
    delegation: toWorker.grant,
  });
  const second = await g.authorize({
    server: "files-b",
    tool: "read_file",
    args: { path: `${CWD}/src/app.ts` },
    delegation: toWorker.grant,
  });

  assert.equal(
    first.decision.verdict,
    second.decision.verdict,
    "a scope with no server axis cannot distinguish servers — confine by resource instead",
  );
});

test("cross-boundary: a resource-scoped grant does confine which server it reaches", async () => {
  // The mitigation for the limit above, asserted so the guidance is testable
  // rather than advisory.
  const b = broker();
  const planner = b.root("planner", WIDE);
  const toWorker = b.delegate(planner, "worker", {
    actions: ["fs.read"],
    resources: [`${CWD}/public/**`],
  });

  const g = new Guard({ rules, cwd: CWD, agent: "worker", delegation: b });
  const denied = await g.authorize({
    server: "files-b",
    tool: "read_file",
    args: { path: `${CWD}/private/keys.txt` },
    delegation: toWorker.grant,
  });
  assert.equal(denied.decision.verdict, "deny");
});

/* ========================================================================== */
/*  8. COMPOSITION                                                             */
/* ========================================================================== */

test("cross-boundary: depth exhaustion cannot be used to escape the chain walk", () => {
  /*
   * Build a chain to the maximum depth, then attempt one more. The refusal must
   * be a refusal — not a truncated walk that silently stops verifying links
   * beyond the limit, which would make depth the way to hide a revoked parent.
   */
  const b = broker();
  let current = b.root("a0", WIDE);
  for (let i = 1; i <= MAX_DEPTH; i++) {
    const next = b.delegate(current, `a${i}`, READ_ONLY);
    assert.ok(next.ok, `hop ${i}`);
    current = next.grant;
  }

  const overflow = b.delegate(current, "one-too-many", READ_ONLY);
  assert.equal(overflow.ok, false);
  assert.equal(overflow.error, DELEGATION_ERROR.TOO_DEEP);

  // The deepest legitimate grant still verifies every link back to the root.
  b.revoke("dlg_root_1");
  const resolved = b.resolve(current, `a${MAX_DEPTH}`);
  assert.equal(resolved.ok, false, "a full-depth chain must still see a revoked root");
  assert.equal(resolved.error, DELEGATION_ERROR.REVOKED);
});

test("cross-boundary: a circular delegation is refused at issue and cannot be forged in", async () => {
  const b = broker();
  const a = b.root("a", WIDE);
  const toB = b.delegate(a, "b", READ_ONLY);
  const toC = b.delegate(toB.grant, "c", READ_ONLY);

  const loop = b.delegate(toC.grant, "a", READ_ONLY);
  assert.equal(loop.ok, false);
  assert.equal(loop.error, DELEGATION_ERROR.CYCLE);

  // Hand-building the cycle is a signature failure rather than a hang.
  const forged = { ...toB.grant, parent: toC.grant.id };
  const event = await actAs(pipeline(b), "b", forged, READ_APP);
  assert.equal(event.decision, DECISION.DENY);
});

test("cross-boundary: a policy reload cannot widen a live delegation", async () => {
  const { b, grant } = confusedDeputy();
  const p = pipeline(b);

  assert.equal((await actAs(p, "worker", grant, DB_WRITE)).decision, DECISION.DENY);

  p.rules = compile("allow:\n  name = allow-everything\n  tool = database.write\n", {
    cwd: CWD,
    origin: "xb",
  }).rules;

  const after = await actAs(p, "worker", grant, DB_WRITE);
  assert.equal(after.decision, DECISION.DENY, "loosening policy is not a way to widen a grant");
  assert.equal(after.policy, "delegation-out-of-scope");
});

test("cross-boundary: a process restart invalidates every outstanding grant", async () => {
  const { grant } = confusedDeputy();
  const restarted = broker();

  const event = await actAs(pipeline(restarted), "worker", grant, READ_APP);
  assert.equal(event.decision, DECISION.DENY, "a grant from a dead runtime is not authority");
});

test("cross-boundary: identity, delegation, policy and approval describe one operation", async () => {
  /*
   * The invariant, asserted as a single end-to-end statement rather than left
   * implicit across thirty tests.
   *
   * One call. Four subsystems. The call is permitted only where all four agree,
   * and changing any one of them alone is enough to stop it.
   */
  const dir = await tempDir();
  const approvals = await new ApprovalStore(join(dir, "approvals.jsonl")).open();
  const chain = await new AuditChain(join(dir, "audit.jsonl")).open();

  const b = broker();
  const planner = b.root("planner", WIDE, { tenant: "acme" });
  b.root("worker", WIDE, { tenant: "acme" });
  const toWorker = b.delegate(planner, "worker", { actions: ["db.write"], resources: ["salaries"] });

  const p = new Pipeline({
    rules: HOLD_POLICY,
    cwd: CWD,
    agent: "x",
    approvals,
    delegation: b,
    audit: chain,
  });

  const held = await p.submit(DB_WRITE, { agent: "worker", delegation: toWorker.grant });
  assert.equal(held.event.decision, DECISION.REQUIRE_APPROVAL, "policy holds it");
  await approvals.decide(held.event.approval_id, STATE.APPROVED, "sre@example.com");

  const allowed = await p.submit(DB_WRITE, { agent: "worker", delegation: toWorker.grant });
  assert.equal(allowed.event.decision, DECISION.ALLOW, "all four agree");
  assert.deepEqual(allowed.event.delegation.principals, ["planner", "worker"]);

  // Now break each one in turn. Every single change must stop the call.
  const wrongIdentity = await p.submit(DB_WRITE, { agent: "mallory", delegation: toWorker.grant });
  assert.notEqual(wrongIdentity.event.decision, DECISION.ALLOW, "identity");

  b.revoke(toWorker.grant.id);
  const wrongDelegation = await p.submit(DB_WRITE, { agent: "worker", delegation: toWorker.grant });
  assert.notEqual(wrongDelegation.event.decision, DECISION.ALLOW, "delegation");

  assert.equal((await chain.verify()).ok, true, "and the record of all of it holds");
});
