/**
 * P0-B — Ed25519 delegation: the property tests.
 *
 * Everything here proves the invariants rather than the implementation:
 *
 *   · child authority ⊆ parent authority at every hop (INV-002);
 *   · widening, expiry, revocation, wrong subject, wrong tenant and replay
 *     all FAIL, at issue time or at use time;
 *   · verification needs only PUBLIC keys — two instances, no shared secret;
 *   · the human originator is reconstructable from the resolved chain;
 *   · the grants gate a LIVE production path (Pipeline, the socket engine),
 *     with missions layered on top — both subtractive (INV-003);
 *   · revocation state is durable and anti-rollback (INV-006).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Pipeline } from "../src/core/pipeline.mjs";
import { MissionRegistry } from "../src/core/authority.mjs";
import { Guard } from "../src/core/guard.mjs";
import {
  Ed25519DelegationIssuer,
  Ed25519DelegationVerifier,
  DelegationStore,
  buildCrossInstanceEnvelope,
  verifyGrantToken,
  signGrant,
  buildGrantPayload,
} from "../src/core/delegation-ed25519.mjs";
import { enrollAgent, createCallerVerifier, signRequest } from "../src/core/identity.mjs";
import { generateProofKeys } from "../src/core/proof.mjs";

const WIDE = { actions: ["*"], resources: ["*"] };
const READ_ALL = { actions: ["fs.read"], resources: ["**"] };
const READ_SRC = { actions: ["fs.read"], resources: ["/workspace/src/**"] };

const RULES = [
  { name: "allow-reads", effect: "permit", actions: ["fs.read"], resources: ["**"] },
  { name: "allow-db", effect: "permit", actions: ["db.write"], resources: ["**"] },
];

async function host() {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-p0b-"));
  const issuer = await new Ed25519DelegationIssuer({ stateDir }).init();
  const verifier = await new Ed25519DelegationVerifier({ stateDir }).init();
  return { stateDir, issuer, verifier };
}

/* ------------------------------------------------------------------ */
/*  Issuance and the narrowing invariant                               */
/* ------------------------------------------------------------------ */

test("P0-B: a human root is signed by the authority key and carries the human", async () => {
  const { issuer, verifier } = await host();
  const { grant, token } = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme", tenant: "acme" });
  assert.equal(grant.issuer, "human");
  assert.equal(grant.human, "dana@acme");
  assert.equal(grant.depth, 0);

  // The token verifies against the AUTHORITY public key — the same key that
  // signs identity credentials, which is what anchors the chain to the host.
  const check = verifyGrantToken(issuer.authority.publicKey, token);
  assert.equal(check.ok, true);
  const res = await verifier.resolveChain([token], "planner");
  assert.equal(res.ok, true);
  assert.equal(res.human, "dana@acme");
});

test("P0-B: child authority ⊆ parent authority — a chain resolves to the intersection", async () => {
  const { issuer, verifier } = await host();
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme" });
  const mid = await issuer.delegate({ parent: root.grant, subject: "worker", scope: READ_ALL });
  const leaf = await issuer.delegate({ parent: mid.grant, subject: "sub", scope: READ_SRC });

  const res = await verifier.resolveChain([leaf.token, mid.token, root.token], "sub");
  assert.equal(res.ok, true);
  // The effective scope is the intersection: nothing wider than ANY link.
  assert.deepEqual(res.scope, READ_SRC);
  assert.deepEqual(res.principals, ["planner", "worker", "sub"]);
  assert.deepEqual(res.chain, [root.grant.id, mid.grant.id, leaf.grant.id]);
  assert.equal(res.human, "dana@acme", "the human originator is reconstructable three hops down");
});

test("P0-B: widening is REFUSED at issue time, not clamped", async () => {
  const { issuer } = await host();
  const root = await issuer.root({ agent: "planner", scope: READ_ALL, human: "dana@acme" });
  await assert.rejects(
    () => issuer.delegate({ parent: root.grant, subject: "greedy", scope: WIDE }),
    (e) => e.code === "widened",
  );
  // And sideways: an action the parent does not hold.
  await assert.rejects(
    () => issuer.delegate({ parent: root.grant, subject: "sneaky", scope: { actions: ["db.write"], resources: ["**"] } }),
    (e) => e.code === "widened",
  );
});

test("P0-B: a mid-chain widening is refused at USE time by the verifier", async () => {
  const { issuer, verifier } = await host();
  const root = await issuer.root({ agent: "a", scope: WIDE, human: "h" });
  const narrow = await issuer.delegate({ parent: root.grant, subject: "b", scope: READ_ALL });

  // Forge a child of `narrow` that is wider than its parent — correctly
  // signed, because the attacker here IS an instance holding the delegation
  // key. What it cannot do is make the chain RESOLVE.
  const forged = buildGrantPayload({
    id: "dlg_forged",
    issuer: narrow.grant.subject,
    subject: "c",
    parent: narrow.grant.id,
    depth: 2,
    scope: WIDE,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  const forgedToken = signGrant({ grant: forged, privateKey: issuer.delegation.privateKey, keyId: issuer.delegation.keyId });
  const res = await verifier.resolveChain([forgedToken, narrow.token, root.token], "c");
  assert.equal(res.ok, false);
  assert.equal(res.error, "widened");
});

test("P0-B: expiry fails at use time", async () => {
  const { issuer, verifier } = await host();
  const root = await issuer.root({ agent: "a", scope: WIDE, human: "h" });
  // Minted 5 minutes in the past with a 30s life: long expired, and outside
  // even the verifier's 60s clock-skew forgiveness.
  const dead = await issuer.delegate({
    parent: root.grant,
    subject: "b",
    scope: READ_ALL,
    ttlMs: 30_000,
    now: () => new Date(Date.now() - 300_000),
  });
  const res = await verifier.resolveChain([dead.token, root.token], "b");
  assert.equal(res.ok, false);
  assert.equal(res.error, "expired");
});

test("P0-B: a delegation with no positive lifetime is refused at issue time", async () => {
  const { issuer } = await host();
  const root = await issuer.root({ agent: "a", scope: WIDE, human: "h" });
  // A negative or zero TTL must not be silently clamped into a live grant.
  for (const ttlMs of [-1000, 0]) {
    await assert.rejects(
      () => issuer.delegate({ parent: root.grant, subject: "b", scope: READ_ALL, ttlMs }),
      (e) => e.code === "expired",
      `ttlMs ${ttlMs} must be refused, not quietly repaired`,
    );
  }
});

test("P0-B: revocation fails at use time, cascades, and is DURABLE", async () => {
  const { issuer, verifier, stateDir } = await host();
  const root = await issuer.root({ agent: "a", scope: WIDE, human: "h" });
  const mid = await issuer.delegate({ parent: root.grant, subject: "b", scope: READ_ALL });
  const leaf = await issuer.delegate({ parent: mid.grant, subject: "c", scope: READ_SRC });

  // Before: resolves.
  assert.equal((await verifier.resolveChain([leaf.token, mid.token, root.token], "c")).ok, true);

  // Revoke the MIDDLE link: the leaf dies with it.
  const cascade = await issuer.store.revoke(mid.grant.id, "compromised");
  assert.ok(cascade.includes(mid.grant.id));
  assert.ok(cascade.includes(leaf.grant.id));

  const res = await verifier.resolveChain([leaf.token, mid.token, root.token], "c");
  assert.equal(res.ok, false);
  assert.equal(res.error, "revoked");

  // DURABILITY: a verifier constructed fresh from disk still refuses — and
  // the revocation journal survived the process that wrote it.
  const fresh = await new Ed25519DelegationVerifier({ stateDir }).init();
  const res2 = await fresh.resolveChain([leaf.token, mid.token, root.token], "c");
  assert.equal(res2.ok, false);
  assert.equal(res2.error, "revoked");
});

test("P0-B: revocation-journal rollback fails closed", async () => {
  const { issuer, stateDir } = await host();
  const root = await issuer.root({ agent: "a", scope: WIDE, human: "h" });
  const d = await issuer.delegate({ parent: root.grant, subject: "b", scope: READ_ALL });
  await issuer.store.revoke(d.grant.id, "later undone by an attacker");

  // The rollback: restore an EMPTY journal, as if the revocation never happened.
  await writeFile(join(stateDir, "delegations", "revocations.jsonl"), "", "utf8");

  const verifier = await new Ed25519DelegationVerifier({ stateDir }).init();
  const res = await verifier.resolveChain([d.token, root.token], "b");
  assert.equal(res.ok, false);
  assert.equal(res.error, "rollback", "a rolled-back journal authorizes NOTHING, including honest grants");
});

test("P0-B: wrong subject fails — a chain presented by anyone but its leaf", async () => {
  const { issuer, verifier } = await host();
  const root = await issuer.root({ agent: "a", scope: WIDE, human: "h" });
  const d = await issuer.delegate({ parent: root.grant, subject: "b", scope: READ_ALL });
  const res = await verifier.resolveChain([d.token, root.token], "mallory");
  assert.equal(res.ok, false);
  assert.equal(res.error, "subject_mismatch");
});

test("P0-B: wrong tenant fails at a boundary pinned to its own", async () => {
  const { issuer } = await host();
  const acmeRoot = await issuer.root({ agent: "acme-planner", scope: WIDE, human: "dana@acme", tenant: "acme" });
  const acmeChain = await issuer.delegate({ parent: acmeRoot.grant, subject: "acme-worker", scope: READ_ALL });

  // globex's instance holds only globex's keys and pins globex.
  const globexVerifier = await new Ed25519DelegationVerifier({ stateDir: issuer.stateDir, expectedTenant: "globex" }).init();
  const res = await globexVerifier.resolveChain([acmeChain.token, acmeRoot.token], "acme-worker");
  assert.equal(res.ok, false);
  assert.equal(res.error, "unknown_tenant");

  // And acme's own boundary accepts its own chain.
  const acmeVerifier = await new Ed25519DelegationVerifier({ stateDir: issuer.stateDir, expectedTenant: "acme" }).init();
  assert.equal((await acmeVerifier.resolveChain([acmeChain.token, acmeRoot.token], "acme-worker")).ok, true);
});

test("P0-B: a chain not terminating in a human root is refused", async () => {
  const { issuer, verifier } = await host();
  const root = await issuer.root({ agent: "a", scope: WIDE, human: "h" });
  const d = await issuer.delegate({ parent: root.grant, subject: "b", scope: READ_ALL });
  // Present WITHOUT the root: the chain has no human anchor. Signature checks
  // come first (a hostile artifact must not steer the verifier), so the child
  // link — signed by the DELEGATION key — fails as bad_signature when read as
  // a root under the authority key. Either way, nothing resolves.
  const res = await verifier.resolveChain([d.token], "b");
  assert.equal(res.ok, false);
  assert.equal(res.error, "bad_signature");
});

test("P0-B: a forged token (wrong key) fails the signature check", async () => {
  const { issuer, verifier } = await host();
  const rogue = generateProofKeys();
  const fake = buildGrantPayload({
    id: "dlg_fake",
    issuer: "human",
    subject: "b",
    parent: null,
    depth: 0,
    scope: WIDE,
    issuedAt: new Date().toISOString(),
    expiresAt: null,
    human: "attacker",
  });
  const fakeToken = signGrant({ grant: fake, privateKey: rogue.privateKey });
  const res = await verifier.resolveChain([fakeToken], "b");
  assert.equal(res.ok, false);
  assert.equal(res.error, "bad_signature");
});

test("P0-B: depth is bounded (MAX_DEPTH) at issue time AND at use time", async () => {
  const { issuer, verifier } = await host();
  const root = await issuer.root({ agent: "a0", scope: READ_ALL, human: "h" });
  const tokens = [root.token];
  let parent = root.grant;
  // The ceiling itself is inside the ceiling: root + MAX_DEPTH hops resolves.
  for (let i = 1; i <= 8; i++) {
    const link = await issuer.delegate({ parent, subject: `a${i}`, scope: READ_ALL });
    tokens.unshift(link.token);
    parent = link.grant;
  }
  const ok = await verifier.resolveChain(tokens, "a8");
  assert.equal(ok.ok, true);
  assert.equal(ok.depth, 8);

  // The next hop is refused where it would be SIGNED, not only where it would
  // be checked: an issuer that cannot mint the link cannot leak it.
  await assert.rejects(
    () => issuer.delegate({ parent, subject: "a9", scope: READ_ALL }),
    (e) => e.code === "too_deep",
  );

  // And a chain that arrives already too deep is refused at USE time, before
  // any signature of it is believed.
  const tooDeep = await verifier.resolveChain([...tokens, root.token], "a8");
  assert.equal(tooDeep.ok, false);
  assert.equal(tooDeep.error, "too_deep");
});

/* ------------------------------------------------------------------ */
/*  Cross-instance verification and the one-time envelope              */
/* ------------------------------------------------------------------ */

test("P0-B: cross-instance verification uses PUBLIC keys only", async () => {
  const { issuer } = await host();
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme", tenant: "acme" });
  const d = await issuer.delegate({ parent: root.grant, subject: "worker", scope: READ_ALL });

  // INSTANCE B: constructed with the issuer's public keys alone. No stateDir
  // keys, no private material, no shared secret — and it needs none.
  const instanceB = await new Ed25519DelegationVerifier({
    stateDir: issuer.stateDir,
    authorityPublicKey: issuer.authority.publicKey,
    delegationPublicKey: issuer.delegation.publicKey,
    expectedTenant: "acme",
  }).init();

  const res = await instanceB.resolveChain([d.token, root.token], "worker");
  assert.equal(res.ok, true);
  assert.deepEqual(res.scope, READ_ALL);
  assert.equal(res.human, "dana@acme");
});

test("P0-B: the one-time envelope executes once and dies (replay fails)", async () => {
  const { issuer } = await host();
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme" });
  const d = await issuer.delegate({ parent: root.grant, subject: "worker", scope: READ_ALL });
  const envelope = await buildCrossInstanceEnvelope({ issuer, chainTokens: [d.token, root.token], subject: "worker" });

  const instanceB = await new Ed25519DelegationVerifier({
    stateDir: issuer.stateDir,
    authorityPublicKey: issuer.authority.publicKey,
    delegationPublicKey: issuer.delegation.publicKey,
  }).init();

  const first = await instanceB.resolveEnvelope(envelope, "worker");
  assert.equal(first.ok, true);
  assert.deepEqual(first.scope, READ_ALL);
  assert.equal(first.singleUse, true);

  const second = await instanceB.resolveEnvelope(envelope, "worker");
  assert.equal(second.ok, false);
  assert.equal(second.error, "replay");
});

test("P0-B: an envelope bound to another subject is refused", async () => {
  const { issuer } = await host();
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "h" });
  const d = await issuer.delegate({ parent: root.grant, subject: "worker", scope: READ_ALL });
  const envelope = await buildCrossInstanceEnvelope({ issuer, chainTokens: [d.token, root.token], subject: "worker" });

  const instanceB = await new Ed25519DelegationVerifier({
    stateDir: issuer.stateDir,
    authorityPublicKey: issuer.authority.publicKey,
    delegationPublicKey: issuer.delegation.publicKey,
  }).init();
  const res = await instanceB.resolveEnvelope(envelope, "mallory");
  assert.equal(res.ok, false);
  assert.equal(res.error, "subject_mismatch");
});

/* ------------------------------------------------------------------ */
/*  LIVE enforcement — the grants gate real production paths           */
/* ------------------------------------------------------------------ */

test("P0-B/LIVE: a Pipeline (socket engine) narrows a real call to the presented chain", async () => {
  const { issuer, verifier } = await host();
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme" });
  const d = await issuer.delegate({ parent: root.grant, subject: "worker", scope: READ_ALL });

  const pipeline = new Pipeline({ rules: RULES, cwd: "/workspace", agent: "host", delegation: verifier });

  // Policy ALLOWS db.write for everyone — the delegation is the only thing
  // stopping it. That is the "constraint, not grant" property, live.
  const narrowed = await pipeline.submit(
    { tool: "database.write", arguments: { table: "salaries" } },
    { agent: "worker", delegation: [d.token, root.token] },
  );
  assert.equal(narrowed.event.decision, "deny");
  assert.equal(narrowed.event.policy, "delegation-out-of-scope");

  const allowed = await pipeline.submit(
    { tool: "read_file", arguments: { path: "/workspace/a.ts" } },
    { agent: "worker", delegation: [d.token, root.token] },
  );
  assert.equal(allowed.event.decision, "allow");
  assert.equal(allowed.event.delegation?.human, "dana@acme", "the audit trail reconstructs the human");
  assert.deepEqual(allowed.event.delegation?.chain, [root.grant.id, d.grant.id]);
});

test("P0-B/LIVE: a stolen chain presented by the wrong agent is refused by the Pipeline", async () => {
  const { issuer, verifier } = await host();
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme" });
  const d = await issuer.delegate({ parent: root.grant, subject: "worker", scope: READ_ALL });

  const pipeline = new Pipeline({ rules: RULES, cwd: "/workspace", agent: "host", delegation: verifier });
  const res = await pipeline.submit(
    { tool: "read_file", arguments: { path: "/workspace/a.ts" } },
    { agent: "mallory", delegation: [d.token, root.token] },
  );
  assert.equal(res.event.decision, "deny");
  assert.equal(res.event.policy, "delegation-subject_mismatch");
});

test("P0-B/LIVE: an expired chain presented over the live path is refused", async () => {
  const { issuer, verifier } = await host();
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme" });
  // Minted five minutes ago with a 30s life: long expired, and outside even
  // the verifier's 60s clock-skew forgiveness. A negative TTL is refused at
  // issue time (above), so the dead grant is minted honestly and then aged.
  const d = await issuer.delegate({
    parent: root.grant,
    subject: "worker",
    scope: READ_ALL,
    ttlMs: 30_000,
    now: () => new Date(Date.now() - 300_000),
  });

  const pipeline = new Pipeline({ rules: RULES, cwd: "/workspace", agent: "host", delegation: verifier });
  const res = await pipeline.submit(
    { tool: "read_file", arguments: { path: "/workspace/a.ts" } },
    { agent: "worker", delegation: [d.token, root.token] },
  );
  assert.equal(res.event.decision, "deny");
  assert.equal(res.event.policy, "delegation-expired");
});

test("P0-B/LIVE: a revoked chain presented over the live path is refused", async () => {
  const { issuer, verifier } = await host();
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme" });
  const d = await issuer.delegate({ parent: root.grant, subject: "worker", scope: READ_ALL });
  await issuer.store.revoke(d.grant.id, "incident");

  const pipeline = new Pipeline({ rules: RULES, cwd: "/workspace", agent: "host", delegation: verifier });
  const res = await pipeline.submit(
    { tool: "read_file", arguments: { path: "/workspace/a.ts" } },
    { agent: "worker", delegation: [d.token, root.token] },
  );
  assert.equal(res.event.decision, "deny");
  assert.equal(res.event.policy, "delegation-revoked");
});

test("P0-B/LIVE: the Guard path narrows Ed25519 chains identically — to the PROVEN principal", async () => {
  const { stateDir, issuer, verifier } = await host();
  const enrollment = await enrollAgent({ stateDir, agentId: "worker", runtime: "test" });
  const identity = await createCallerVerifier({ stateDir });
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme" });
  const d = await issuer.delegate({ parent: root.grant, subject: "worker", scope: READ_ALL });

  // A production boundary: the acting agent is the one that PROVED itself, and
  // the chain binds to that principal through the same `applyDelegation` the
  // Pipeline runs — one decision path, not two.
  const guard = new Guard({
    rules: RULES,
    agent: "host",
    cwd: "/workspace",
    identityMode: "production",
    identity,
    delegation: verifier,
  });
  const proven = (params) => ({
    callerMeta: {
      credential: enrollment.credentialToken,
      ...signRequest({ privateKey: enrollment.identityPrivateKey, agentId: "worker", method: "tools/call", params }),
    },
    method: "tools/call",
    params,
  });

  // Policy ALLOWS db.write for everyone — the delegation is the only thing
  // stopping it. That is the "constraint, not grant" property, live.
  const dbParams = { name: "database.write", arguments: { table: "salaries" } };
  const outOfScope = await guard.authorize(
    { tool: "database.write", args: dbParams.arguments, delegation: [d.token, root.token] },
    proven(dbParams),
  );
  assert.equal(outOfScope.decision.verdict, "deny");
  assert.equal(outOfScope.decision.rule, "delegation-out-of-scope");

  const readParams = { name: "read_file", arguments: { path: "/workspace/a.ts" } };
  const inScope = await guard.authorize(
    { tool: "read_file", args: readParams.arguments, delegation: [d.token, root.token] },
    proven(readParams),
  );
  assert.equal(inScope.decision.verdict, "permit");
  assert.deepEqual(inScope.record.delegation?.principals, ["planner", "worker"]);
  assert.equal(inScope.record.delegation?.human, "dana@acme", "the audit trail reconstructs the human");

  /*  A NAME IS NOT AN IDENTITY — including at the delegation stage.
   *
   *  The same request with the same valid chain, presented by a caller whose
   *  only claim to being `worker` is the string in the request: denied before
   *  delegation is even reached, because identity is established FIRST. */
  const typed = await guard.authorize({
    tool: "read_file",
    args: { path: "/workspace/a.ts" },
    agent: "worker",
    delegation: [d.token, root.token],
  });
  assert.equal(typed.decision.verdict, "deny");
  assert.equal(typed.decision.rule, "identity-unverified");
  assert.equal(typed.record.agent, "host", "the chain did not resolve against the claim");
  assert.equal(typed.record.claimed_agent, "worker");

  /*  On an in-process boundary with no identity at all, the acting agent comes
   *  from the AUTHENTICATED HOST CONTEXT (`ctx.agent`, the Pipeline channel),
   *  while the request's claim still selects nothing. This is the difference
   *  between a trusted channel and a declared name, made testable. */
  const sdk = new Guard({ rules: RULES, agent: "host", cwd: "/workspace", delegation: verifier });
  const viaContext = await sdk.authorize(
    { tool: "database.write", args: { table: "salaries" }, delegation: [d.token, root.token] },
    { agent: "worker" },
  );
  assert.equal(viaContext.decision.rule, "delegation-out-of-scope", "the host context names worker, so the chain binds");

  const viaClaim = await sdk.authorize({
    tool: "database.write",
    args: { table: "salaries" },
    agent: "worker",
    delegation: [d.token, root.token],
  });
  assert.equal(viaClaim.decision.verdict, "deny");
  assert.equal(viaClaim.decision.rule, "delegation-subject_mismatch", "a typed name binds nothing");
  assert.equal(viaClaim.record.claimed_agent, "worker");
});

test("P0-B/LIVE: missions and delegations stack, both subtractive (INV-003 + INV-002)", async () => {
  const { issuer, verifier } = await host();
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme" });
  // The chain allows ALL reads; the mission will take most of them back.
  const d = await issuer.delegate({ parent: root.grant, subject: "worker", scope: READ_ALL });

  const missions = new MissionRegistry();
  missions.issue({
    id: "msn-1",
    agent: "worker",
    name: "src sweep",
    capabilities: [{ name: "src", scope: { actions: ["fs.read"], resources: ["/workspace/src/**"] } }],
  });

  const pipeline = new Pipeline({ rules: RULES, cwd: "/workspace", agent: "host", delegation: verifier, missions });

  const inside = await pipeline.submit(
    { tool: "read_file", arguments: { path: "/workspace/src/app.ts" } },
    { agent: "worker", delegation: [d.token, root.token] },
  );
  assert.equal(inside.event.decision, "allow", "inside BOTH the chain and the mission: allowed");

  const missionOnly = await pipeline.submit(
    { tool: "read_file", arguments: { path: "/workspace/docs/notes.md" } },
    { agent: "worker", delegation: [d.token, root.token] },
  );
  assert.equal(missionOnly.event.decision, "deny", "the mission narrows what the chain allowed");

  const neither = await pipeline.submit(
    { tool: "database.write", arguments: { table: "x" } },
    { agent: "worker", delegation: [d.token, root.token] },
  );
  assert.equal(neither.event.decision, "deny", "outside both: refused");
});

test("P0-B/LIVE: identity + delegation compose — the verified agent must hold the chain", async () => {
  const { stateDir, issuer, verifier } = await host();
  const worker = await enrollAgent({ stateDir, agentId: "worker", runtime: "test" });
  // A SECOND enrolled agent, so the theft below is a real identity presenting
  // somebody else's chain — not an unsigned caller being waved away.
  const mallory = await enrollAgent({ stateDir, agentId: "mallory", runtime: "test" });
  const identity = await createCallerVerifier({ stateDir });

  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme" });
  const d = await issuer.delegate({ parent: root.grant, subject: "worker", scope: READ_ALL });

  const guard = new Guard({
    rules: RULES,
    agent: "host",
    cwd: "/workspace",
    identityMode: "production",
    identity,
    delegation: verifier,
  });
  const signed = (enrollment, agentId, params) => ({
    callerMeta: {
      credential: enrollment.credentialToken,
      ...signRequest({ privateKey: enrollment.identityPrivateKey, agentId, method: "tools/call", params }),
    },
    method: "tools/call",
    params,
  });

  const readParams = { name: "read_file", arguments: { path: "/workspace/a.ts" } };

  // 1. The VERIFIED worker with no delegation: policy alone decides — allow,
  //    attributed to the agent that PROVED itself.
  const good = await guard.authorize({ tool: "read_file", args: readParams.arguments }, signed(worker, "worker", readParams));
  assert.equal(good.decision.verdict, "permit");
  assert.equal(good.record.agent, "worker");
  assert.equal(good.record.identity.verified, true);

  // 2. The verified worker presents its chain and asks for more than the chain
  //    covers, where policy WOULD have allowed the write: the delegation is
  //    what refuses it.
  const dbParams = { name: "database.write", arguments: { table: "x" } };
  const narrowed = await guard.authorize(
    { tool: "database.write", args: dbParams.arguments, delegation: [d.token, root.token] },
    signed(worker, "worker", dbParams),
  );
  assert.equal(narrowed.decision.verdict, "deny");
  assert.equal(narrowed.decision.rule, "delegation-out-of-scope");

  // 3. A DIFFERENT verified agent presents worker's chain. Both signatures are
  //    genuine and both identities are real — the binding BETWEEN them is what
  //    refuses. Token theft is stopped by the chain's subject, not by manners.
  const stolen = await guard.authorize(
    { tool: "read_file", args: readParams.arguments, delegation: [d.token, root.token] },
    signed(mallory, "mallory", readParams),
  );
  assert.equal(stolen.decision.verdict, "deny");
  assert.equal(stolen.decision.rule, "delegation-subject_mismatch");

  // 4. A verified agent presenting something that is not a chain is refused by
  //    the delegation stage rather than being ignored.
  const garbage = await guard.authorize(
    { tool: "read_file", args: readParams.arguments, delegation: "not-a-token" },
    signed(worker, "worker", readParams),
  );
  assert.equal(garbage.decision.verdict, "deny");
  assert.match(garbage.decision.rule, /delegation-/);
});

/* ------------------------------------------------------------------ */
/*  Store mechanics                                                    */
/* ------------------------------------------------------------------ */

test("P0-B: the store round-trips tokens and revocation sequence across reopen", async () => {
  const { issuer, stateDir } = await host();
  const root = await issuer.root({ agent: "a", scope: READ_ALL, human: "h" });
  const d = await issuer.delegate({ parent: root.grant, subject: "b", scope: READ_SRC });
  await issuer.store.revoke(d.grant.id, "x");

  const reopened = await new DelegationStore(stateDir).init();
  assert.equal(reopened.isRevoked(d.grant.id), true);
  assert.equal(reopened.isRevoked(root.grant.id), false);
  assert.equal(reopened.token(root.grant.id), root.token);
  assert.ok(reopened.revocationSeq >= 1);
});
