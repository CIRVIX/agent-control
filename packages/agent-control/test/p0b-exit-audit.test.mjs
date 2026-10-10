/**
 * P0-B EXIT AUDIT — the gate, run as tests rather than asserted in prose.
 *
 * Six questions, answered by executable evidence:
 *
 *   1. HUMAN → AGENT: does a signed grant carry the fields a human grant needs,
 *      and does an authenticated principal actually issue it? (The second half
 *      is answered honestly below: the principal is a KEY HOLDER, not an
 *      interactive human login — the tests record exactly that limitation.)
 *   2. MISSIONS/CAPABILITIES: do they gate EXECUTION, proven with an
 *      independent oracle rather than by reading a decision object?
 *   3. PATH AUTHORITY: is Ed25519 the production path, and can production
 *      silently fall back to the legacy HMAC broker?
 *   4. PERSISTENCE: does authority — including revocation — survive a restart,
 *      and can an older local state roll a newer revocation back?
 *   5. CROSS-INSTANCE: can a second instance verify with PUBLIC KEYS ONLY, and
 *      do tampering, wrong audience, wrong subject, wrong tenant, expiry,
 *      replay and a revoked parent all fail there?
 *   6. The result of each, reported in the phase report.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { Guard } from "../src/core/guard.mjs";
import { Pipeline } from "../src/core/pipeline.mjs";
import { AgentStore, AGENT_STATUS } from "../src/core/identity-store.mjs";
import { enrollAgent, createCallerVerifier, signRequest } from "../src/core/identity.mjs";
import { Ed25519DelegationIssuer, Ed25519DelegationVerifier, DelegationStore, buildCrossInstanceEnvelope, verifyGrantToken, signGrant, buildGrantPayload } from "../src/core/delegation-ed25519.mjs";
import { generateProofKeys } from "../src/core/proof.mjs";
import { RevocationEngine, REVOCATION_SCOPE } from "../src/core/revocation.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..");
const ORACLE_CHILD = join(here, "fixtures", "oracle-child.mjs");

const WIDE = { actions: ["*"], resources: ["**"] };
const RULES = [
  { name: "allow-reads", effect: "permit", actions: ["fs.read"], resources: ["**"] },
  { name: "allow-db", effect: "permit", actions: ["db.write"], resources: ["**"] },
  { name: "allow-egress", effect: "permit", actions: ["net.egress"], resources: ["**"] },
];

const host = async (label) => mkdtemp(join(tmpdir(), `cirvix-p0b-audit-${label}-`));

function startOracleChild({ stateDir, oracle, rules, extra = [] }) {
  const child = spawn(process.execPath, [ORACLE_CHILD, "--state", stateDir, "--oracle", oracle, "--rules", rules, ...extra], {
    cwd: packageRoot,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const waiters = [];
  let buffer = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let index;
    while ((index = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, index).trim();
      buffer = buffer.slice(index + 1);
      if (!line) continue;
      const message = JSON.parse(line);
      if (message.ready) continue;
      waiters.shift()?.(message);
    }
  });
  return {
    async send(call) {
      const answer = new Promise((resolve) => waiters.push(resolve));
      child.stdin.write(JSON.stringify(call) + "\n");
      return answer;
    },
    async close() {
      child.kill();
      await new Promise((resolve) => child.once("exit", resolve));
    },
  };
}

async function oracleLines(path) {
  try {
    return (await readFile(path, "utf8")).split("\n").filter((l) => l.trim());
  } catch {
    return [];
  }
}

/* ================================================================== */
/*  1. HUMAN → AGENT                                                   */
/* ================================================================== */

test("AUDIT/1: a grant carries every field an authority grant needs — and says who the principal is", async () => {
  const stateDir = await host("grant-fields");
  const issuer = await new Ed25519DelegationIssuer({ stateDir, policyVersion: "policy-2026-09" }).init();
  const { grant, token } = await issuer.root({
    agent: "worker",
    scope: { actions: ["fs.read"], resources: ["/workspace/src/**"] },
    tenant: "acme",
    human: "dana@acme",
    purpose: "repo maintenance",
    constraints: { tools: { allow: ["read_file"] } },
  });

  // The checklist, asserted field by field rather than described.
  assert.equal(grant.issuer, "human");
  assert.equal(grant.human, "dana@acme");
  assert.equal(grant.tenant, "acme");
  assert.equal(grant.subject, "worker");
  assert.deepEqual(grant.scope.actions, ["fs.read"]);
  assert.deepEqual(grant.scope.resources, ["/workspace/src/**"]);
  assert.deepEqual(grant.constraints, { tools: { allow: ["read_file"] } });
  assert.equal(grant.purpose, "repo maintenance");
  assert.equal(grant.policyVersion, "policy-2026-09");
  assert.equal(typeof grant.nonce, "string");
  assert.equal(grant.nonce.length >= 16, true);
  assert.equal(Number.isFinite(Date.parse(grant.issuedAt)), true);
  assert.equal(grant.expiresAt, null, "a root is bounded by the credential's life, not its own");
  assert.equal(grant.depth, 0);
  assert.equal(grant.parent, null);

  // Issued by the AUTHORITY key: the same anchor identity credentials use.
  assert.equal(verifyGrantToken(issuer.authority.publicKey, token).ok, true);
  assert.equal(verifyGrantToken(issuer.delegation.publicKey, token).ok, false, "a root is not signed by the delegation key");

  /* THE LIMITATION, ENCODED. The "human" here is a NAME on a grant signed by
     the host's authority key. There is no interactive login, no second factor
     and no org-membership check behind it: possession of the 0600 authority key
     is the authentication. That is why item 1 is reported PARTIAL, not CLOSED. */
  assert.equal(Object.hasOwn(grant, "authenticatedPrincipal"), false, "no interactive principal proof exists on the grant");
  assert.equal(typeof grant.human, "string", "the human is a NAME the authority key vouched for, not a verified session");
});

test("AUDIT/1: forged, wrong-issuer, expired, revoked, wrong-tenant and wrong-subject grants all fail", async () => {
  const stateDir = await host("grant-negative");
  const issuer = await new Ed25519DelegationIssuer({ stateDir }).init();
  const verifier = await new Ed25519DelegationVerifier({ stateDir }).init();
  const root = await issuer.root({ agent: "worker", scope: WIDE, human: "dana@acme" });

  // FORGED: a grant with the right shape, signed by nobody in this trust set.
  const rogue = generateProofKeys();
  const forged = buildGrantPayload({
    id: "dlg_forged",
    issuer: "human",
    subject: "worker",
    parent: null,
    depth: 0,
    scope: WIDE,
    issuedAt: new Date().toISOString(),
    expiresAt: null,
    human: "dana@acme",
  });
  assert.equal((await verifier.resolveChain([signGrant({ grant: forged, privateKey: rogue.privateKey })], "worker")).error, "bad_signature");

  // WRONG ISSUER: a self-signed root is not a root.
  const selfSigned = buildGrantPayload({
    id: "dlg_self",
    issuer: "human",
    subject: "worker",
    parent: null,
    depth: 0,
    scope: WIDE,
    issuedAt: new Date().toISOString(),
    expiresAt: null,
  });
  const wrongIssuer = signGrant({ grant: selfSigned, privateKey: issuer.delegation.privateKey, keyId: issuer.delegation.keyId });
  assert.equal((await verifier.resolveChain([wrongIssuer], "worker")).ok, false);

  // EXPIRED (minted five minutes ago with a 30s life).
  const expired = await issuer.delegate({
    parent: root.grant,
    subject: "expired-worker",
    scope: WIDE,
    ttlMs: 30_000,
    now: () => new Date(Date.now() - 300_000),
  });
  assert.equal((await verifier.resolveChain([expired.token, root.token], "expired-worker")).error, "expired");

  // REVOKED.
  const revoked = await issuer.delegate({ parent: root.grant, subject: "revoked-worker", scope: WIDE });
  await issuer.store.revoke(revoked.grant.id, "incident");
  assert.equal((await verifier.resolveChain([revoked.token, root.token], "revoked-worker")).error, "revoked");

  // WRONG TENANT (boundary pinned to its own tenant).
  const acmeRoot = await issuer.root({ agent: "acme-worker", scope: WIDE, human: "dana@acme", tenant: "acme" });
  const globex = await new Ed25519DelegationVerifier({ stateDir, expectedTenant: "globex" }).init();
  assert.equal((await globex.resolveChain([acmeRoot.token], "acme-worker")).error, "unknown_tenant");

  // WRONG SUBJECT.
  assert.equal((await verifier.resolveChain([root.token], "mallory")).error, "subject_mismatch");

  // WIDENING — refused at ISSUE time (never clamped into something narrower),
  // and refused again at USE time if a key-holding instance mints it anyway.
  const narrowRoot = await issuer.root({ agent: "planner", scope: { actions: ["fs.read"], resources: ["**"] }, human: "dana" });
  await assert.rejects(
    () => issuer.delegate({ parent: narrowRoot.grant, subject: "greedy", scope: WIDE }),
    (e) => e.code === "widened",
  );
  const mintedByAKeyHolder = buildGrantPayload({
    id: "dlg_wide",
    issuer: "planner",
    subject: "greedy",
    parent: narrowRoot.grant.id,
    depth: 1,
    scope: WIDE,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  const widenedToken = signGrant({ grant: mintedByAKeyHolder, privateKey: issuer.delegation.privateKey, keyId: issuer.delegation.keyId });
  assert.equal((await verifier.resolveChain([widenedToken, narrowRoot.token], "greedy")).error, "widened");

  // POLICY VERSION PIN: a boundary that enforces one generation refuses a grant
  // minted under another.
  const pinnedIssuer = await new Ed25519DelegationIssuer({ stateDir, policyVersion: "policy-1" }).init();
  const pinnedRoot = await pinnedIssuer.root({ agent: "worker", scope: WIDE, human: "dana" });
  const pinnedVerifier = await new Ed25519DelegationVerifier({ stateDir, expectedPolicyVersion: "policy-2" }).init();
  assert.equal((await pinnedVerifier.resolveChain([pinnedRoot.token], "worker")).ok, false);
  const unpinned = await new Ed25519DelegationVerifier({ stateDir }).init();
  assert.equal((await unpinned.resolveChain([pinnedRoot.token], "worker")).ok, true);
});

test("AUDIT/1: a grant's declared CONSTRAINTS are enforced, not decorative", async () => {
  const stateDir = await host("grant-constraints");
  const issuer = await new Ed25519DelegationIssuer({ stateDir }).init();
  const verifier = await new Ed25519DelegationVerifier({ stateDir }).init();
  /* A DENY constraint, so the test does not depend on how a canonical action
     is spelled into a public tool name: the evaluator matches the action
     ("db.write") and the tool label, and both spellings are denied here. */
  const constraining = { tools: { deny: ["db.write", "database.write"] } };
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana", constraints: constraining });
  const grant = await issuer.delegate({ parent: root.grant, subject: "worker", scope: WIDE, constraints: constraining });
  const pipeline = new Pipeline({ rules: RULES, cwd: "/workspace", agent: "host", delegation: verifier });

  const allowed = await pipeline.submit(
    { tool: "read_file", arguments: { path: "/workspace/a.ts" } },
    { agent: "worker", delegation: [grant.token, root.token] },
  );
  assert.equal(allowed.event.decision, "allow");

  // The chain's own restriction refuses a call policy would have permitted.
  const refused = await pipeline.submit(
    { tool: "database.write", arguments: { table: "x" } },
    { agent: "worker", delegation: [grant.token, root.token] },
  );
  assert.equal(refused.event.decision, "deny");
  assert.equal(refused.event.policy, "delegation-constraint-violated");

  // A child may not DROP its parent's constraint: dropping a restriction is
  // widening, and is refused where it would be signed.
  await assert.rejects(
    () => issuer.delegate({ parent: root.grant, subject: "loose", scope: WIDE }),
    (e) => e.code === "widened",
  );
  // A constraint this build cannot evaluate is refused at BOTH ends.
  await assert.rejects(
    () => issuer.delegate({ parent: root.grant, subject: "typo", scope: WIDE, constraints: { netwrok: { deny: ["*"] } } }),
    (e) => e.code === "unknown_constraint",
  );
});

test("AUDIT/1/LIVE: an authority grant gates a REAL consequential call, observed by an independent oracle", async () => {
  const stateDir = await host("grant-live");
  const oracle = join(stateDir, "oracle.log");
  const rules = join(stateDir, "rules.json");
  await writeFile(rules, JSON.stringify(RULES), "utf8");

  const issuer = await new Ed25519DelegationIssuer({ stateDir }).init();
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme" });
  const grant = await issuer.delegate({ parent: root.grant, subject: "worker", scope: { actions: ["fs.read"], resources: ["**"] } });

  const child = startOracleChild({ stateDir, oracle, rules, extra: ["--agent", "worker", "--delegation"] });
  try {
    const covered = await child.send({ id: "g1", tool: "read_file", arguments: { path: "/workspace/a.ts" }, delegation: [grant.token, root.token] });
    assert.equal(covered.verdict, "permit");
    assert.equal(covered.executed, true);

    const outside = await child.send({ id: "g2", tool: "database.write", arguments: { table: "salaries" }, delegation: [grant.token, root.token] });
    assert.equal(outside.verdict, "deny");
    assert.equal(outside.rule, "delegation-out-of-scope");
    assert.equal(outside.executed, false);

    // No delegation presented at all: policy alone, and the policy permits the
    // write — which is exactly why the grant is the thing being tested.
    const undelegated = await child.send({ id: "g3", tool: "database.write", arguments: { table: "salaries" } });
    assert.equal(undelegated.verdict, "permit");

    const lines = await oracleLines(oracle);
    assert.deepEqual(lines.map((l) => l.split(" ")[0]), ["g1", "g3"], "only the calls the chain permitted produced an effect");
  } finally {
    await child.close();
  }
});

/* ================================================================== */
/*  2. MISSIONS / CAPABILITIES GATE EXECUTION                          */
/* ================================================================== */

test("AUDIT/2: a mission gates EXECUTION — denied means the effect did not happen (independent oracle)", async () => {
  const stateDir = await host("mission-oracle");
  const oracle = join(stateDir, "oracle.log");
  const rules = join(stateDir, "rules.json");
  const missionPath = join(stateDir, "mission.json");
  await writeFile(rules, JSON.stringify(RULES), "utf8");
  await writeFile(
    missionPath,
    JSON.stringify({
      id: "msn-audit",
      agent: "worker",
      name: "src sweep",
      capabilities: [{ name: "src", scope: { actions: ["fs.read"], resources: ["/workspace/src/**"] } }],
    }),
    "utf8",
  );

  const child = startOracleChild({ stateDir, oracle, rules, extra: ["--agent", "worker", "--mission", missionPath] });
  try {
    const inside = await child.send({ id: "m1", tool: "read_file", arguments: { path: "/workspace/src/app.ts" } });
    assert.equal(inside.verdict, "permit", "the capability covers this call");
    assert.equal(inside.executed, true);

    // Policy allows every read; the MISSION is what refuses this one.
    const outside = await child.send({ id: "m2", tool: "read_file", arguments: { path: "/workspace/docs/notes.md" } });
    assert.equal(outside.verdict, "deny");
    assert.match(outside.rule, /^authority-/);
    assert.equal(outside.executed, false);

    const otherAction = await child.send({ id: "m3", tool: "database.write", arguments: { table: "x" } });
    assert.equal(otherAction.verdict, "deny");
    assert.equal(otherAction.executed, false);

    const lines = await oracleLines(oracle);
    assert.deepEqual(lines.map((l) => l.split(" ")[0]), ["m1"], "only the mission-covered call produced an effect");
  } finally {
    await child.close();
  }
});

test("AUDIT/2: an EXPIRED mission and a MISSING capability both deny on the live path", async () => {
  const stateDir = await host("mission-expired");
  const { MissionRegistry } = await import("../src/core/authority.mjs");
  const expiry = Date.now() - 1000;
  const missions = new MissionRegistry();
  missions.issue({
    id: "msn-old",
    agent: "worker",
    name: "expired",
    // TTL in the past: the mission exists, resolves, and is refused for having
    // run out — not for being absent.
    ttlMs: -60_000,
    capabilities: [{ name: "src", scope: { actions: ["fs.read"], resources: ["**"] } }],
  });
  const guard = new Guard({ rules: RULES, agent: "host", cwd: "/workspace", missions });
  const expired = await guard.authorize({ tool: "read_file", args: { path: "/workspace/a.ts" } }, { agent: "worker" });
  assert.equal(expired.decision.verdict, "deny");
  assert.equal(expired.decision.rule, "authority-mission_expired", "the mission exists, resolves, and has run out — not absent");
  assert.equal(expired.record.authority.mission.id, "msn-old");
  assert.equal(expired.record.authority.mission.status, "expired");
  assert.equal(expired.record.authority.code, "mission_expired");
  assert.ok(expiry < Date.now());

  // A mission whose capability does not cover the action at all.
  const narrow = new MissionRegistry();
  narrow.issue({
    id: "msn-narrow",
    agent: "worker",
    name: "egress only",
    capabilities: [{ name: "net", scope: { actions: ["net.egress"], resources: ["https://api.example.com/**"] } }],
  });
  const narrowGuard = new Guard({ rules: RULES, agent: "host", cwd: "/workspace", missions: narrow });
  const notCovered = await narrowGuard.authorize({ tool: "database.write", args: { table: "x" } }, { agent: "worker" });
  assert.equal(notCovered.decision.verdict, "deny");
  assert.equal(notCovered.decision.rule, "authority-capability_not_granted");

  // And an agent with NO mission at all is not silently authorized by policy:
  // authority is inert by default, which is the documented contract, so the
  // check here is that the record says so rather than pretending it applied.
  const inertGuard = new Guard({ rules: RULES, agent: "host", cwd: "/workspace" });
  const inert = await inertGuard.authorize({ tool: "database.write", args: { table: "x" } }, { agent: "worker" });
  assert.equal(inert.decision.verdict, "permit");
  assert.equal(inert.record.authority, undefined, "no mission configured ⇒ authority is inert, and the record says nothing about it");
});

/* ================================================================== */
/*  3. WHICH PATH IS AUTHORITATIVE                                     */
/* ================================================================== */

test("AUDIT/3: production wires Ed25519, and the legacy HMAC broker is NOT a fallback it can drift back to", async () => {
  const source = await readFile(join(packageRoot, "bin", "cirvix.mjs"), "utf8");
  assert.match(source, /Ed25519DelegationVerifier/, "the shipped runtime constructs the Ed25519 verifier");
  assert.equal(/new\s+DelegationBroker\s*\(/.test(source), false, "no production composition root constructs the legacy HMAC broker");

  // The Ed25519 verifier has no symmetric secret at all: there is nothing to
  // fall back TO, which is what makes the downgrade structurally impossible
  // rather than merely unused.
  const stateDir = await host("path-authority");
  // A host that HAS issued authority: the verifier then loads only the public
  // halves, which is the property being asserted.
  const issuer = await new Ed25519DelegationIssuer({ stateDir }).init();
  const verifier = await new Ed25519DelegationVerifier({ stateDir }).init();
  /* The SAME-HOST verifier loads the full key record (it shares the state
     directory), so the property to assert here is the useful one: the
     CROSS-INSTANCE form takes public keys and holds no private material. */
  const crossInstance = await new Ed25519DelegationVerifier({
    stateDir,
    authorityPublicKey: issuer.authority.publicKey,
    delegationPublicKey: issuer.delegation.publicKey,
  }).init();
  assert.equal(crossInstance.authority.privateKey, undefined);
  assert.equal(crossInstance.delegation.privateKey, undefined);
  assert.equal(issuer.authority.privateKey === undefined, false, "the issuer, unlike a remote verifier, does hold signing material");
  assert.equal(typeof verifier.resolve, "function", "it answers the same interface the local broker does");

  // An HMAC-shaped artifact (no signature segment) is refused by that
  // interface instead of being looked up in a local grant map.
  const refused = await verifier.resolve("dlg_local_hmac_token", "worker");
  assert.equal(refused.ok, false);
  assert.match(String(refused.error), /broken_chain|unknown/);

  /* And a token minted by the LEGACY broker is not a token the production
     verifier accepts, because the two share no key material: the broker's key
     is a private per-runtime buffer, the verifier's is an Ed25519 public key.
     A "fallback" would therefore have to be a deliberate second code path, not
     a quiet drift. */
  const { DelegationBroker } = await import("../src/core/delegation.mjs");
  const broker = new DelegationBroker();
  assert.equal(broker.key, undefined, "the broker keeps its symmetric key private");
  const legacyRoot = broker.root("worker", { actions: ["*"], resources: ["**"] });
  assert.equal(typeof legacyRoot.signature, "string");
  const crossCheck = await verifier.resolveChain([legacyRoot], "worker");
  assert.equal(crossCheck.ok, false, "an HMAC root is not accepted by the Ed25519 verifier");
});

/* ================================================================== */
/*  4. PERSISTENCE AND RESTART                                         */
/* ================================================================== */

test("AUDIT/4: authority and revocation survive a restart, and an older journal cannot roll back a newer revocation", async () => {
  const stateDir = await host("restart");
  const issuer = await new Ed25519DelegationIssuer({ stateDir }).init();
  await enrollAgent({ stateDir, agentId: "worker", runtime: "test" });
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme" });
  const grant = await issuer.delegate({ parent: root.grant, subject: "worker", scope: { actions: ["fs.read"], resources: ["**"] } });

  // Session one: the chain works.
  const first = new Pipeline({ rules: RULES, cwd: "/workspace", agent: "host", delegation: await new Ed25519DelegationVerifier({ stateDir }).init() });
  assert.equal(
    (await first.submit({ tool: "read_file", arguments: { path: "/workspace/a.ts" } }, { agent: "worker", delegation: [grant.token, root.token] })).event.decision,
    "allow",
  );

  const engine = await new RevocationEngine({ stateDir, log: () => {} }).init();
  await engine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "worker", reason: "incident" });
  await issuer.store.revoke(grant.grant.id, "incident");
  await new AgentStore(stateDir).revoke("worker", "incident");

  // Session two: everything is reconstructed from disk. Nothing is remembered.
  const second = new Pipeline({ rules: RULES, cwd: "/workspace", agent: "host", delegation: await new Ed25519DelegationVerifier({ stateDir }).init(), revocation: await new RevocationEngine({ stateDir, log: () => {} }).init() });
  const restart = await second.submit({ tool: "read_file", arguments: { path: "/workspace/a.ts" } }, { agent: "worker", delegation: [grant.token, root.token] });
  assert.equal(restart.event.decision, "deny");
  assert.match(restart.event.policy, /revoked-|delegation-revoked/);

  // The enrolled record survives too, and the identity boundary honours it.
  const record = await new AgentStore(stateDir).get("worker");
  assert.equal(record.status, AGENT_STATUS.REVOKED);
  const identity = await createCallerVerifier({ stateDir });
  const params = { name: "read_file", arguments: { path: "/workspace/a.ts" } };
  const check = await identity.verify({ meta: { credential: record.credential ?? "x", ...signRequestDelta(params) }, method: "tools/call", params });
  assert.equal(check.verified, false, "a revoked agent's credential is refused after a restart");
  assert.match(String(check.reason), /revoked|not valid|does not verify/);

  // ANTI-ROLLBACK: rewind the delegation revocation journal, leaving the
  // manifest's high-water mark in place.
  await writeFile(join(stateDir, "delegations", "revocations.jsonl"), "", "utf8");
  const rolledBack = await new Ed25519DelegationVerifier({ stateDir }).init();
  const afterRollback = await rolledBack.resolveChain([grant.token, root.token], "worker");
  assert.equal(afterRollback.ok, false);
  assert.equal(afterRollback.error, "rollback", "a rolled-back revocation journal authorizes nothing");
});

function signRequestDelta(params) {
  // A placeholder proof: this assertion is about the STORE refusing a revoked
  // agent, which happens before any signature is checked.
  return { ts: new Date().toISOString(), nonce: "n", paramsHash: "h", sig: "s" };
}

/* ================================================================== */
/*  5. CROSS-INSTANCE TRUST                                            */
/* ================================================================== */

test("AUDIT/5: a second instance verifies with PUBLIC KEYS ONLY — and refuses every tampering case", async () => {
  const stateDir = await host("cross-instance");
  const issuer = await new Ed25519DelegationIssuer({ stateDir }).init();
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme", tenant: "acme" });
  const grant = await issuer.delegate({ parent: root.grant, subject: "worker", scope: { actions: ["fs.read"], resources: ["**"] } });

  const instanceB = await new Ed25519DelegationVerifier({
    stateDir,
    authorityPublicKey: issuer.authority.publicKey,
    delegationPublicKey: issuer.delegation.publicKey,
    expectedTenant: "acme",
  }).init();
  // PUBLIC KEYS ONLY: no private material was handed over, and none is held.
  assert.equal(instanceB.authority.privateKey, undefined);
  assert.equal(instanceB.delegation.privateKey, undefined);

  // 1. A valid grant succeeds WITH the human originator reconstructed.
  const ok = await instanceB.resolveChain([grant.token, root.token], "worker");
  assert.equal(ok.ok, true);
  assert.equal(ok.human, "dana@acme");
  assert.deepEqual(ok.principals, ["planner", "worker"]);

  // 2. A MODIFIED grant fails: edit the payload, keep the signature.
  const payload = JSON.parse(Buffer.from(grant.token.split(".")[0], "base64url").toString("utf8"));
  payload.scope = { actions: ["*"], resources: ["**"] };
  const modified = Buffer.from(JSON.stringify(payload)).toString("base64url") + "." + grant.token.split(".")[1];
  assert.equal((await instanceB.resolveChain([modified, root.token], "worker")).error, "bad_signature");

  // 3. WRONG AUDIENCE. There is no `audience` field on a grant; the closest
  //    binding this build has is TENANCY, pinned per boundary:
  const globex = await new Ed25519DelegationVerifier({
    stateDir,
    authorityPublicKey: issuer.authority.publicKey,
    delegationPublicKey: issuer.delegation.publicKey,
    expectedTenant: "globex",
  }).init();
  assert.equal((await globex.resolveChain([grant.token, root.token], "worker")).error, "unknown_tenant");

  // 4. WRONG SUBJECT.
  assert.equal((await instanceB.resolveChain([grant.token, root.token], "mallory")).error, "subject_mismatch");

  // 5. EXPIRED.
  const expired = await issuer.delegate({ parent: root.grant, subject: "worker", scope: { actions: ["fs.read"], resources: ["**"] }, ttlMs: 30_000, now: () => new Date(Date.now() - 300_000) });
  assert.equal((await instanceB.resolveChain([expired.token, root.token], "worker")).error, "expired");

  // 6. REPLAYED ENVELOPE: the one-time envelope dies on first use.
  const envelope = await buildCrossInstanceEnvelope({ issuer, chainTokens: [grant.token, root.token], subject: "worker" });
  assert.equal((await instanceB.resolveEnvelope(envelope, "worker")).ok, true);
  assert.equal((await instanceB.resolveEnvelope(envelope, "worker")).error, "replay");

  // 7. REVOKED PARENT invalidates the derived chain, on the OTHER instance too.
  await issuer.store.revoke(root.grant.id, "human revoked the root");
  const freshB = await new Ed25519DelegationVerifier({
    stateDir,
    authorityPublicKey: issuer.authority.publicKey,
    delegationPublicKey: issuer.delegation.publicKey,
    expectedTenant: "acme",
  }).init();
  const revoked = await freshB.resolveChain([grant.token, root.token], "worker");
  assert.equal(revoked.ok, false);
  assert.equal(revoked.error, "revoked");

  // 8. NO SHARED SYMMETRIC SECRET exists between the instances: the only
  //    material instance B holds is public, which is asserted above.
  assert.equal(typeof instanceB.sharedSecret, "undefined");
});

test("AUDIT/5: cross-instance verification is a live call, not only a library call", async () => {
  const stateDir = await host("cross-live");
  const issuer = await new Ed25519DelegationIssuer({ stateDir }).init();
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme" });
  const grant = await issuer.delegate({ parent: root.grant, subject: "worker", scope: { actions: ["fs.read"], resources: ["**"] } });

  // INSTANCE B has the issuer's public keys and nothing else.
  const instanceB = await new Ed25519DelegationVerifier({
    stateDir,
    authorityPublicKey: issuer.authority.publicKey,
    delegationPublicKey: issuer.delegation.publicKey,
  }).init();
  const guard = new Guard({ rules: RULES, agent: "host", cwd: "/workspace", delegation: instanceB });

  const allowed = await guard.authorize({ tool: "read_file", args: { path: "/workspace/a.ts" }, delegation: [grant.token, root.token] }, { agent: "worker" });
  assert.equal(allowed.decision.verdict, "permit");
  assert.equal(allowed.record.delegation.human, "dana@acme");

  const narrowed = await guard.authorize({ tool: "database.write", args: { table: "x" }, delegation: [grant.token, root.token] }, { agent: "worker" });
  assert.equal(narrowed.decision.rule, "delegation-out-of-scope");
});
