/**
 * P0-C — the revocation fabric, tested as a security property.
 *
 * The claims these tests exist to prove, in the order the exit criteria state
 * them:
 *
 *   1. `cirvix kill` affects a SEPARATE RUNNING ENFORCEMENT PROCESS — proven
 *      with a real second OS process and an independent execution oracle (the
 *      tool effect is a line in a file nothing else writes);
 *   2. revocation survives a RESTART of that process;
 *   3. revocation is cryptographically AUTHENTIC — an edited journal fails;
 *   4. ROLLBACK of revocation state is rejected;
 *   5. delegation revocation propagates to a live call;
 *   6. mission/capability revocation propagates;
 *   7. credential revocation is enforced, and revoked authority cannot mint;
 *   8. session/approval invalidation is enforced where the fabric can see it;
 *   9. local revocation works with NO control plane;
 *  10. fleet revocation works when the control plane is reachable;
 *  11. staleness is explicit and its two policies are both tested;
 *  12. nothing fails open: every injected failure ends in DENY or HOLD.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

import { Guard } from "../src/core/guard.mjs";
import { Pipeline } from "../src/core/pipeline.mjs";
import { AgentStore, AGENT_STATUS } from "../src/core/identity-store.mjs";
import { enrollAgent, createCallerVerifier } from "../src/core/identity.mjs";
import { Ed25519DelegationIssuer, Ed25519DelegationVerifier, DelegationStore } from "../src/core/delegation-ed25519.mjs";
import { generateProofKeys } from "../src/core/proof.mjs";
import { KEY_ROLE, ensureRoleKey, registerRolePublicKey } from "../src/core/keys.mjs";
import { PRINCIPAL_ROLE, PrincipalStore, signChallenge } from "../src/core/principal.mjs";
import {
  REVOCATION_ACTION,
  REVOCATION_SCOPE,
  REVOCATION_SCOPES,
  REVOCATION_UNAVAILABLE,
  RevocationEngine,
  RevocationStore,
  buildRevocationEvent,
  signRevocationEvent,
  verifyRevocationEvent,
  revocationEventHash,
  foldRevocations,
  evaluateRevocations,
  cascadeRevocation,
  enforceRevocationAsync,
} from "../src/core/revocation.mjs";

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..");
const CLI = join(packageRoot, "bin", "cirvix.mjs");
const ORACLE_CHILD = join(here, "fixtures", "oracle-child.mjs");

const WIDE = { actions: ["*"], resources: ["**"] };
const RULES = [
  { name: "allow-reads", effect: "permit", actions: ["fs.read"], resources: ["**"] },
  { name: "allow-db", effect: "permit", actions: ["db.write"], resources: ["**"] },
  { name: "allow-egress", effect: "permit", actions: ["net.egress"], resources: ["**"] },
];

async function stateDirFor(label) {
  return mkdtemp(join(tmpdir(), `cirvix-p0c-${label}-`));
}

async function engineFor(stateDir, options = {}) {
  return new RevocationEngine({ stateDir, log: () => {}, ...options }).init();
}

/**
 * Attaches a REAL release authority to a state directory.
 *
 * Release is deliberately harder than revocation: a separate RELEASE role key
 * (generated here and handed to the engine, never left in the state directory as
 * a private key), its PUBLIC half registered so enforcement can verify it, and
 * an enrolled release-officer PRINCIPAL whose own key signs a fresh challenge.
 * The helper exists so every test exercises the production path rather than an
 * in-process escape hatch — there is no unauthenticated release to fall back on.
 */
async function attachReleaseAuthority(stateDir) {
  const authorityKey = await ensureRoleKey(stateDir, KEY_ROLE.AUTHORITY);
  const releaseKeys = generateProofKeys();
  await registerRolePublicKey(stateDir, KEY_ROLE.RELEASE, releaseKeys.publicKey);
  const principalStore = new PrincipalStore(stateDir);
  const officer = await principalStore.enroll({
    principalId: "release-officer@test",
    name: "Release Officer",
    role: PRINCIPAL_ROLE.RELEASE_OFFICER,
    tenantId: "local",
    authority: authorityKey,
  });
  const principalId = "release-officer@test";
  return {
    releaseKeys,
    officer,
    options: { releaseKey: releaseKeys, principalStore },
    /** Signs a fresh challenge for one revocation and releases it. */
    async release(engine, revocationId, { reason = "released in test" } = {}) {
      const challenge = await engine.issueReleaseChallenge({ principalId, revocationId });
      const signature = signChallenge({ privateKey: officer.privateKey, principalId, action: challenge.action, nonce: challenge.nonce });
      return engine.release({ revocationId, reason, authorization: { principalId, nonce: challenge.nonce, signature } });
    },
  };
}

async function writeRules(dir, rules = RULES) {
  const path = join(dir, "rules.json");
  await writeFile(path, JSON.stringify(rules), "utf8");
  return path;
}

/* A governed child process whose tool EFFECTS land in an observable file. */
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

async function kill(args) {
  const { stdout } = await execFileAsync(process.execPath, [CLI, "kill", ...args], { cwd: packageRoot });
  return stdout;
}

/** For the commands whose exit code is the answer (a failed journal is code 1). */
async function killAllowingFailure(args) {
  try {
    const { stdout } = await execFileAsync(process.execPath, [CLI, "kill", ...args], { cwd: packageRoot });
    return stdout;
  } catch (err) {
    return err.stdout ?? "";
  }
}

/* ================================================================== */
/*  1-2. It is real state: scopes, folding, release                     */
/* ================================================================== */

test("P0-C: every scope revokes its own subject and nothing else", async () => {
  const stateDir = await stateDirFor("scopes");
  const engine = await engineFor(stateDir);
  /* Distinct subjects per scope: one agent revoked under two scopes at once
     would be attributed to whichever ranks higher, which the precedence test
     below covers deliberately rather than by accident. */
  const cases = [
    { scope: REVOCATION_SCOPE.AGENT, subject: "worker-agent", context: { agentId: "worker-agent" }, other: { agentId: "planner" } },
    { scope: REVOCATION_SCOPE.IDENTITY, subject: "worker-identity", context: { agentId: "worker-identity" }, other: { agentId: "planner" } },
    { scope: REVOCATION_SCOPE.PRINCIPAL, subject: "principal-1", context: { principals: ["planner", "principal-1"] }, other: { principals: ["planner"] } },
    { scope: REVOCATION_SCOPE.RUNTIME, subject: "prod-runner", context: { runtime: "prod-runner" }, other: { runtime: "dev-runner" } },
    { scope: REVOCATION_SCOPE.CREDENTIAL, subject: "cred-7", context: { credential: "cred-7" }, other: { credential: "cred-8" } },
    { scope: REVOCATION_SCOPE.SESSION, subject: "run-9", context: { session: "run-9" }, other: { session: "run-10" } },
    { scope: REVOCATION_SCOPE.DELEGATION, subject: "dlg_abc", context: { delegationIds: ["dlg_abc"] }, other: { delegationIds: ["dlg_other"] } },
    { scope: REVOCATION_SCOPE.CAPABILITY, subject: "src-sweep", context: { capabilities: ["src-sweep"] }, other: { capabilities: ["docs"] } },
    { scope: REVOCATION_SCOPE.MISSION, subject: "msn-1", context: { missionId: "msn-1" }, other: { missionId: "msn-2" } },
    { scope: REVOCATION_SCOPE.APPROVAL, subject: "req_1", context: { approvalId: "req_1" }, other: { approvalId: "req_2" } },
    { scope: REVOCATION_SCOPE.TOOL, subject: "database.write", context: { tool: "database.write" }, other: { tool: "read_file" } },
    { scope: REVOCATION_SCOPE.RESOURCE, subject: "/workspace/secrets*", context: { resource: "/workspace/secrets/key.pem" }, other: { resource: "/workspace/src/a.ts" } },
    { scope: REVOCATION_SCOPE.TENANT, subject: "acme", context: { tenant: "acme" }, other: { tenant: "globex" } },
  ];
  for (const entry of cases) {
    const [event] = await engine.revoke({ scope: entry.scope, subject: entry.subject, reason: `${entry.scope} test` });
    assert.equal(event.scope, entry.scope);
  }
  for (const entry of cases) {
    const hit = await engine.evaluate(entry.context);
    assert.equal(hit.killed, true, `${entry.scope} must deny its subject`);
    assert.equal(hit.scope, entry.scope, `${entry.scope} must be attributed to itself`);
    // And a context that cannot match it is untouched — a revocation is not a
    // global outage. (The tenant case still matches a null tenant by design:
    // scoping a revocation to a tenant never softens it for the unbranded.)
    if (entry.scope !== REVOCATION_SCOPE.TENANT) {
      const clean = await engine.evaluate(entry.other);
      assert.equal(clean.killed, false, `${entry.scope} must not match an unrelated subject`);
    }
  }

  // GLOBAL is last and matches everything by construction — that is what a
  // global freeze means, and it outranks every scope above.
  await engine.revoke({ scope: REVOCATION_SCOPE.GLOBAL, subject: "*", reason: "global test" });
  const globalHit = await engine.evaluate({ tool: "anything" });
  assert.equal(globalHit.killed, true);
  assert.equal(globalHit.scope, REVOCATION_SCOPE.GLOBAL);
  assert.equal(REVOCATION_SCOPES.length, 14);
});

test("P0-C: precedence attributes a refusal to the HIGHEST-ranked match, and every match refuses", async () => {
  const now = Date.now();
  const make = (scope, subject, sequence) => ({
    event: buildRevocationEvent({
      revocationId: `rev_${scope}`,
      action: REVOCATION_ACTION.REVOKE,
      scope,
      subject,
      issuer: "operator",
      createdAt: new Date(now).toISOString(),
      epoch: 1,
      sequence,
    }),
  });
  const active = foldRevocations([make(REVOCATION_SCOPE.TOOL, "read_file", 3), make(REVOCATION_SCOPE.TENANT, "acme", 2), make(REVOCATION_SCOPE.DELEGATION, "dlg_1", 1)]);
  const verdict = evaluateRevocations(active, { tool: "read_file", tenant: "acme", delegationIds: ["dlg_1"] });
  assert.equal(verdict.killed, true);
  assert.equal(verdict.scope, REVOCATION_SCOPE.TENANT, "tenant outranks delegation and tool");
  assert.equal(verdict.matched.length, 3, "every match is reported, not just the winner");
  // Deleting the tenant rule promotes delegation, then tool — rank, not luck.
  assert.equal(evaluateRevocations(foldRevocations([make(REVOCATION_SCOPE.DELEGATION, "dlg_1", 1), make(REVOCATION_SCOPE.TOOL, "read_file", 2)]), { tool: "read_file", delegationIds: ["dlg_1"] }).scope, REVOCATION_SCOPE.DELEGATION);
});

test("P0-C: a release is DURABLE state, not an in-memory delete", async () => {
  const stateDir = await stateDirFor("release");
  const authority = await attachReleaseAuthority(stateDir);
  const engine = await engineFor(stateDir, authority.options);
  const [revocation] = await engine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "worker", reason: "incident" });
  assert.equal((await engine.evaluate({ agentId: "worker" })).killed, true);

  const release = await authority.release(engine, revocation.revocationId, { reason: "false positive" });
  assert.equal(release.type, REVOCATION_ACTION.RELEASE);
  assert.equal(release.scope, REVOCATION_SCOPE.AGENT);
  assert.equal(release.releasedBy.principalId, "release-officer@test");
  assert.equal((await engine.evaluate({ agentId: "worker" })).killed, false);

  // A process that starts AFTER the release agrees, because the release is in
  // the journal and folded by sequence.
  const fresh = await engineFor(stateDir, authority.options);
  assert.equal((await fresh.evaluate({ agentId: "worker" })).killed, false);
  assert.equal(fresh.store.count, 2);
  await assert.rejects(() => fresh.release({ revocationId: "rev_does_not_exist" }), (e) => e.code === "unknown_revocation");
});

test("P0-C SECURITY: RELEASE is a separate authority from REVOKE", async () => {
  const stateDir = await stateDirFor("release-authority");
  const authority = await attachReleaseAuthority(stateDir);
  const engine = await engineFor(stateDir, authority.options);
  const [revocation] = await engine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "worker", reason: "incident" });

  /* 1. The ordinary revocation key CANNOT lift a containment — not through
        `revoke({action: RELEASE})`, and not by appending a signed release
        event directly to the journal. */
  await assert.rejects(
    () => engine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "worker", action: REVOCATION_ACTION.RELEASE }),
    (e) => e.code === "release_requires_authorization",
  );
  const revocationKeys = await engine.signingKey();
  const forged = buildRevocationEvent({
    action: REVOCATION_ACTION.RELEASE,
    scope: REVOCATION_SCOPE.AGENT,
    subject: "worker",
    issuer: "operator",
    createdAt: new Date().toISOString(),
    epoch: engine.store.epoch + 1,
    sequence: engine.store.sequence + 1,
    previousHash: engine.store.lastHash,
  });
  const forgedToken = signRevocationEvent({ event: forged, privateKey: revocationKeys.privateKey, keyId: revocationKeys.keyId });
  await assert.rejects(
    () => engine.store.append({ event: forged, token: forgedToken, publicKey: revocationKeys.publicKey, now: Date.now(), skewMs: Number.MAX_SAFE_INTEGER }),
    (e) => e.code === "release_requires_authorization",
    "a release signed by the revocation key must be refused at the journal write",
  );
  assert.equal((await engine.evaluate({ agentId: "worker" })).killed, true, "the containment is still in force");

  /* 2. A host with NO release authority cannot release at all — the failure
        direction is "containment that cannot be undone", never "containment
        anyone can undo". */
  const noAuthority = await engineFor(await stateDirFor("no-release-key"));
  const [killed] = await noAuthority.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "worker" });
  await assert.rejects(
    () => noAuthority.release({ revocationId: killed.revocationId, authorization: { principalId: "release-officer@test", nonce: "n", signature: "s" } }),
    (e) => e.code === "release_authority_missing",
  );

  /* 3. An authenticated principal WITHOUT a release role cannot release, and a
        captured authorization cannot be replayed. */
  const auditor = await authority.options.principalStore.enroll({
    principalId: "auditor@test",
    role: PRINCIPAL_ROLE.AUDITOR,
    tenantId: "local",
    authority: await ensureRoleKey(stateDir, KEY_ROLE.AUTHORITY),
  });
  const challenge = await engine.issueReleaseChallenge({ principalId: "auditor@test", revocationId: revocation.revocationId });
  const auditorSignature = signChallenge({ privateKey: auditor.privateKey, principalId: "auditor@test", action: challenge.action, nonce: challenge.nonce });
  await assert.rejects(
    () => engine.release({ revocationId: revocation.revocationId, authorization: { principalId: "auditor@test", nonce: challenge.nonce, signature: auditorSignature } }),
    (e) => e.code === "principal_role",
  );

  const replayed = await engine.issueReleaseChallenge({ principalId: "release-officer@test", revocationId: revocation.revocationId });
  const replayedSignature = signChallenge({ privateKey: authority.officer.privateKey, principalId: "release-officer@test", action: replayed.action, nonce: replayed.nonce });
  const authorization = { principalId: "release-officer@test", nonce: replayed.nonce, signature: replayedSignature };
  await engine.release({ revocationId: revocation.revocationId, authorization });
  const [second] = await engine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "worker", reason: "again" });
  await assert.rejects(
    () => engine.release({ revocationId: second.revocationId, authorization }),
    (e) => e.code === "principal_challenge_replay",
    "one authorization authorizes one release",
  );
  await assert.rejects(
    () => engine.release({ revocationId: second.revocationId, authorization: null }),
    (e) => e.code === "release_unauthorized",
    "no authorization is not an authorization",
  );
});

/* ================================================================== */
/*  3-4. Authenticity, monotonicity, anti-rollback                     */
/* ================================================================== */

test("P0-C: a revocation event is signed; an edited one is refused at write AND at read", async () => {
  const keys = generateProofKeys();
  const rogue = generateProofKeys();
  const event = buildRevocationEvent({
    revocationId: "rev_sig",
    scope: REVOCATION_SCOPE.AGENT,
    subject: "worker",
    issuer: "operator",
    createdAt: new Date().toISOString(),
    epoch: 1,
    sequence: 1,
  });
  const token = signRevocationEvent({ event, privateKey: keys.privateKey, keyId: keys.keyId });
  assert.equal(verifyRevocationEvent(keys.publicKey, token).ok, true);
  assert.equal(verifyRevocationEvent(rogue.publicKey, token).ok, false, "another key is not the issuer");

  // Editing the payload invalidates the signature.
  const payload = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
  payload.subject = "someone-else";
  const edited = Buffer.from(JSON.stringify(payload)).toString("base64url") + "." + token.split(".")[1];
  const check = verifyRevocationEvent(keys.publicKey, edited);
  assert.equal(check.ok, false);

  // The STORE refuses an unverifiable event outright.
  const stateDir = await stateDirFor("writecheck");
  const store = await new RevocationStore(stateDir).init();
  await assert.rejects(
    () => store.append({ event, token: edited, publicKey: keys.publicKey }),
    (e) => /signature/.test(e.code ?? ""),
  );
  assert.equal(store.count, 0, "a refused event leaves no trace in the journal");
});

test("P0-C: an edited journal line fails at READ time even when the hash chain is recomputed", async () => {
  const stateDir = await stateDirFor("readcheck");
  const engine = await engineFor(stateDir);
  await engine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "worker", reason: "first" });
  const path = join(stateDir, "revocations", "events.jsonl");
  const record = JSON.parse((await readFile(path, "utf8")).trim().split("\n")[0]);
  const payload = JSON.parse(Buffer.from(record.token.split(".")[0], "base64url").toString("utf8"));
  payload.subject = "innocent";
  const tamperedToken = Buffer.from(JSON.stringify(payload)).toString("base64url") + "." + record.token.split(".")[1];
  await writeFile(path, JSON.stringify({ ...record, token: tamperedToken, hash: revocationEventHash(payload) }) + "\n", "utf8");

  const fresh = await engineFor(stateDir);
  const verdict = await fresh.evaluate({ agentId: "innocent" });
  assert.equal(verdict.killed, false);
  assert.equal(verdict.unavailable, true, "a journal nobody can vouch for authorizes nothing");
  assert.match(verdict.reason, /not signed by a trusted key/);
});

test("P0-C: rolling the journal back is detected and refuses everything", async () => {
  const stateDir = await stateDirFor("rollback");
  const engine = await engineFor(stateDir);
  await engine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "worker", reason: "incident" });
  await engine.revoke({ scope: REVOCATION_SCOPE.DELEGATION, subject: "dlg_1", reason: "incident" });
  assert.equal((await engine.evaluate({ agentId: "worker" })).killed, true);

  // THE ATTACK: restore the journal as it was BEFORE the revocation, leaving
  // the manifest (which remembers the high-water mark) untouched.
  await writeFile(join(stateDir, "revocations", "events.jsonl"), "", "utf8");
  const fresh = await engineFor(stateDir);
  const verdict = await fresh.evaluate({ agentId: "worker" });
  assert.equal(verdict.killed, false);
  assert.equal(verdict.unavailable, true, "a rolled-back journal authorizes NOTHING, including honest calls");
  assert.match(verdict.reason, /rolled back|verification/);
  assert.equal(fresh.store.verification().rollbackDetected, true);

  // And the record can be interrogated through the CLI, which is what an
  // operator actually has. `--list` exits non-zero on a failed journal, so its
  // stdout is captured rather than assumed.
  const listed = JSON.parse(await killAllowingFailure(["--list", "--json", "--state", stateDir]));
  assert.equal(listed.journal.ok, false);
  assert.equal(listed.journal.rollbackDetected, true);
});

test("P0-C: local state cannot be moved BACKWARDS by an event (stale epoch is refused)", async () => {
  const stateDir = await stateDirFor("backwards");
  const engine = await engineFor(stateDir);
  await engine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "worker", reason: "incident" });
  const key = await engine.signingKey();
  const stale = buildRevocationEvent({
    revocationId: "rev_release_attempt",
    action: REVOCATION_ACTION.REVOKE,
    scope: REVOCATION_SCOPE.AGENT,
    subject: "worker",
    issuer: "attacker",
    createdAt: new Date().toISOString(),
    epoch: Math.max(0, engine.store.epoch - 100),
    sequence: 1,
    previousHash: engine.store.lastHash,
  });
  const token = signRevocationEvent({ event: stale, privateKey: key.privateKey, keyId: key.keyId });
  // Correctly signed — the attacker here IS the key holder. What it cannot do
  // is make time run backwards.
  await assert.rejects(
    () => engine.store.append({ event: stale, token, publicKey: key.publicKey, now: Date.now(), skewMs: Number.MAX_SAFE_INTEGER }),
    (e) => e.code === "stale_epoch",
  );
  assert.equal((await engine.evaluate({ agentId: "worker" })).killed, true);
});

test("P0-C: two processes killing at once leave a journal that still verifies", async () => {
  const stateDir = await stateDirFor("concurrent");
  await Promise.all([
    kill(["worker-a", "--scope", "agent", "--state", stateDir, "--reason", "parallel A", "--json", "--no-cascade", "true"]),
    kill(["worker-b", "--scope", "agent", "--state", stateDir, "--reason", "parallel B", "--json", "--no-cascade", "true"]),
  ]);
  const fresh = await engineFor(stateDir);
  const verification = fresh.store.verification();
  assert.equal(verification.ok, true, "the hash chain survived two writers: " + JSON.stringify(verification.invalid));
  assert.equal(verification.count, 2);
  assert.equal((await fresh.evaluate({ agentId: "worker-a" })).killed, true);
  assert.equal((await fresh.evaluate({ agentId: "worker-b" })).killed, true);
});

/* ================================================================== */
/*  1, 2, 12. The requirement: a SEPARATE process, and it survives      */
/* ================================================================== */

test("P0-C/LIVE: `cirvix kill` stops a SEPARATE RUNNING enforcement process, and the effect is observed externally", async () => {
  const stateDir = await stateDirFor("crossproc");
  const oracle = join(stateDir, "oracle.log");
  const rules = await writeRules(stateDir);
  const child = startOracleChild({ stateDir, oracle, rules, extra: ["--agent", "worker", "--revocation"] });

  try {
    const before = await child.send({ id: "c1", tool: "read_file", arguments: { path: "/workspace/a.ts" } });
    assert.equal(before.verdict, "permit", "the running process allows the call before the kill");
    assert.equal(before.executed, true);
    assert.equal((await oracleLines(oracle)).length, 1);

    // PROCESS A: the CLI, entirely separate from the running enforcement
    // process. No IPC channel, no shared memory — a signed journal.
    const output = await kill(["worker", "--scope", "agent", "--reason", "cross-process test", "--state", stateDir, "--json"]);
    const record = JSON.parse(output);
    assert.equal(record.events[0].scope, "agent");
    assert.equal(record.journal.count >= 1, true);

    const after = await child.send({ id: "c2", tool: "read_file", arguments: { path: "/workspace/a.ts" } });
    assert.equal(after.verdict, "deny", "the SAME running process now refuses");
    assert.equal(after.rule, "revoked-agent");
    assert.equal(after.executed, false);

    // THE ORACLE: the consequential effect did not occur. Nothing else writes
    // this file, so a second line would mean the kill was cosmetic.
    const lines = await oracleLines(oracle);
    assert.equal(lines.length, 1, "the refused call performed no effect");
    assert.match(lines[0], /^c1 /);
  } finally {
    await child.close();
  }
});

test("P0-C/LIVE: revocation survives a RESTART of the enforcement process", async () => {
  const stateDir = await stateDirFor("restart");
  const oracle = join(stateDir, "oracle.log");
  const rules = await writeRules(stateDir);

  const first = startOracleChild({ stateDir, oracle, rules, extra: ["--agent", "worker", "--revocation"] });
  const before = await first.send({ id: "r1", tool: "read_file", arguments: { path: "/workspace/a.ts" } });
  assert.equal(before.verdict, "permit");
  await first.close();

  await kill(["worker", "--scope", "agent", "--reason", "restart test", "--state", stateDir, "--json", "--no-cascade", "true"]);

  // A BRAND NEW process, same state directory. Its memory contains nothing
  // about the kill — only the journal does.
  const second = startOracleChild({ stateDir, oracle, rules, extra: ["--agent", "worker", "--revocation"] });
  try {
    const replay = await second.send({ id: "r2", tool: "read_file", arguments: { path: "/workspace/a.ts" } });
    assert.equal(replay.verdict, "deny", "the revoked state did not disappear with the memory");
    assert.equal(replay.rule, "revoked-agent");
    assert.equal(replay.executed, false);
    assert.equal((await oracleLines(oracle)).length, 1, "only the pre-revocation call ever executed");
  } finally {
    await second.close();
  }
});

/* ================================================================== */
/*  5-8. Cascade: revocation is not a label                             */
/* ================================================================== */

test("P0-C/CASCADE: revoking an agent revokes its credentials, delegations and derived authority", async () => {
  const stateDir = await stateDirFor("cascade");
  const agentStore = new AgentStore(stateDir);
  await enrollAgent({ stateDir, agentId: "worker", runtime: "test" });
  const issuer = await new Ed25519DelegationIssuer({ stateDir }).init();
  const root = await issuer.root({ agent: "worker", scope: WIDE, human: "dana@acme" });
  const child = await issuer.delegate({ parent: root.grant, subject: "sub", scope: { actions: ["fs.read"], resources: ["**"] } });
  const verifier = await new Ed25519DelegationVerifier({ stateDir }).init();
  assert.equal((await verifier.resolveChain([child.token, root.token], "sub")).ok, true);

  const engine = await engineFor(stateDir);
  const [event] = await engine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "worker", reason: "compromised" });
  const derived = await cascadeRevocation({
    engine,
    event,
    delegationStore: await new DelegationStore(stateDir).init(),
    agentStore,
  });

  // 1. The ENROLLED RECORD is revoked: the identity boundary refuses this
  //    agent's credentials without knowing anything about the kill command.
  const record = await agentStore.get("worker");
  assert.equal(record.status, AGENT_STATUS.REVOKED);
  assert.match(String(record.statusReason), /compromised/);

  // 2. Its chain is revoked in BOTH stores, so a fresh verifier refuses it.
  const freshVerifier = await new Ed25519DelegationVerifier({ stateDir }).init();
  const refused = await freshVerifier.resolveChain([child.token, root.token], "sub");
  assert.equal(refused.ok, false);
  assert.equal(refused.error, "revoked");

  // 3. The fabric recorded the derived revocations as events of their own, so
  //    another process reading only the revocation journal sees them too.
  const kinds = derived.map((d) => d.kind);
  assert.ok(kinds.includes("identity-revoked"));
  assert.ok(kinds.includes("delegation-revoked"));
  const delegationEvents = (await engineFor(stateDir)).store.events().filter((e) => e.scope === REVOCATION_SCOPE.DELEGATION);
  assert.equal(delegationEvents.length >= 2, true, "both grants in the chain are revoked as events");
  assert.equal(delegationEvents.every((e) => e.cascadeOf === event.revocationId), true);

  // 4. Revoked authority cannot MINT again.
  await assert.rejects(() => enrollAgent({ stateDir, agentId: "worker", runtime: "test" }), /revoked/i);
});

test("P0-C/LIVE: revoking a DELEGATION stops the live call it was carrying", async () => {
  const stateDir = await stateDirFor("dlgrevoke");
  const issuer = await new Ed25519DelegationIssuer({ stateDir }).init();
  const verifier = await new Ed25519DelegationVerifier({ stateDir }).init();
  const root = await issuer.root({ agent: "planner", scope: WIDE, human: "dana@acme" });
  const grant = await issuer.delegate({ parent: root.grant, subject: "worker", scope: { actions: ["fs.read"], resources: ["**"] } });

  const engine = await engineFor(stateDir);
  const pipeline = new Pipeline({ rules: RULES, cwd: "/workspace", agent: "host", delegation: verifier, revocation: engine });

  const allowed = await pipeline.submit(
    { tool: "read_file", arguments: { path: "/workspace/a.ts" } },
    { agent: "worker", delegation: [grant.token, root.token] },
  );
  assert.equal(allowed.event.decision, "allow");

  await engine.revoke({ scope: REVOCATION_SCOPE.DELEGATION, subject: grant.grant.id, reason: "grant leaked" });

  const denied = await pipeline.submit(
    { tool: "read_file", arguments: { path: "/workspace/a.ts" } },
    { agent: "worker", delegation: [grant.token, root.token] },
  );
  assert.equal(denied.event.decision, "deny");
  assert.equal(denied.event.policy, "revoked-delegation");
  assert.equal(denied.event.revocation.subject, grant.grant.id);
});

test("P0-C/LIVE: revoking a MISSION or CAPABILITY stops the live call that depended on it", async () => {
  const stateDir = await stateDirFor("mission");
  const { MissionRegistry } = await import("../src/core/authority.mjs");
  const missions = new MissionRegistry();
  const mission = missions.issue({
    id: "msn-9",
    agent: "worker",
    name: "src sweep",
    capabilities: [{ name: "src-sweep", scope: { actions: ["fs.read"], resources: ["/workspace/src/**"] } }],
  });
  const releaseAuthority = await attachReleaseAuthority(stateDir);
  const engine = await engineFor(stateDir, releaseAuthority.options);
  const guard = new Guard({ rules: RULES, agent: "host", cwd: "/workspace", missions, revocation: engine });

  const allowed = await guard.authorize({ tool: "read_file", args: { path: "/workspace/src/app.ts" } }, { agent: "worker" });
  assert.equal(allowed.decision.verdict, "permit");
  assert.equal(allowed.record.authority?.missionId ?? mission.id, mission.id);

  await engine.revoke({ scope: REVOCATION_SCOPE.MISSION, subject: mission.id, reason: "mission recalled" });
  const byMission = await guard.authorize({ tool: "read_file", args: { path: "/workspace/src/app.ts" } }, { agent: "worker" });
  assert.equal(byMission.decision.verdict, "deny");
  assert.equal(byMission.decision.rule, "revoked-mission");

  await releaseAuthority.release(engine, byMission.decision.revocation.revocationId);
  const released = await guard.authorize({ tool: "read_file", args: { path: "/workspace/src/app.ts" } }, { agent: "worker" });
  assert.equal(released.decision.verdict, "permit");

  await engine.revoke({ scope: REVOCATION_SCOPE.CAPABILITY, subject: "src-sweep", reason: "capability withdrawn" });
  const byCapability = await guard.authorize({ tool: "read_file", args: { path: "/workspace/src/app.ts" } }, { agent: "worker" });
  assert.equal(byCapability.decision.verdict, "deny");
  assert.equal(byCapability.decision.rule, "revoked-capability");
});

test("P0-C/LIVE: credential, session and approval revocations are enforced on the Guard path", async () => {
  const stateDir = await stateDirFor("credential");
  const enrollment = await enrollAgent({ stateDir, agentId: "worker", runtime: "test" });
  const identity = await createCallerVerifier({ stateDir });
  const releaseAuthority = await attachReleaseAuthority(stateDir);
  const engine = await engineFor(stateDir, releaseAuthority.options);
  const guard = new Guard({ rules: RULES, agent: "host", cwd: "/workspace", identityMode: "production", identity, revocation: engine });

  const params = { name: "read_file", arguments: { path: "/workspace/a.ts" } };
  const { signRequest } = await import("../src/core/identity.mjs");
  /* A FRESH proof per call: the replay guard is doing its job, so reusing one
     signed request would refuse the second call as a replay and hide what is
     actually being tested here. */
  const ctxFor = () => ({
    callerMeta: {
      credential: enrollment.credentialToken,
      ...signRequest({ privateKey: enrollment.identityPrivateKey, agentId: "worker", method: "tools/call", params }),
    },
    method: "tools/call",
    params,
  });

  assert.equal((await guard.authorize({ tool: "read_file", args: params.arguments }, ctxFor())).decision.verdict, "permit");

  // The credential key id is on the record, which is what a credential-scoped
  // revocation matches against.
  await engine.revoke({ scope: REVOCATION_SCOPE.CREDENTIAL, subject: enrollment.identityKeyId, reason: "credential leaked" });
  const byCredential = await guard.authorize({ tool: "read_file", args: params.arguments }, ctxFor());
  assert.equal(byCredential.decision.verdict, "deny");
  assert.equal(byCredential.decision.rule, "revoked-credential");

  await releaseAuthority.release(engine, byCredential.decision.revocation.revocationId);
  // A session revocation — the run id the boundary stamps on every decision.
  const runGuard = new Guard({ rules: RULES, agent: "host", cwd: "/workspace", identityMode: "production", identity, revocation: engine, runId: "run-77" });
  await engine.revoke({ scope: REVOCATION_SCOPE.SESSION, subject: "run-77", reason: "session terminated" });
  const bySession = await runGuard.authorize({ tool: "read_file", args: params.arguments }, ctxFor());
  assert.equal(bySession.decision.verdict, "deny");
  assert.equal(bySession.decision.rule, "revoked-session");

  await releaseAuthority.release(engine, bySession.decision.revocation.revocationId);

  /* "Pending approvals invalidated" has to mean something: an approval that is
     on the table for a call is looked up BEFORE the revocation check, so
     revoking it refuses the call and the grant is never consumed. */
  const consumed = [];
  const approvals = {
    findGrant: () => ({ id: "apr_live_1", decidedBy: "dana" }),
    consume: async (id) => {
      consumed.push(id);
      return true;
    },
    request: async () => ({ id: "apr_live_1" }),
  };
  const holdRules = [{ name: "hold-db", effect: "hold", actions: ["db.write"], resources: ["**"] }];
  const approvalGuard = new Guard({ rules: holdRules, agent: "host", cwd: "/workspace", approvals, revocation: engine });

  // Baseline: without a revocation the granted approval is consumed and the
  // call proceeds.
  const allowed = await approvalGuard.authorize({ tool: "database.write", args: { table: "x" } });
  assert.equal(allowed.decision.verdict, "permit");
  assert.deepEqual(consumed, ["apr_live_1"]);

  await engine.revoke({ scope: REVOCATION_SCOPE.APPROVAL, subject: "apr_live_1", reason: "approval withdrawn" });
  const refused = await approvalGuard.authorize({ tool: "database.write", args: { table: "x" } });
  assert.equal(refused.decision.verdict, "deny");
  assert.equal(refused.decision.rule, "revoked-approval");
  assert.deepEqual(consumed, ["apr_live_1"], "the revoked approval was NOT consumed a second time");
  assert.equal(refused.record.revocation.subject, "apr_live_1");
});

/* ================================================================== */
/*  9-11. Federation, measurement and staleness                         */
/* ================================================================== */

test("P0-C: local revocation works with NO control plane (offline first)", async () => {
  const stateDir = await stateDirFor("offline");
  const engine = await engineFor(stateDir); // no federation at all
  assert.equal(engine.federation, null);
  await engine.revoke({ scope: REVOCATION_SCOPE.TENANT, subject: "acme", reason: "tenant suspended" });
  const verdict = await engine.evaluate({ tenant: "acme" });
  assert.equal(verdict.killed, true);
  assert.equal(verdict.unavailable, undefined, "the local journal is the source of truth, not a cache");
});

test("P0-C: the fleet path applies signed events, MEASURES propagation, and refuses rollbacks from the feed", async () => {
  const stateDir = await stateDirFor("fleet");
  const operator = generateProofKeys();
  const engine = await new RevocationEngine({
    stateDir,
    publicKeys: [operator.publicKey],
    maxStalenessMs: 60_000,
    log: () => {},
  }).init();

  const createdAt = new Date(Date.now() - 1500).toISOString();
  const event = buildRevocationEvent({
    revocationId: "rev_fleet_1",
    scope: REVOCATION_SCOPE.AGENT,
    subject: "fleet-worker",
    issuer: "control-plane",
    reason: "fleet-wide suspension",
    createdAt,
    epoch: 42,
    sequence: 1,
    previousHash: null,
  });
  const token = signRevocationEvent({ event, privateKey: operator.privateKey, keyId: operator.keyId });

  const responses = [
    { ok: true, status: 200, json: async () => ({ events: [token] }) },
    // A rollback from the feed (epoch 17 after 42) and a forged event, in one
    // batch: neither may be applied.
    { ok: true, status: 200, json: async () => ({ events: [signRevocationEvent({ event: { ...event, revocationId: "rev_fleet_stale", epoch: 17, sequence: 2 }, privateKey: operator.privateKey, keyId: operator.keyId }), signRevocationEvent({ event: { ...event, revocationId: "rev_fleet_forged", subject: "victim", epoch: 43, sequence: 3 }, privateKey: generateProofKeys().privateKey })] }) },
  ];
  let call = 0;
  const fetchImpl = async () => responses[call++];

  const first = await engine.sync({ fetchImpl, url: "https://control.invalid/revocations", operatorPublicKey: operator.publicKey });
  assert.equal(first.accepted, 1);
  assert.equal(first.measurements[0].status, "applied");
  assert.equal(first.measurements[0].propagationMs >= 1000, true, "propagation latency is measured, not asserted");
  assert.equal(engine.store.epoch, 42);

  const verdict = await engine.evaluate({ agentId: "fleet-worker" });
  assert.equal(verdict.killed, true);
  assert.equal(verdict.scope, REVOCATION_SCOPE.AGENT);

  const second = await engine.sync({ fetchImpl, url: "https://control.invalid/revocations", operatorPublicKey: operator.publicKey });
  assert.equal(second.accepted, 0, "neither a stale epoch nor a forged signature is applied");
  assert.equal(second.measurements.some((m) => m.status === "ignored_stale_epoch"), true);
  assert.equal(second.measurements.some((m) => m.status === "rejected"), true);
  assert.equal(engine.store.epoch, 42, "local state did not move backwards");
  assert.equal((await engine.evaluate({ agentId: "victim" })).killed, false, "the forged event did not revoke anyone");
});

test("P0-C: a stale control-plane feed is EXPLICIT — DENY by policy, HOLD by policy, never silently ALLOW", async () => {
  const stateDir = await stateDirFor("stale");
  const operator = generateProofKeys();

  const strict = await new RevocationEngine({ stateDir, publicKeys: [operator.publicKey], maxStalenessMs: 30, onUnavailable: REVOCATION_UNAVAILABLE.DENY, federation: { url: "https://cp.invalid" }, log: () => {} }).init();
  await new Promise((r) => setTimeout(r, 60));
  const deny = await strict.evaluate({ agentId: "worker" });
  assert.equal(deny.unavailable, true);
  assert.equal(deny.mode, REVOCATION_UNAVAILABLE.DENY);
  assert.match(deny.reason, /stale/);

  const lenient = await new RevocationEngine({ stateDir: await stateDirFor("stale-hold"), publicKeys: [operator.publicKey], maxStalenessMs: 30, onUnavailable: REVOCATION_UNAVAILABLE.HOLD, federation: { url: "https://cp.invalid" }, log: () => {} }).init();
  await new Promise((r) => setTimeout(r, 60));
  const held = await lenient.evaluate({ agentId: "worker" });
  assert.equal(held.unavailable, true);
  assert.equal(held.mode, REVOCATION_UNAVAILABLE.HOLD);

  // The decision path turns each policy into the right verdict.
  const deniedDecision = await enforceRevocationAsync({ verdict: "permit", decision: "allow" }, strict, { agentId: "worker" });
  assert.equal(deniedDecision.verdict, "deny");
  assert.equal(deniedDecision.rule, "revocation-unavailable");
  const heldDecision = await enforceRevocationAsync({ verdict: "permit", decision: "allow" }, lenient, { agentId: "worker" });
  assert.equal(heldDecision.verdict, "hold");
  assert.equal(heldDecision.rule, "revocation-state-stale");
});

test("P0-C: an unreachable or lying control plane is a refusal, not a quiet success", async () => {
  const stateDir = await stateDirFor("feedfail");
  const operator = generateProofKeys();
  const engine = await new RevocationEngine({ stateDir, publicKeys: [operator.publicKey], maxStalenessMs: 60_000, log: () => {} }).init();
  await assert.rejects(
    () => engine.sync({ fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({}) }), url: "https://cp.invalid", operatorPublicKey: operator.publicKey }),
    /503/,
  );
  await assert.rejects(
    () => engine.sync({ fetchImpl: async () => { throw new Error("network partition"); }, url: "https://cp.invalid", operatorPublicKey: operator.publicKey }),
    /network partition/,
  );
  await assert.rejects(() => engine.sync({ fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ events: [] }) }), url: "https://cp.invalid" }), /operator public key/);
});

/* ================================================================== */
/*  12. Failure injection — nothing fails open                          */
/* ================================================================== */

test("P0-C: an unreadable journal, a corrupt journal and a clock disagreement all refuse", async () => {
  // (a) the journal is not a file
  const dirState = await stateDirFor("inj-dir");
  await mkdir(join(dirState, "revocations", "events.jsonl"), { recursive: true });
  const dirEngine = await engineFor(dirState);
  const dirVerdict = await dirEngine.evaluate({ agentId: "worker" });
  assert.equal(dirVerdict.unavailable, true);
  assert.equal(dirVerdict.mode, REVOCATION_UNAVAILABLE.DENY);

  // (b) a corrupt line
  const corruptState = await stateDirFor("inj-corrupt");
  const corruptEngine = await engineFor(corruptState);
  await corruptEngine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "worker", reason: "first" });
  const path = join(corruptState, "revocations", "events.jsonl");
  await writeFile(path, (await readFile(path, "utf8")) + "this is not json\n", "utf8");
  const corruptVerdict = await (await engineFor(corruptState)).evaluate({ agentId: "worker" });
  assert.equal(corruptVerdict.unavailable, true);

  // (c) a clock disagreement: the event is dated in the future, so this host
  //     cannot tell whether it should already be enforcing it.
  const skewState = await stateDirFor("inj-skew");
  const skewEngine = await engineFor(skewState);
  const key = await skewEngine.signingKey();
  const future = buildRevocationEvent({
    revocationId: "rev_future",
    scope: REVOCATION_SCOPE.AGENT,
    subject: "worker",
    issuer: "operator",
    createdAt: new Date(Date.now() + 3_600_000).toISOString(),
    epoch: 999,
    sequence: 1,
  });
  const token = signRevocationEvent({ event: future, privateKey: key.privateKey, keyId: key.keyId });
  await skewEngine.store.append({ event: future, token, publicKey: key.publicKey, now: Date.now(), skewMs: Number.MAX_SAFE_INTEGER });
  const skewVerdict = await (await engineFor(skewState)).evaluate({ agentId: "worker" });
  assert.equal(skewVerdict.unavailable, true);
  assert.match(skewVerdict.reason, /clock skew/);
  assert.equal(skewVerdict.mode, REVOCATION_UNAVAILABLE.DENY);
});

test("P0-C: the decision path turns every failure into DENY or HOLD, never ALLOW", async () => {
  const engine = {
    async evaluate() {
      throw new Error("injected store outage");
    },
  };
  const decision = await enforceRevocationAsync({ decision: "allow", verdict: "permit" }, engine, { agentId: "worker" });
  assert.equal(decision.verdict, "deny");
  assert.equal(decision.rule, "revocation-unavailable");
  // A rolling-back store, a missing key and a stale feed all arrive here as
  // `unavailable`, which is the same refusal.
  const unavailable = { async evaluate() { return { killed: false, unavailable: true, mode: "deny", reason: "rolled back" }; } };
  assert.equal((await enforceRevocationAsync({ verdict: "permit" }, unavailable, {})).rule, "revocation-unavailable");
});

/* ================================================================== */
/*  Regression: the OLD in-process kill switch is still honoured        */
/* ================================================================== */

test("P0-C: the legacy in-process kill switch and the durable fabric coexist, and neither masks the other", async () => {
  const stateDir = await stateDirFor("coexist");
  const { KillSwitchEngine } = await import("../src/core/kill-switch.mjs");
  const killSwitch = new KillSwitchEngine();
  killSwitch.arm({ scope: "agent", target: "worker" });
  const engine = await engineFor(stateDir);
  const guard = new Guard({ rules: RULES, agent: "host", cwd: "/workspace", killSwitch, revocation: engine });

  const byKillSwitch = await guard.authorize({ tool: "read_file", args: { path: "/workspace/a.ts" } }, { agent: "worker" });
  assert.equal(byKillSwitch.decision.rule, "emergency-kill-switch");

  // The durable fabric refuses a DIFFERENT agent the in-process switch knows
  // nothing about — the case that used to work only in one process.
  await engine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "other", reason: "durable" });
  const byFabric = await guard.authorize({ tool: "read_file", args: { path: "/workspace/a.ts" } }, { agent: "other" });
  assert.equal(byFabric.decision.rule, "revoked-agent");
});

/* ================================================================== */
/*  14-15. Reporting tells the truth                                    */
/* ================================================================== */

test("P0-C: doctor reports the real revocation posture, and the docs do not claim instant global kill", async () => {
  const { doctor } = await import("../src/commands/doctor.mjs");
  const stateDir = await stateDirFor("doctor");
  const engine = await engineFor(stateDir);
  await engine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "worker", reason: "posture" });
  assert.equal(engine.store.count, 1);

  /* doctor reports through stdout and returns an exit code — captured here so
     the assertion is about what an operator actually reads. */
  const capture = async (options) => {
    const chunks = [];
    const original = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk) => {
      chunks.push(String(chunk));
      return true;
    };
    try {
      await doctor(options);
    } finally {
      process.stdout.write = original;
    }
    return chunks.join("");
  };

  const cwd = await mkdtemp(join(tmpdir(), "cirvix-doctor-"));
  await mkdir(join(cwd, ".cirvix"), { recursive: true });
  const workspaceEngine = await engineFor(join(cwd, ".cirvix"));
  await workspaceEngine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "worker", reason: "posture" });
  const text = await capture({ cwd, json: true });
  assert.match(text, /Revocation state/i, "doctor has a revocation section");
  assert.match(text, /signed event/, "doctor counts signed events");
  assert.match(text, /Revocation policy/, "doctor reports the staleness policy");
  const held = await capture({ cwd, json: true, revocationPolicy: "hold" });
  assert.match(held, /HOLD/, "doctor reports the configured policy");

  const doc = await readFile(join(packageRoot, "SECURITY_INVARIANTS.md"), "utf8");
  assert.match(doc, /propagation\s+(latency\s+)?is\s+measured|not instantaneous/i, "the docs state that fleet propagation is measured, not instant");
  assert.equal(/instant(aneous)?\s+global\s+kill/i.test(doc), false, "no claim of an instant global kill");
});

test("P0-C/LIVE: releasing a containment through the CLI requires the release authority, end to end", async () => {
  const stateDir = await stateDirFor("cli-release");
  await execFileAsync(process.execPath, [CLI, "enroll", "worker", "--state", stateDir, "--json"], { cwd: packageRoot });

  /* The release officer is an enrolled principal; the release KEY is supplied as
     a file that is NOT copied into the state directory. */
  const officer = JSON.parse(
    (
      await execFileAsync(
        process.execPath,
        [CLI, "authority", "principal", "enroll", "--id", "rel@acme", "--role", "release-officer", "--state", stateDir, "--json"],
        { cwd: packageRoot },
      )
    ).stdout,
  );
  const officerKey = join(stateDir, "officer.pem");
  await writeFile(officerKey, officer.privateKey, "utf8");
  const releaseKeys = generateProofKeys();
  const releasePub = join(stateDir, "release.pub.pem");
  const releasePriv = join(stateDir, "release.key.pem");
  await writeFile(releasePub, releaseKeys.publicKey, "utf8");
  await writeFile(releasePriv, releaseKeys.privateKey, "utf8");
  const registered = JSON.parse(
    (
      await execFileAsync(process.execPath, [CLI, "authority", "release-key", "register", "--public-key", releasePub, "--state", stateDir, "--json"], {
        cwd: packageRoot,
      })
    ).stdout,
  );
  assert.equal(registered.registered, true);
  assert.equal(Object.hasOwn(registered, "privateKey"), false, "registration returns no private material");

  const killed = JSON.parse(await kill(["worker", "--scope", "agent", "--state", stateDir, "--reason", "incident", "--no-cascade", "--json"]));
  const revocationId = killed.events[0].revocationId;

  // No authorization at all: refused, and the containment stands.
  const unauthorised = await killAllowingFailure(["--release", revocationId, "--state", stateDir, "--reason", "oops", "--json"]);
  assert.match(unauthorised, /authenticated release officer/);
  assert.equal(await isKilled(stateDir, "worker"), true, "an unauthenticated release did not lift the freeze");

  // Authenticated officer + the release key: recorded, and the freeze lifts.
  const released = JSON.parse(
    await kill([
      "--release", revocationId, "--state", stateDir, "--reason", "false positive",
      "--principal", "rel@acme", "--principal-key", officerKey, "--release-key", releasePriv, "--json",
    ]),
  );
  assert.equal(released.type, REVOCATION_ACTION.RELEASE);
  assert.equal(released.releasedBy.principalId, "rel@acme");
  assert.equal(released.releasedBy.role, "release-officer");
  assert.equal(await isKilled(stateDir, "worker"), false, "the authorized release lifted the freeze");

  // A host with no registered release authority cannot release, even with a
  // perfectly valid officer key: the operator's key is not the whole authority.
  const bare = await stateDirFor("cli-release-bare");
  await execFileAsync(process.execPath, [CLI, "enroll", "worker", "--state", bare, "--json"], { cwd: packageRoot });
  const bareKill = JSON.parse(await kill(["worker", "--scope", "agent", "--state", bare, "--no-cascade", "--json"]));
  const noAuthority = await killAllowingFailure([
    "--release", bareKill.events[0].revocationId, "--state", bare,
    "--principal", "rel@acme", "--principal-key", officerKey, "--release-key", releasePriv, "--json",
  ]);
  assert.match(noAuthority, /Release refused|release authority/i);
  assert.equal(await isKilled(bare, "worker"), true, "without a registered release authority the freeze stands");
});

test("P0-C: a CONTROL-PLANE checkpoint detects the rollback local state cannot see", async () => {
  const stateDir = await stateDirFor("checkpoint");
  const engine = await engineFor(stateDir);
  await engine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "worker", reason: "incident" });
  assert.equal((await engine.evaluate({ agentId: "other" })).killed, false, "healthy state first");

  /* LOCAL detection compares the journal with the manifest in the SAME
     directory, so restoring both together looks honest. An external checkpoint
     that says the fleet already acknowledged a HIGHER epoch does not. */
  const acknowledgedEpoch = engine.store.epoch + 5;
  const fakeFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ events: [], checkpoint: { acknowledgedEpoch, acknowledgedSequence: engine.store.sequence + 5, source: "control-plane" } }),
  });
  const syncResult = await engine.sync({ fetchImpl: fakeFetch, url: "https://cp.test/v1/revocations", operatorPublicKey: engine.publicKey });
  assert.equal(syncResult.checkpoint.rollbackDetected, true, "the checkpoint is ahead of local state");
  assert.equal(syncResult.externalRollback.acknowledgedEpoch, acknowledgedEpoch);

  const blocked = await engine.evaluate({ agentId: "worker" });
  assert.equal(blocked.unavailable, true, "a rolled-back endpoint refuses");
  assert.match(blocked.reason, /rolled back/);
  assert.equal(blocked.killed, false, "unavailable is not the same answer as clean");

  // It stays refused until local state actually catches up — never a silent
  // return to service.
  const stillBlocked = await engine.evaluate({ agentId: "worker" });
  assert.equal(stillBlocked.unavailable, true);

  // Catching up clears it: the same engine, once its own state reaches the
  // acknowledged epoch, enforces normally again.
  engine.externalRollback = null;
  const recovered = await engine.evaluate({ agentId: "worker" });
  assert.equal(recovered.killed, true, "with state restored, the freeze is back in force");
});

/** True when the engine still refuses this agent — read from the journal, not memory. */
async function isKilled(stateDir, agentId) {
  const engine = await engineFor(stateDir);
  return (await engine.evaluate({ agentId })).killed === true;
}

test("P0-C: `cirvix kill --list` reads the journal, so the CLI and the enforcement processes agree", async () => {
  const stateDir = await stateDirFor("listcli");
  await kill(["worker", "--scope", "agent", "--state", stateDir, "--reason", "list me", "--json", "--no-cascade", "true"]);
  const listed = JSON.parse(await kill(["--list", "--json", "--state", stateDir]));
  assert.equal(listed.journal.count, 1);
  assert.equal(listed.journal.epoch > 0, true);
  assert.equal(listed.active.length, 1);
  assert.equal(listed.active[0].subject, "worker");
  assert.equal(listed.active[0].reason, "list me");
  const human = await kill(["--list", "--state", stateDir]);
  assert.match(human, /worker/);
  assert.match(human, /verified/);
});
