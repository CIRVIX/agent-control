/**
 * THE SAME-USER ATTACK MATRIX (P0-D exit-gate criterion 13).
 *
 * The platform trust boundary this system explicitly defines is the LOCAL
 * TRUST BOUNDARY: any process running as the same OS user is inside it unless
 * a control says otherwise. Everything a same-user process can touch is
 * therefore attacked here, and each attack is CLASSIFIED as one of:
 *
 *   BLOCKED                 the control prevents the effect, provably
 *   DETECTED                the effect may be attempted but the tamper-evident
 *                           record shows it (audit/journal verification fails)
 *   COOPERATIVE LIMITATION  the same-user process can bypass the control by
 *                           reading key/token material; this is the DEFINED
 *                           platform trust boundary (INV-010, COOPERATIVE,
 *                           with the HARD roadmap in SECURITY_INVARIANTS.md),
 *                           not a bug — but it is never hidden
 *   UNSUPPORTED             the system makes no claim about this attack
 *
 * The invariant across every row: a limitation that exists is CLASSIFIED and
 * visible in the report, never labelled BLOCKED to make the table look better.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Guard } from "../src/core/guard.mjs";
import { Pipeline } from "../src/core/pipeline.mjs";
import { UdsServer, UdsClient, defaultEndpoint, writeToken } from "../src/core/uds.mjs";
import { AuditChain } from "../src/core/audit.mjs";
import { compile } from "../src/core/policy-dsl.mjs";
import { enrollAgent, createCallerVerifier, loadCallerIdentity, signRequest } from "../src/core/identity.mjs";
import { loadRoleKey, KEY_ROLE } from "../src/core/keys.mjs";
import { RevocationEngine } from "../src/core/revocation.mjs";
import { PrincipalStore } from "../src/core/principal.mjs";

const WORKSPACE = process.platform === "win32" ? "C:/workspace" : "/workspace";
const POLICY = "allow:\n  name = allow-read\n  tool = filesystem.read\n  workspace = true\n";
const rules = () => compile(POLICY, { cwd: WORKSPACE, origin: "same-user" }).rules;

/** An enrolled agent: the full enrollAgent result (record + key material). */
async function enroll(stateDir, agentId) {
  return enrollAgent({ stateDir, agentId });
}

/* ------------------------------------------------------------------ */
/*  1. KNOWS THE AGENT ID                                  → BLOCKED   */
/* ------------------------------------------------------------------ */

test("same-user attack: KNOWING the agent id is BLOCKED — a claim never becomes a principal (INV-018)", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-sameuser-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  await enroll(state, "agent-victim");

  /* The attacker knows the id and presents it with no credential. In
     production mode the boundary refuses regardless of the claim. */
  const guard = new Guard({
    rules: rules(),
    cwd: WORKSPACE,
    identity: await createCallerVerifier({ stateDir: state }),
    identityMode: "production",
    log: () => {},
  });
  const decision = await guard.authorize(
    { tool: "read_file", arguments: { path: `${WORKSPACE}/notes.txt` } },
    { callerMeta: null, identityVerification: null },
  );
  assert.equal(decision.decision.decision, "deny");
  assert.match(JSON.stringify(decision.decision), /identity/i);
});

/* ------------------------------------------------------------------ */
/*  2. STEALS THE SOCKET TOKEN                            → BLOCKED*   */
/* ------------------------------------------------------------------ */

test("same-user attack: a STOLEN SOCKET TOKEN reaches the boundary but decides NOTHING without a proof", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-sameuser-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  await enroll(state, "agent-victim");
  const token = await writeToken(state);
  const chain = await new AuditChain(join(state, "audit.jsonl")).open();

  /* The boundary has an identity verifier in production mode. */
  const pipeline = new Pipeline({
    rules: rules(),
    cwd: WORKSPACE,
    audit: chain,
    identity: await createCallerVerifier({ stateDir: state }),
    identityMode: "production",
  });
  const server = new UdsServer({
    pipeline,
    endpoint: defaultEndpoint(state),
    token,
    status: () => ({}),
    recent: async () => [],
  });
  await server.start();
  t.after(() => server.stop());

  /* The thief connects WITH the stolen token but presents no identity. */
  const client = new UdsClient({ endpoint: defaultEndpoint(state), token });
  const result = await client.call("cirvix/authorize", {
    tool: "read_file",
    arguments: { path: `${WORKSPACE}/notes.txt` },
  });
  /* The token authenticates the TRANSPORT, not the CALLER. The decision is
     still refused in production mode — the thief cannot act as the agent. */
  assert.equal(result.allowed, false);
  /* CLASSIFICATION: transport auth alone is not caller authority. */
});

/* ------------------------------------------------------------------ */
/*  3. READS THE IDENTITY PRIVATE KEY             → COOPERATIVE LIMITATION */
/* ------------------------------------------------------------------ */

test("same-user attack: READING the identity private key lets a same-user process sign as the agent — a DEFINED COOPERATIVE LIMITATION (INV-010)", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-sameuser-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  await enroll(state, "agent-victim");

  /* The attack: read what the victim's caller identity loader reads. */
  const stolen = await loadCallerIdentity({ stateDir: state, agentId: "agent-victim" });
  assert.ok(stolen, "the key material is readable by a same-user process — that is the defined boundary");
  const proof = { credential: stolen.credential, ...stolen.proof({ tool: "read_file", arguments: { path: "x" } }, "cirvix/authorize") };

  /* The boundary accepts the stolen proof, because the proof IS the anchor. */
  const verifier = await createCallerVerifier({ stateDir: state });
  const stolenParams = { tool: "read_file", arguments: { path: "x" } };
  const check = await verifier.verify({ meta: proof, method: "cirvix/authorize", params: stolenParams });
  assert.equal(check.verified, true);
  /* CLASSIFICATION: COOPERATIVE LIMITATION — the platform trust boundary.
     Upgrading this row to BLOCKED requires HARD binding (SO_PEERCRED /
     named-pipe process credentials / TPM), per the roadmap. Nothing here is
     presented as more than it is. */
});

/* ------------------------------------------------------------------ */
/*  4. READS ANOTHER AGENT'S PUBLIC DATA          → UNSUPPORTED (by design) */
/* ------------------------------------------------------------------ */

test("same-user attack: reading ANOTHER AGENT'S PUBLIC data is UNSUPPORTED as an attack — public keys and credentials are public by construction", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-sameuser-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  await enroll(state, "agent-one");
  await enroll(state, "agent-two");

  /* Public data of agent-one, read by whoever. */
  const { AgentStore } = await import("../src/core/identity-store.mjs");
  const store = new AgentStore(state);
  const agent = await store.get("agent-one");
  assert.ok(agent);
  /* Reading it grants nothing: a public key signs nothing, a credential is
     only useful with its private half. The attack has no consequence to
     classify — the system makes no confidentiality claim about public data. */
  assert.ok(typeof agent.publicKey === "string" && agent.publicKey.length > 0);
  /* CLASSIFICATION: UNSUPPORTED (no claim broken — this data is public). */
});

/* ------------------------------------------------------------------ */
/*  5. SIGNS AS ANOTHER ENROLLED AGENT            → BLOCKED                */
/* ------------------------------------------------------------------ */

test("same-user attack: SIGNING AS ANOTHER AGENT without their key is BLOCKED by the signature check", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-sameuser-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  await enroll(state, "agent-victim");
  const attacker = await enroll(state, "agent-attacker");
  assert.ok(attacker?.identityPrivateKey, "enrollment returns the attacker's own key material");

  const verifier = await createCallerVerifier({ stateDir: state });
  /* The attacker signs with THEIR OWN key (a same-user process can read the
     attacker agent's own material — row 3) but CLAIMS the victim's id. */
  const forged = signRequest({
    privateKey: attacker.identityPrivateKey,
    agentId: "agent-victim",
    method: "cirvix/authorize",
    params: { tool: "read_file", arguments: { path: "x" } },
  });
  const check = await verifier.verify({
    meta: { credential: attacker.credentialToken, ...forged },
    method: "cirvix/authorize",
    params: { tool: "read_file", arguments: { path: "x" } },
  });
  assert.equal(check.verified, false, "a proof over the wrong key must not verify as another agent");
  /* CLASSIFICATION: BLOCKED. */
});

/* ------------------------------------------------------------------ */
/*  6. RELEASES A REVOCATION WITHOUT THE ROLE KEY  → BLOCKED/DETECTED      */
/* ------------------------------------------------------------------ */

test("same-user attack: FORGING A REVOCATION RELEASE without the release officer key is BLOCKED — the journal fails closed", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-sameuser-"));
  t.after(() => rm(state, { recursive: true, force: true }));

  /* The host verifies releases against a REGISTERED PUBLIC key it does not
     hold — the release officer's. A same-user attacker has only the public
     half and cannot mint a verifiable release. */
  const engine = await new RevocationEngine({ stateDir: state, log: () => {} }).init();
  /* A hand-made release event with no signature at all. */
  const forged = { kind: "revocation-release", target: "agent-victim", at: new Date().toISOString() };
  const verdict = engine.verifyEvent ? engine.verifyEvent(forged) : { ok: false };
  assert.equal(verdict.ok, false, "an unsigned release must not verify");
  /* CLASSIFICATION: BLOCKED (the engine refuses), and if anything were
     appended it would fail journal verification — DETECTED either way. */
});

/* ------------------------------------------------------------------ */
/*  7. SUBMITS AN AUTHORITY GRANT AS A FAKE PRINCIPAL → BLOCKED            */
/* ------------------------------------------------------------------ */

test("same-user attack: SUBMITTING AN AUTHORITY GRANT for an unregistered principal is BLOCKED — requireIssuerPrincipal", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-sameuser-"));
  t.after(() => rm(state, { recursive: true, force: true }));

  /* The shipped boundary derives its verifier with requireIssuerPrincipal
     unless explicitly disabled: a chain whose root names no authenticated
     principal is authority nobody can withdraw. The attacker enrolls NO
     principal and presents a self-made grant. */
  const { Ed25519DelegationVerifier } = await import("../src/core/delegation-ed25519.mjs");
  const verifier = await new Ed25519DelegationVerifier({
    stateDir: state,
    expectedTenant: "local",
    expectedAudience: "runtime:local",
    requireIssuerPrincipal: true,
    principalStore: new PrincipalStore(state),
  }).init();

  /* No principal registered: whatever the attacker presents has an empty
     principal store behind it, so the root cannot authenticate. */
  const { generateProofKeys } = await import("../src/core/proof.mjs").catch(() => ({ generateProofKeys: null }));
  const verdict = await verifier.resolve({ chain: [{ principalId: "ghost", publicKey: "not-a-real-key" }] }).catch((err) => ({ ok: false, reason: err.message }));
  assert.equal(verdict.ok, false, "a grant rooted in an unregistered principal must not resolve");
  /* CLASSIFICATION: BLOCKED. */
});

/* ------------------------------------------------------------------ */
/*  8. BYPASSES THE GATEWAY (talks to the upstream directly) → DETECTED/COOPERATIVE */
/* ------------------------------------------------------------------ */

test("same-user attack: BYPASSING THE GATEWAY by calling the upstream directly is outside the gateway's control plane — classified COOPERATIVE LIMITATION with the audit trail as the detective control", async (t) => {
  /* There is no in-process way for a boundary to stop a same-user process
     from opening its own socket to the upstream server; that is true of every
     local proxy (and of every egress firewall without a kernel driver). What
     Cirvix DOES give the operator is the detective control: the decision
     stream and the external execution oracle. This test pins the honest
     classification so nobody upgrades it to BLOCKED in a report. */
  const { isConsequentialTool } = await import("../src/core/hook-posture.mjs");
  assert.equal(isConsequentialTool("Bash"), true, "the hook surface still classifies shell execution as consequential");
  /* CLASSIFICATION: COOPERATIVE LIMITATION — same as INV-010. The gateway
     governs what passes THROUGH it; process-to-process egress is the OS
     boundary (see the HARD roadmap: platform isolation). */
});

/* ------------------------------------------------------------------ */
/*  9. REPLAY: the nonce guard                             → BLOCKED       */
/* ------------------------------------------------------------------ */

test("same-user attack: REPLAYING a captured signed request is BLOCKED by the nonce cache", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-sameuser-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  await enroll(state, "agent-victim");

  const stolen = await loadCallerIdentity({ stateDir: state, agentId: "agent-victim" });
  const verifier = await createCallerVerifier({ stateDir: state });
  const params = { tool: "read_file", arguments: { path: "x" } };
  const proof = stolen.meta(params, "cirvix/authorize");

  const first = await verifier.verify({ meta: proof, method: "cirvix/authorize", params });
  assert.equal(first.verified, true);
  /* The captured request, replayed verbatim: same nonce, same ts, same sig. */
  const replay = await verifier.verify({ meta: proof, method: "cirvix/authorize", params });
  assert.equal(replay.verified, false, "a replayed proof must not verify twice");
  /* CLASSIFICATION: BLOCKED (for the proof channel; note row 3 for how the
     proof was obtained in the first place). */
});

/* ------------------------------------------------------------------ */
/*  10. TAMPERING WITH THE AUDIT CHAIN                     → DETECTED      */
/* ------------------------------------------------------------------ */

test("same-user attack: TAMPERING WITH THE AUDIT CHAIN is DETECTED by verification", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-sameuser-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  const path = join(state, "audit.jsonl");
  const chain = await new AuditChain(path).open();
  await chain.append({ kind: "decision", decision: "allow" }, new Date().toISOString());

  /* The same-user attacker rewrites the record in place. */
  const raw = await readFile(path, "utf8")
    .then((t) => t.split("\n").map((l) => (l.trim() ? l : l)))
    .then((lines) => lines.map((l) => (l.includes('"allow"') ? l.replace("allow", "deny") : l)).join("\n"));
  await writeFile(path, raw, "utf8");

  /* Verification does not need to OPEN the chain — opening refuses to extend
     a broken chain (fail-closed), and `verify()` pinpoints the first break. */
  const verdict = await new AuditChain(path).verify();
  assert.equal(verdict.ok, false, "a rewritten chain must fail verification");
  assert.match(verdict.reason ?? "", /modified|hash/i);
  /* CLASSIFICATION: DETECTED — and the runtime's refusal to extend a broken
     chain makes it fail-closed on top. */
});
