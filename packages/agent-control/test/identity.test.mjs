/**
 * Authenticated agent identity — the boundary tests.
 *
 * These are written against the property the plan fixes, not the shape of the
 * implementation: a caller cannot satisfy identity-bound policy unless it can
 * PROVE it holds the enrolled runtime key. Every "reject" case below is a way
 * somebody could try to be an agent they are not.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Guard } from "../src/core/guard.mjs";
import { AGENT_STATUS, AgentStore } from "../src/core/identity-store.mjs";
import {
  CallerVerifier,
  createCallerVerifier,
  enrollAgent,
  signRequest,
  verifyIdentityCredential,
} from "../src/core/identity.mjs";
import { ensureRoleKey, loadRoleKey, KEY_ROLE } from "../src/core/keys.mjs";
import { generateProofKeys } from "../src/core/proof.mjs";

const CWD = "/workspace";
const RULES = [{ name: "allow-reads", effect: "permit", actions: ["fs.read"], resources: ["*"] }];

const newState = () => mkdtemp(join(tmpdir(), "cirvix-id-"));

async function enrolled(opts = {}) {
  const stateDir = await newState();
  const result = await enrollAgent({ stateDir, agentId: "agent-A", name: "Agent A", runtime: "node", ...opts });
  return { stateDir, result };
}

function proofFor(result, params, method = "tools/call", over = {}) {
  const proof = signRequest({
    privateKey: result.identityPrivateKey,
    agentId: result.record.agentId,
    method,
    params,
  });
  // The credential travels with every request; the signature proves possession
  // of the key the credential binds, so neither half is sufficient alone.
  return { credential: result.credentialToken, ...proof, ...over };
}

/* ------------------------------------------------------------------ */
/*  The credential                                                     */
/* ------------------------------------------------------------------ */

test("a signed request verifies and yields the enrolled agent", async () => {
  const { stateDir, result } = await enrolled();
  const verifier = await createCallerVerifier({ stateDir });
  const params = { name: "read_file", arguments: { path: "/workspace/a.ts" } };
  const check = await verifier.verify({ meta: proofFor(result, params), method: "tools/call", params });
  assert.equal(check.verified, true);
  assert.equal(check.agentId, "agent-A");
  assert.equal(check.issuer, "local");
  assert.equal(check.binding, "cooperative");
});

test("a bare agent name with no credential does not verify", async () => {
  const { stateDir } = await enrolled();
  const verifier = await createCallerVerifier({ stateDir });
  const check = await verifier.verify({ meta: { agent: "agent-A" }, method: "tools/call", params: {} });
  assert.equal(check.verified, false);
  assert.match(check.reason, /no identity credential/);
});

test("a self-signed credential cannot stand in for an issued one", async () => {
  const { stateDir } = await enrolled();
  const verifier = await createCallerVerifier({ stateDir });
  const { createIdentityCredential, signIdentityCredential } = await import("../src/core/identity.mjs");
  const fakeKeys = generateProofKeys();
  const forged = createIdentityCredential({ agentId: "agent-A", publicKey: fakeKeys.publicKey });
  const { token } = signIdentityCredential({ credential: forged, privateKey: fakeKeys.privateKey });
  const check = await verifier.verify({ meta: { credential: token }, method: "tools/call", params: {} });
  assert.equal(check.verified, false);
  assert.match(check.reason, /signature/);
});

test("an expired credential does not verify", async () => {
  const { stateDir, result } = await enrolled({ ttlMs: -300_000 });
  const verifier = await createCallerVerifier({ stateDir });
  const check = await verifier.verify({ meta: proofFor(result, {}), method: "tools/call", params: {} });
  assert.equal(check.verified, false);
  assert.match(check.reason, /expired/);
});

test("a revoked agent does not verify", async () => {
  const { stateDir, result } = await enrolled();
  const verifier = await createCallerVerifier({ stateDir });
  await new AgentStore(stateDir).revoke("agent-A", "test");
  const check = await verifier.verify({ meta: proofFor(result, {}), method: "tools/call", params: {} });
  assert.equal(check.verified, false);
  assert.match(check.reason, /revoked/);
});

test("a credential for one agent cannot be presented as another", async () => {
  const { stateDir, result } = await enrolled();
  const verifier = await createCallerVerifier({ stateDir });
  const meta = proofFor(result, {}, "tools/call", { agent: "agent-B" });
  const check = await verifier.verify({ meta, method: "tools/call", params: {} });
  assert.equal(check.verified, false);
  assert.match(check.reason, /claims agent/);
});

test("a replayed request is refused", async () => {
  const { stateDir, result } = await enrolled();
  const verifier = await createCallerVerifier({ stateDir });
  const meta = proofFor(result, {});
  const first = await verifier.verify({ meta, method: "tools/call", params: {} });
  const second = await verifier.verify({ meta, method: "tools/call", params: {} });
  assert.equal(first.verified, true);
  assert.equal(second.verified, false);
  assert.match(second.reason, /replay/);
});

test("a request changed after signing is refused", async () => {
  const { stateDir, result } = await enrolled();
  const verifier = await createCallerVerifier({ stateDir });
  const meta = {
    credential: result.credentialToken,
    ...signRequest({
      privateKey: result.identityPrivateKey,
      agentId: "agent-A",
      method: "tools/call",
      params: { name: "read_file" },
    }),
  };
  const check = await verifier.verify({ meta, method: "tools/call", params: { name: "delete_file" } });
  assert.equal(check.verified, false);
  assert.match(check.reason, /does not match/);
});

test("a signature from a different key is refused", async () => {
  const { stateDir, result } = await enrolled();
  const verifier = await createCallerVerifier({ stateDir });
  const other = generateProofKeys();
  const meta = {
    credential: result.credentialToken,
    ...signRequest({ privateKey: other.privateKey, agentId: "agent-A", method: "tools/call", params: {} }),
  };
  const check = await verifier.verify({ meta, method: "tools/call", params: {} });
  assert.equal(check.verified, false);
  assert.match(check.reason, /signature does not verify/);
});

test("an agent that was never enrolled is refused", async () => {
  const { stateDir, result } = await enrolled();
  const authority = await loadRoleKey(stateDir, KEY_ROLE.AUTHORITY);
  const verifier = new CallerVerifier({
    issuerPublicKey: authority.publicKey,
    store: new AgentStore(await newState()),
  });
  const check = await verifier.verify({ meta: proofFor(result, {}), method: "tools/call", params: {} });
  assert.equal(check.verified, false);
  assert.match(check.reason, /not enrolled/);
});

/* ------------------------------------------------------------------ */
/*  The guard                                                          */
/* ------------------------------------------------------------------ */

test("Guard denies an unverified caller even when policy would permit", async () => {
  const { stateDir } = await enrolled();
  const guard = new Guard({ rules: RULES, agent: "local", cwd: CWD, identity: await createCallerVerifier({ stateDir }) });
  const { decision } = await guard.authorize({ tool: "read_file", args: { path: "/workspace/a.ts" } });
  assert.equal(decision.verdict, "deny");
  assert.equal(decision.rule, "identity-unverified");
});

test("Guard permits a verified caller and records the verified identity", async () => {
  const { stateDir, result } = await enrolled();
  const guard = new Guard({ rules: RULES, agent: "local", cwd: CWD, identity: await createCallerVerifier({ stateDir }) });
  const params = { name: "read_file", arguments: { path: "/workspace/a.ts" } };
  const { decision, record } = await guard.authorize(
    { tool: "read_file", args: { path: "/workspace/a.ts" } },
    { callerMeta: proofFor(result, params), method: "tools/call", params },
  );
  assert.equal(decision.verdict, "permit");
  assert.equal(record.identity.verified, true);
  assert.equal(record.agent, "agent-A");
});

test("INV-009: a claimed agent name cannot establish identity", async () => {
  const { stateDir, result } = await enrolled();
  const guard = new Guard({ rules: RULES, agent: "local", cwd: CWD, identity: await createCallerVerifier({ stateDir }) });
  const params = { name: "read_file", arguments: { path: "/workspace/a.ts" } };

  // A caller that CLAIMS to be "alice" but proves only agent-A is evaluated as
  // agent-A: the claimed name is ignored, because it proves nothing.
  const { record } = await guard.authorize(
    { tool: "read_file", args: { path: "/workspace/a.ts" }, agent: "alice" },
    { callerMeta: proofFor(result, params), method: "tools/call", params },
  );
  assert.equal(record.agent, "agent-A");

  // And a caller claiming "alice" with no proof at all is refused outright,
  // even though the name is the one policy would have trusted before.
  const { decision } = await guard.authorize({
    tool: "read_file",
    args: { path: "/workspace/a.ts" },
    agent: "alice",
  });
  assert.equal(decision.verdict, "deny");
  assert.equal(decision.rule, "identity-unverified");
});
