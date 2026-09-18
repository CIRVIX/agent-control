import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, mkdir, rename } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ApprovalStore, approvalFingerprint } from "../src/core/approvals.mjs";
import { SecretsClient } from "../src/core/secrets.mjs";
import { assessAuthority, applyAuthority, normalizeMission, evaluateConstraints } from "../src/core/authority.mjs";
import { DelegationBroker, applyDelegation } from "../src/core/delegation.mjs";
import { DECISION } from "../src/core/decisions.mjs";
import { AuditChain } from "../src/core/audit.mjs";
import { Vault } from "../src/core/vault.mjs";
import { Meter } from "../src/core/meter.mjs";
import { estimateCents, costRefusal, CostLedger } from "../src/core/cost.mjs";
import { SessionTracker } from "../src/core/session.mjs";
import { KillSwitchEngine, KILL_SCOPES } from "../src/core/kill-switch.mjs";
import { summarize } from "../src/core/journal.mjs";
import { generateAgentKeypair, issueCryptographicPassport, rotatePassportKeys, verifyPassportSignature, buildPassport, signPassport, verifyPassport } from "../src/core/passport.mjs";
import { buildProofEnvelope } from "../src/core/proof.mjs";

async function approvalStore(t) {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-core-security-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "approvals.jsonl");
  const store = await new ApprovalStore(path).open();
  return { dir, path, store };
}

test("approval consume is single-use across independent stores", async (t) => {
  const { path, store } = await approvalStore(t);
  const { id } = await store.request({ fingerprint: "local-call" });
  await store.decide(id, "approved", "operator");
  const other = await new ApprovalStore(path).open();
  const results = await Promise.allSettled([store.consume(id, "one"), other.consume(id, "two")]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal((await new ApprovalStore(path).open()).get(id).state, "consumed");
});

test("failed approval decision persistence never exposes a grant", async (t) => {
  const { path, store } = await approvalStore(t);
  const { id } = await store.request({ fingerprint: "local-call" });
  await rename(path, `${path}.saved`);
  await mkdir(path);
  await assert.rejects(store.decide(id, "approved", "operator"));
  assert.equal(store.findGrant("local-call"), null);
});

test("approval snapshots cannot be mutated into grants", async (t) => {
  const { store } = await approvalStore(t);
  const { id } = await store.request({ fingerprint: "local-call" });
  const snapshot = store.get(id);
  snapshot.state = "approved";
  snapshot.decidedAt = new Date().toISOString();
  assert.equal(store.findGrant("local-call"), null);
});

test("approval fingerprints retain array-form delegation and environment boundaries", () => {
  const call = { agent: "worker", action: "fs.read", arguments: {} };
  assert.notEqual(approvalFingerprint({ ...call, delegation: ["owner", "worker"] }), approvalFingerprint(call));
  assert.equal(approvalFingerprint({ ...call, delegation: ["owner", "worker"] }), approvalFingerprint({ ...call, delegation: { principals: ["owner", "worker"] } }));
  assert.notEqual(approvalFingerprint({ ...call, environment: "local" }), approvalFingerprint({ ...call, environment: "test" }));
  assert.equal(
    approvalFingerprint({ ...call, arguments: { a: 1, b: 2 } }),
    approvalFingerprint({ ...call, arguments: { b: 2, a: 1 } }),
  );
});

test("secret resolution identifies the caller rather than the client owner", async () => {
  let body;
  const client = new SecretsClient({ apiUrl: "http://local.test", apiKey: "test", agent: "owner", fetchImpl: async (_, init) => {
    body = JSON.parse(init.body);
    return { status: 403, json: async () => ({ outcome: "wrong_subject" }) };
  } });
  const result = await client.substitute({ key: "sec_handle_01" }, { destination: "https://local.test", subject: "worker" });
  assert.equal(result.ok, false);
  assert.equal(body.agent, "worker");
});

test("capability conditions cannot replace mission constraints", () => {
  const mission = normalizeMission({ agent: "worker", constraints: { spend: { maxUsd: 1 } }, capabilities: [{ actions: ["fs.read"], conditions: { spend: { maxUsd: 100 } } }] });
  assert.equal(assessAuthority({ agent: "worker", action: "fs.read", costUsd: 2 }, mission).authorized, false);
  assert.equal(assessAuthority({ agent: "worker", action: "fs.read", costUsd: 0.5 }, mission).authorized, true);
  assert.equal(assessAuthority({ action: "fs.read" }, mission).authorized, false);
  for (const costUsd of [-1, NaN, Infinity]) {
    assert.equal(assessAuthority({ agent: "worker", action: "fs.read", costUsd }, mission).authorized, false);
  }
});

test("authority and delegation narrow held decisions before approval release", () => {
  const mission = normalizeMission({ agent: "worker", capabilities: [] });
  const decision = { decision: DECISION.REQUIRE_APPROVAL, verdict: "hold" };
  applyAuthority(decision, assessAuthority({ agent: "worker", action: "fs.read" }, mission));
  assert.equal(decision.decision, DECISION.DENY);
  const broker = new DelegationBroker();
  const grant = broker.root("worker", { actions: ["fs.read"] });
  const held = { decision: DECISION.REQUIRE_APPROVAL, verdict: "hold" };
  applyDelegation(held, { broker, presented: grant, agent: "worker", action: "fs.write", resource: "file" });
  assert.equal(held.decision, DECISION.DENY);
});

test("passport issuance derives the public key and rotation requires the old key", () => {
  const keys = generateAgentKeypair();
  const issued = issueCryptographicPassport({ name: "worker" }, keys.privateKey);
  assert.equal(verifyPassportSignature(issued.passport), true);
  assert.throws(() => rotatePassportKeys(issued.passport, generateAgentKeypair().privateKey));
  const rotated = rotatePassportKeys(issued.passport, keys.privateKey);
  assert.equal(verifyPassportSignature(rotated.passport), true);
  assert.equal(rotated.passport.previousPublicKey, keys.publicKey);
});

test("audit snapshots inputs and owns chain metadata", async (t) => {
  const { dir } = await approvalStore(t);
  const chain = await new AuditChain(join(dir, "audit.jsonl")).open();
  const entry = { seq: 99, prev_hash: "forged", context: { result: "original" }, date: new Date(0), sparse: Array(2) };
  const pending = chain.append(entry);
  entry.context.result = "changed";
  const record = await pending;
  assert.equal(record.seq, 1);
  assert.equal(record.context.result, "original");
  assert.equal((await chain.verify()).ok, true);
});

test("vault failed substitution does not spend valid handles and inventory cannot widen scope", async () => {
  const vault = new Vault();
  const handle = vault.issue("key", "local-test-material", { maxUses: 1, destinations: ["allowed.test"] });
  vault.inventory()[0].destinations.push("other.test");
  assert.equal((await vault.substitute({ key: handle }, { destination: "https://other.test" })).ok, false);
  assert.equal((await vault.substitute({ key: handle, missing: "sec_handle_99" }, { destination: "https://allowed.test" })).ok, false);
  assert.equal((await vault.substitute({ key: handle }, { destination: "https://allowed.test" })).ok, true);
  assert.equal((await vault.substitute({ key: handle }, { destination: "https://allowed.test" })).outcome, "exhausted");
  for (const maxUses of [NaN, -1, 1.5]) assert.throws(() => vault.issue("invalid", "material", { maxUses }));
});

test("cost estimates refuse inherited prices, invalid units and missing usage", () => {
  for (const tool of ["constructor", "toString", "__proto__"]) assert.equal(estimateCents({}, { tool }), null);
  for (const units of [-1, NaN, Infinity, "invalid"]) assert.equal(estimateCents({ paid: { centsPerCall: 1, centsPerUnit: 2 } }, { tool: "paid", units }), null);
  assert.equal(estimateCents({ paid: -1 }, { tool: "paid" }), null);
  assert.equal(estimateCents({ paid: { centsPerCall: 1, centsPerUnit: 2 } }, { tool: "paid" }), null);
  assert.equal(estimateCents({ paid: { centsPerCall: 1, centsPerUnit: 2 } }, { tool: "paid", units: 3 }), 7);
});

test("cost budgets fail closed on invalid configuration and ledger increments", () => {
  const ledger = new CostLedger();
  for (const capCents of [NaN, Infinity, -1, "100", undefined]) {
    assert.equal(costRefusal({ ledger, budget: { capCents }, rates: { paid: 1 }, tool: "paid" }).decision, "deny");
  }
  for (const budget of [{ capCents: 10, window: "unknown" }, { capCents: 10, unpriced: "unknown" }]) {
    assert.equal(costRefusal({ ledger, budget, rates: { paid: 1 }, tool: "paid" }).decision, "deny");
  }
  for (const cents of [-1, NaN, Infinity, "1"]) assert.throws(() => ledger.commit("worker", "day", cents));
  assert.equal(ledger.spent("worker", "day"), 0);
  assert.equal(costRefusal({ ledger, budget: { capCents: 10 }, rates: { paid: 1 }, tool: "paid" }), null);
});

test("passport envelopes require consistent identity and policy bindings", () => {
  const { privateKey, publicKey } = generateAgentKeypair();
  const passport = buildPassport({ agentId: "worker", records: [], environment: "local", policy: { version: 1, rules: [] } });
  const signed = signPassport({ passport, privateKey, policyHash: "fixture-policy" });
  assert.equal(verifyPassport(publicKey, signed.token).ok, true);
  for (const payload of [null, { ...signed.payload, passport: null }, { ...signed.payload, agent: "other" }, { ...signed.payload, policyHash: null }, { ...signed.payload, environment: "production" }]) {
    const token = buildProofEnvelope({ payload, privateKey }).token;
    assert.equal(verifyPassport(publicKey, token).ok, false);
  }
});

test("passport rotation carries verifiable old-key authorization", () => {
  const issued = issueCryptographicPassport({ name: "worker" });
  const rotated = rotatePassportKeys(issued.passport, issued.privateKey);
  const { previousSignature, ...withoutAuthorization } = rotated.passport;
  assert.equal(typeof previousSignature, "string");
  assert.equal(verifyPassportSignature(withoutAuthorization), false);
  assert.equal(verifyPassportSignature({ ...rotated.passport, previousSignature: "invalid" }), false);
  assert.equal(verifyPassportSignature(rotatePassportKeys(rotated.passport, rotated.privateKey).passport), true);
  assert.throws(() => rotatePassportKeys(issued.passport, issued.privateKey, { ...generateAgentKeypair(), publicKey: issued.passport.publicKey }));
});

test("session recognizes canonical HTTP actions and bounds history configuration", () => {
  for (const maxHistory of [NaN, Infinity, -1, 0, 2, 3.5]) assert.throws(() => new SessionTracker("session", { maxHistory }));
  const tracker = new SessionTracker("session");
  tracker.recordStep({ action: "fs.read", resource: "customer-fixture.csv", decision: "allow" });
  assert.equal(tracker.recordStep({ action: "http.request", resource: "https://service.example", decision: "sanitize" }).suspicious, true);
});

test("kill rules reject absent targets and cannot be changed through snapshots", () => {
  const engine = new KillSwitchEngine();
  for (const target of [undefined, null, "", " ", 42]) assert.throws(() => engine.arm({ scope: "agent", target }));
  engine.arm({ scope: "agent", target: "worker" });
  assert.throws(() => { engine.list()[0].active = false; });
  assert.equal(engine.evaluate({ agentId: "worker" }).killed, true);
});

test("meter refuses counter rollback and nonnumeric increments", async (t) => {
  const { dir } = await approvalStore(t);
  const meter = new Meter({ cwd: dir });
  t.after(() => meter.close());
  assert.equal(meter.count(), 1);
  for (const n of [-1, NaN, Infinity, "1", 0.5]) assert.throws(() => meter.count(n));
  assert.equal(meter.used(), 1);
});

test("session status and risk cannot be bypassed with prototype names", () => {
  const tracker = new SessionTracker("session");
  assert.equal(tracker.recordStep({ action: "fs.read", risk: "constructor" }).risk, 1);
  tracker.quarantine("paused");
  assert.equal(tracker.recordStep({ action: "fs.read" }).suspicious, true);
  tracker.terminate("ended");
  assert.equal(tracker.recordStep({ action: "fs.read" }).suspicious, true);
});

test("every kill scope returns a defined denial", () => {
  const fields = { agent: "agentId", family: "family", org: "orgId", environment: "environment", mcp: "mcp", credential: "credential", session: "session", model: "model", tool: "tool" };
  for (const scope of Object.values(KILL_SCOPES)) {
    const engine = new KillSwitchEngine();
    engine.arm({ scope, target: "target" });
    assert.equal(engine.evaluate({ [fields[scope]]: "target" }).decision, DECISION.DENY);
  }
});

test("journal counters ignore prototype property names", () => {
  const result = summarize([{ decision: "constructor", risk: "__proto__" }]);
  assert.equal(Object.hasOwn(result.counts, "constructor"), false);
  assert.equal(Object.getPrototypeOf(result.risks), Object.prototype);
});

test("constraint names never dispatch through Object.prototype", () => {
  for (const key of ["constructor", "toString", "__proto__"]) {
    const result = evaluateConstraints({ [key]: {} }, {}, null);
    assert.deepEqual(result.unknown, [key]);
    assert.deepEqual(result.checked, []);
  }
});
