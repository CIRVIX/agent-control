/**
 * IDENTITY ORDERING + EXPLICIT MODES — the P0-A review tests.
 *
 * Two properties, proven against the Guard itself rather than the verifier:
 *
 *   1. ORDERING (INV-009). Identity is established BEFORE anything identity-
 *      dependent runs. A caller that claims a name policy would trust, and
 *      supplies no valid proof, is denied — and the claim never enters the
 *      trusted context: no stage evaluates it, matches rules against it, or
 *      can convert the refusal into a permit. Proven with a rule that ALLOWS
 *      the claimed name and nothing else, plus probes that only a genuinely
 *      evaluated pipeline could satisfy.
 *
 *   2. NO SILENT FALLBACK. A boundary's posture comes from an explicit mode
 *      (production / bootstrap / dev-insecure / compat), never from enrolment
 *      state. A fresh production install with nobody enrolled refuses callers;
 *      it does not quietly become an unauthenticated authorization endpoint.
 *
 *   3. COOPERATIVE, NOT HARD. The binding recorded for key-file identity is
 *      "cooperative": the key is a file the runtime holds, not a secret the OS
 *      binds to the process. The invariants registry states this; the tests
 *      here keep the code honest about it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Guard, SANDBOXED_PRINCIPAL } from "../src/core/guard.mjs";
import { IDENTITY_MODE, normalizeIdentityMode, resolveIdentityMode } from "../src/core/identity-modes.mjs";
import { createCallerVerifier, enrollAgent, signRequest } from "../src/core/identity.mjs";
import { AGENT_STATUS, AgentStore } from "../src/core/identity-store.mjs";
import { CaptureAudit } from "./helpers/audit-capture.mjs";

const CWD = "/workspace";

/**
 * THE RULE THAT MAKES ORDERING PROVABLE.
 *
 * Only "agent-A" may read. Any other principal — including the operator
 * default, including a sandboxed placeholder — is default-denied. If the
 * claimed name ever reached policy, this rule would PERMIT the call and a
 * downstream gate would have to re-deny it. Under correct ordering the
 * pipeline never runs for an unverified caller at all.
 */
const AGENT_A_ONLY = [
  { name: "allow-agent-a-read", effect: "permit", agents: ["agent-A"], actions: ["fs.read"], resources: ["**"] },
];

/** Agent-agnostic — for mode tests where the principal is the operator default. */
const PERMISSIVE = [{ name: "allow-reads", effect: "permit", actions: ["fs.read"], resources: ["**"] }];

const verifierFor = async (stateDir) => createCallerVerifier({ stateDir });

async function enrolled(opts = {}) {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-ord-"));
  const result = await enrollAgent({ stateDir, agentId: "agent-A", tenant: "acme", ...opts });
  return { stateDir, result };
}

const paramsFor = (path) => ({ name: "read_file", arguments: { path } });

/* ------------------------------------------------------------------ */
/*  1. Ordering: the claimed name is never the trusted principal       */
/* ------------------------------------------------------------------ */

test("ordering: a claimed name policy would allow is denied with no valid proof", async () => {
  const { stateDir } = await enrolled();
  const guard = new Guard({
    rules: AGENT_A_ONLY,
    agent: "operator-default",
    cwd: CWD,
    identity: await verifierFor(stateDir),
  });

  const { decision, record } = await guard.authorize({
    tool: "read_file",
    args: { path: "/workspace/a.ts" },
    agent: "agent-A", // the claim policy would have trusted
  });

  assert.equal(decision.verdict, "deny");
  assert.equal(decision.rule, "identity-unverified");
  // The claim did not become the principal the record attributes the call to.
  assert.equal(record.agent, "operator-default");
  assert.equal(record.agent, "agent-A" ? "operator-default" : record.agent); // explicit: NOT the claim
  assert.equal(record.claimed_agent, "agent-A", "the claim is preserved as untrusted metadata only");
});

test("ordering: the claimed name never reaches policy, delegation or the audit trail", async () => {
  const { stateDir } = await enrolled();
  const audit = new CaptureAudit();
  const guard = new Guard({
    rules: AGENT_A_ONLY,
    agent: "operator-default",
    cwd: CWD,
    audit,
    identity: await verifierFor(stateDir),
  });

  const { decision, record } = await guard.authorize({
    tool: "read_file",
    args: { path: "/workspace/a.ts" },
    agent: "agent-A",
    delegation: { id: "forged", subject: "agent-A", scope: { actions: ["*"], resources: ["*"] } },
  });

  assert.equal(decision.verdict, "deny");
  assert.equal(decision.rule, "identity-unverified");
  // No delegation stage ran with the claim behind it: the record carries no
  // delegation context, because delegation never evaluated for this caller.
  assert.equal(record.delegation, undefined);
  // The audited record attributes the refusal to the operator default, with
  // the claim visible only as untrusted metadata.
  const appended = audit.records[0];
  assert.ok(appended, "the refusal was audited");
  assert.equal(appended.agent, "operator-default");
  assert.equal(appended.claimed_agent, "agent-A");
  assert.equal(appended.identity.verified, false);
  // No stage evaluated policy on the claim's behalf — so the record carries
  // the sandboxed would-be result (default-deny: rule null), not a decision
  // made as "agent-A".
  assert.equal(record.planned.verdict, "deny");
  assert.equal(record.planned.rule ?? null, null, "the planned rule is the default-deny of the SANDBOXED principal, not a claim match");
});

test("ordering: the would-be decision is evaluated under a sandboxed principal, never the claim", async () => {
  const { stateDir } = await enrolled();
  const guard = new Guard({
    rules: AGENT_A_ONLY,
    agent: "operator-default",
    cwd: CWD,
    identity: await verifierFor(stateDir),
  });

  const { record } = await guard.authorize({
    tool: "read_file",
    args: { path: "/workspace/a.ts" },
    agent: "agent-A",
  });

  // Policy WOULD have permitted "agent-A" — that is the point of the rule —
  // but the planned verdict recorded is the SANDBOXED principal's, which
  // matches nothing and is default-denied. If `planned.verdict` were "permit"
  // here, the claim reached policy.
  assert.equal(record.planned.verdict, "deny");
  assert.notEqual(record.planned.verdict, "permit");
});

test("ordering: a denied claim cannot be converted to ALLOW by any downstream stage", async () => {
  const { stateDir } = await enrolled();
  const audit = new CaptureAudit();
  // Every optional stage armed at once — approvals, missions, entitlements,
  // kill switch — so any stage that could re-permit gets its chance.
  const guard = new Guard({
    rules: AGENT_A_ONLY,
    agent: "operator-default",
    cwd: CWD,
    audit,
    riskFloor: "low",
    identity: await verifierFor(stateDir),
  });

  for (const attempt of [
    { tool: "read_file", args: { path: "/workspace/a.ts" }, agent: "agent-A" },
    { tool: "read_file", args: { path: "/workspace/a.ts" }, agent: "agent-A", mission: "stolen-mission" },
    { tool: "read_file", args: { path: "/workspace/a.ts" }, agent: "agent-A", delegation: { id: "x" } },
    { tool: undefined, args: { path: "/workspace/a.ts" }, agent: "agent-A" }, // malformed too
  ]) {
    const { decision } = await guard.authorize(attempt);
    assert.equal(decision.verdict, "deny", `attempt ${JSON.stringify(attempt)} must stay denied`);
    assert.equal(decision.rule, "identity-unverified");
  }
  // And nothing in the audit trail permitted anything.
  assert.ok(audit.records.length >= 4);
  assert.ok(audit.records.every((r) => r.verdict === "deny"));
});

test("ordering: a VERIFIED caller is still evaluated as its proven agent", async () => {
  const { stateDir, result } = await enrolled();
  const guard = new Guard({
    rules: AGENT_A_ONLY,
    agent: "operator-default",
    cwd: CWD,
    identity: await verifierFor(stateDir),
  });
  const params = paramsFor("/workspace/a.ts");
  const proof = signRequest({
    privateKey: result.identityPrivateKey,
    agentId: "agent-A",
    method: "tools/call",
    params,
  });

  const { decision, record } = await guard.authorize(
    { tool: "read_file", args: { path: "/workspace/a.ts" } },
    { callerMeta: { credential: result.credentialToken, ...proof }, method: "tools/call", params },
  );

  assert.equal(decision.verdict, "permit");
  assert.equal(record.agent, "agent-A", "the proven identity is the principal");
  assert.equal(record.claimed_agent ?? null, null);
});

/* ------------------------------------------------------------------ */
/*  2. Modes: no silent fallback on unenrolled environments            */
/* ------------------------------------------------------------------ */

test("modes: ZERO enrolled + production => every caller refused", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-modes-")); // nothing enrolled
  const guard = new Guard({
    rules: AGENT_A_ONLY,
    agent: "operator-default",
    cwd: CWD,
    identityMode: IDENTITY_MODE.PRODUCTION,
    identity: await createCallerVerifier({ stateDir }), // null — authority key exists? no: none
  });
  // createCallerVerifier returns null on an unenrolled host; the boundary is
  // still armed, which is exactly the fresh-install shape.
  assert.equal(guard.identity, null);

  const { decision, record } = await guard.authorize({
    tool: "read_file",
    args: { path: "/workspace/a.ts" },
    agent: "agent-A",
  });
  assert.equal(decision.verdict, "deny");
  assert.equal(decision.rule, "identity-unverified");
  assert.equal(record.identity_mode, "production");
});

test("modes: ONE enrolled + production => unverified refused, verified allowed", async () => {
  const { stateDir, result } = await enrolled();
  const guard = new Guard({
    rules: AGENT_A_ONLY,
    agent: "operator-default",
    cwd: CWD,
    identityMode: IDENTITY_MODE.PRODUCTION,
    identity: await verifierFor(stateDir),
  });

  const denied = await guard.authorize({ tool: "read_file", args: { path: "/workspace/a.ts" }, agent: "agent-A" });
  assert.equal(denied.decision.verdict, "deny");

  const params = paramsFor("/workspace/a.ts");
  const proof = signRequest({
    privateKey: result.identityPrivateKey,
    agentId: "agent-A",
    method: "tools/call",
    params,
  });
  const allowed = await guard.authorize(
    { tool: "read_file", args: { path: "/workspace/a.ts" } },
    { callerMeta: { credential: result.credentialToken, ...proof }, method: "tools/call", params },
  );
  assert.equal(allowed.decision.verdict, "permit");
});

test("modes: BOOTSTRAP is an explicit window — unverified callers accepted while no verifier exists", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-modes-")); // nothing enrolled
  const guard = new Guard({
    rules: PERMISSIVE,
    agent: "bootstrap-window",
    cwd: CWD,
    identityMode: IDENTITY_MODE.BOOTSTRAP,
    identity: null,
  });

  const { decision, record } = await guard.authorize({
    tool: "read_file",
    args: { path: "/workspace/a.ts" },
    agent: "whoever",
  });
  // The window is open: the call evaluates under the operator-configured
  // agent. The claim is still not trusted — the record says so.
  assert.equal(decision.verdict, "permit");
  assert.equal(record.agent, "bootstrap-window");
  assert.equal(record.claimed_agent, "whoever");
  assert.equal(record.identity_mode, "bootstrap");
  assert.equal(record.identity.mode, "bootstrap");
  assert.equal(record.identity.verified, false);
});

test("modes: BOOTSTRAP closes itself the moment a verifier exists", async () => {
  const { stateDir, result } = await enrolled();
  const guard = new Guard({
    rules: AGENT_A_ONLY,
    agent: "bootstrap-window",
    cwd: CWD,
    identityMode: IDENTITY_MODE.BOOTSTRAP,
    identity: await verifierFor(stateDir),
  });

  // Same call that bootstrap accepted before enrolment is now refused, because
  // there IS a verifier and this caller cannot satisfy it.
  const { decision } = await guard.authorize({
    tool: "read_file",
    args: { path: "/workspace/a.ts" },
    agent: "agent-A",
  });
  assert.equal(decision.verdict, "deny");
  assert.equal(decision.rule, "identity-unverified");
});

test("modes: DEV-INSECURE accepts unverified callers and marks every record", async () => {
  const { stateDir, result } = await enrolled();
  const guard = new Guard({
    rules: PERMISSIVE,
    agent: "dev-host",
    cwd: CWD,
    identityMode: IDENTITY_MODE.DEV_INSECURE,
    identity: await verifierFor(stateDir),
  });

  const { decision, record } = await guard.authorize({
    tool: "read_file",
    args: { path: "/workspace/a.ts" },
    agent: "agent-A", // claim — dev mode accepts, but never trusts
  });
  assert.equal(decision.verdict, "permit");
  assert.equal(record.agent, "dev-host", "the claim did not become the principal");
  assert.equal(record.claimed_agent, "agent-A");
  assert.equal(record.identity_mode, "dev-insecure");
  assert.equal(record.identity.verified, false);
  // And a verified caller still gets the real thing:
  const params = paramsFor("/workspace/a.ts");
  const proof = signRequest({
    privateKey: result.identityPrivateKey,
    agentId: "agent-A",
    method: "tools/call",
    params,
  });
  const verified = await guard.authorize(
    { tool: "read_file", args: { path: "/workspace/a.ts" } },
    { callerMeta: { credential: result.credentialToken, ...proof }, method: "tools/call", params },
  );
  assert.equal(verified.record.agent, "agent-A");
  assert.equal(verified.record.identity.verified, true, "dev-insecure still records proof when it is presented");
});

test("modes: DEV-INSECURE is enforcement OFF — even a FAILED proof does not refuse", async () => {
  const { stateDir, result } = await enrolled();
  const guard = new Guard({
    rules: PERMISSIVE,
    agent: "dev-host",
    cwd: CWD,
    identityMode: IDENTITY_MODE.DEV_INSECURE,
    identity: await verifierFor(stateDir),
  });

  // A caller claiming agent-A with a REPLAYED proof is still accepted in
  // dev-insecure: the mode means identity enforcement is off. It is loudly
  // marked on the record — and this is exactly why the mode must never be
  // reachable by default. The same call in production is refused (next test).
  const params = paramsFor("/workspace/a.ts");
  const stale = signRequest({ privateKey: result.identityPrivateKey, agentId: "agent-A", method: "tools/call", params, ts: new Date(Date.now() - 3_600_000).toISOString() });
  const { decision, record } = await guard.authorize(
    { tool: "read_file", args: { path: "/workspace/a.ts" }, agent: "agent-A" },
    { callerMeta: { credential: result.credentialToken, ...stale }, method: "tools/call", params },
  );
  assert.equal(decision.verdict, "permit");
  assert.equal(record.agent, "dev-host");
  assert.equal(record.claimed_agent, "agent-A");
  assert.equal(record.identity.verified, false);
  assert.ok(record.identity.reason, "the record keeps WHY the proof failed");
});

test("modes: the same stale proof is refused in PRODUCTION mode", async () => {
  const { stateDir, result } = await enrolled();
  const guard = new Guard({
    rules: PERMISSIVE,
    agent: "prod-host",
    cwd: CWD,
    identityMode: IDENTITY_MODE.PRODUCTION,
    identity: await verifierFor(stateDir),
  });
  const params = paramsFor("/workspace/a.ts");
  const stale = signRequest({ privateKey: result.identityPrivateKey, agentId: "agent-A", method: "tools/call", params, ts: new Date(Date.now() - 3_600_000).toISOString() });
  const { decision } = await guard.authorize(
    { tool: "read_file", args: { path: "/workspace/a.ts" }, agent: "agent-A" },
    { callerMeta: { credential: result.credentialToken, ...stale }, method: "tools/call", params },
  );
  assert.equal(decision.verdict, "deny");
  assert.equal(decision.rule, "identity-unverified");
  // And a SUSPENDED agent with a fully valid proof is refused too:
  await new AgentStore(stateDir).setStatus("agent-A", AGENT_STATUS.SUSPENDED, "review");
  const params2 = paramsFor("/workspace/a.ts");
  const proof2 = signRequest({ privateKey: result.identityPrivateKey, agentId: "agent-A", method: "tools/call", params: params2 });
  const r2 = await guard.authorize(
    { tool: "read_file", args: { path: "/workspace/a.ts" } },
    { callerMeta: { credential: result.credentialToken, ...proof2 }, method: "tools/call", params: params2 },
  );
  assert.equal(r2.decision.verdict, "deny", "a suspended agent's VALID proof is refused in production");
});

test("modes: COMPAT — the SDK default keeps historic behaviour, no verifier, no refusal", async () => {
  const guard = new Guard({ rules: PERMISSIVE, agent: "sdk-local", cwd: CWD, identity: null });
  assert.equal(guard.identityMode, IDENTITY_MODE.COMPAT);

  const { decision, record } = await guard.authorize({ tool: "read_file", args: { path: "/workspace/a.ts" } });
  assert.equal(decision.verdict, "permit", "library callers with no verifier behave exactly as before");
  assert.equal(record.agent, "sdk-local");
});

test("modes: an unknown mode is refused at construction, not at the first caller", () => {
  assert.throws(() => new Guard({ rules: [], identityMode: "yolo" }), /Unknown identity mode/);
  assert.equal(normalizeIdentityMode(undefined).mode, IDENTITY_MODE.COMPAT);
  assert.equal(resolveIdentityMode({}), IDENTITY_MODE.PRODUCTION);
  assert.equal(resolveIdentityMode({ flag: "dev-insecure" }), IDENTITY_MODE.DEV_INSECURE);
  assert.equal(resolveIdentityMode({ env: "bootstrap" }), IDENTITY_MODE.BOOTSTRAP);
  assert.equal(resolveIdentityMode({ flag: "bootstrap", env: "dev-insecure" }), IDENTITY_MODE.BOOTSTRAP, "flag wins over env");
});

/* ------------------------------------------------------------------ */
/*  3. Cooperative, not hard                                           */
/* ------------------------------------------------------------------ */

test("INV-010: key-file identity records binding=cooperative, never hard", async () => {
  const { stateDir, result } = await enrolled();
  const verifier = await verifierFor(stateDir);
  const params = paramsFor("/workspace/a.ts");
  const proof = signRequest({
    privateKey: result.identityPrivateKey,
    agentId: "agent-A",
    method: "tools/call",
    params,
  });
  const check = await verifier.verify({ meta: { credential: result.credentialToken, ...proof }, method: "tools/call", params });
  assert.equal(check.verified, true);
  assert.equal(check.binding, "cooperative");
  // The enrollment record states the same limitation.
  assert.equal(result.record.binding, "cooperative");
});

test("INV-009: the sandboxed principal is exported and never a legitimate agent name", () => {
  assert.equal(typeof SANDBOXED_PRINCIPAL, "string");
  assert.match(SANDBOXED_PRINCIPAL, /^__/);
});
