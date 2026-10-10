/**
 * THE P0-A IDENTITY SECURITY MATRIX.
 *
 * A decision value alone proves nothing: a gateway can print "deny" and forward
 * anyway, and a "deny" record can still leak what the caller wanted to know.
 * Every row below therefore asserts the full chain —
 *
 *     input -> decision -> trusted identity/context -> actual execution result
 *
 * — where "execution result" is ground truth the caller cannot fake: the
 * upstream server's own access log for gateway rows, and the pipeline/record
 * context for the rest.
 *
 * Rows (each maps to an audit-finding probe):
 *   forged passport, wrong issuer, expired passport, revoked passport,
 *   wrong runtime, wrong tenant, wrong agent, missing credential, missing
 *   proof, tampered params, replayed request, stale timestamp, claimed-name
 *   override, cross-process verification, gateway boundary, UDS boundary, SDK
 *   behaviour, fresh/un-enrolled endpoint, production vs compatibility mode.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { Guard, CirvixDenied, SANDBOXED_PRINCIPAL } from "../src/core/guard.mjs";
import { Gateway } from "../src/core/gateway.mjs";
import { Pipeline } from "../src/core/pipeline.mjs";
import { UdsServer, UdsClient, defaultEndpoint, writeToken } from "../src/core/uds.mjs";
import { AuditChain } from "../src/core/audit.mjs";
import { MessageFramer } from "../src/core/jsonrpc.mjs";
import { compile } from "../src/core/policy-dsl.mjs";
import { createCallerVerifier, enrollAgent, signRequest, signIdentityCredential, createIdentityCredential } from "../src/core/identity.mjs";
import { AGENT_STATUS, AgentStore } from "../src/core/identity-store.mjs";
import { generateProofKeys } from "../src/core/proof.mjs";
import { guard as guardSdk } from "../src/core/guard.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = join(HERE, "fixtures", "mock-mcp-server.mjs");
const CWD = "/workspace";
const READABLE_RULES = [{ name: "allow-reads", effect: "permit", actions: ["fs.read"], resources: ["**"] }];

const paramsFor = (path = "/workspace/a.ts") => ({ name: "read_file", arguments: { path } });

/** Fresh enrolled host + verifier. Every row gets its own, so nonces never collide. */
async function freshHost(opts = {}) {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-mx-"));
  const enrollment = await enrollAgent({ stateDir, agentId: "agent-A", runtime: "node", tenant: "globex", ...opts.enroll });
  const verifier = await createCallerVerifier({ stateDir, ...opts.verifier });
  return { stateDir, enrollment, verifier };
}

/** The `ctx.callerMeta` a legitimate agent-A would send for `params`. */
function proofFor(enrollment, params, over = {}) {
  const proof = signRequest({ privateKey: enrollment.identityPrivateKey, agentId: "agent-A", method: "tools/call", params });
  return { credential: enrollment.credentialToken, ...proof, ...over };
}

/**
 * Runs one verifier row and returns the full chain. The guard is armed with a
 * permissive rule so "deny" can only be identity's doing, and an operator
 * default agent so any leakage of the claim into the record is visible.
 */
async function runRow({ enroll = {}, verifier = {}, meta, params = paramsFor(), beforeVerify = null }) {
  const { stateDir, enrollment } = await freshHost({ enroll, verifier });
  if (beforeVerify) await beforeVerify({ stateDir, enrollment });
  const identity = await createCallerVerifier({ stateDir, ...verifier });
  const guard = new Guard({ rules: READABLE_RULES, agent: "operator-default", cwd: CWD, identityMode: "production", identity });
  const { decision, record } = await guard.authorize(
    { tool: "read_file", args: params.arguments, agent: "agent-A" },
    { callerMeta: typeof meta === "function" ? meta(enrollment) : meta, method: "tools/call", params },
  );
  return { decision, record, stateDir, enrollment };
}

/* ------------------------------------------------------------------ */
/*  Part 1 — the verifier matrix (one Guard, full context assertions)  */
/* ------------------------------------------------------------------ */

const MATRIX = [
  {
    name: "forged passport (self-signed credential)",
    meta: () => {
      const fake = generateProofKeys();
      const { token } = signIdentityCredential({
        credential: createIdentityCredential({ agentId: "agent-A", publicKey: fake.publicKey }),
        privateKey: fake.privateKey,
      });
      return { credential: token, ...signRequest({ privateKey: fake.privateKey, agentId: "agent-A", method: "tools/call", params: paramsFor() }) };
    },
    expectReason: /signature/,
  },
  {
    name: "wrong issuer (credential signed by another authority)",
    meta: (enrollment) => {
      // Signed by a DIFFERENT host's key than the verifier trusts.
      const rogue = generateProofKeys();
      const { token } = signIdentityCredential({
        credential: createIdentityCredential({ agentId: "agent-A", publicKey: enrollment.identityPublicKey }),
        privateKey: rogue.privateKey,
      });
      return { credential: token, ...signRequest({ privateKey: enrollment.identityPrivateKey, agentId: "agent-A", method: "tools/call", params: paramsFor() }) };
    },
    expectReason: /signature/,
  },
  {
    name: "expired passport",
    enroll: { ttlMs: -300_000 },
    meta: (enrollment) => proofFor(enrollment, paramsFor()),
    expectReason: /expired/,
  },
  {
    name: "revoked passport (agent revoked after enrollment)",
    beforeVerify: async ({ stateDir }) => new AgentStore(stateDir).setStatus("agent-A", AGENT_STATUS.REVOKED, "matrix"),
    meta: (enrollment) => proofFor(enrollment, paramsFor()),
    expectReason: /revoked/,
  },
  {
    name: "wrong runtime (credential issued for another runtime)",
    verifier: { expectedRuntime: "claude-code" },
    enroll: { runtime: "node" },
    meta: (enrollment) => proofFor(enrollment, paramsFor()),
    expectReason: /runtime/,
  },
  {
    name: "wrong tenant (credential minted for another tenant)",
    verifier: { expectedTenant: "acme" },
    enroll: { tenant: "globex" },
    meta: (enrollment) => proofFor(enrollment, paramsFor()),
    expectReason: /tenant/,
  },
  {
    name: "wrong agent (credential of agent-A presented as agent-B)",
    meta: (enrollment) => proofFor(enrollment, paramsFor(), { agent: "agent-B" }),
    expectReason: /claims agent/,
  },
  {
    name: "missing credential (proof without the passport)",
    meta: (enrollment) => {
      const p = proofFor(enrollment, paramsFor());
      const { credential, ...rest } = p;
      return rest;
    },
    expectReason: /no identity credential/,
  },
  {
    name: "missing proof (passport without the request signature)",
    meta: (enrollment) => ({ credential: enrollment.credentialToken, agent: "agent-A" }),
    expectReason: /no identity signature/,
  },
  {
    name: "tampered params (request changed after signing)",
    meta: (enrollment) => proofFor(enrollment, paramsFor("/workspace/other.ts")),
    params: paramsFor("/workspace/a.ts"),
    expectReason: /does not match/,
  },
  {
    name: "stale timestamp (outside the accepted clock skew)",
    meta: (enrollment) => proofFor(enrollment, paramsFor(), { ts: new Date(Date.now() - 3_600_000).toISOString() }),
    expectReason: /clock skew/,
  },
  {
    name: "claimed-name override (valid agent-A proof claiming 'admin')",
    meta: (enrollment) => proofFor(enrollment, paramsFor(), { agent: "admin" }),
    expectReason: /claims agent/,
  },
];

for (const row of MATRIX) {
  test(`matrix: ${row.name} -> deny, claim not trusted, nothing executed`, async () => {
    const { decision, record } = await runRow(row);

    // INPUT -> DECISION
    assert.equal(decision.verdict, "deny", "decision");
    assert.equal(decision.rule, "identity-unverified", "rule");
    // TRUSTED IDENTITY / CONTEXT
    assert.equal(record.identity.verified, false, "identity.verified");
    assert.equal(record.agent, "operator-default", "recorded principal is the operator default, never the claim");
    assert.equal(record.claimed_agent, "agent-A", "the claim is kept as untrusted metadata only");
    assert.equal(record.identity_mode, "production");
    assert.ok(row.expectReason.test(record.identity.reason ?? ""), `identity.reason (${record.identity.reason}) matches ${row.expectReason}`);
    // The would-be pipeline outcome is recorded for audit — computed under the
    // SANDBOXED principal, never as the claim. Its verdict may honestly be
    // "permit" (the tool itself is allowed); what must never happen is the
    // claim becoming the principal of ANY decision.
    assert.ok(record.planned && typeof record.planned.verdict === "string", "the planned evaluation is recorded");
    assert.notEqual(record.agent, "agent-A");
    assert.ok(!JSON.stringify(record).includes(`"agent":"agent-A"`), "no field of the record treats the claim as the principal");
  });
}

test("matrix: replayed request -> first executes, replay is refused", async () => {
  const { stateDir, enrollment } = await freshHost();
  const verifier = await createCallerVerifier({ stateDir });
  const guard = new Guard({ rules: READABLE_RULES, agent: "operator-default", cwd: CWD, identityMode: "production", identity: verifier });
  const params = paramsFor();
  const meta = proofFor(enrollment, params);

  const first = await guard.authorize(
    { tool: "read_file", args: params.arguments, agent: "agent-A" },
    { callerMeta: meta, method: "tools/call", params },
  );
  assert.equal(first.decision.verdict, "permit");
  assert.equal(first.record.identity.verified, true);
  assert.equal(first.record.agent, "agent-A", "the proven principal");

  const second = await guard.authorize(
    { tool: "read_file", args: params.arguments, agent: "agent-A" },
    { callerMeta: meta, method: "tools/call", params },
  );
  // DECISION + CONTEXT
  assert.equal(second.decision.verdict, "deny");
  assert.equal(second.decision.rule, "identity-unverified");
  assert.match(second.record.identity.reason ?? "", /replay/);
  assert.equal(second.record.agent, "operator-default");
  assert.equal(second.record.claimed_agent, "agent-A");
});

test("matrix: cross-process verification — a second verifier instance (public key + store only) proves the same call", async () => {
  const { stateDir, enrollment } = await freshHost();
  const params = paramsFor();
  const meta = proofFor(enrollment, params);

  // "Process 1" created the enrollment. "Process 2" holds no private key of
  // the authority — only the public key and the agent store, which is exactly
  // what createCallerVerifier loads from disk.
  const verifier2 = await createCallerVerifier({ stateDir });
  assert.ok(verifier2, "a second process can arm its boundary from the shared state");
  const guard2 = new Guard({ rules: READABLE_RULES, agent: "operator-default", cwd: CWD, identityMode: "production", identity: verifier2 });
  const { decision, record } = await guard2.authorize(
    { tool: "read_file", args: params.arguments, agent: "agent-A" },
    { callerMeta: meta, method: "tools/call", params },
  );
  assert.equal(decision.verdict, "permit", "cross-process verification works with public-key material only");
  assert.equal(record.identity.verified, true);
  assert.equal(record.agent, "agent-A");
  assert.equal(record.identity.issuer, "local");
});

/* ------------------------------------------------------------------ */
/*  Part 2 — the gateway boundary (execution ground truth)             */
/* ------------------------------------------------------------------ */

class McpClient {
  #pending = new Map();
  #nextId = 1;
  constructor(gateway) {
    this.gateway = gateway;
    this.framer = new MessageFramer({
      onMessage: (m) => {
        const entry = this.#pending.get(m.id);
        if (!entry) return;
        this.#pending.delete(m.id);
        entry(m);
      },
    });
    gateway.start((msg) => this.framer.push(Buffer.from(JSON.stringify(msg) + "\n")));
  }
  request(method, params = {}, timeoutMs = 8000) {
    return new Promise((resolve, reject) => {
      const id = this.#nextId++;
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`timed out on ${method}`));
      }, timeoutMs);
      this.#pending.set(id, (m) => {
        clearTimeout(timer);
        resolve(m);
      });
      void this.gateway.handleClientMessage({ jsonrpc: "2.0", id, method, params });
    });
  }
}

/**
 * A real gateway over a real MCP server, with the server's own access log as
 * ground truth. `identityMode` selects the posture under test; `enroll`
 * decides whether the host has any agents at all.
 */
async function withGateway(fn, { identityMode = "production", enroll = true } = {}) {
  const root = await mkdtemp(join(tmpdir(), "cirvix-mx-gw-"));
  const workspace = join(root, "workspace").split("\\").join("/");
  const home = join(root, "home").split("\\").join("/");
  await mkdir(join(workspace, "src"), { recursive: true });
  await writeFile(join(workspace, "src", "app.ts"), "export const answer = 42;\n", "utf8");

  const accessLog = join(root, "access.jsonl").split("\\").join("/");
  await writeFile(accessLog, "", "utf8");

  const { rules } = compile(
    `allow:\n  name = allow-workspace-read\n  tool = filesystem.read\n  workspace = true\n`,
    { cwd: workspace, origin: "identity-matrix" },
  );
  const chain = await new AuditChain(join(root, "audit.jsonl")).open();
  const stateDir = join(root, "state");

  let enrollment = null;
  let identity = null;
  if (enroll) {
    enrollment = await enrollAgent({ stateDir, agentId: "agent-A", runtime: "claude-code" });
    identity = await createCallerVerifier({ stateDir });
  }

  const gateway = new Gateway({
    servers: {
      files: {
        command: process.execPath,
        args: [SERVER],
        env: { CIRVIX_TEST_SERVER_NAME: "files", CIRVIX_TEST_ACCESS_LOG: accessLog, CIRVIX_TEST_RESOURCE_ROOT: home },
      },
    },
    rules,
    audit: chain,
    cwd: workspace,
    log: () => {},
    identity,
    identityMode,
  });
  const client = new McpClient(gateway);

  const accesses = async () => {
    const text = await readFile(accessLog, "utf8");
    return text.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  };
  const signedParams = (params) => {
    const proof = signRequest({ privateKey: enrollment.identityPrivateKey, agentId: "agent-A", method: "tools/call", params });
    return { ...params, _meta: { cirvix: { credential: enrollment.credentialToken, ...proof } } };
  };

  try {
    return await fn({ client, workspace, accesses, signedParams, chain, enrollment });
  } finally {
    gateway.stop();
  }
}

test("matrix/gateway: unsigned call -> deny + identity context + server opened nothing", async () => {
  await withGateway(async ({ client, workspace, accesses, chain }) => {
    const res = await client.request("tools/call", {
      name: "files__read_file",
      arguments: { path: `${workspace}/src/app.ts` },
      _meta: { cirvix: { agent: "agent-A" } }, // the claim, no proof
    });
    // DECISION
    assert.equal(res.result.isError, true);
    assert.equal(res.result._meta["cirvix/verdict"], "deny");
    assert.equal(res.result._meta["cirvix/rule"], "identity-unverified");
    // TRUSTED CONTEXT (audit record)
    const records = await chain.read();
    const rec = records.filter((r) => r.rule === "identity-unverified").pop();
    assert.ok(rec, "the refusal was recorded");
    assert.equal(rec.identity.verified, false);
    assert.equal(rec.claimed_agent, "agent-A");
    assert.notEqual(rec.agent, "agent-A");
    // EXECUTION RESULT (ground truth)
    assert.equal((await accesses()).length, 0, "the server never opened anything");
  }, { enroll: true });
});

test("matrix/gateway: signed call -> executes exactly once as the verified agent", async () => {
  await withGateway(async ({ client, workspace, accesses, signedParams, chain }) => {
    const params = { name: "files__read_file", arguments: { path: `${workspace}/src/app.ts` } };
    const res = await client.request("tools/call", signedParams(params));
    assert.ok(!res.result.isError);
    assert.match(res.result.content[0].text, /export const answer = 42/);

    const records = await chain.read();
    const rec = records.filter((r) => r.decision === "allow").pop();
    assert.equal(rec.identity.verified, true);
    assert.equal(rec.identity.agentId, "agent-A");
    assert.equal(rec.agent, "agent-A");

    const log = await accesses();
    assert.equal(log.length, 1, "executed exactly once");
  }, { enroll: true });
});

test("matrix/gateway: replayed signed call -> second attempt refused, no further execution", async () => {
  await withGateway(async ({ client, workspace, accesses, signedParams }) => {
    const params = { name: "files__read_file", arguments: { path: `${workspace}/src/app.ts` } };
    const stolen = signedParams(params); // captured once by an attacker
    await client.request("tools/call", stolen);
    assert.equal((await accesses()).length, 1);

    const replay = await client.request("tools/call", stolen);
    assert.equal(replay.result.isError, true);
    assert.equal(replay.result._meta["cirvix/rule"], "identity-unverified");
    assert.equal((await accesses()).length, 1, "the replay executed NOTHING");
  }, { enroll: true });
});

test("matrix/gateway: tampered params -> refused before the server is touched", async () => {
  await withGateway(async ({ client, workspace, accesses, signedParams }) => {
    const signed = signedParams({ name: "files__read_file", arguments: { path: `${workspace}/src/app.ts` } });
    // Swap the path AFTER signing: the signature covers the original params.
    signed.arguments = { path: `${workspace}/src/../home/.aws/credentials` };
    const res = await client.request("tools/call", signed);
    assert.equal(res.result.isError, true);
    assert.equal(res.result._meta["cirvix/rule"], "identity-unverified");
    assert.equal((await accesses()).length, 0, "the tampered request never executed");
  }, { enroll: true });
});

/* ------------------------------------------------------------------ */
/*  Part 3 — the UDS boundary                                          */
/* ------------------------------------------------------------------ */

async function withUds(fn, { identityMode = "production", enroll = true } = {}) {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-mx-uds-"));
  const enrollment = enroll ? await enrollAgent({ stateDir, agentId: "agent-A", runtime: "test" }) : null;
  const identity = enroll ? await createCallerVerifier({ stateDir }) : null;
  const token = await writeToken(stateDir);
  const endpoint = defaultEndpoint(stateDir);
  const server = new UdsServer({
    pipeline: new Pipeline({ rules: READABLE_RULES, agent: "socket-test", cwd: "/workspace" }),
    endpoint,
    token,
    identity,
    identityMode,
    status: () => ({}),
    recent: async () => [],
  });
  await server.start();
  try {
    const client = new UdsClient({ endpoint, token });
    const sign = (params) => {
      const proof = signRequest({ privateKey: enrollment.identityPrivateKey, agentId: "agent-A", method: "cirvix/authorize", params });
      return { ...params, _meta: { cirvix: { credential: enrollment.credentialToken, ...proof } } };
    };
    return await fn({ client, sign, enrollment });
  } finally {
    await server.stop();
  }
}

test("matrix/uds: FRESH UN-ENROLLED endpoint in production mode -> refused, claimed name never reaches the pipeline", async () => {
  await withUds(async ({ client }) => {
    const result = await client.call("cirvix/authorize", {
      tool: "read_file",
      arguments: { path: "/workspace/a.ts" },
      agent: "agent-A", // self-declared
    });
    // DECISION
    assert.equal(result.decision, "deny");
    assert.equal(result.allowed, false);
    assert.equal(result.policy, "identity-unverified");
    // CONTEXT
    assert.equal(result.identity.verified, false);
    assert.equal(result.identity.mode, "production");
    // EXECUTION RESULT: nothing was authorized, so there is no args substitution
    // and no path by which this call could have run.
    assert.equal(result.enforced, true);
  }, { enroll: false, identityMode: "production" });
});

test("matrix/uds: production endpoint WITH enrollment -> unsigned refused, signed permitted as the verified agent", async () => {
  await withUds(async ({ client, sign }) => {
    const unsigned = await client.call("cirvix/authorize", {
      tool: "read_file",
      arguments: { path: "/workspace/a.ts" },
      agent: "agent-A",
    });
    assert.equal(unsigned.decision, "deny");
    assert.equal(unsigned.policy, "identity-unverified");
    assert.equal(unsigned.identity.verified, false);

    const signed = await client.call("cirvix/authorize", sign({
      tool: "read_file",
      arguments: { path: "/workspace/a.ts" },
      agent: "agent-A",
    }));
    assert.equal(signed.decision, "allow");
    assert.equal(signed.identity.verified, true);
    assert.equal(signed.identity.agentId, "agent-A");
  }, { enroll: true, identityMode: "production" });
});

/* ------------------------------------------------------------------ */
/*  Part 4 — SDK behaviour + production vs compatibility               */
/* ------------------------------------------------------------------ */

test("matrix/sdk: guard.wrap over a PRODUCTION boundary throws CirvixDenied for an unproven caller", async () => {
  const { stateDir, enrollment } = await freshHost();
  let executed = false;
  const tools = guardSdk.wrap(
    { read_file: async () => { executed = true; return "contents"; } },
    {
      rules: READABLE_RULES,
      agent: "operator-default",
      cwd: CWD,
      identityMode: "production",
      identity: await createCallerVerifier({ stateDir }),
    },
  );

  await assert.rejects(() => tools.read_file({ path: "/workspace/a.ts" }), (err) => {
    assert.ok(err instanceof CirvixDenied);
    assert.equal(err.policy, "identity-unverified");
    return true;
  });
  assert.equal(executed, false, "the wrapped tool never ran");
  assert.ok(enrollment, "the host was enrolled; the caller simply proved nothing");
});

test("matrix/sdk: guard.wrap over a COMPAT boundary keeps the historic SDK behaviour", async () => {
  let executed = false;
  const tools = guardSdk.wrap(
    { read_file: async () => { executed = true; return "contents"; } },
    { rules: READABLE_RULES, agent: "sdk-local", cwd: CWD, identity: null },
  );
  const out = await tools.read_file({ path: "/workspace/a.ts" });
  assert.equal(out, "contents");
  assert.equal(executed, true, "in-process library use is unchanged (no transport boundary)");
});

test("matrix/modes: production vs compatibility — the same unverified call, two postures", async () => {
  const call = { tool: "read_file", args: { path: "/workspace/a.ts" }, agent: "agent-A" };

  // PRODUCTION + verifier present + unproven caller: refused.
  const { stateDir } = await freshHost();
  const prod = new Guard({
    rules: READABLE_RULES,
    agent: "operator-default",
    cwd: CWD,
    identityMode: "production",
    identity: await createCallerVerifier({ stateDir }),
  });
  const prodResult = await prod.authorize(call);
  assert.equal(prodResult.decision.verdict, "deny");
  assert.equal(prodResult.record.identity_mode, "production");

  // COMPAT (SDK default, no verifier): historic behaviour, and the record says
  // which mode made the choice.
  const compat = new Guard({ rules: READABLE_RULES, agent: "sdk-local", cwd: CWD, identity: null });
  const compatResult = await compat.authorize({ tool: "read_file", args: { path: "/workspace/a.ts" } });
  assert.equal(compatResult.decision.verdict, "permit");
  assert.equal(compatResult.record.identity_mode, "compat");
  assert.equal(compatResult.record.identity.verified, false);
  assert.equal(compatResult.record.identity.mode, "compat");
});

test("matrix/modes: bootstrap gateway executes unverified calls but marks every record", async () => {
  await withGateway(async ({ client, workspace, accesses, chain }) => {
    const res = await client.request("tools/call", {
      name: "files__read_file",
      arguments: { path: `${workspace}/src/app.ts` },
      _meta: { cirvix: { agent: "agent-A" } },
    });
    // The window is open: it executes.
    assert.ok(!res.result.isError);
    assert.equal((await accesses()).length, 1);
    // But nothing about it is mistakable for authenticated.
    const records = await chain.read();
    const rec = records.filter((r) => r.decision === "allow").pop();
    assert.equal(rec.identity_mode, "bootstrap");
    assert.equal(rec.identity.verified, false);
    assert.equal(rec.identity.mode, "bootstrap");
    assert.equal(rec.claimed_agent, "agent-A");
    assert.notEqual(rec.agent, "agent-A");
  }, { enroll: false, identityMode: "bootstrap" });
});

test("matrix/sandbox: the sandboxed principal matches only a rule that names it", async () => {
  // A rule that names SANDBOXED_PRINCIPAL matches only it — pinning the value
  // so a policy can be written to trap any code path that evaluates under it.
  const guard = new Guard({
    rules: [{ name: "trap", effect: "permit", agents: [SANDBOXED_PRINCIPAL], actions: ["fs.read"], resources: ["**"] }],
    agent: SANDBOXED_PRINCIPAL,
    cwd: CWD,
  });
  const { decision, record } = await guard.authorize({ tool: "read_file", args: { path: "/workspace/a.ts" } });
  assert.equal(decision.verdict, "permit", "only a rule explicitly naming the sandbox matches it");
  assert.equal(record.agent, SANDBOXED_PRINCIPAL);
});
