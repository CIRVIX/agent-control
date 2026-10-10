/**
 * The boundary itself: a real MCP client, the real gateway, a real server.
 *
 * The identity unit tests prove the verifier works. This proves the GATEWAY
 * enforces it, and — the part that matters — that an unverified call does not
 * reach the server. As in the main e2e suite, the proof is the server access
 * log rather than the gateway response: a gateway that printed DENIED and
 * forwarded the call anyway would pass every assertion that only read the reply.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Gateway } from "../src/core/gateway.mjs";
import { AuditChain } from "../src/core/audit.mjs";
import { MessageFramer } from "../src/core/jsonrpc.mjs";
import { compile } from "../src/core/policy-dsl.mjs";
import { createCallerVerifier, enrollAgent, signRequest } from "../src/core/identity.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = join(HERE, "fixtures", "mock-mcp-server.mjs");

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
 * Same shape as the main e2e harness, with one addition: the host is enrolled
 * and the gateway is built with the identity verifier, so the boundary really
 * has something to verify against.
 */
async function withGateway(fn) {
  const root = await mkdtemp(join(tmpdir(), "cirvix-gwid-"));
  const workspace = join(root, "workspace").split(String.fromCharCode(92)).join("/");
  const home = join(root, "home").split(String.fromCharCode(92)).join("/");

  await mkdir(join(workspace, "src"), { recursive: true });
  await mkdir(join(home, ".aws"), { recursive: true });
  await writeFile(join(workspace, "src", "app.ts"), "export const answer = 42;\n", "utf8");
  await writeFile(
    join(home, ".aws", "credentials"),
    "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
    "utf8",
  );

  const accessLog = join(root, "access.jsonl").split(String.fromCharCode(92)).join("/");
  await writeFile(accessLog, "", "utf8");

  const source = `
deny:
  name = deny-aws
  tool = filesystem.read
  path = **/.aws/**
  reason = "Cloud credentials are never readable by an agent."

allow:
  name = allow-workspace-read
  tool = filesystem.read
  workspace = true
`;
  const { rules } = compile(source, { cwd: workspace, origin: "gateway-identity" });
  const chain = await new AuditChain(join(root, "audit.jsonl")).open();

  const stateDir = join(root, "state");
  const enrollment = await enrollAgent({ stateDir, agentId: "agent-A", runtime: "claude-code" });
  const identity = await createCallerVerifier({ stateDir });

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
    rules,
    audit: chain,
    cwd: workspace,
    log: () => {},
    identity,
  });

  const client = new McpClient(gateway);

  /** Every filesystem access the server actually attempted. */
  const accesses = async () => {
    const text = await readFile(accessLog, "utf8");
    return text.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  };

  /** Signs a tools/call params object with the enrolled runtime key. */
  const signedParams = (params) => {
    const proof = signRequest({
      privateKey: enrollment.identityPrivateKey,
      agentId: "agent-A",
      method: "tools/call",
      params,
    });
    // The credential travels with the proof: it names the agent and its key,
    // the signature proves possession. Neither half alone verifies.
    return { ...params, _meta: { cirvix: { credential: enrollment.credentialToken, ...proof } } };
  };

  try {
    return await fn({ client, workspace, accesses, signedParams, chain });
  } finally {
    gateway.stop();
  }
}

/* -------------------------------------------------------------------------- */
/*  The boundary                                                              */
/* -------------------------------------------------------------------------- */

test("e2e identity: an unsigned call is denied and does NOT reach the server", async () => {
  await withGateway(async ({ client, workspace, accesses }) => {
    const res = await client.request("tools/call", {
      name: "files__read_file",
      arguments: { path: `${workspace}/src/app.ts` },
    });

    // 1. The agent is refused, with a reason it can act on.
    assert.equal(res.result.isError, true);
    assert.equal(res.result._meta["cirvix/verdict"], "deny");
    assert.equal(res.result._meta["cirvix/rule"], "identity-unverified");

    // 2. The independent ground truth: the server never opened anything.
    assert.equal((await accesses()).length, 0, "a denied call must not execute");
  });
});

test("e2e identity: a signed call executes and records the verified identity", async () => {
  await withGateway(async ({ client, workspace, accesses, signedParams, chain }) => {
    const params = { name: "files__read_file", arguments: { path: `${workspace}/src/app.ts` } };
    const res = await client.request("tools/call", signedParams(params));

    assert.ok(!res.result.isError, "a verified call should be permitted");
    assert.match(res.result.content[0].text, /export const answer = 42/);

    const log = await accesses();
    assert.equal(log.length, 1, "the server really read the file exactly once");

    // The audit record shows the verified identity, not a self-asserted name.
    const records = await chain.read();
    const decision = records.filter((r) => r.decision === "allow").pop();
    assert.ok(decision, "a permit was recorded");
    assert.equal(decision.identity.verified, true);
    assert.equal(decision.identity.agentId, "agent-A");
  });
});

test("e2e identity: a stolen credential without the key is denied", async () => {
  await withGateway(async ({ client, workspace, accesses, signedParams }) => {
    // The credential is public — it travels on every request. Without the
    // private key an attacker can attach it but cannot produce a signature the
    // verifier accepts.
    const stolen = signedParams({
      name: "files__read_file",
      arguments: { path: `${workspace}/src/app.ts` },
    });
    delete stolen._meta.cirvix.sig;

    const res = await client.request("tools/call", stolen);
    assert.equal(res.result.isError, true);
    assert.equal(res.result._meta["cirvix/rule"], "identity-unverified");
    assert.equal((await accesses()).length, 0, "the credential alone must not execute anything");
  });
});
