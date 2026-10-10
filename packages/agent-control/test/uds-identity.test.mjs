/**
 * The socket boundary: identity over `cirvix/authorize`.
 *
 * The socket token authenticates a PROCESS. It does not say which agent is
 * acting, and before this boundary existed any authenticated process could
 * claim any agent name. These tests pin the new contract: once the host has
 * enrolled agents, an authorize call carries a credential plus a signed proof,
 * the verified agent replaces the claimed name, and an unverifiable call is
 * denied before the authorization core ever sees it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Pipeline } from "../src/core/pipeline.mjs";
import { UdsServer, UdsClient, defaultEndpoint, writeToken } from "../src/core/uds.mjs";
import { createCallerVerifier, enrollAgent, signRequest } from "../src/core/identity.mjs";

const RULES = [{ name: "allow-reads", effect: "permit", actions: ["fs.read"], resources: ["*"] }];

async function withServer(fn) {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-uds-id-"));
  const enrollment = await enrollAgent({ stateDir, agentId: "agent-A", runtime: "test" });
  const identity = await createCallerVerifier({ stateDir });
  const token = await writeToken(stateDir);
  const endpoint = defaultEndpoint(stateDir);

  const server = new UdsServer({
    pipeline: new Pipeline({ rules: RULES, agent: "socket-test", cwd: "/workspace" }),
    endpoint,
    token,
    identity,
    status: () => ({}),
    recent: async () => [],
  });
  await server.start();

  try {
    const client = new UdsClient({ endpoint, token });
    const sign = (params) => {
      const proof = signRequest({
        privateKey: enrollment.identityPrivateKey,
        agentId: "agent-A",
        method: "cirvix/authorize",
        params,
      });
      return { ...params, _meta: { cirvix: { credential: enrollment.credentialToken, ...proof } } };
    };
    return await fn({ client, sign, stateDir });
  } finally {
    await server.stop();
  }
}

test("socket identity: an unsigned authorize is denied before policy runs", async () => {
  await withServer(async ({ client }) => {
    const result = await client.call("cirvix/authorize", {
      agent: "agent-A",
      tool: "read_file",
      arguments: { path: "/workspace/a.ts" },
    });
    assert.equal(result.allowed, false);
    assert.equal(result.decision, "deny");
    assert.equal(result.policy, "identity-unverified");
  });
});

test("socket identity: a signed authorize is permitted as the enrolled agent", async () => {
  await withServer(async ({ client, sign }) => {
    const result = await client.call(
      "cirvix/authorize",
      sign({ agent: "agent-A", tool: "read_file", arguments: { path: "/workspace/a.ts" } }),
    );
    assert.equal(result.allowed, true);
    assert.equal(result.identity.verified, true);
    assert.equal(result.identity.agentId, "agent-A");
  });
});

test("socket identity: a claimed name cannot override the verified agent", async () => {
  await withServer(async ({ client, sign }) => {
    // The payload claims "admin" — a name policy might trust. The proof is for
    // agent-A, and the verified identity wins: the decision is made for the
    // agent that proved itself, not the name that was typed.
    const result = await client.call(
      "cirvix/authorize",
      sign({ agent: "admin", tool: "read_file", arguments: { path: "/workspace/a.ts" } }),
    );
    assert.equal(result.allowed, true);
    assert.equal(result.identity.agentId, "agent-A", "the verified agent must replace the claimed name");
  });
});

test("socket identity: a replayed proof is refused", async () => {
  await withServer(async ({ client, sign }) => {
    const params = sign({ agent: "agent-A", tool: "read_file", arguments: { path: "/workspace/a.ts" } });
    const first = await client.call("cirvix/authorize", params);
    assert.equal(first.allowed, true);

    const replay = await client.call("cirvix/authorize", params);
    assert.equal(replay.allowed, false);
    assert.equal(replay.policy, "identity-unverified");
    assert.match(String(replay.reason), /replay/);
  });
});
