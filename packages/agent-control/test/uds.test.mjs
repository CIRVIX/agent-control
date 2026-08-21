import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:net";

import {
  UdsClient,
  UdsServer,
  defaultEndpoint,
  readToken,
  tokenPath,
  writeToken,
} from "../src/core/uds.mjs";
import { Pipeline } from "../src/core/pipeline.mjs";
import { Vault } from "../src/core/vault.mjs";
import { compile } from "../src/core/policy-dsl.mjs";
import { serialize } from "../src/core/jsonrpc.mjs";
import { DECISION } from "../src/core/decisions.mjs";

const CWD = process.platform === "win32" ? "C:/workspace" : "/workspace";

const POLICY = `
allow:
  tool = git.status
allow:
  tool = filesystem.read
  workspace = true
deny:
  tool = filesystem.read
  path = **/.aws/**
deny:
  tool = shell.exec
  command = "rm -rf"
require_approval:
  tool = database.write
  approvers = oncall
`;

/** Spins up a server on a fresh state directory and tears it down after. */
async function withServer(fn, { pipelineOptions = {} } = {}) {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-uds-"));
  const token = await writeToken(stateDir);
  const endpoint = defaultEndpoint(stateDir);
  const { rules } = compile(POLICY, { cwd: CWD, origin: "test" });

  const pipeline = new Pipeline({ rules, cwd: CWD, agent: "test", ...pipelineOptions });
  const server = new UdsServer({
    pipeline,
    endpoint,
    token,
    status: () => ({ mode: pipeline.mode, rules: pipeline.rules.length, calls: pipeline.stats.calls }),
    recent: async () => [{ request_id: "req_x", decision: "allow" }],
  });

  await server.start();
  try {
    return await fn({ server, pipeline, endpoint, token, stateDir });
  } finally {
    await server.stop();
  }
}

/* -------------------------------------------------------------------------- */
/*  Authorization decisions over the socket                                    */
/* -------------------------------------------------------------------------- */

test("a permitted call comes back allowed", async () => {
  await withServer(async ({ endpoint, token }) => {
    const client = new UdsClient({ endpoint, token });
    const result = await client.call("cirvix/authorize", {
      tool: "git_status",
      arguments: {},
      agent: "test-agent",
    });
    assert.equal(result.decision, DECISION.ALLOW);
    assert.equal(result.allowed, true);
    assert.equal(result.risk, "low");
    assert.ok(typeof result.latency_ms === "number");
  });
});

test("a denied call comes back with the rule and a reason", async () => {
  await withServer(async ({ endpoint, token }) => {
    const client = new UdsClient({ endpoint, token });
    const result = await client.call("cirvix/authorize", {
      tool: "read_file",
      arguments: { path: "~/.aws/credentials" },
    });
    assert.equal(result.decision, DECISION.DENY);
    assert.equal(result.allowed, false);
    assert.ok(result.policy);
    assert.ok(result.reason.length > 10);
  });
});

test("a held call names an approval", async () => {
  await withServer(async ({ endpoint, token }) => {
    const client = new UdsClient({ endpoint, token });
    const result = await client.call("cirvix/authorize", { tool: "database.write", arguments: {} });
    assert.equal(result.decision, DECISION.REQUIRE_APPROVAL);
    assert.equal(result.allowed, false);
    assert.ok(result.approval_id);
  });
});

test("substituted arguments come back, so the client sends what was authorized", async () => {
  const vault = new Vault();
  const handle = vault.issue("KEY", "rk_live_REALMATERIAL0123456789");

  await withServer(
    async ({ endpoint, token }) => {
      const client = new UdsClient({ endpoint, token });
      const result = await client.call("cirvix/authorize", {
        tool: "read_file",
        arguments: { path: `${CWD}/src/a.ts`, note: handle },
      });
      assert.equal(result.allowed, true);
      // No destination, so a handle cannot be brokered — the call is refused
      // rather than the handle being forwarded as a literal string.
      assert.ok(result.decision === DECISION.DENY || result.arguments.note !== handle);
    },
    { pipelineOptions: { secrets: vault } },
  );
});

/* -------------------------------------------------------------------------- */
/*  The socket is a security boundary                                          */
/* -------------------------------------------------------------------------- */

test("a connection with no token is refused", async () => {
  await withServer(async ({ endpoint }) => {
    const result = await raw(endpoint, [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
    ]);
    assert.ok(result[0].error, "initialize without a token must fail");
    assert.match(result[0].error.message, /session token/);
  });
});

test("a connection with the wrong token is refused", async () => {
  await withServer(async ({ endpoint }) => {
    const result = await raw(endpoint, [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: { token: "b".repeat(64) } },
    ]);
    assert.ok(result[0].error);
  });
});

test("authorize before initialize is refused", async () => {
  await withServer(async ({ endpoint }) => {
    const result = await raw(endpoint, [
      { jsonrpc: "2.0", id: 1, method: "cirvix/authorize", params: { tool: "git_status" } },
    ]);
    assert.ok(result[0].error);
    assert.match(result[0].error.message, /initialize/);
  });
});

test("there is no method that returns a secret", async () => {
  // The socket must not be usable to exfiltrate the vault. This asserts the
  // absence of a capability, which is the kind of property that quietly
  // regresses when someone adds a convenience method.
  await withServer(async ({ endpoint, token }) => {
    const client = new UdsClient({ endpoint, token });
    const hello = await client.call("initialize", { token });
    for (const method of hello.methods) {
      assert.ok(
        !/vault|secret|resolve|issue|reveal/i.test(method),
        `"${method}" looks like it could return credential material`,
      );
    }
  });
});

test("an unknown method is rejected rather than ignored", async () => {
  await withServer(async ({ endpoint, token }) => {
    const client = new UdsClient({ endpoint, token });
    await assert.rejects(() => client.call("cirvix/doAnything", {}), /Unknown method/);
  });
});

test("the token file is written 0600", async (t) => {
  if (process.platform === "win32") {
    t.skip("POSIX permission bits are not meaningful on Windows");
    return;
  }
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-uds-"));
  await writeToken(stateDir);
  const info = await stat(tokenPath(stateDir));
  assert.equal(info.mode & 0o777, 0o600);
});

test("the socket file is created 0600", async (t) => {
  if (process.platform === "win32") {
    t.skip("named pipes have no filesystem mode");
    return;
  }
  await withServer(async ({ endpoint }) => {
    const info = await stat(endpoint);
    assert.equal(info.mode & 0o777, 0o600);
  });
});

test("the token round-trips through the state directory", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-uds-"));
  const written = await writeToken(stateDir);
  assert.equal(await readToken(stateDir), written);
  assert.equal(written.length, 64, "32 bytes of entropy, hex encoded");
});

/* -------------------------------------------------------------------------- */
/*  Other methods                                                              */
/* -------------------------------------------------------------------------- */

test("status reports what the runtime actually has loaded", async () => {
  await withServer(async ({ endpoint, token, pipeline }) => {
    const client = new UdsClient({ endpoint, token });
    const status = await client.call("cirvix/status", {});
    assert.equal(status.rules, pipeline.rules.length);
    assert.equal(status.mode, "enforce");
  });
});

test("logs are served from the journal", async () => {
  await withServer(async ({ endpoint, token }) => {
    const client = new UdsClient({ endpoint, token });
    const result = await client.call("cirvix/logs", { limit: 10 });
    assert.ok(Array.isArray(result.events));
  });
});

test("result scrubbing is available over the socket", async () => {
  await withServer(async ({ endpoint, token }) => {
    const client = new UdsClient({ endpoint, token });
    const result = await client.call("cirvix/result", {
      request_id: "req_x",
      result: { text: "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" },
    });
    assert.ok(!JSON.stringify(result.result).includes("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"));
  });
});

/* -------------------------------------------------------------------------- */
/*  Robustness                                                                 */
/* -------------------------------------------------------------------------- */

test("a malformed frame does not kill the connection", async () => {
  await withServer(async ({ endpoint, token }) => {
    const responses = await raw(
      endpoint,
      [{ jsonrpc: "2.0", id: 1, method: "initialize", params: { token } }],
      { prefix: "this is not json\n" },
    );
    assert.ok(responses[0]?.result, "the server survived the garbage and answered");
  });
});

test("authorize with no tool is an invalid-params error", async () => {
  await withServer(async ({ endpoint, token }) => {
    const client = new UdsClient({ endpoint, token });
    await assert.rejects(() => client.call("cirvix/authorize", {}), /needs a tool name/);
  });
});

test("the endpoint is derived from the state directory", () => {
  const a = defaultEndpoint(join(tmpdir(), "project-a"));
  const b = defaultEndpoint(join(tmpdir(), "project-b"));
  assert.notEqual(a, b, "two projects on one machine must not collide");
});

/* -------------------------------------------------------------------------- */

/** Sends raw frames and collects every reply. Used for protocol-level cases. */
function raw(endpoint, messages, { prefix = "", timeoutMs = 4000 } = {}) {
  return new Promise((resolve, reject) => {
    const socket = connect(endpoint);
    const replies = [];
    let buffer = "";

    const timer = setTimeout(() => {
      socket.destroy();
      resolve(replies);
    }, timeoutMs);

    socket.on("connect", () => {
      if (prefix) socket.write(prefix);
      for (const m of messages) socket.write(serialize(m));
    });

    socket.on("data", (chunk) => {
      buffer += chunk.toString();
      let i;
      while ((i = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, i).trim();
        buffer = buffer.slice(i + 1);
        if (!line) continue;
        try {
          replies.push(JSON.parse(line));
        } catch {
          /* ignore */
        }
        if (replies.length >= messages.length) {
          clearTimeout(timer);
          socket.destroy();
          resolve(replies);
          return;
        }
      }
    });

    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}
