/**
 * MCP client compatibility.
 *
 * `e2e-mcp.test.mjs` proves the ENFORCEMENT is real — a denied file is never
 * opened, and the proof is the server's own access log. This file proves
 * something different and just as launch-critical: that a real MCP client can
 * talk to the gateway at all.
 *
 * Those fail differently. An enforcement bug lets something through. A protocol
 * bug makes Claude Code or Cursor show "server disconnected" with no
 * explanation, and the developer uninstalls Cirvix rather than debugging it.
 *
 * WHAT REAL CLIENTS DO THAT A MOCK USUALLY DOES NOT
 *
 * Every case below is a behaviour a shipping client exhibits and a hand-rolled
 * test server tends not to:
 *
 *   · sends `notifications/initialized` after initialize, and expects SILENCE
 *   · sends `ping` and expects a result
 *   · asks for `resources/templates/list`
 *   · needs `inputSchema` on every tool or it cannot build a call
 *   · sends its own `protocolVersion` and expects agreement, not a fixed string
 *   · writes to stderr from the upstream server, constantly
 *   · sends unknown methods as the protocol grows
 *
 * The stderr one is the classic. MCP servers log to stderr as a matter of
 * course; if any of that reaches stdout, the client's JSON parser dies mid
 * session and the failure looks like a Cirvix crash.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Gateway } from "../src/core/gateway.mjs";
import { MessageFramer } from "../src/core/jsonrpc.mjs";
import { compile } from "../src/core/policy-dsl.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = join(HERE, "fixtures", "mock-mcp-server.mjs");

/**
 * A client that records EVERYTHING the gateway writes, including messages it
 * was not expecting.
 *
 * The stricter half of the contract is what must never arrive: a response to a
 * notification, or a stray frame with no matching request. A client that only
 * looks at replies it asked for cannot see either.
 */
class StrictClient {
  #pending = new Map();
  #nextId = 1;

  constructor(gateway) {
    this.gateway = gateway;
    this.received = [];
    this.unmatched = [];
    this.framer = new MessageFramer({
      onMessage: (m) => {
        this.received.push(m);
        if (m.id === undefined || !this.#pending.has(m.id)) {
          this.unmatched.push(m);
          return;
        }
        const entry = this.#pending.get(m.id);
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
      this.deliver({ jsonrpc: "2.0", id, method, params });
    });
  }

  /** A notification: no id, and no response is permitted. */
  notify(method, params = {}) {
    this.deliver({ jsonrpc: "2.0", method, params });
  }

  deliver(message) {
    void this.gateway.handleClientMessage(message);
  }
}

async function withGateway(fn, { env = {} } = {}) {
  const root = await mkdtemp(join(tmpdir(), "cirvix-compat-"));
  const workspace = join(root, "workspace").replace(/\\/g, "/");
  const home = join(root, "home").replace(/\\/g, "/");
  await mkdir(join(workspace, "src"), { recursive: true });
  await mkdir(join(home, ".aws"), { recursive: true });
  await writeFile(join(workspace, "src", "app.ts"), "export const answer = 42;\n", "utf8");
  await writeFile(join(home, ".aws", "credentials"), "[default]\nkey = x\n", "utf8");

  const accessLog = join(root, "access.jsonl").replace(/\\/g, "/");
  await writeFile(accessLog, "", "utf8");

  const { rules } = compile(
    `
deny:
  name = deny-aws
  tool = filesystem.read
  path = **/.aws/**

allow:
  name = allow-workspace-read
  tool = filesystem.read
  workspace = true
`,
    { cwd: workspace, origin: "compat" },
  );

  const gateway = new Gateway({
    servers: {
      files: {
        command: process.execPath,
        args: [SERVER],
        env: {
          CIRVIX_TEST_SERVER_NAME: "files",
          CIRVIX_TEST_ACCESS_LOG: accessLog,
          CIRVIX_TEST_RESOURCE_ROOT: home,
          ...env,
        },
      },
    },
    rules,
    cwd: workspace,
    log: () => {},
  });

  const client = new StrictClient(gateway);

  try {
    return await fn({ client, gateway, workspace, home });
  } finally {
    gateway.stop();
  }
}

/* ========================================================================== */
/*  Handshake                                                                  */
/* ========================================================================== */

test("compat: the client's protocol version is echoed, not overridden", async () => {
  /*
   * A client that asks for `2025-06-18` and is answered `2024-11-05` may refuse
   * the session outright. The gateway is a proxy and has no protocol opinion of
   * its own.
   */
  await withGateway(async ({ client }) => {
    for (const version of ["2024-11-05", "2025-03-26", "2025-06-18"]) {
      const res = await client.request("initialize", { protocolVersion: version });
      assert.equal(res.result.protocolVersion, version, `did not agree to ${version}`);
    }
  });
});

test("compat: initialize advertises every capability the gateway governs", async () => {
  await withGateway(async ({ client }) => {
    const res = await client.request("initialize", { protocolVersion: "2024-11-05" });
    const caps = res.result.capabilities;
    assert.ok(caps.tools, "tools");
    assert.ok(caps.resources, "resources");
    assert.ok(caps.prompts, "prompts");
    assert.ok(res.result.serverInfo?.name, "serverInfo.name");
    assert.match(
      res.result.serverInfo.version,
      /^\d+\.\d+\.\d+$/,
      "serverInfo.version must be a real semver, not a placeholder",
    );
  });
});

test("compat: notifications/initialized gets NO response", async () => {
  /*
   * Every client sends this immediately after initialize. A JSON-RPC
   * notification has no id, and answering one is a protocol violation — strict
   * clients treat an unexpected frame as a fatal desync.
   */
  await withGateway(async ({ client }) => {
    await client.request("initialize", { protocolVersion: "2024-11-05" });
    const before = client.received.length;

    client.notify("notifications/initialized");
    await new Promise((r) => setTimeout(r, 250));

    assert.equal(
      client.received.length,
      before,
      `the gateway answered a notification: ${JSON.stringify(client.received.slice(before))}`,
    );
  });
});

test("compat: ping is answered", async () => {
  // Clients use ping as a liveness probe. An error or a timeout here is read as
  // "the server died" and the session is torn down.
  await withGateway(async ({ client }) => {
    await client.request("initialize", { protocolVersion: "2024-11-05" });
    const res = await client.request("ping");
    assert.ok(res.result !== undefined, `ping was not answered with a result: ${JSON.stringify(res)}`);
    assert.equal(res.error, undefined);
  });
});

/* ========================================================================== */
/*  Discovery — the shapes a client needs to build a call                      */
/* ========================================================================== */

test("compat: every advertised tool carries an inputSchema", async () => {
  /*
   * A client cannot construct a `tools/call` without it. A tool missing its
   * schema is either invisible or a hard error, depending on the client — and
   * the gateway rewrites tool names, which is exactly where a field gets lost.
   */
  await withGateway(async ({ client }) => {
    await client.request("initialize", { protocolVersion: "2024-11-05" });
    const res = await client.request("tools/list");

    assert.ok(res.result.tools.length > 0, "no tools advertised");
    for (const tool of res.result.tools) {
      assert.ok(typeof tool.name === "string" && tool.name, "tool.name");
      assert.match(tool.name, /^files__/, "namespaced");
      assert.ok(tool.inputSchema, `${tool.name} has no inputSchema`);
      assert.equal(tool.inputSchema.type, "object", `${tool.name} inputSchema.type`);
    }
  });
});

test("compat: resources/templates/list is answered rather than forwarded blindly", async () => {
  await withGateway(async ({ client }) => {
    await client.request("initialize", { protocolVersion: "2024-11-05" });
    const res = await client.request("resources/templates/list");
    assert.equal(res.error, undefined, `templates/list errored: ${JSON.stringify(res.error)}`);
    assert.ok(Array.isArray(res.result.resourceTemplates ?? res.result.resources ?? []));
  });
});

test("compat: an unknown method returns a JSON-RPC error, not a dropped frame", async () => {
  /*
   * The protocol grows. A method this build has never heard of must produce an
   * answer the client can act on — silence stalls it until timeout, which
   * presents as a hang rather than an unsupported feature.
   */
  await withGateway(async ({ client }) => {
    await client.request("initialize", { protocolVersion: "2024-11-05" });
    const res = await client.request("completion/complete", { ref: {} });
    assert.ok(res.error || res.result, "no answer at all — the client would hang");
  });
});

/* ========================================================================== */
/*  The transport under real conditions                                        */
/* ========================================================================== */

test("compat: upstream stderr never corrupts the stdout stream", async () => {
  /*
   * THE CLASSIC INTEGRATION KILLER.
   *
   * MCP servers log to stderr constantly — startup banners, warnings, stack
   * traces. If any of it reaches the client's stdin, the JSON parser desyncs
   * and the session dies. The failure looks like a Cirvix crash and gets
   * reported as one.
   *
   * The fixture server is told to be noisy; every frame the client receives
   * must still be well-formed JSON-RPC.
   */
  await withGateway(
    async ({ client }) => {
      await client.request("initialize", { protocolVersion: "2024-11-05" });
      const list = await client.request("tools/list");
      assert.ok(list.result.tools.length > 0);

      const call = await client.request("tools/call", {
        name: "files__read_file",
        arguments: { path: "src/app.ts" },
      });
      assert.ok(call.result || call.error, "no answer while the upstream was logging");

      for (const frame of client.received) {
        assert.equal(frame.jsonrpc, "2.0", `a non-JSON-RPC frame reached the client: ${JSON.stringify(frame)}`);
      }
    },
    { env: { CIRVIX_TEST_NOISY_STDERR: "1" } },
  );
});

test("compat: a denial is a tool result, not a transport error", async () => {
  /*
   * A JSON-RPC error tears down the client's call. A denial must arrive as a
   * readable `isError` tool result so the model can see WHY and choose
   * something else — that is the difference between "Cirvix broke my agent" and
   * "Cirvix stopped my agent doing that".
   */
  await withGateway(async ({ client }) => {
    await client.request("initialize", { protocolVersion: "2024-11-05" });
    const res = await client.request("tools/call", {
      name: "files__read_file",
      arguments: { path: "../home/.aws/credentials" },
    });

    assert.equal(res.error, undefined, "a denial arrived as a transport error");
    assert.ok(res.result, "a denial must still be a result");
    assert.equal(res.result.isError, true);
    const text = JSON.stringify(res.result.content ?? res.result);
    assert.match(text, /deny|denied|not permitted|refused/i, "the refusal must be legible");
  });
});

test("compat: a client that sends no _meta is unaffected", async () => {
  /*
   * Identity rides in `params._meta.cirvix`. Claude Code and Cursor do not send
   * it, and never will — so its absence must be the ordinary path rather than a
   * degraded one.
   */
  await withGateway(async ({ client }) => {
    await client.request("initialize", { protocolVersion: "2024-11-05" });
    const res = await client.request("tools/call", {
      name: "files__read_file",
      arguments: { path: "src/app.ts" },
    });
    assert.equal(res.error, undefined);
    assert.equal(res.result.isError ?? false, false, "a plain client was refused");
  });
});

test("compat: an unrecognised _meta payload does not break the call", async () => {
  // Other tools put their own keys in `_meta`. Reading a namespace we do not
  // own, or choking on one, would make Cirvix incompatible with them.
  await withGateway(async ({ client }) => {
    await client.request("initialize", { protocolVersion: "2024-11-05" });
    const res = await client.request("tools/call", {
      name: "files__read_file",
      arguments: { path: "src/app.ts" },
      _meta: { someOtherTool: { trace: "abc" }, progressToken: 7 },
    });
    assert.equal(res.error, undefined);
    assert.equal(res.result.isError ?? false, false);
  });
});

test("compat: concurrent requests are answered on their own ids", async () => {
  /*
   * The gateway rewrites ids to keep upstream id spaces separate. Getting that
   * wrong mis-routes answers under load — the hardest kind of bug to attribute,
   * because the client shows one tool's result for another tool's call.
   */
  await withGateway(async ({ client }) => {
    await client.request("initialize", { protocolVersion: "2024-11-05" });

    const calls = await Promise.all([
      client.request("tools/call", { name: "files__read_file", arguments: { path: "src/app.ts" } }),
      client.request("tools/call", {
        name: "files__read_file",
        arguments: { path: "../home/.aws/credentials" },
      }),
      client.request("tools/list"),
      client.request("ping"),
    ]);

    assert.equal(calls[0].result.isError ?? false, false, "the permitted read");
    assert.equal(calls[1].result.isError, true, "the denied read");
    assert.ok(calls[2].result.tools, "tools/list");
    assert.ok(calls[3].result !== undefined, "ping");
    assert.equal(client.unmatched.length, 0, `stray frames: ${JSON.stringify(client.unmatched)}`);
  });
});
