/**
 * End to end: a real MCP client, the real gateway, a real MCP server.
 *
 * Everything else in this suite tests a layer. This tests the product:
 *
 *   MCP client  ──stdio──▶  cirvix gateway  ──stdio──▶  MCP server (subprocess)
 *                                  │                          │
 *                                  ├─ normalize               └─ really opens files
 *                                  ├─ risk
 *                                  ├─ policy
 *                                  ├─ decision
 *                                  └─ audit chain (on disk)
 *
 * THE PROOF IS THE ACCESS LOG, NOT THE GATEWAY'S OWN OUTPUT.
 *
 * Anyone can write a gateway that prints DENIED. The question a buyer actually
 * has is whether the file was opened. So the server writes a receipt to disk
 * before every read it attempts, and the credential tests assert that receipt
 * is EMPTY — while the same server, in the same run, demonstrably reads every
 * file it is allowed to read.
 *
 * A test that only checked the gateway's response would pass against a gateway
 * that logged a denial and forwarded the call anyway.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { Gateway } from "../src/core/gateway.mjs";
import { AuditChain } from "../src/core/audit.mjs";
import { MessageFramer } from "../src/core/jsonrpc.mjs";
import { compile } from "../src/core/policy-dsl.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = join(HERE, "fixtures", "mock-mcp-server.mjs");

/* -------------------------------------------------------------------------- */
/*  Harness                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * A real MCP client.
 *
 * Speaks the protocol over the same framer the gateway uses, so the test
 * exercises the actual wire format — including the id rewriting, which is where
 * a proxy silently mis-routes responses under concurrency.
 */
class McpClient {
  #pending = new Map();
  #nextId = 1;

  constructor(gateway) {
    this.gateway = gateway;
    // The gateway writes to us; we feed it back through a framer so the bytes
    // really are serialized and parsed rather than passed as objects.
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
 * Builds a real workspace on disk, spawns the gateway over a real server
 * subprocess, and runs `fn`. Everything is torn down afterwards.
 */
async function withGateway(fn, { policy } = {}) {
  const root = await mkdtemp(join(tmpdir(), "cirvix-e2e-"));
  const workspace = join(root, "workspace").replace(/\\/g, "/");
  const home = join(root, "home").replace(/\\/g, "/");

  await mkdir(join(workspace, "src"), { recursive: true });
  await mkdir(join(home, ".aws"), { recursive: true });

  await writeFile(join(workspace, "src", "app.ts"), "export const answer = 42;\n", "utf8");
  await writeFile(
    join(home, ".aws", "credentials"),
    "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n",
    "utf8",
  );

  const accessLog = join(root, "access.jsonl").replace(/\\/g, "/");
  await writeFile(accessLog, "", "utf8");

  const source =
    policy ??
    `
deny:
  name = deny-aws
  tool = filesystem.read
  path = **/.aws/**
  reason = "Cloud credentials are never readable by an agent."

deny:
  name = deny-destructive
  tool = shell.exec
  command = "rm -rf"

require_approval:
  name = approve-shell
  tool = shell.exec
  risk >= HIGH
  approvers = oncall

allow:
  name = allow-workspace-read
  tool = filesystem.read
  workspace = true

allow:
  name = allow-search
  tool = filesystem.search

allow:
  name = allow-safe-shell
  tool = shell.exec
  risk <= MEDIUM
`;

  const { rules } = compile(source, { cwd: workspace, origin: "e2e" });
  const chain = await new AuditChain(join(root, "audit.jsonl")).open();

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
  });
  gateway.agentName = "claude-code";

  const client = new McpClient(gateway);

  /** Every filesystem access the server actually attempted. */
  const accesses = async () => {
    const text = await readFile(accessLog, "utf8");
    return text.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  };

  try {
    return await fn({ client, gateway, workspace, home, accesses, chain, root });
  } finally {
    gateway.stop();
  }
}

const credentialUri = (home) => pathToFileURL(`${home}/.aws/credentials`).href;

/* -------------------------------------------------------------------------- */
/*  The protocol really works                                                  */
/* -------------------------------------------------------------------------- */

test("e2e: initialize negotiates and advertises what the gateway governs", async () => {
  await withGateway(async ({ client }) => {
    const res = await client.request("initialize", { protocolVersion: "2024-11-05" });
    assert.equal(res.result.serverInfo.name, "cirvix-gateway");
    assert.ok(res.result.capabilities.tools);
    assert.ok(res.result.capabilities.resources, "resources are governed, so they are advertised");
    assert.ok(res.result.capabilities.prompts);
  });
});

test("e2e: tools/list aggregates the real server's tools, namespaced", async () => {
  await withGateway(async ({ client }) => {
    const res = await client.request("tools/list");
    const names = res.result.tools.map((t) => t.name);
    assert.deepEqual(names.sort(), [
      "files__fetch_url",
      "files__read_file",
      "files__run_command",
      "files__search_docs",
    ]);
    // Schemas survive: an agent needs them to call the tool at all.
    const read = res.result.tools.find((t) => t.name === "files__read_file");
    assert.equal(read.inputSchema.properties.path.type, "string");
  });
});

test("e2e: resources/list aggregates and namespaces", async () => {
  await withGateway(async ({ client }) => {
    const res = await client.request("resources/list");
    assert.equal(res.result.resources.length, 2);
    for (const r of res.result.resources) {
      assert.ok(r.uri.startsWith("files__"), `not namespaced: ${r.uri}`);
      assert.equal(r._meta["cirvix/server"], "files");
    }
  });
});

test("e2e: prompts/list aggregates and namespaces", async () => {
  await withGateway(async ({ client }) => {
    const res = await client.request("prompts/list");
    assert.equal(res.result.prompts[0].name, "files__summarize");
  });
});

/* -------------------------------------------------------------------------- */
/*  A permitted call really executes                                           */
/* -------------------------------------------------------------------------- */

test("e2e: a permitted read reaches the server and returns the real file contents", async () => {
  await withGateway(async ({ client, workspace, accesses }) => {
    const res = await client.request("tools/call", {
      name: "files__read_file",
      arguments: { path: `${workspace}/src/app.ts` },
    });

    assert.ok(!res.result.isError, "should not be an error");
    assert.match(res.result.content[0].text, /export const answer = 42/);

    // The server really opened it. This is the control for every denial test
    // below: it proves the access log records reads that do happen.
    const log = await accesses();
    assert.equal(log.length, 1);
    assert.match(log[0].target, /app\.ts$/);
  });
});

/* -------------------------------------------------------------------------- */
/*  THE CENTRAL CLAIM                                                          */
/* -------------------------------------------------------------------------- */

test("e2e: a credential read is denied and the file is never opened", async () => {
  await withGateway(async ({ client, home, accesses, chain }) => {
    const res = await client.request("tools/call", {
      name: "files__read_file",
      arguments: { path: `${home}/.aws/credentials` },
    });

    // 1. The agent gets a readable refusal, as a tool result rather than a
    //    transport error, so it can re-plan instead of crashing.
    assert.equal(res.result.isError, true);
    assert.equal(res.result._meta["cirvix/verdict"], "deny");
    assert.equal(res.result._meta["cirvix/rule"], "deny-aws");
    assert.match(res.result.content[0].text, /Cloud credentials are never readable/);

    // 2. THE PROOF: the server never opened the file.
    const log = await accesses();
    assert.equal(log.length, 0, `the server attempted: ${JSON.stringify(log)}`);

    // 3. The secret is not in the response anywhere.
    const serialized = JSON.stringify(res);
    assert.ok(!serialized.includes("AKIAIOSFODNN7EXAMPLE"));
    assert.ok(!serialized.includes("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"));

    // 4. The decision is in the audit chain, and the chain verifies.
    const records = await chain.read();
    const denial = records.find((r) => r.verdict === "deny");
    assert.ok(denial, "the denial was recorded");
    assert.equal(denial.rule, "deny-aws");
    assert.equal(denial.agent, "claude-code");
    assert.equal((await chain.verify()).ok, true);

    // 5. The audit record does not contain the credential either.
    assert.ok(!JSON.stringify(records).includes("AKIAIOSFODNN7EXAMPLE"));
  });
});

test("e2e: the same credential requested as a RESOURCE is also denied", async () => {
  // The bypass this closes: a gateway that governs `tools/call` and forwards
  // `resources/read` untouched hands over the identical file with no rule
  // consulted and no record written.
  await withGateway(async ({ client, home, accesses, chain }) => {
    const res = await client.request("resources/read", {
      uri: `files__${credentialUri(home)}`,
    });

    assert.equal(res.result.isError, true, "resources/read must be governed like tools/call");
    assert.equal(res.result._meta["cirvix/rule"], "deny-aws");

    const log = await accesses();
    assert.equal(log.length, 0, `the server attempted: ${JSON.stringify(log)}`);

    const records = await chain.read();
    assert.ok(
      records.some((r) => r.verdict === "deny" && r.tool === "resources.read"),
      "the resource denial is recorded as its own decision",
    );
  });
});

test("e2e: subscribing to a forbidden resource is denied too", async () => {
  // A subscription is a standing read. Governing the one-shot read and not the
  // subscription is a hole with a delay on it.
  await withGateway(async ({ client, home, accesses }) => {
    const res = await client.request("resources/subscribe", {
      uri: `files__${credentialUri(home)}`,
    });
    assert.equal(res.result.isError, true);
    assert.equal((await accesses()).length, 0);
  });
});

test("e2e: a permitted resource read does reach the server", async () => {
  await withGateway(async ({ client, workspace, accesses }) => {
    const uri = pathToFileURL(`${workspace}/src/app.ts`).href;
    const res = await client.request("resources/read", { uri: `files__${uri}` });

    assert.ok(!res.result?.isError, JSON.stringify(res).slice(0, 200));
    assert.match(res.result.contents[0].text, /answer = 42/);
    assert.equal((await accesses()).length, 1);
  });
});

/* -------------------------------------------------------------------------- */
/*  Other decisions, over the wire                                             */
/* -------------------------------------------------------------------------- */

test("e2e: a destructive command is denied and never executes", async () => {
  await withGateway(async ({ client }) => {
    const res = await client.request("tools/call", {
      name: "files__run_command",
      arguments: { command: "rm -rf /" },
    });
    assert.equal(res.result.isError, true);
    assert.equal(res.result._meta["cirvix/rule"], "deny-destructive");
    assert.ok(!res.result.content[0].text.includes("EXECUTED"));
  });
});

test("e2e: a safe command executes", async () => {
  await withGateway(async ({ client }) => {
    const res = await client.request("tools/call", {
      name: "files__run_command",
      arguments: { command: "npm test" },
    });
    assert.ok(!res.result.isError);
    assert.match(res.result.content[0].text, /EXECUTED run_command/);
  });
});

test("e2e: an unrecognised command is held for a named human", async () => {
  await withGateway(async ({ client }) => {
    const res = await client.request("tools/call", {
      name: "files__run_command",
      arguments: { command: "./scripts/whatever.sh --force" },
    });
    assert.equal(res.result._meta["cirvix/verdict"], "hold");
    assert.ok(res.result._meta["cirvix/approval_id"]);
    assert.match(res.result.content[0].text, /oncall/);
    assert.ok(!res.result.content[0].text.includes("EXECUTED"));
  });
});

test("e2e: a call to an unregistered server is refused, not forwarded", async () => {
  await withGateway(async ({ client }) => {
    const res = await client.request("tools/call", {
      name: "ghost__read_file",
      arguments: { path: "/etc/passwd" },
    });
    assert.ok(res.error, "an unknown server is a transport-level error");
    assert.match(res.error.message, /No registered server/);
  });
});

/* -------------------------------------------------------------------------- */
/*  Traversal and spelling                                                     */
/* -------------------------------------------------------------------------- */

test("e2e: traversal to the credential file is denied", async () => {
  await withGateway(async ({ client, workspace, accesses }) => {
    // The agent never names `.aws` in a way a string match would catch.
    const res = await client.request("tools/call", {
      name: "files__read_file",
      arguments: { path: `${workspace}/src/../../home/.aws/credentials` },
    });
    assert.equal(res.result.isError, true);
    assert.equal((await accesses()).length, 0);
  });
});

/* -------------------------------------------------------------------------- */
/*  Concurrency — where a proxy silently mis-routes                            */
/* -------------------------------------------------------------------------- */

test("e2e: concurrent calls get their own answers, and the denials stay denied", async () => {
  await withGateway(async ({ client, workspace, home, accesses }) => {
    const calls = [];
    for (let i = 0; i < 12; i++) {
      calls.push(
        client.request("tools/call", {
          name: "files__read_file",
          arguments: { path: `${workspace}/src/app.ts` },
        }),
      );
      calls.push(
        client.request("tools/call", {
          name: "files__read_file",
          arguments: { path: `${home}/.aws/credentials` },
        }),
      );
    }

    const results = await Promise.all(calls);
    const permitted = results.filter((r) => !r.result.isError);
    const denied = results.filter((r) => r.result.isError);

    assert.equal(permitted.length, 12);
    assert.equal(denied.length, 12);
    for (const r of permitted) assert.match(r.result.content[0].text, /answer = 42/);
    for (const r of denied) assert.equal(r.result._meta["cirvix/rule"], "deny-aws");

    // Exactly the twelve permitted reads reached the disk. Not thirteen.
    const log = await accesses();
    assert.equal(log.length, 12);
    assert.ok(!log.some((a) => a.target.includes(".aws")));
  });
});

/* -------------------------------------------------------------------------- */
/*  Audit integrity across the whole session                                   */
/* -------------------------------------------------------------------------- */

test("e2e: every decision in a session is chained, and tampering is detectable", async () => {
  await withGateway(async ({ client, workspace, home, chain, root }) => {
    await client.request("tools/call", { name: "files__read_file", arguments: { path: `${workspace}/src/app.ts` } });
    await client.request("tools/call", { name: "files__read_file", arguments: { path: `${home}/.aws/credentials` } });
    await client.request("tools/call", { name: "files__run_command", arguments: { command: "npm test" } });

    const before = await chain.verify();
    assert.equal(before.ok, true);
    assert.equal(before.records, 3);

    // Rewrite a denial into a permit, exactly as someone covering their tracks
    // would. The chain must notice.
    const path = join(root, "audit.jsonl");
    const lines = (await readFile(path, "utf8")).split("\n").filter(Boolean);
    const tampered = lines.map((line) => {
      const record = JSON.parse(line);
      if (record.verdict === "deny") record.verdict = "permit";
      return JSON.stringify(record);
    });
    await writeFile(path, tampered.join("\n") + "\n", "utf8");

    const after = await new AuditChain(path).verify();
    assert.equal(after.ok, false, "an altered record must break verification");
    assert.ok(after.brokenAt, "and it must say where");
  });
});

test("e2e: the fixture server really is on disk and executable", () => {
  // Guards against the whole suite silently passing because the server path
  // moved and every spawn failed the same way.
  assert.ok(existsSync(SERVER), SERVER);
});
