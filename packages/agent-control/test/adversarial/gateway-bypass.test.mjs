/**
 * Adversarial: the gateway is the boundary, not the suggestion.
 *
 * Each test below attacks a path that REACHED an upstream server in a previous
 * version of this file's subject — unmodeled methods, stray notifications,
 * prompt templates — with no rule consulted and no record written. The proof
 * in every case is the server's own access log, never the gateway's output:
 * a denial the server never heard is the only denial that counts.
 *
 * What this file does NOT claim: none of these tests cover an agent reaching
 * a server WITHOUT going through the gateway (direct config entry, built-in
 * runtime tools, its own subprocess). That is a routing property of the
 * deployment, and it is asserted by `cirvix doctor`, not here.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import { Gateway } from "../../src/core/gateway.mjs";
import { Guard, guard } from "../../src/core/guard.mjs";
import { AuditChain } from "../../src/core/audit.mjs";
import { MessageFramer } from "../../src/core/jsonrpc.mjs";
import { compile } from "../../src/core/policy-dsl.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = join(HERE, "..", "fixtures", "mock-mcp-server.mjs");

const BASE_POLICY = `
deny:
  name = deny-aws
  tool = filesystem.read
  path = **/.aws/**
  reason = "Cloud credentials are never readable by an agent."

deny:
  name = deny-destructive
  tool = shell.exec
  command = "rm -rf"

allow:
  name = allow-workspace-read
  tool = filesystem.read
  workspace = true

allow:
  name = allow-search
  tool = filesystem.search
`;

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

  /** Fire-and-forget: notifications carry no id and expect no answer. */
  notify(method, params = {}) {
    return this.gateway.handleClientMessage({ jsonrpc: "2.0", method, params });
  }
}

async function withGateway(fn, { policy = BASE_POLICY, onDecision } = {}) {
  const root = await mkdtemp(join(tmpdir(), "cirvix-bypass-"));
  const workspace = join(root, "workspace").replace(/\\/g, "/");
  const home = join(root, "home").replace(/\\/g, "/");

  await mkdir(join(workspace, "src"), { recursive: true });
  await mkdir(join(home, ".aws"), { recursive: true });
  await writeFile(join(workspace, "src", "app.ts"), "export const answer = 42;\n", "utf8");
  await writeFile(
    join(home, ".aws", "credentials"),
    "[default]\naws_access_key_id = «redacted:AKIA…»\n",
    "utf8",
  );

  const accessLog = join(root, "access.jsonl").replace(/\\/g, "/");
  await writeFile(accessLog, "", "utf8");

  const { rules } = compile(policy, { cwd: workspace, origin: "bypass-tests" });
  const chain = await new AuditChain(join(root, "audit.jsonl")).open();

  const decisions = [];
  const gateway = new Gateway({
    servers: {
      files: {
        command: process.execPath,
        args: [SERVER],
        env: {
          CIRVIX_TEST_SERVER_NAME: "files",
          CIRVIX_TEST_ACCESS_LOG: accessLog,
          CIRVIX_TEST_RESOURCE_ROOT: workspace,
        },
      },
    },
    rules,
    audit: chain,
    cwd: workspace,
    log: () => {},
    onDecision: (d) => {
      decisions.push(d);
      onDecision?.(d);
    },
  });
  gateway.agentName = "redteam";

  const client = new McpClient(gateway);
  const accesses = async () => {
    const text = await readFile(accessLog, "utf8");
    return text.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  };
  const records = () => chain.read();

  try {
    return await fn({ client, gateway, workspace, home, accesses, records, chain, decisions });
  } finally {
    gateway.stop();
  }
}

/* -------------------------------------------------------------------------- */
/*  Unmodeled methods: default-deny applies to methods, not just tools         */
/* -------------------------------------------------------------------------- */

test("bypass: an unmodeled method is denied, never forwarded, and audited", async () => {
  await withGateway(async ({ client, accesses, records }) => {
    const res = await client.request("elicitation/create", {
      message: "Approve?",
      requestedSchema: { type: "object", properties: {} },
    });
    assert.equal(res.error, undefined, "denial must be a tool result, not a transport error");
    assert.equal(res.result.isError, true);
    assert.equal(res.result._meta["cirvix/verdict"], "deny");

    // The server speaks no such method — but that is not the proof. The proof
    // is that NOTHING arrived: no access of any kind.
    assert.deepEqual(await accesses(), [], "unmodeled method must never reach upstream");

    const recs = await records();
    const hit = recs.find((r) => r.tool === "mcp.elicitation/create");
    assert.ok(hit, "every denied method must leave an audit record");
    assert.equal(hit.verdict, "deny");
    assert.ok(hit.decision_id, "record must carry its decision id");
  });
});

test("bypass: an explicitly permitted unmodeled method forwards to upstream", async () => {
  const policy =
    BASE_POLICY +
    `
allow:
  name = allow-custom-ping
  tool = tool.*
`;
  await withGateway(
    async ({ client }) => {
      // No rule permits elicitation/create, so it stays denied even here —
      // while the named custom method with an explicit permit forwards. The
      // mock answers "Method not found", which is exactly the proof: that
      // error text can only come from the upstream process.
      const denied = await client.request("elicitation/create", {});
      assert.equal(denied.result.isError, true);

      const res = await client.request("custom.ping", { note: "hello" });
      assert.ok(
        res.error?.message?.match(/Method not found/),
        `expected the upstream's own error, got ${JSON.stringify(res).slice(0, 160)}`,
      );
    },
    { policy },
  );
});

test("bypass: completion/complete is evaluated, and denied by default", async () => {
  await withGateway(async ({ client, accesses, records }) => {
    const res = await client.request("completion/complete", {
      ref: { type: "ref/prompt", name: "files__deploy-checklist" },
      argument: { name: "path", value: "~/.aws" },
    });
    assert.equal(res.result.isError, true);
    assert.equal(res.result._meta["cirvix/verdict"], "deny");
    assert.deepEqual(await accesses(), [], "completion must not reach upstream when denied");
    const recs = await records();
    assert.ok(
      recs.some((r) => r.tool === "completion.complete" && r.verdict === "deny"),
      "completion denial must be audited",
    );
  });
});

/* -------------------------------------------------------------------------- */
/*  Prompt templates are reads: server-authored instructions for the model      */
/* -------------------------------------------------------------------------- */

test("bypass: prompts/get of a hostile template is denied with zero render", async () => {
  await withGateway(async ({ client, accesses, records }) => {
    const res = await client.request("prompts/get", {
      name: "files__deploy-checklist",
      arguments: {},
    });
    assert.equal(res.result.isError, true);
    assert.equal(res.result._meta["cirvix/verdict"], "deny");

    // The template body contains an injected credential-read instruction. The
    // server logs BEFORE rendering, so an empty log proves the hostile text
    // never left the server process.
    assert.deepEqual(await accesses(), [], "denied prompt must never render upstream");

    const recs = await records();
    const hit = recs.find((r) => r.tool === "prompts.get");
    assert.ok(hit, "prompt denial must leave an audit record");
    assert.equal(hit.verdict, "deny");
  });
});

test("prompts/get with an explicit permit renders, and the render is logged", async () => {
  const policy =
    BASE_POLICY +
    `
allow:
  name = allow-prompts
  tool = mcp.files.prompts.get
`;
  await withGateway(
    async ({ client, accesses }) => {
      const res = await client.request("prompts/get", { name: "files__summarize", arguments: {} });
      assert.equal(res.result.isError, undefined);
      assert.match(res.result.description, /PROMPT-EXECUTED summarize/);
      const log = await accesses();
      assert.ok(
        log.some((a) => a.kind === "prompts/get" && a.target === "summarize"),
        "permitted render must reach upstream and be receipted",
      );
    },
    { policy },
  );
});

/* -------------------------------------------------------------------------- */
/*  Notifications: most are plumbing; the rest are evaluated, then dropped     */
/* -------------------------------------------------------------------------- */

test("bypass: a non-allowlisted notification is dropped, audited, never sent", async () => {
  await withGateway(async ({ client, accesses, records }) => {
    // Shaped like an action, framed as a notification (no id, no answer
    // expected): the exact shape that used to broadcast to every upstream.
    await client.notify("tools/progress", { tool: "read_file", arguments: { path: "~/.aws/credentials" } });
    await new Promise((r) => setTimeout(r, 300));

    assert.deepEqual(await accesses(), [], "unevaluated notification must never reach upstream");

    const recs = await records();
    const hit = recs.find((r) => r.tool === "mcp.notification.tools/progress");
    assert.ok(hit, "dropped notification must leave an audit record");
    assert.equal(hit.verdict, "deny");
  });
});

test("allowlisted lifecycle notifications still flow and the session survives", async () => {
  await withGateway(async ({ client, workspace }) => {
    await client.notify("notifications/initialized", {});
    const res = await client.request("tools/call", {
      name: "files__read_file",
      arguments: { path: `${workspace}/src/app.ts` },
    });
    assert.equal(res.result.isError, undefined);
    assert.match(res.result.content[0].text, /^EXECUTED read_file/);
  });
});

test("unsubscribe forwards and is visible without fabricating a decision", async () => {
  await withGateway(async ({ client, decisions }) => {
    const res = await client.request("resources/subscribe", { uri: "files__app" }).catch(() => null);
    void res;
    const before = decisions.length;
    const unsub = await client.request("resources/unsubscribe", { uri: "files__app" });
    assert.deepEqual(unsub.result, {});
    const proto = decisions.slice(before).filter((d) => d.kind === "protocol");
    assert.ok(
      proto.some((d) => d.method === "resources/unsubscribe" && d.action === "forward"),
      "unsubscribe forward must be reported on the protocol sink, not as a fake decision",
    );
    assert.ok(
      decisions.slice(before).every((d) => d.kind !== "decision" || d.tool !== "resources.unsubscribe"),
      "no fabricated policy decision for protocol plumbing",
    );
  });
});

/* -------------------------------------------------------------------------- */
/*  Hold still means hold on the wire                                          */
/* -------------------------------------------------------------------------- */

test("bypass: a held call pauses before execution, with an approval id", async () => {
  const policy =
    BASE_POLICY +
    `
require_approval:
  name = approve-search
  tool = filesystem.search
  approvers = oncall
`;
  await withGateway(
    async ({ client, accesses, records }) => {
      const res = await client.request("tools/call", {
        name: "files__search_docs",
        arguments: { query: "deploy" },
      });
      // A hold arrives as isError — deliberately, so no agent mistakes
      // "waiting on a human" for success — while carrying the hold verdict
      // and the approval id, not a failure.
      assert.equal(res.result.isError, true);
      assert.equal(res.result._meta["cirvix/verdict"], "hold");
      assert.match(String(res.result.content[0].text), /apr_/);

      assert.deepEqual(await accesses(), [], "held call must not execute while pending");

      // Retrying the held call must not execute it either.
      const retry = await client.request("tools/call", {
        name: "files__search_docs",
        arguments: { query: "deploy" },
      });
      assert.equal(retry.result._meta["cirvix/verdict"], "hold");
      assert.deepEqual(await accesses(), [], "replay of a held call must not execute it");

      const recs = await records();
      assert.ok(
        recs.some((r) => r.action === "fs.search" && r.verdict === "hold"),
        "hold must be audited",
      );
    },
    { policy },
  );
});

/* -------------------------------------------------------------------------- */
/*  Same capability, both doors: wrap AND gateway refuse together              */
/* -------------------------------------------------------------------------- */

test("bypass: wrapped tool and gateway refuse the same capability together", async () => {
  await withGateway(async ({ client, workspace, home, accesses }) => {
    const { rules } = compile(BASE_POLICY, { cwd: workspace, origin: "bypass-tests" });

    let ran = false;
    const tools = guard.wrap(
      {
        read_file: async ({ path }) => {
          ran = true;
          return `contents of ${path}`;
        },
      },
      { agent: "redteam", environment: "local", cwd: workspace, rules },
    );

    await assert.rejects(
      tools.read_file({ path: `${home}/.aws/credentials` }),
      /Denied/,
      "wrapped credential read must throw",
    );
    assert.equal(ran, false, "denied wrapped tool must never run");

    // Same capability through the gateway: the server's receipt log is the
    // proof, not the gateway's message.
    const res = await client.request("tools/call", {
      name: "files__read_file",
      arguments: { path: `${home}/.aws/credentials` },
    });
    void res;
    assert.deepEqual(
      (await accesses()).filter((a) => String(a.target).includes("credentials")),
      [],
      "gateway must refuse the same credential the wrapper refused",
    );
  });
});

/* -------------------------------------------------------------------------- */
/*  The chain stays verifiable under attack                                    */
/* -------------------------------------------------------------------------- */

test("bypass: every refused decision verifies in one intact chain", async () => {
  await withGateway(async ({ client, home, chain, records }) => {
    await client.request("tools/call", {
      name: "files__read_file",
      arguments: { path: `${home}/.aws/credentials` },
    });
    await client.request("elicitation/create", { message: "x" });
    await client.request("prompts/get", { name: "files__deploy-checklist", arguments: {} });
    await client.notify("tools/progress", { tool: "x" });
    await new Promise((r) => setTimeout(r, 300));

    const verdict = await chain.verify();
    assert.equal(verdict.ok, true, `chain must verify, got: ${verdict.reason ?? "ok"}`);

    const recs = await records();
    const denies = recs.filter((r) => r.verdict === "deny");
    assert.ok(denies.length >= 4, `expected >=4 deny records, got ${denies.length}`);
    for (const d of denies) {
      assert.ok(d.decision_id, "every deny carries its decision id");
      assert.ok(d.tool, "every deny names its tool");
    }
  });
});

test("legitimate work survives the lockdown", async () => {
  await withGateway(async ({ client, workspace, accesses }) => {
    const res = await client.request("tools/call", {
      name: "files__read_file",
      arguments: { path: `${workspace}/src/app.ts` },
    });
    assert.equal(res.result.isError, undefined);
    assert.match(res.result.content[0].text, /^EXECUTED read_file/);
    assert.match(res.result.content[0].text, /answer = 42/);
    assert.ok((await accesses()).length >= 1, "permitted read must reach upstream");
  });
});
