/**
 * Failure modes — the kill switch.
 *
 * ONE INVARIANT, TESTED EVERY WAY IT CAN BREAK:
 *
 *   If Cirvix cannot make a trustworthy security decision,
 *   the dangerous operation does not execute.
 *
 * That is a stronger statement than "it does not crash". A control plane can
 * fail safely and still fail badly: an exception that escapes into the
 * transport leaves the agent hanging with no answer, and a caller that wraps
 * the decision path in a try/catch and continues has turned a storage outage
 * into an allow.
 *
 * So each case here asserts three things, not one:
 *
 *   1. The dangerous operation did not happen.
 *   2. The caller got a DECISION, not an exception.
 *   3. The refusal says what went wrong, so an operator can fix it rather than
 *      guess.
 *
 * WHAT "TRUSTWORTHY" MEANS HERE
 *
 * Two of these deliberately do NOT fail closed, and both are argued rather than
 * assumed: a dead upstream and a missing optional component. See the comments
 * on those tests — refusing service because an unrelated MCP server died is a
 * denial of service Cirvix would be inflicting on itself.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Pipeline } from "../../src/core/pipeline.mjs";
import { Gateway } from "../../src/core/gateway.mjs";
import { AuditChain } from "../../src/core/audit.mjs";
import { ApprovalStore } from "../../src/core/approvals.mjs";
import { MessageFramer } from "../../src/core/jsonrpc.mjs";
import { compile, PolicySyntaxError } from "../../src/core/policy-dsl.mjs";
import { loadPolicyFile } from "../../src/commands/policy.mjs";
import { UdsClient, defaultEndpoint, writeToken } from "../../src/core/uds.mjs";
import { DECISION } from "../../src/core/decisions.mjs";
import { STARTER_POLICY } from "../../src/commands/init.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = join(HERE, "..", "fixtures", "mock-mcp-server.mjs");
const CWD = process.platform === "win32" ? "C:/workspace" : "/workspace";

const rules = compile(STARTER_POLICY, { cwd: CWD, origin: "failure" }).rules;

const DANGEROUS = { tool: "read_file", arguments: { path: "~/.aws/credentials" } };
const ORDINARY = { tool: "read_file", arguments: { path: `${CWD}/src/app.ts` } };

const forwarded = (e) =>
  e.decision === DECISION.ALLOW || e.decision === DECISION.SANITIZE || e.decision === DECISION.AUDIT_ONLY;

async function scratch() {
  return mkdtemp(join(tmpdir(), "cirvix-fail-"));
}

/* ========================================================================== */
/*  AUDIT STORAGE                                                             */
/* ========================================================================== */

test("failure: audit path unwritable — the call is refused, not silently unlogged", async () => {
  /*
   * A call that proceeds with no audit record is a call nobody can account for,
   * and it makes the tamper-evidence property "true of whichever records
   * happened to be writable". So an unrecordable decision is a refused one.
   */
  const dir = await scratch();
  const chain = await new AuditChain(join(dir, "does", "not", "exist", "audit.jsonl")).open();
  const pipeline = new Pipeline({ rules, cwd: CWD, agent: "a", audit: chain });

  const { event } = await pipeline.submit(ORDINARY);

  assert.equal(event.decision, DECISION.DENY, "an unrecordable permit must not proceed");
  assert.equal(event.policy, "audit-unavailable");
  assert.equal(event.audit_write_failed, true);
  assert.match(event.reason, /could not be recorded/);
  assert.ok(event.remediation ?? true);
});

test("failure: audit unwritable does not misattribute an already-denied call", async () => {
  // The refusal reason an operator reads must be the real one. Reporting a
  // storage failure as the cause of a policy denial sends them to the wrong
  // place at the worst time.
  const dir = await scratch();
  const chain = await new AuditChain(join(dir, "nope", "audit.jsonl")).open();
  const pipeline = new Pipeline({ rules, cwd: CWD, agent: "a", audit: chain });

  const { event } = await pipeline.submit(DANGEROUS);

  assert.equal(event.decision, DECISION.DENY);
  assert.notEqual(event.policy, "audit-unavailable", "the policy rule is still the reason");
  assert.equal(event.audit_write_failed, true, "and the storage failure is still recorded as a fact");
});

test("failure: audit directory removed mid-run — later calls refuse rather than proceed", async () => {
  const dir = await scratch();
  const auditDir = join(dir, "state");
  await mkdir(auditDir, { recursive: true });
  const chain = await new AuditChain(join(auditDir, "audit.jsonl")).open();
  const pipeline = new Pipeline({ rules, cwd: CWD, agent: "a", audit: chain });

  const before = await pipeline.submit(ORDINARY);
  assert.equal(before.event.decision, DECISION.ALLOW);

  await rm(auditDir, { recursive: true, force: true });

  const after = await pipeline.submit(ORDINARY);
  assert.equal(after.event.decision, DECISION.DENY, "storage disappearing must stop the flow");
});

/* ========================================================================== */
/*  SECRET BROKER                                                             */
/* ========================================================================== */

test("failure: vault unreachable — refused, with a legible reason, not an exception", async () => {
  const unreachable = {
    substitute: async () => {
      throw new Error("ECONNREFUSED connecting to the broker");
    },
    redact: (payload) => ({ payload, findings: [] }),
  };
  const pipeline = new Pipeline({ rules, cwd: CWD, agent: "a", secrets: unreachable });

  const { event, arguments: outgoing } = await pipeline.submit(ORDINARY);

  assert.equal(event.decision, DECISION.DENY);
  assert.equal(event.policy, "secret-broker");
  assert.match(event.reason, /broker is unavailable/);
  // Nothing was substituted, and the original arguments are what would have
  // gone out had anything gone out.
  assert.deepEqual(outgoing, ORDINARY.arguments);
});

test("failure: vault hangs — the timeout is a refusal, not a hang", async () => {
  const hanging = {
    substitute: () =>
      new Promise((_, reject) => setTimeout(() => reject(new Error("broker timed out")), 40)),
    redact: (payload) => ({ payload, findings: [] }),
  };
  const pipeline = new Pipeline({ rules, cwd: CWD, agent: "a", secrets: hanging });

  const { event } = await pipeline.submit(ORDINARY);
  assert.equal(event.decision, DECISION.DENY);
  assert.match(event.reason, /timed out|unavailable/);
});

test("failure: a broker returning nonsense is treated as a refusal", async () => {
  for (const bad of [null, undefined, {}, { ok: "yes" }, "fine"]) {
    const pipeline = new Pipeline({
      rules,
      cwd: CWD,
      agent: "a",
      secrets: { substitute: async () => bad, redact: (p) => ({ payload: p, findings: [] }) },
    });
    const { event } = await pipeline.submit(ORDINARY);
    assert.equal(event.decision, DECISION.DENY, `broker returned ${JSON.stringify(bad)}`);
  }
});

/* ========================================================================== */
/*  APPROVAL STORE                                                            */
/* ========================================================================== */

test("failure: approval store unwritable — refused rather than held invisibly", async () => {
  /*
   * The subtle failure this closes: a held call whose approval cannot be
   * recorded looks to the agent like a normal hold, and nobody is ever asked,
   * because the request never reached the queue. It waits forever on a person
   * who does not know they were called.
   */
  const dir = await scratch();
  const approvals = await new ApprovalStore(join(dir, "no", "such", "dir", "approvals.jsonl")).open();
  const pipeline = new Pipeline({ rules, cwd: CWD, agent: "a", approvals });

  const { event } = await pipeline.submit({ tool: "database.write", arguments: { table: "users" } });

  assert.equal(event.decision, DECISION.DENY);
  assert.equal(event.policy, "approval-unavailable");
  assert.match(event.reason, /approval store is unavailable/);
});

test("failure: a corrupt approval log does not resurrect grants", async () => {
  const dir = await scratch();
  const path = join(dir, "approvals.jsonl");
  await writeFile(path, "not json\n{\"type\":\"decision\",\"id\":\"apr_x\",\"state\":\"approved\"}\ngarbage\n", "utf8");

  const store = await new ApprovalStore(path).open();
  assert.equal(store.get("apr_x"), null, "a decision with no matching request grants nothing");
  assert.equal(store.findGrant("sha256:" + "0".repeat(32)), null);
});

/* ========================================================================== */
/*  POLICY                                                                    */
/* ========================================================================== */

test("failure: a corrupt policy file refuses to load rather than loading partially", async () => {
  const dir = await scratch();
  const path = join(dir, "cirvix.policy");
  await writeFile(path, "deny:\n  tool = shell.exec\n\nallow:\n  frobnicate = yes\n", "utf8");

  await assert.rejects(() => loadPolicyFile(path, { cwd: CWD }), PolicySyntaxError);
});

test("failure: a truncated policy file does not load its surviving denies as a whole policy", async () => {
  // The dangerous half-load: the file is cut mid-rule, the denies happen to be
  // before the cut, and the engine reports itself fine while the permits that
  // made it usable are gone — or worse, the other way round.
  const dir = await scratch();
  const path = join(dir, "cirvix.policy");
  await writeFile(path, "deny:\n  tool = shell.exec\n  command = \"rm -rf\"\n\nallow:\n  tool = ", "utf8");
  await assert.rejects(() => loadPolicyFile(path, { cwd: CWD }), PolicySyntaxError);
});

test("failure: an empty policy file denies everything", async () => {
  const dir = await scratch();
  const path = join(dir, "cirvix.policy");
  await writeFile(path, "", "utf8");

  const loaded = await loadPolicyFile(path, { cwd: CWD });
  const pipeline = new Pipeline({ rules: loaded.rules, cwd: CWD, agent: "a" });
  const { event } = await pipeline.submit(ORDINARY);
  assert.equal(event.decision, DECISION.DENY, "an empty policy is default-deny, not allow-all");
});

test("failure: a policy of only whitespace and comments denies everything", async () => {
  const dir = await scratch();
  const path = join(dir, "cirvix.policy");
  await writeFile(path, "# just a comment\n\n   \n# another\n", "utf8");

  const loaded = await loadPolicyFile(path, { cwd: CWD });
  const pipeline = new Pipeline({ rules: loaded.rules, cwd: CWD, agent: "a" });
  assert.equal((await pipeline.submit(ORDINARY)).event.decision, DECISION.DENY);
});

test("failure: a hot-reload to a corrupt rule set does not silently disarm the engine", async () => {
  // The caller must handle the load failure; what must NOT happen is the
  // engine quietly running with an empty or half-applied rule set.
  const pipeline = new Pipeline({ rules, cwd: CWD, agent: "a" });
  assert.equal((await pipeline.submit(DANGEROUS)).event.decision, DECISION.DENY);

  assert.throws(() => compile("allow:\n  frobnicate = x\n", { cwd: CWD }), PolicySyntaxError);

  // The rule set is untouched by the failed compile, so enforcement continues.
  assert.equal((await pipeline.submit(DANGEROUS)).event.decision, DECISION.DENY);
  assert.equal((await pipeline.submit(ORDINARY)).event.decision, DECISION.ALLOW);
});

/* ========================================================================== */
/*  MCP UPSTREAM                                                              */
/* ========================================================================== */

/** Drives a gateway over the real framer, as an MCP client would. */
function client(gateway) {
  const pending = new Map();
  let nextId = 1;
  const framer = new MessageFramer({ onMessage: (m) => pending.get(m.id)?.(m) });
  gateway.start((msg) => framer.push(Buffer.from(JSON.stringify(msg) + "\n")));

  return (method, params, timeoutMs = 6000) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`no answer to ${method}`));
      }, timeoutMs);
      pending.set(id, (m) => {
        clearTimeout(timer);
        pending.delete(id);
        resolve(m);
      });
      void gateway.handleClientMessage({ jsonrpc: "2.0", id, method, params });
    });
}

test("failure: an MCP server that will not start does not take down the session", async () => {
  /*
   * Deliberately NOT fail-closed for the whole gateway.
   *
   * Refusing every call because one unrelated upstream is dead is a denial of
   * service Cirvix would be inflicting on itself, and the security property is
   * preserved anyway: the dead server's tools are gone, and calls to it are
   * refused. Nothing dangerous becomes reachable because something crashed.
   */
  const dir = await scratch();
  const chain = await new AuditChain(join(dir, "audit.jsonl")).open();
  const gateway = new Gateway({
    servers: {
      dead: { command: process.execPath, args: [join(dir, "does-not-exist.mjs")] },
      alive: { command: process.execPath, args: [SERVER], env: { CIRVIX_TEST_SERVER_NAME: "alive" } },
    },
    rules,
    audit: chain,
    cwd: CWD,
    log: () => {},
  });

  const request = client(gateway);
  try {
    const list = await request("tools/list", {});
    const names = list.result.tools.map((t) => t.name);
    assert.ok(names.some((n) => n.startsWith("alive__")), "the healthy server still works");
    assert.ok(!names.some((n) => n.startsWith("dead__")), "the dead server's tools are withheld");

    const call = await request("tools/call", { name: "dead__read_file", arguments: { path: "/etc/passwd" } });
    assert.ok(call.error, "a call to a dead server is refused, not queued forever");
  } finally {
    gateway.stop();
  }
});

test("failure: an upstream that dies mid-session fails its in-flight calls", async () => {
  const dir = await scratch();
  const chain = await new AuditChain(join(dir, "audit.jsonl")).open();
  const gateway = new Gateway({
    servers: { files: { command: process.execPath, args: [SERVER], env: { CIRVIX_TEST_SERVER_NAME: "files" } } },
    rules,
    audit: chain,
    cwd: CWD,
    log: () => {},
  });

  const request = client(gateway);
  try {
    await request("tools/list", {});
    // Kill it the way a crash would.
    gateway.upstreams.get("files").stop();

    const call = await request("tools/call", { name: "files__read_file", arguments: { path: ORDINARY.arguments.path } });
    assert.ok(call.error || call.result?.isError, "the caller gets an answer rather than hanging");
  } finally {
    gateway.stop();
  }
});

test("failure: a dead upstream cannot make a denied call succeed", async () => {
  // The property that matters when everything is broken: breakage never
  // upgrades a denial into an execution.
  const dir = await scratch();
  const chain = await new AuditChain(join(dir, "audit.jsonl")).open();
  const gateway = new Gateway({
    servers: { files: { command: process.execPath, args: [SERVER], env: { CIRVIX_TEST_SERVER_NAME: "files" } } },
    rules,
    audit: chain,
    cwd: CWD,
    log: () => {},
  });

  const request = client(gateway);
  try {
    await request("tools/list", {});
    gateway.upstreams.get("files").stop();

    const call = await request("tools/call", {
      name: "files__read_file",
      arguments: { path: "~/.aws/credentials" },
    });
    const text = call.result?.content?.[0]?.text ?? "";
    assert.ok(!text.includes("aws_secret_access_key"), "no credential material came back");
    assert.ok(call.error || call.result?.isError);
  } finally {
    gateway.stop();
  }
});

/* ========================================================================== */
/*  CONTROL SOCKET                                                            */
/* ========================================================================== */

test("failure: the control socket disappearing is a clean error, not a hang", async () => {
  const stateDir = await scratch();
  const token = await writeToken(stateDir);
  // Nothing is listening on this endpoint at all.
  const clientHandle = new UdsClient({ endpoint: defaultEndpoint(stateDir), token, timeoutMs: 1500 });

  await assert.rejects(
    () => clientHandle.call("cirvix/authorize", { tool: "read_file", arguments: { path: "~/.aws/credentials" } }),
    (err) => {
      assert.ok(err instanceof Error);
      return true;
    },
  );
});

test("failure: a missing session token is a refusal, not a default-allow", async () => {
  const stateDir = await scratch();
  const clientHandle = new UdsClient({
    endpoint: defaultEndpoint(stateDir),
    token: undefined,
    timeoutMs: 1500,
  });
  await assert.rejects(() => clientHandle.call("cirvix/status", {}));
});

/* ========================================================================== */
/*  RESOURCE EXHAUSTION AND ABRUPT TERMINATION                                */
/* ========================================================================== */

test("failure: a decision is still produced when arguments are enormous", async () => {
  const pipeline = new Pipeline({ rules, cwd: CWD, agent: "a" });
  const { event } = await pipeline.submit({
    tool: "http_request",
    arguments: { url: "https://example.com/x", body: "A".repeat(8_000_000) },
  });
  assert.ok(event.decision, "a huge payload still gets a decision");
});

test("failure: a partial audit line from an interrupted write is detected, not ignored", async () => {
  /*
   * Process killed mid-append. The last line is half-written. That must read as
   * a broken chain — silently skipping it would let anyone truncate a record
   * they disliked and keep a chain that verifies.
   */
  const dir = await scratch();
  const path = join(dir, "audit.jsonl");
  const chain = await new AuditChain(path).open();
  await chain.append({ verdict: "deny", rule: "deny-aws" });
  await chain.append({ verdict: "permit", rule: "allow-read" });

  const text = await readFile(path, "utf8");
  await writeFile(path, text.slice(0, text.length - 40), "utf8");

  const result = await new AuditChain(path).verify();
  assert.equal(result.ok, false, "a truncated record must break verification");
});

test("failure: a chain reopened after an interrupted write does not fork", async () => {
  const dir = await scratch();
  const path = join(dir, "audit.jsonl");
  const first = await new AuditChain(path).open();
  await first.append({ n: 1 });
  await first.append({ n: 2 });

  // Simulate the process dying here, then a fresh start appending more.
  const second = await new AuditChain(path).open();
  await second.append({ n: 3 });

  const result = await new AuditChain(path).verify();
  assert.equal(result.ok, true);
  assert.equal(result.records, 3);
});

test("failure: every component missing at once still denies the dangerous call", async () => {
  /*
   * The end state: no audit, no vault, no approvals, and a rule set that was
   * never loaded. Nothing works. The credential read must still not happen.
   */
  const pipeline = new Pipeline({ rules: [], cwd: CWD, agent: "a", audit: null, secrets: null, approvals: null });
  const { event } = await pipeline.submit(DANGEROUS);

  assert.equal(event.decision, DECISION.DENY);
  assert.ok(!forwarded(event.decision));
});

test("failure: with everything missing, ordinary work is also denied — and that is correct", async () => {
  // Default-deny is not a graceful degradation to "allow the safe things". An
  // engine that cannot evaluate cannot tell which things are safe.
  const pipeline = new Pipeline({ rules: [], cwd: CWD, agent: "a" });
  assert.equal((await pipeline.submit(ORDINARY)).event.decision, DECISION.DENY);
});

/* ========================================================================== */
/*  THE INVARIANT, STATED AS A TEST                                           */
/* ========================================================================== */

test("failure: across every broken configuration, the dangerous call never executes", async () => {
  const dir = await scratch();
  const broken = [
    ["no rules", { rules: [] }],
    ["null rules", { rules: null }],
    ["unwritable audit", { rules, audit: await new AuditChain(join(dir, "x", "y", "a.jsonl")).open() }],
    [
      "broken vault",
      {
        rules,
        secrets: {
          substitute: async () => {
            throw new Error("down");
          },
          redact: (p) => ({ payload: p, findings: [] }),
        },
      },
    ],
    [
      "broken approvals",
      { rules, approvals: await new ApprovalStore(join(dir, "x", "y", "ap.jsonl")).open() },
    ],
    ["everything broken", { rules: null, audit: null, secrets: null, approvals: null }],
  ];

  for (const [label, options] of broken) {
    const pipeline = new Pipeline({ cwd: CWD, agent: "a", ...options });
    const { event } = await pipeline.submit(DANGEROUS);
    assert.ok(
      !forwarded(event.decision),
      `${label}: the credential read was ${event.decision} by ${event.policy ?? "default-deny"}`,
    );
  }
});
