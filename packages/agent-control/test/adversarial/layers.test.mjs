/**
 * Per-layer attacks.
 *
 *   MCP transport → parser → normalizer → secrets → risk → policy →
 *   approval → sanitizer → execution → audit → CLI
 *
 * Each section attacks one layer with what that layer is specifically bad at.
 * The recurring theme, and the reason these are worth writing separately from
 * the corpus: a layer does not usually fail by deciding wrongly. It fails by
 * *not being reached* — a frame that never parses, a rule that never matches, a
 * record that is never written. Those are invisible to a test that only checks
 * verdicts.
 *
 * The standing requirement across all of them: nothing here may throw. A crash
 * on hostile input is a denial-of-service against the control plane, and a
 * control plane that is down is a control plane that is not enforcing.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:net";

import { MessageFramer, serialize } from "../../src/core/jsonrpc.mjs";
import { Pipeline } from "../../src/core/pipeline.mjs";
import { AuditChain } from "../../src/core/audit.mjs";
import { ApprovalStore, STATE } from "../../src/core/approvals.mjs";
import { UdsClient, UdsServer, defaultEndpoint, writeToken } from "../../src/core/uds.mjs";
import { compile, PolicySyntaxError } from "../../src/core/policy-dsl.mjs";
import { parseRules, validateRules, evaluate } from "../../src/core/policy.mjs";
import { STARTER_POLICY } from "../../src/commands/init.mjs";
import { DECISION, MODE } from "../../src/core/decisions.mjs";
import { assertAllowedEndpoint } from "../../src/core/http-transport.mjs";

const CWD = process.platform === "win32" ? "C:/workspace" : "/workspace";
const { rules } = compile(STARTER_POLICY, { cwd: CWD, origin: "layers" });

const pipeline = () => new Pipeline({ rules, cwd: CWD, agent: "adversary" });
const blocked = (e) => e.decision === DECISION.DENY || e.decision === DECISION.REQUIRE_APPROVAL;

/* ========================================================================== */
/*  LAYER 1 — TRANSPORT                                                       */
/* ========================================================================== */

test("transport: a malformed frame is reported, not thrown", () => {
  const invalid = [];
  const framer = new MessageFramer({
    onMessage: () => assert.fail("must not parse"),
    onInvalid: (line) => invalid.push(line),
  });

  for (const junk of [
    "not json at all\n",
    "{unclosed\n",
    "[1,2,3\n",
    '{"jsonrpc":}\n',
    "\u0000\u0001\u0002\n",
    '{"a":' + '['.repeat(5000) + "\n",
  ]) {
    framer.push(Buffer.from(junk));
  }
  assert.equal(invalid.length, 6, "every bad frame surfaced, none crashed the framer");
});

test("transport: a message split across chunks is reassembled, including mid-UTF-8", () => {
  const seen = [];
  const framer = new MessageFramer({ onMessage: (m) => seen.push(m) });

  // A multi-byte character split across a chunk boundary is the classic way a
  // proxy corrupts payloads under load.
  const payload = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "héllo—wörld" } });
  const bytes = Buffer.from(payload + "\n", "utf8");
  for (let i = 0; i < bytes.length; i++) framer.push(bytes.subarray(i, i + 1));

  assert.equal(seen.length, 1);
  assert.equal(seen[0].params.name, "héllo—wörld");
});

test("transport: several messages in one chunk all arrive", () => {
  const seen = [];
  const framer = new MessageFramer({ onMessage: (m) => seen.push(m) });
  framer.push(Buffer.from([1, 2, 3].map((id) => JSON.stringify({ jsonrpc: "2.0", id })).join("\n") + "\n"));
  assert.deepEqual(seen.map((m) => m.id), [1, 2, 3]);
});

test("transport: a bad frame between good ones does not lose the good ones", () => {
  const seen = [];
  const invalid = [];
  const framer = new MessageFramer({ onMessage: (m) => seen.push(m), onInvalid: (l) => invalid.push(l) });
  framer.push(Buffer.from('{"jsonrpc":"2.0","id":1}\nGARBAGE\n{"jsonrpc":"2.0","id":2}\n'));
  assert.deepEqual(seen.map((m) => m.id), [1, 2]);
  assert.equal(invalid.length, 1);
});

test("transport: the HTTP upstream refuses link-local and metadata endpoints outright", () => {
  // Configuration is not a licence to become an SSRF primitive.
  for (const url of [
    "http://169.254.169.254/mcp",
    "http://metadata.google.internal/mcp",
    "http://100.100.100.200/mcp",
  ]) {
    assert.throws(() => assertAllowedEndpoint(url), /never a legitimate MCP endpoint/, url);
  }
});

test("transport: a non-http scheme is refused rather than attempted", () => {
  for (const url of ["file:///etc/passwd", "ftp://example.com/x", "gopher://example.com"]) {
    assert.throws(() => assertAllowedEndpoint(url), /http\(s\)|valid MCP endpoint/, url);
  }
});

/* ========================================================================== */
/*  LAYER 2 — PARSER / NORMALIZER                                             */
/* ========================================================================== */

test("parser: every malformed call shape is denied, never thrown on", async () => {
  const p = pipeline();
  const shapes = [
    {},
    { tool: null },
    { tool: 42 },
    { tool: "" },
    { tool: "x", arguments: null },
    { tool: "x", arguments: "a string" },
    { tool: "x", arguments: [1, 2, 3] },
    { tool: {}, arguments: {} },
    { tool: "x", arguments: { path: 42 } },
    { tool: "x", arguments: { path: null } },
    { method: "tools/call" },
    { method: "tools/call", params: null },
    { method: "tools/call", params: { name: null } },
    { jsonrpc: "2.0", id: 1 },
  ];

  for (const shape of shapes) {
    const { event } = await p.submit(shape);
    assert.ok(blocked(event), `${JSON.stringify(shape)} was ${event.decision}`);
  }
});

test("parser: deeply nested arguments do not blow the stack", async () => {
  let deep = { path: "x" };
  for (let i = 0; i < 5000; i++) deep = { nested: deep };
  const { event } = await pipeline().submit({ tool: "read_file", arguments: deep });
  assert.ok(event.decision, "a decision was still produced");
});

test("parser: a self-referential argument object does not hang", async () => {
  const cyclic = { path: `${CWD}/src/app.ts` };
  cyclic.self = cyclic;
  const { event } = await pipeline().submit({ tool: "read_file", arguments: cyclic });
  assert.ok(event.decision);
});

test("parser: an oversized argument is bounded, not unbounded", async () => {
  const started = Date.now();
  const { event } = await pipeline().submit({
    tool: "http_request",
    arguments: { url: "https://example.com/x", body: "A".repeat(5_000_000) },
  });
  assert.ok(event.decision);
  assert.ok(Date.now() - started < 10_000, `took ${Date.now() - started}ms on a 5MB argument`);
});

test("parser: a pathological glob input cannot make matching hang", async () => {
  // The two-pointer matcher exists precisely so this is O(n·m). A backtracking
  // implementation sits here for minutes, and the input is attacker-chosen.
  const started = Date.now();
  await pipeline().submit({ tool: "read_file", arguments: { path: "a".repeat(50_000) + "!" } });
  assert.ok(Date.now() - started < 5_000, `glob matching took ${Date.now() - started}ms`);
});

/* ========================================================================== */
/*  LAYER 3 — POLICY                                                          */
/* ========================================================================== */

test("policy: a malformed policy fails to load rather than loading permissively", () => {
  // The dangerous failure is a rule set that half-parses: some rules load, the
  // denies are among the ones that did not, and the engine reports itself fine.
  for (const bad of [
    "allow:\n  frobnicate = x\n",
    "maybe:\n  tool = x\n",
    "  tool = orphan\n",
    "deny:\n  tool = shell.exec\n  risk >= SPICY\n",
    "allow:\n  name = everything\n",
  ]) {
    assert.throws(() => compile(bad, { cwd: CWD }), PolicySyntaxError, JSON.stringify(bad));
  }
});

test("policy: JSON rules with an unknown effect are rejected, not skipped", () => {
  assert.throws(() => parseRules([{ name: "x", effect: "maybe" }]), /expected/);
  // A skipped rule would be a silently missing control.
  assert.throws(() => parseRules([{ name: "x", effect: "permit", when: [{ path: "a", op: "zzz" }] }]), /unknown operator/i);
});

test("policy: conflicting allow and deny — deny wins in every ordering", () => {
  const call = { agent: "a", action: "fs.read", resource: `${CWD}/.env`, context: {} };
  const deny = { name: "d", effect: "forbid", actions: ["fs.read"], resources: ["**/.env"] };
  const allow = { name: "a", effect: "permit", actions: ["fs.read"], resources: ["*"] };

  assert.equal(evaluate(call, [deny, allow], { cwd: CWD }).verdict, "deny");
  assert.equal(evaluate(call, [allow, deny], { cwd: CWD }).verdict, "deny");
  // And with many permits stacked around it.
  const many = [allow, allow, deny, allow, allow].map((r, i) => ({ ...r, name: `${r.name}${i}` }));
  assert.equal(evaluate(call, many, { cwd: CWD }).verdict, "deny");
});

test("policy: a hold cannot be downgraded by adding permits", () => {
  const call = { agent: "a", action: "db.write", resource: "users", context: {} };
  const hold = { name: "h", effect: "hold", actions: ["db.write"], resources: ["*"], approvers: ["oncall"] };
  const allow = { name: "a", effect: "permit", actions: ["db.write"], resources: ["*"] };
  assert.equal(evaluate(call, [allow, hold], { cwd: CWD }).verdict, "hold");
  assert.equal(evaluate(call, [hold, allow], { cwd: CWD }).verdict, "hold");
});

test("policy: an audit_only rule cannot authorize anything, in any position", () => {
  const call = { agent: "a", action: "fs.read", resource: `${CWD}/.env`, context: {} };
  const observe = { name: "o", effect: "audit_only", actions: ["fs.read"], resources: ["*"] };
  const deny = { name: "d", effect: "forbid", actions: ["fs.read"], resources: ["**/.env"] };

  assert.equal(evaluate(call, [observe], { cwd: CWD }).verdict, "deny", "observation is not authorization");
  assert.equal(evaluate(call, [observe, deny], { cwd: CWD }).verdict, "deny");
  assert.equal(evaluate(call, [deny, observe], { cwd: CWD }).verdict, "deny");
});

test("policy: an empty rule set denies everything rather than permitting it", () => {
  const call = { agent: "a", action: "fs.read", resource: `${CWD}/x`, context: {} };
  assert.equal(evaluate(call, [], { cwd: CWD }).verdict, "deny");
  assert.equal(evaluate(call, null, { cwd: CWD }).verdict, "deny");
  assert.equal(evaluate(call, undefined, { cwd: CWD }).verdict, "deny");
});

test("policy: an unknown comparator fails closed", () => {
  const call = { agent: "a", action: "fs.read", resource: "x", context: { a: 1 } };
  const rule = { name: "r", effect: "permit", actions: ["*"], resources: ["*"], when: [{ path: "a", op: "totallyMadeUp", value: 1 }] };
  assert.equal(evaluate(call, [rule], { cwd: CWD }).verdict, "deny", "a typo must not match everything");
});

test("policy: validation reports a permissive rule rather than accepting it silently", () => {
  const result = validateRules([{ name: "everything", effect: "permit" }]);
  assert.ok(result.warnings.some((w) => /every agent, action, and resource/.test(w.message)));
});

test("policy: hot-swapping the rule set takes effect on the next call, not retroactively", async () => {
  // A live rule swap must be atomic from the caller's point of view: no call is
  // evaluated against half of each rule set.
  const p = pipeline();
  const call = { tool: "read_file", arguments: { path: `${CWD}/src/app.ts` } };

  const before = await p.submit(call);
  assert.equal(before.event.decision, DECISION.ALLOW);

  p.rules = compile("deny:\n  tool = filesystem.read\n  path = **/*\n", { cwd: CWD }).rules;

  const after = await p.submit(call);
  assert.equal(after.event.decision, DECISION.DENY, "the new rules apply immediately");
  // The earlier record is unchanged — a policy change does not rewrite history.
  assert.equal(before.event.decision, DECISION.ALLOW);
});

test("policy: audit mode never converts a deny into an executed call", async () => {
  const p = new Pipeline({ rules, cwd: CWD, agent: "adversary", mode: MODE.AUDIT });
  const { event } = await p.submit({ tool: "read_file", arguments: { path: "~/.aws/credentials" } });

  assert.equal(event.decision, DECISION.AUDIT_ONLY);
  assert.equal(event.enforced, false, "and it says so, so nobody mistakes it for protection");
  assert.equal(event.would_have.decision, DECISION.DENY);
});

/* ========================================================================== */
/*  LAYER 4 — APPROVAL                                                        */
/* ========================================================================== */

async function store() {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-layers-"));
  return { dir, approvals: await new ApprovalStore(join(dir, "approvals.jsonl")).open() };
}

test("approval: a decided approval cannot be re-decided", async () => {
  const { approvals } = await store();
  const { id } = await approvals.request({ tool: "shell.exec" });
  await approvals.decide(id, STATE.APPROVED, "sre@example.com");
  await assert.rejects(() => approvals.decide(id, STATE.DENIED, "attacker"), /already approved/);
});

test("approval: an unknown id cannot be approved into existence", async () => {
  const { approvals } = await store();
  await assert.rejects(() => approvals.decide("apr_doesnotexist", STATE.APPROVED, "x@e.com"), /No approval/);
});

test("approval: an approval cannot be made anonymous", async () => {
  const { approvals } = await store();
  const { id } = await approvals.request({ tool: "shell.exec" });
  for (const who of ["", null, undefined]) {
    await assert.rejects(() => approvals.decide(id, STATE.APPROVED, who), /must name/);
  }
});

test("approval: only approved and denied are accepted as verdicts", async () => {
  const { approvals } = await store();
  const { id } = await approvals.request({ tool: "shell.exec" });
  for (const state of ["maybe", "pending", "expired", "APPROVED "]) {
    await assert.rejects(() => approvals.decide(id, state, "x@e.com"), /approved or denied/);
  }
});

test("approval: a forged log entry cannot flip a terminal decision", async () => {
  const { dir, approvals } = await store();
  const path = join(dir, "approvals.jsonl");
  const { id } = await approvals.request({ tool: "shell.exec" });
  await approvals.decide(id, STATE.DENIED, "sre@example.com");

  const { appendFile } = await import("node:fs/promises");
  await appendFile(
    path,
    JSON.stringify({ type: "decision", id, ts: new Date().toISOString(), state: STATE.APPROVED, decidedBy: "attacker" }) + "\n",
    "utf8",
  );

  const reopened = await new ApprovalStore(path).open();
  assert.equal(reopened.get(id).state, STATE.DENIED);
  assert.equal(reopened.get(id).decidedBy, "sre@example.com");
});

test("approval: an expired request cannot be revived", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-layers-"));
  const approvals = new ApprovalStore(join(dir, "approvals.jsonl"), { ttlMs: -1 });
  await approvals.open();
  const { id } = await approvals.request({ tool: "shell.exec" });
  await assert.rejects(() => approvals.decide(id, STATE.APPROVED, "x@e.com"), /expired/);
});

/* ========================================================================== */
/*  LAYER 5 — AUDIT                                                           */
/* ========================================================================== */

async function chainWith(records) {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-audit-"));
  const path = join(dir, "audit.jsonl");
  const chain = await new AuditChain(path).open();
  for (const r of records) await chain.append(r);
  return { path, chain };
}

test("audit: editing a record breaks verification and names where", async () => {
  const { path } = await chainWith([{ verdict: "deny", rule: "d" }, { verdict: "permit", rule: "a" }]);
  const lines = (await readFile(path, "utf8")).split("\n").filter(Boolean);
  const tampered = lines.map((l) => {
    const r = JSON.parse(l);
    if (r.verdict === "deny") r.verdict = "permit";
    return JSON.stringify(r);
  });
  await writeFile(path, tampered.join("\n") + "\n", "utf8");

  const result = await new AuditChain(path).verify();
  assert.equal(result.ok, false);
  assert.ok(result.brokenAt);
});

test("audit: deleting a record breaks verification", async () => {
  const { path } = await chainWith([{ n: 1 }, { n: 2 }, { n: 3 }]);
  const lines = (await readFile(path, "utf8")).split("\n").filter(Boolean);
  await writeFile(path, [lines[0], lines[2]].join("\n") + "\n", "utf8");
  assert.equal((await new AuditChain(path).verify()).ok, false);
});

test("audit: reordering records breaks verification", async () => {
  const { path } = await chainWith([{ n: 1 }, { n: 2 }, { n: 3 }]);
  const lines = (await readFile(path, "utf8")).split("\n").filter(Boolean);
  await writeFile(path, [lines[0], lines[2], lines[1]].join("\n") + "\n", "utf8");
  assert.equal((await new AuditChain(path).verify()).ok, false);
});

test("audit: appending a forged record breaks verification", async () => {
  // The interesting case: an attacker who can write to the file cannot append a
  // record that verifies, because they do not know the true head hash chain.
  const { path } = await chainWith([{ n: 1 }]);
  const { appendFile } = await import("node:fs/promises");
  await appendFile(
    path,
    JSON.stringify({ seq: 2, ts: new Date().toISOString(), prev_hash: "sha256:" + "0".repeat(64), verdict: "permit", hash: "sha256:" + "f".repeat(64) }) + "\n",
    "utf8",
  );
  assert.equal((await new AuditChain(path).verify()).ok, false);
});

test("audit: a malformed line is a break, not a skip", async () => {
  const { path } = await chainWith([{ n: 1 }]);
  const { appendFile } = await import("node:fs/promises");
  await appendFile(path, "not json\n", "utf8");
  const result = await new AuditChain(path).verify();
  assert.equal(result.ok, false, "a corrupt line must not be silently ignored");
});

test("audit: concurrent appends still produce a verifying chain", async () => {
  // The failure this pins: advancing the hash chain synchronously while writing
  // asynchronously makes on-disk order diverge from chain order, so an ordinary
  // burst of load produces a chain that reports itself tampered with.
  const dir = await mkdtemp(join(tmpdir(), "cirvix-audit-"));
  const path = join(dir, "audit.jsonl");
  const chain = await new AuditChain(path).open();

  await Promise.all(Array.from({ length: 200 }, (_, i) => chain.append({ n: i, verdict: "permit" })));

  const result = await chain.verify();
  assert.equal(result.ok, true, `chain broke under concurrency: ${result.reason}`);
  assert.equal(result.records, 200);
});

test("audit: sequence numbers are dense and ordered after a concurrent burst", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-audit-"));
  const chain = await new AuditChain(join(dir, "audit.jsonl")).open();
  await Promise.all(Array.from({ length: 100 }, (_, i) => chain.append({ n: i })));

  const records = await chain.read();
  assert.deepEqual(
    records.map((r) => r.seq),
    Array.from({ length: 100 }, (_, i) => i + 1),
    "gaps or duplicates in the sequence mean a record was lost or double-written",
  );
});

test("audit: a reopened chain continues rather than forking", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-audit-"));
  const path = join(dir, "audit.jsonl");

  const first = await new AuditChain(path).open();
  await first.append({ n: 1 });
  await first.append({ n: 2 });

  const second = await new AuditChain(path).open();
  await second.append({ n: 3 });

  const result = await new AuditChain(path).verify();
  assert.equal(result.ok, true, "a restart must not fork the chain");
  assert.equal(result.records, 3);
});

/* ========================================================================== */
/*  LAYER 6 — CONTROL SOCKET                                                  */
/* ========================================================================== */

async function socket() {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-uds-adv-"));
  const token = await writeToken(stateDir);
  const endpoint = defaultEndpoint(stateDir);
  const server = new UdsServer({ pipeline: pipeline(), endpoint, token, status: () => ({}) });
  await server.start();
  return { server, endpoint, token };
}

/** Sends raw frames without authenticating first. */
function rawCall(endpoint, messages, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const s = connect(endpoint);
    const replies = [];
    let buffer = "";
    const done = () => {
      s.destroy();
      resolve(replies);
    };
    const timer = setTimeout(done, timeoutMs);
    s.on("connect", () => messages.forEach((m) => s.write(serialize(m))));
    s.on("data", (c) => {
      buffer += c.toString();
      let i;
      while ((i = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, i).trim();
        buffer = buffer.slice(i + 1);
        if (line) {
          try {
            replies.push(JSON.parse(line));
          } catch {
            /* ignore */
          }
        }
        if (replies.length >= messages.length) {
          clearTimeout(timer);
          return done();
        }
      }
    });
    s.on("error", () => {
      clearTimeout(timer);
      done();
    });
  });
}

test("socket: no token means no service", async () => {
  const { server, endpoint } = await socket();
  try {
    const replies = await rawCall(endpoint, [{ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }]);
    assert.ok(replies[0]?.error, "initialize with no token must fail");
  } finally {
    await server.stop();
  }
});

test("socket: a wrong token of the right length is refused", async () => {
  // Constant-time comparison means a wrong token of equal length must still
  // fail; a length-only check would be a trivial bypass.
  const { server, endpoint } = await socket();
  try {
    const replies = await rawCall(endpoint, [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: { token: "a".repeat(64) } },
    ]);
    assert.ok(replies[0]?.error);
  } finally {
    await server.stop();
  }
});

test("socket: authorize before initialize is refused", async () => {
  const { server, endpoint } = await socket();
  try {
    const replies = await rawCall(endpoint, [
      { jsonrpc: "2.0", id: 1, method: "cirvix/authorize", params: { tool: "read_file", arguments: { path: "~/.aws/credentials" } } },
    ]);
    assert.ok(replies[0]?.error);
    assert.match(replies[0].error.message, /initialize/);
  } finally {
    await server.stop();
  }
});

test("socket: authentication does not carry across connections", async () => {
  // A second connection must authenticate on its own; per-process state would
  // mean one authenticated client authenticates every later one.
  const { server, endpoint, token } = await socket();
  try {
    await new UdsClient({ endpoint, token }).call("cirvix/status", {});
    const replies = await rawCall(endpoint, [
      { jsonrpc: "2.0", id: 1, method: "cirvix/authorize", params: { tool: "git_status" } },
    ]);
    assert.ok(replies[0]?.error, "a fresh connection is unauthenticated");
  } finally {
    await server.stop();
  }
});

test("socket: garbage before the handshake does not open the door", async () => {
  const { server, endpoint } = await socket();
  try {
    const replies = await rawCall(endpoint, [
      { jsonrpc: "2.0", id: 1, method: "cirvix/status" },
      { jsonrpc: "2.0", id: 2, method: "cirvix/logs" },
    ]);
    for (const r of replies) assert.ok(r.error, "every pre-auth call is refused");
  } finally {
    await server.stop();
  }
});

test("socket: there is no method that returns credential material", async () => {
  const { server, endpoint, token } = await socket();
  try {
    const hello = await new UdsClient({ endpoint, token }).call("initialize", { token });
    for (const method of hello.methods) {
      assert.ok(!/vault|secret|resolve|reveal|dump|export/i.test(method), `"${method}" could return material`);
    }
    // And an invented one is not silently accepted.
    await assert.rejects(
      () => new UdsClient({ endpoint, token }).call("cirvix/vault.dump", {}),
      /Unknown method/,
    );
  } finally {
    await server.stop();
  }
});

/* ========================================================================== */
/*  LAYER 7 — RESILIENCE                                                      */
/* ========================================================================== */

test("resilience: a burst of concurrent decisions stays correct", async () => {
  const p = pipeline();
  const results = await Promise.all(
    Array.from({ length: 300 }, (_, i) =>
      p.submit(
        i % 2 === 0
          ? { tool: "read_file", arguments: { path: `${CWD}/src/app.ts` } }
          : { tool: "read_file", arguments: { path: "~/.aws/credentials" } },
      ),
    ),
  );

  const allowed = results.filter((r) => r.event.decision === DECISION.ALLOW);
  const denied = results.filter((r) => r.event.decision === DECISION.DENY);
  assert.equal(allowed.length, 150);
  assert.equal(denied.length, 150);

  // Every request id is distinct: a collision makes two calls one record.
  const ids = new Set(results.map((r) => r.event.request_id));
  assert.equal(ids.size, 300);
});

test("resilience: nothing in the corpus of hostile shapes throws", async () => {
  const p = pipeline();
  const hostile = [
    { tool: "read_file", arguments: { path: "\u0000" } },
    { tool: "read_file", arguments: { path: "\uD800" } },
    { tool: "read_file", arguments: { path: "%" } },
    { tool: "read_file", arguments: { path: "%%%%" } },
    { tool: "read_file", arguments: { path: "%ZZ" } },
    { tool: "read_file", arguments: { path: "../".repeat(10_000) } },
    { tool: "http_request", arguments: { url: "http://" } },
    { tool: "http_request", arguments: { url: "http://[" } },
    { tool: "http_request", arguments: { url: "http://999.999.999.999/" } },
    { tool: "shell_exec", arguments: { command: "\u0000\u0001" } },
    { tool: "\u0000", arguments: {} },
    { tool: "a".repeat(100_000), arguments: {} },
  ];

  for (const call of hostile) {
    const { event } = await p.submit(call);
    assert.ok(event.decision, `no decision for ${JSON.stringify(call).slice(0, 60)}`);
  }
});

test("resilience: the latency window is bounded so a long run cannot grow without limit", async () => {
  const p = pipeline();
  for (let i = 0; i < 300; i++) await p.submit({ tool: "git_status", arguments: {} });
  assert.ok(p.stats.latencies.length <= 10_000);
  assert.equal(p.stats.calls, 300, "the counter still counts everything");
});
