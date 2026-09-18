import test from "node:test";
import assert from "node:assert/strict";
import { Guard } from "../src/core/guard.mjs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Pipeline } from "../src/core/pipeline.mjs";
import { Gateway, fingerprintTool } from "../src/core/gateway.mjs";
import { normalize } from "../src/core/normalize.mjs";
import { MessageFramer, isRequest, isResponse, isNotification } from "../src/core/jsonrpc.mjs";
import { HttpUpstream, HttpGatewayServer } from "../src/core/http-transport.mjs";
import { KillSwitchEngine } from "../src/core/kill-switch.mjs";
import { createServer } from "node:net";
import { randomUUID } from "node:crypto";
import { UdsClient, UdsServer } from "../src/core/uds.mjs";
import { once } from "node:events";

const rules = [{ name: "read", effect: "permit", actions: ["fs.read"], resources: ["*"] }];
const call = { tool: "read_file", arguments: { path: "document.txt" } };

for (const [name, substitute] of [
  ["null", async () => null],
  ["truthy success", async () => ({ ok: "yes", value: {}, substituted: [] })],
  ["missing value", async () => ({ ok: true, substituted: [] })],
  ["exception", async () => { throw new Error("offline"); }],
]) {
  test(`Guard refuses invalid broker response: ${name}`, async () => {
    const records = [];
    const guard = new Guard({ rules, secrets: { substitute }, audit: { append: async (r) => records.push(r) } });
    const result = await guard.authorize(call);
    assert.equal(result.decision.verdict, "deny");
    assert.equal(result.decision.decision, "deny");
    assert.equal(result.decision.rule, "secret-broker");
    assert.equal(records.length, 1);
    assert.deepEqual(result.args, call.arguments);
  });
}

test("Guard returns a recorded refusal when audit storage fails", async () => {
  const guard = new Guard({ rules, audit: { append: async () => { throw new Error("offline"); } } });
  const result = await guard.authorize(call);
  assert.equal(result.decision.rule, "audit-unavailable");
  assert.equal(result.decision.verdict, "deny");
  assert.equal(result.record.audit_write_failed, true);
});

test("Guard and Pipeline use the same resource and argument policy context", async () => {
  const policy = [...rules, { name: "flag", effect: "forbid", actions: ["fs.read"], resources: ["*"], when: [{ path: "arguments.flag", op: "eq", value: true }] }];
  const input = { tool: "read_file", arguments: { content: "irrelevant", file_path: "document.txt", flag: true } };
  const g = await new Guard({ rules: policy }).authorize(input);
  const p = await new Pipeline({ rules: policy }).submit(input);
  assert.equal(g.decision.verdict, "deny");
  assert.equal(g.record.resource, p.event.resource);
  assert.equal(g.decision.rule, p.decision.rule);
  assert.equal(g.record.context.arguments, undefined);
});

test("Guard honors argument sanitization without a broker", async () => {
  const guard = new Guard({ rules: [...rules, { name: "clean", effect: "sanitize", actions: ["fs.read"], resources: ["*"], sanitize: { targets: ["arguments", "result"] } }] });
  const input = { ...call, arguments: { path: "document.txt", text: "AKIAIOSFODNN7EXAMPLE" } };
  const result = await guard.authorize(input);
  assert.equal(result.decision.decision, "sanitize");
  assert.doesNotMatch(JSON.stringify(result.args), /AKIAIOSFODNN7EXAMPLE/);
  assert.doesNotMatch(JSON.stringify(guard.scrub({ text: "AKIAIOSFODNN7EXAMPLE" }).payload), /AKIAIOSFODNN7EXAMPLE/);
});

test("normalization treats a localhost-prefixed DNS name as external", () => {
  assert.equal(normalize({ tool: "network.request", arguments: { url: "https://localhost.example.com" } }).egress, "external");
  assert.equal(normalize({ tool: "network.request", arguments: { url: "http://[::1]" } }).egress, "none");
});

for (const raw of [null, undefined, { method: "tools/call", params: { name: 42 } }, { ...call, request_id: 42 }]) {
  test(`Pipeline rejects malformed input ${JSON.stringify(raw)}`, async () => {
    const result = await new Pipeline({ rules }).submit(raw);
    assert.equal(result.decision.verdict, "deny");
    assert.equal(result.decision.decision, "deny");
    assert.match(result.event.decision_id, /^dec_/);
  });
}

test("Pipeline kill switch returns a defined denial and retains its decision id", async () => {
  const killSwitch = new KillSwitchEngine();
  killSwitch.arm({ scope: "agent", target: "local" });
  const result = await new Pipeline({ rules, killSwitch }).submit(call);
  assert.equal(result.decision.decision, "deny");
  assert.equal(result.decision.verdict, "deny");
  assert.match(result.event.decision_id, /^dec_/);
});

function gatewayRig(options = {}) {
  const output = [];
  const sent = [];
  const gw = new Gateway({ servers: {}, rules, ...options }).start((m) => output.push(m));
  const up = { name: "files", alive: true, tools: new Map(), send: (m) => { sent.push(m); return true; }, stop() {} };
  gw.upstreams.set("files", up);
  return { gw, up, sent, output };
}

test("Gateway enforces tool scope at invocation, not only listing", async () => {
  const { gw, sent, output } = gatewayRig({ scopeFor: () => [] });
  await gw.handleClientMessage({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "files__read_file", arguments: call.arguments } });
  assert.equal(sent.length, 0);
  assert.ok(output[0].error || output[0].result?.isError);
});

test("Gateway refuses a cached definition that no longer matches its pin", async () => {
  const { gw, up, sent, output } = gatewayRig({ pins: new Map([["files__read_file", fingerprintTool({ name: "read_file", description: "original" })]]) });
  up.tools.set("read_file", { fingerprint: fingerprintTool({ name: "read_file", description: "changed" }) });
  await gw.handleClientMessage({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "files__read_file", arguments: call.arguments } });
  assert.equal(sent.length, 0);
  assert.ok(output[0].error || output[0].result?.isError);
});

test("Gateway does not broadcast request-only methods as notifications", async () => {
  const { gw, sent } = gatewayRig();
  await gw.handleClientMessage({ jsonrpc: "2.0", method: "tools/call", params: { name: "read_file", arguments: call.arguments } });
  assert.equal(sent.length, 0);
});

test("Gateway validates malformed request parameters without throwing", async () => {
  const { gw, sent, output } = gatewayRig();
  await gw.handleClientMessage(null);
  await gw.handleClientMessage({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: 42 } });
  assert.equal(sent.length, 0);
  assert.equal(output.length, 2);
  assert.ok(output.every((m) => m.error));
});

test("JSON-RPC predicates reject invalid envelopes", () => {
  assert.equal(Boolean(isRequest({ jsonrpc: "2.0", id: {}, method: "ping" })), false);
  assert.equal(Boolean(isNotification({ jsonrpc: "2.0", method: 1 })), false);
  assert.equal(Boolean(isResponse({ jsonrpc: "2.0", id: 1 })), false);
  assert.equal(Boolean(isResponse({ jsonrpc: "2.0", id: 1, result: {}, error: {} })), false);
  assert.equal(Boolean(isResponse({ jsonrpc: "2.0", id: null, result: null })), true);
});

test("framing discards oversized lines and recovers at the next boundary", () => {
  const seen = [];
  const invalid = [];
  const framer = new MessageFramer({ maxFrameBytes: 64, onMessage: (m) => seen.push(m), onInvalid: (line, err) => invalid.push(err) });
  framer.push(Buffer.from(" ".repeat(65)));
  assert.equal(invalid.length, 1);
  framer.push(Buffer.from('continued\n{"jsonrpc":"2.0","id":1,"result":{}}\n'));
  framer.end();
  assert.equal(invalid.length, 1);
  assert.equal(seen.length, 1);
});

test("HTTP upstream probe refuses redirects and has a deadline", async () => {
  let options;
  const up = new HttpUpstream("mock", { url: "https://mcp.example.com", fetchImpl: async (url, opts) => { options = opts; return new Response(null, { status: 405 }); } });
  await up.start();
  up.stop();
  assert.equal(options.redirect, "error");
  assert.ok(options.signal);
});

test("HTTP upstream requests reject at the deadline instead of hanging on a stalled server", async () => {
  // The fetch deliberately ignores the abort signal and stalls far longer than
  // the deadline, so this asserts the deadline itself rather than a race.
  const stalled = async () => {
    await new Promise((resolve) => setTimeout(resolve, 500));
    return new Response(null, { status: 405 });
  };
  const up = new HttpUpstream("mock", { url: "https://mcp.example.com", timeoutMs: 50, fetchImpl: stalled });
  await up.start();
  try {
    const started = Date.now();
    await assert.rejects(() => up.request("tools/list", {}), /timed out|not running/i);
    assert.ok(Date.now() - started < 500, "the deadline must fire before the stalled fetch resolves");
  } finally {
    up.stop();
  }
});

test("an unauthenticated connection is refused promptly and never reaches the pipeline", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-uds-"));
  const endpoint = process.platform === "win32" ? `\\\\.\\pipe\\cirvix-test-${randomUUID()}` : join(dir, "test.sock");
  let consulted = 0;
  const server = new UdsServer({
    pipeline: {
      mode: "enforce",
      submit: async () => {
        consulted++;
        return {};
      },
    },
    endpoint,
    token: "secret-token",
  });
  await server.start();
  try {
    // The property this socket has to hold: without the token file there is no
    // decision, no hang, and no reachable pipeline.
    const client = new UdsClient({ endpoint, token: "wrong-token", timeoutMs: 3000 });
    const started = Date.now();
    await assert.rejects(() => client.call("cirvix/authorize", { tool: "read_file" }), /session token/i);
    assert.ok(Date.now() - started < 1500, "the refusal must be prompt, not a hang");
    assert.equal(consulted, 0, "an unauthenticated client must never reach a decision");
    assert.ok(server.stats.rejected >= 1);
  } finally {
    await server.stop();
  }
});
