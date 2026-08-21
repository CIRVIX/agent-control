import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Daemon } from "../src/core/daemon.mjs";

const dir = () => mkdtemp(join(tmpdir(), "cirvix-daemon-"));

/**
 * A scriptable control plane. `handlers` maps "METHOD /path" to a function;
 * anything unmapped 404s, and `offline` makes every call throw the way a real
 * network failure does.
 */
function mockPlane({ handlers = {}, offline = false } = {}) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    const path = new URL(url).pathname;
    const key = `${init.method ?? "GET"} ${path}`;
    calls.push({ key, body: init.body ? JSON.parse(init.body) : null });
    if (offline) throw new Error("ECONNREFUSED");
    const generic = Object.keys(handlers).find(
      (h) => h.includes(":") && new RegExp("^" + h.replace(/:[a-z]+/gi, "[^/]+") + "$").test(key),
    );
    const handler = handlers[key] ?? (generic ? handlers[generic] : undefined);
    if (!handler) return { ok: false, status: 404, text: async () => "not found" };
    const result = await handler(init.body ? JSON.parse(init.body) : null);
    return { ok: true, status: 200, json: async () => result, text: async () => JSON.stringify(result) };
  };
  return { fetchImpl, calls };
}

const BASE_HANDLERS = {
  "POST /v1/endpoints": () => ({ id: "ep_test" }),
  "POST /v1/endpoints/:id/heartbeat": () => ({ policyVersion: 1, policyStale: true }),
  "GET /v1/policy": () => ({
    version: 1,
    rules: [{ name: "deny-env", effect: "forbid", actions: ["fs.read"] }],
  }),
  "POST /v1/decisions": () => ({ accepted: 1 }),
};

/* -------------------------------------------------------------------------- */

test("registers, heartbeats, and pulls policy on first start", async () => {
  const stateDir = await dir();
  const { fetchImpl, calls } = mockPlane({ handlers: BASE_HANDLERS });
  const d = new Daemon({ apiUrl: "http://cp.test", apiKey: "cvx_x", stateDir, fetchImpl });

  await d.start();
  d.stop();

  assert.ok(calls.some((c) => c.key === "POST /v1/endpoints"));
  assert.ok(calls.some((c) => c.key.startsWith("POST /v1/endpoints/")));
  assert.ok(calls.some((c) => c.key === "GET /v1/policy"));
  assert.equal(d.policy.version, 1);
  assert.equal(d.currentRules().length, 1);
});

test("policy is cached to disk and enforced without the network", async () => {
  const stateDir = await dir();

  const first = new Daemon({
    apiUrl: "http://cp.test",
    apiKey: "cvx_x",
    stateDir,
    fetchImpl: mockPlane({ handlers: BASE_HANDLERS }).fetchImpl,
  });
  await first.start();
  first.stop();

  // Cold start with the control plane unreachable.
  const offline = new Daemon({
    apiUrl: "http://cp.test",
    apiKey: "cvx_x",
    stateDir,
    fetchImpl: mockPlane({ offline: true }).fetchImpl,
  });
  await offline.start();
  offline.stop();

  assert.equal(offline.online, false, "should know it is offline");
  assert.equal(
    offline.currentRules().length,
    1,
    "must still enforce from cache — this is the whole design",
  );
});

test("a sync failure never throws and never clears the policy", async () => {
  const stateDir = await dir();
  const d = new Daemon({
    apiUrl: "http://cp.test",
    apiKey: "cvx_x",
    stateDir,
    fetchImpl: mockPlane({ offline: true }).fetchImpl,
  });
  await d.start();
  await d.tick();
  d.stop();

  assert.equal(d.online, false);
  assert.ok(d.stats.failures >= 1);
  assert.deepEqual(d.currentRules(), [], "no policy yet, but no crash either");
});

test("decisions spool to disk and survive being offline", async () => {
  const stateDir = await dir();
  const d = new Daemon({
    apiUrl: "http://cp.test",
    apiKey: "cvx_x",
    stateDir,
    fetchImpl: mockPlane({ offline: true }).fetchImpl,
  });
  await d.start();

  await d.record({ decision_id: "d1", verdict: "deny" });
  await d.record({ decision_id: "d2", verdict: "permit" });
  await d.tick();
  d.stop();

  const spool = await readFile(join(stateDir, "spool.jsonl"), "utf8");
  assert.equal(spool.trim().split("\n").length, 2, "records must not be lost while offline");
});

test("the spool drains when connectivity returns", async () => {
  const stateDir = await dir();
  const shipped = [];

  const offlineDaemon = new Daemon({
    apiUrl: "http://cp.test",
    apiKey: "cvx_x",
    stateDir,
    fetchImpl: mockPlane({ offline: true }).fetchImpl,
  });
  await offlineDaemon.start();
  await offlineDaemon.record({ decision_id: "d1", verdict: "deny" });
  await offlineDaemon.record({ decision_id: "d2", verdict: "hold" });
  offlineDaemon.stop();

  const online = new Daemon({
    apiUrl: "http://cp.test",
    apiKey: "cvx_x",
    stateDir,
    fetchImpl: mockPlane({
      handlers: {
        ...BASE_HANDLERS,
        "POST /v1/decisions": (body) => {
          shipped.push(...body.decisions);
          return { accepted: body.decisions.length };
        },
      },
    }).fetchImpl,
  });
  await online.start();
  online.stop();

  assert.equal(shipped.length, 2);
  assert.deepEqual(
    shipped.map((d) => d.decision_id).sort(),
    ["d1", "d2"],
  );
  const spool = await readFile(join(stateDir, "spool.jsonl"), "utf8");
  assert.equal(spool.trim(), "", "shipped records are cleared from the spool");
});

test("a corrupt spool line does not wedge the queue", async () => {
  const stateDir = await dir();
  await writeFile(
    join(stateDir, "spool.jsonl"),
    '{"decision_id":"good","verdict":"deny"}\n{broken\n',
    "utf8",
  );
  const shipped = [];
  const d = new Daemon({
    apiUrl: "http://cp.test",
    apiKey: "cvx_x",
    stateDir,
    fetchImpl: mockPlane({
      handlers: {
        ...BASE_HANDLERS,
        "POST /v1/decisions": (body) => {
          shipped.push(...body.decisions);
          return { accepted: body.decisions.length };
        },
      },
    }).fetchImpl,
  });
  await d.start();
  d.stop();

  assert.equal(shipped.length, 1);
  assert.equal(shipped[0].decision_id, "good");
});

test("a lower policy version is refused, so a replay cannot weaken enforcement", async () => {
  const stateDir = await dir();
  let version = 5;
  const d = new Daemon({
    apiUrl: "http://cp.test",
    apiKey: "cvx_x",
    stateDir,
    fetchImpl: mockPlane({
      handlers: {
        ...BASE_HANDLERS,
        "GET /v1/policy": () => ({
          version,
          rules: version === 5 ? [{ name: "strict", effect: "forbid" }] : [],
        }),
      },
    }).fetchImpl,
  });

  await d.start();
  assert.equal(d.policy.version, 5);
  assert.equal(d.currentRules().length, 1);

  // The control plane now answers with an older, emptier policy.
  version = 2;
  await d.tick();
  d.stop();

  assert.equal(d.policy.version, 5, "must not roll back");
  assert.equal(d.currentRules().length, 1, "enforcement must not weaken");
});

test("endpoint identity persists across restarts", async () => {
  const stateDir = await dir();
  const mk = () =>
    new Daemon({
      apiUrl: "http://cp.test",
      apiKey: "cvx_x",
      stateDir,
      fetchImpl: mockPlane({ handlers: BASE_HANDLERS }).fetchImpl,
    });

  const a = mk();
  await a.start();
  a.stop();
  const id = a.endpointId;

  const b = mk();
  await b.start();
  b.stop();

  assert.equal(b.endpointId, id, "must not re-register and fragment the fleet list");
});

test("a malformed policy from the control plane is rejected", async () => {
  const stateDir = await dir();
  const d = new Daemon({
    apiUrl: "http://cp.test",
    apiKey: "cvx_x",
    stateDir,
    fetchImpl: mockPlane({
      handlers: { ...BASE_HANDLERS, "GET /v1/policy": () => ({ version: 9, rules: "not-an-array" }) },
    }).fetchImpl,
  });
  await d.start();
  d.stop();

  assert.equal(d.policy.version, 0);
  assert.equal(d.online, false, "a bad policy response counts as a failed sync");
});

/* -------------------------------------------------------------------------- */
/*  Shutdown flush — regression                                                */
/* -------------------------------------------------------------------------- */

test("shutdown flushes the spool so a short-lived run does not strand telemetry", async () => {
  const stateDir = await dir();
  const shipped = [];
  const plane = mockPlane({
    handlers: {
      ...BASE_HANDLERS,
      "POST /v1/decisions": (body) => {
        shipped.push(...body.decisions);
        return { accepted: body.decisions.length };
      },
    },
  });

  const d = new Daemon({
    apiUrl: "http://cp.test",
    apiKey: "cvx_x",
    stateDir,
    // Longer than the test, so only an explicit flush can ship these.
    intervalMs: 600_000,
    fetchImpl: plane.fetchImpl,
  });
  await d.start();

  await d.record({ decision_id: "d1", verdict: "deny" });
  await d.record({ decision_id: "d2", verdict: "permit" });

  // This is the bug this test exists for: a gateway that exits between ticks
  // used to leave both records on disk indefinitely.
  const flushed = await d.shutdown();

  assert.equal(flushed, true);
  assert.equal(shipped.length, 2, "records must ship before the process exits");
  const spool = await readFile(join(stateDir, "spool.jsonl"), "utf8");
  assert.equal(spool.trim(), "", "the spool is cleared once accepted");
});

test("shutdown while offline keeps the spool rather than dropping it", async () => {
  const stateDir = await dir();
  const d = new Daemon({
    apiUrl: "http://cp.test",
    apiKey: "cvx_x",
    stateDir,
    fetchImpl: mockPlane({ offline: true }).fetchImpl,
  });
  await d.start();
  await d.record({ decision_id: "d1", verdict: "deny" });

  const flushed = await d.shutdown();
  assert.equal(flushed, false, "an offline flush reports failure rather than throwing");

  const spool = await readFile(join(stateDir, "spool.jsonl"), "utf8");
  assert.match(spool, /d1/, "records survive for the next start");
});

test("shutdown is idempotent", async () => {
  const stateDir = await dir();
  const d = new Daemon({
    apiUrl: "http://cp.test",
    apiKey: "cvx_x",
    stateDir,
    fetchImpl: mockPlane({ handlers: BASE_HANDLERS }).fetchImpl,
  });
  await d.start();
  await d.shutdown();
  await d.shutdown(); // must not throw
  assert.ok(true);
});
