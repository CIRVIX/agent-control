/**
 * Testing a rule set like code.
 *
 * Run from the repository root:
 *   node --test docs/examples/policy.test.mjs
 *
 * A rule set decides what an agent may do. It deserves unit tests that run in
 * CI next to everything else, because the failure mode of an untested policy is
 * not a broken build — it is a permission nobody meant to grant, discovered
 * later.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { evaluate, expectNoLoosening } from "../../packages/agent-control/src/testing.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const POLICY = join(HERE, "cirvix.policy.json");

/* -------------------------------------------------------------------------- */
/*  The guardrails hold                                                        */
/* -------------------------------------------------------------------------- */

test("reading a .env file is refused, with a way forward", async () => {
  const d = await evaluate({
    policyFile: POLICY,
    action: "fs.read",
    resource: ".env.production",
  });

  assert.equal(d.verdict, "deny");
  assert.equal(d.rule, "deny-dotenv-read");
  // The remediation is the part that lets an agent re-plan instead of
  // retrying the same call until it gives up.
  assert.match(d.remediation, /handle/);
});

test("traversal does not get around the .env rule", async () => {
  // `./src/../.env` and `.env` are one resource. A rule that matched raw
  // strings would be bypassed by the first agent that used a relative path.
  const d = await evaluate({
    policyFile: POLICY,
    action: "fs.read",
    resource: "./src/../.env",
  });

  assert.equal(d.verdict, "deny");
  assert.equal(d.rule, "deny-dotenv-read");
});

test("a permit cannot punch through a forbid", async () => {
  // `allow-read-only-tools` matches `fs.read` too. Forbid wins regardless of
  // order, which is what makes the rule set safe to extend.
  const d = await evaluate({
    policyFile: POLICY,
    action: "fs.read",
    resource: "~/.aws/credentials",
    context: { path: { insideWorkspace: false } },
  });

  assert.equal(d.verdict, "deny");
});

/* -------------------------------------------------------------------------- */
/*  Holds reach a person                                                       */
/* -------------------------------------------------------------------------- */

test("production deploys wait for a named human", async () => {
  const d = await evaluate({
    policyFile: POLICY,
    agent: "deploy-bot",
    action: "k8s.apply",
    resource: "production/checkout",
    context: { environment: "production" },
  });

  assert.equal(d.verdict, "hold");
  assert.equal(d.rule, "hold-production-changes");
  assert.ok(d.approvers.includes("platform-oncall"));
});

test("the same deploy in staging is not held", async () => {
  const d = await evaluate({
    policyFile: POLICY,
    agent: "deploy-bot",
    action: "k8s.apply",
    resource: "staging/checkout",
    context: { environment: "staging" },
  });

  // No rule permits k8s.apply outside production either — default deny is the
  // point. Assert what is true rather than what would be convenient.
  assert.equal(d.verdict, "deny");
  assert.equal(d.rule, null);
});

test("an experimental agent has every call reviewed", async () => {
  const d = await evaluate({
    policyFile: POLICY,
    agent: "experimental-triage",
    action: "fs.read",
    resource: "src/index.ts",
  });

  // A hold outranks a permit: `allow-workspace-read` matches, and is not
  // allowed to quietly skip the reviewer.
  assert.equal(d.verdict, "hold");
  assert.equal(d.rule, "hold-untrusted-agents");
});

/* -------------------------------------------------------------------------- */
/*  Ordinary work is not interrupted                                           */
/* -------------------------------------------------------------------------- */

test("reading inside the workspace is permitted", async () => {
  const d = await evaluate({
    policyFile: POLICY,
    action: "fs.read",
    resource: "src/index.ts",
  });

  assert.equal(d.verdict, "permit");
  assert.equal(d.rule, "allow-workspace-read");
});

/* -------------------------------------------------------------------------- */
/*  Session state                                                              */
/* -------------------------------------------------------------------------- */

test("a session that read a secret cannot then post outside", async () => {
  const d = await evaluate({
    policyFile: POLICY,
    action: "http.request",
    resource: "https://api.example.net/collect",
    context: {
      egress: { external: true, allowlisted: true },
      session: { touchedSecret: true },
    },
  });

  // Allowlisted *and* still denied — this is the rule that makes "read a
  // credential, then post it somewhere" fail even when both calls are
  // individually fine.
  assert.equal(d.verdict, "deny");
  assert.equal(d.rule, "deny-external-egress-after-secret");
});

/* -------------------------------------------------------------------------- */
/*  Gating a policy change                                                     */
/* -------------------------------------------------------------------------- */

test("a candidate rule set does not quietly permit more than the current one", async () => {
  const CALLS = [
    { action: "fs.read", resource: ".env.production" },
    { action: "fs.read", resource: "~/.ssh/id_rsa", context: { path: { insideWorkspace: false } } },
    { action: "shell.exec", resource: "postgres://prod-db/orders" },
    {
      action: "k8s.apply",
      resource: "production/checkout",
      context: { environment: "production" },
    },
  ];

  const { ok, loosened } = await expectNoLoosening({
    before: { policyFile: POLICY },
    after: { policyFile: POLICY },
    calls: CALLS,
  });

  assert.ok(ok, `these calls became more permissive: ${JSON.stringify(loosened)}`);
});
