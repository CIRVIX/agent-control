import { test } from "node:test";
import assert from "node:assert/strict";

import {
  canonicalizeResource,
  evaluate,
  matchGlob,
  parseRules,
  STARTER_RULES,
} from "../src/core/policy.mjs";

const ctx = (over = {}) => ({
  environment: "local",
  path: { insideWorkspace: true },
  egress: { external: false, allowlisted: false },
  session: { touchedSecret: false },
  ...over,
});

/* -------------------------------------------------------------------------- */
/*  The three load-bearing properties                                          */
/* -------------------------------------------------------------------------- */

test("forbid always wins, even when a permit matches first", () => {
  const rules = [
    { name: "permit-everything", effect: "permit", actions: ["*"], resources: ["*"] },
    {
      name: "deny-dotenv",
      effect: "forbid",
      actions: ["fs.read"],
      resources: ["**/.env*"],
      reason: "no",
    },
  ];
  const d = evaluate(
    { agent: "a", action: "fs.read", resource: "/repo/.env.production", context: ctx() },
    rules,
    { cwd: "/repo" },
  );
  assert.equal(d.verdict, "deny");
  assert.equal(d.rule, "deny-dotenv");
});

test("a request matching nothing is denied (default deny)", () => {
  const d = evaluate(
    { agent: "a", action: "exotic.action", resource: "thing", context: ctx() },
    [],
  );
  assert.equal(d.verdict, "deny");
  assert.equal(d.rule, null);
  assert.match(d.reason, /default-deny/);
});

test("a hold outranks a permit so a human is never skipped", () => {
  const rules = [
    { name: "allow-writes", effect: "permit", actions: ["db.write"], resources: ["*"] },
    {
      name: "hold-prod",
      effect: "hold",
      actions: ["db.write"],
      resources: ["*"],
      when: [{ path: "environment", op: "eq", value: "production" }],
      approvers: ["oncall"],
    },
  ];
  const d = evaluate(
    {
      agent: "a",
      action: "db.write",
      resource: "orders",
      context: ctx({ environment: "production" }),
    },
    rules,
  );
  assert.equal(d.verdict, "hold");
  assert.deepEqual(d.approvers, ["oncall"]);
});

/* -------------------------------------------------------------------------- */
/*  Canonicalization — the traversal bypass                                    */
/* -------------------------------------------------------------------------- */

test("path traversal cannot dodge a resource rule", () => {
  const rules = [
    { name: "deny-dotenv", effect: "forbid", actions: ["fs.read"], resources: ["**/.env*"] },
    { name: "allow", effect: "permit", actions: ["*"], resources: ["*"] },
  ];
  for (const attempt of [
    "/repo/.env",
    "/repo/src/../.env",
    "./.env",
    "src/../../repo/.env",
  ]) {
    const d = evaluate(
      { agent: "a", action: "fs.read", resource: attempt, context: ctx() },
      rules,
      { cwd: "/repo" },
    );
    assert.equal(d.verdict, "deny", `traversal not caught: ${attempt}`);
  }
});

test("urls canonicalize host case and trailing slash", () => {
  assert.equal(
    canonicalizeResource("HTTPS://API.Example.com/v1/"),
    "https://api.example.com/v1",
  );
});

/* -------------------------------------------------------------------------- */
/*  Glob safety                                                                */
/* -------------------------------------------------------------------------- */

test("a dot in a pattern is literal, not any-character", () => {
  assert.ok(matchGlob("fs.read", "fs.read"));
  assert.ok(!matchGlob("fs.read", "fsXread"), "an unescaped dot would widen the rule");
});

test("regex metacharacters in a pattern are literals", () => {
  for (const [pattern, near] of [
    ["a+b", "aab"],
    ["a(b)c", "abc"],
    ["a[bc]d", "abd"],
    ["a{2}", "aa"],
  ]) {
    assert.ok(!matchGlob(pattern, near), `"${pattern}" behaved as a regex against "${near}"`);
    assert.ok(matchGlob(pattern, pattern), `"${pattern}" no longer matches itself`);
  }
});

test("single star does not cross a path segment", () => {
  assert.ok(matchGlob("/repo/*", "/repo/file"));
  assert.ok(!matchGlob("/repo/*", "/repo/nested/file"));
  assert.ok(matchGlob("/repo/**", "/repo/nested/file"));
  assert.ok(matchGlob("**/.env", "/repo/nested/.env"));
  assert.ok(!matchGlob("**/.env", "/repo/xenv"));
});

test("a question mark matches one character but never a separator", () => {
  assert.ok(matchGlob("/a?c", "/abc"));
  assert.ok(!matchGlob("/a?c", "/ac"));
  assert.ok(!matchGlob("a?b", "a/b"));
});

test("matching is case-insensitive, as a rule author expects", () => {
  assert.ok(matchGlob("**/.ENV", "/repo/.env"));
  assert.ok(matchGlob("FS.READ", "fs.read"));
});

test("a hostile pattern cannot hang the evaluator", () => {
  // The regex implementation this replaced was exponential here. The pattern
  // comes from a rule and the input from whatever resource an agent named, so
  // a caller on the far side of the enforcement boundary picks the input —
  // and a hung evaluator is a hung gateway.
  const started = Date.now();
  for (const pattern of ["*a*a*a*a*a*a*a*a*a*b", "**a**a**a**a**a**b", "*".repeat(40) + "b"]) {
    assert.equal(matchGlob(pattern, "a".repeat(2000)), false);
  }
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 500, `hostile globs took ${elapsed}ms`);
});

/* -------------------------------------------------------------------------- */
/*  Conditions                                                                 */
/* -------------------------------------------------------------------------- */

test("an unknown operator fails closed rather than matching", () => {
  const rules = [
    {
      name: "bad",
      effect: "permit",
      actions: ["*"],
      resources: ["*"],
      when: [{ path: "environment", op: "definitelyNotAnOperator", value: "local" }],
    },
  ];
  const d = evaluate({ agent: "a", action: "x.read", resource: "y", context: ctx() }, rules);
  assert.equal(d.verdict, "deny");
});

test("conditions are data, never evaluated as code", () => {
  const rules = [
    {
      name: "injection-attempt",
      effect: "permit",
      actions: ["*"],
      resources: ["*"],
      when: [{ path: "environment", op: "eq", value: "local" }],
    },
  ];
  // A value that would be catastrophic if the engine ever ran expressions.
  const d = evaluate(
    {
      agent: "a",
      action: "x.read",
      resource: "y",
      context: ctx({ environment: "process.exit(1)" }),
    },
    rules,
  );
  assert.equal(d.verdict, "deny", "no expression evaluation, so no match");
});

/* -------------------------------------------------------------------------- */
/*  Starter rules behave as advertised                                         */
/* -------------------------------------------------------------------------- */

test("starter rules deny reading .env.production", () => {
  const d = evaluate(
    {
      agent: "pr-triage",
      action: "fs.read",
      resource: "/repo/.env.production",
      context: ctx(),
    },
    STARTER_RULES,
    { cwd: "/repo" },
  );
  assert.equal(d.verdict, "deny");
  assert.equal(d.rule, "deny-dotenv-read");
  assert.match(d.remediation, /secrets\.get/);
});

test("starter rules permit an ordinary workspace read", () => {
  const d = evaluate(
    { agent: "pr-triage", action: "fs.read", resource: "/repo/src/index.ts", context: ctx() },
    STARTER_RULES,
    { cwd: "/repo" },
  );
  assert.equal(d.verdict, "permit");
});

test("starter rules deny reading outside the workspace", () => {
  const d = evaluate(
    {
      agent: "pr-triage",
      action: "fs.read",
      resource: "/etc/passwd",
      context: ctx({ path: { insideWorkspace: false } }),
    },
    STARTER_RULES,
    { cwd: "/repo" },
  );
  assert.equal(d.verdict, "deny");
  assert.equal(d.rule, "deny-workspace-escape");
});

test("starter rules hold a production deploy for a human", () => {
  const d = evaluate(
    {
      agent: "deploy-bot",
      action: "k8s.apply",
      resource: "production/checkout",
      context: ctx({ environment: "production" }),
    },
    STARTER_RULES,
  );
  assert.equal(d.verdict, "hold");
  assert.deepEqual(d.approvers, ["platform-oncall"]);
});

test("starter rules block egress after the session touched a secret", () => {
  const d = evaluate(
    {
      agent: "scraper",
      action: "http.request",
      resource: "https://evil.example/collect",
      context: ctx({
        egress: { external: true, allowlisted: true },
        session: { touchedSecret: true },
      }),
    },
    STARTER_RULES,
  );
  assert.equal(d.verdict, "deny");
  assert.equal(d.rule, "deny-external-egress-after-secret");
});

/* -------------------------------------------------------------------------- */
/*  Parsing                                                                    */
/* -------------------------------------------------------------------------- */

test("parseRules rejects an unknown effect", () => {
  assert.throws(
    () => parseRules([{ name: "x", effect: "maybe", actions: ["*"] }]),
    /expected permit, forbid, hold, sanitize, audit_only/,
  );
});

test("parseRules rejects an unknown operator", () => {
  assert.throws(
    () => parseRules([{ name: "x", effect: "permit", when: [{ path: "a", op: "zzz" }] }]),
    /unknown operator/,
  );
});

test("every decision explains itself", () => {
  const d = evaluate(
    { agent: "a", action: "fs.read", resource: "/repo/.env", context: ctx() },
    STARTER_RULES,
    { cwd: "/repo" },
  );
  assert.ok(d.reason.length > 0);
  assert.ok(Array.isArray(d.considered) && d.considered.length > 0);
  assert.ok(d.considered.some((c) => c.matched));
});
