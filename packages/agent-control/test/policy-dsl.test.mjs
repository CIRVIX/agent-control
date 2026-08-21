import test from "node:test";
import assert from "node:assert/strict";

import { compile, parse, toSource, anchor, PolicySyntaxError } from "../src/core/policy-dsl.mjs";
import { evaluate, validateRules } from "../src/core/policy.mjs";
import { normalize, policyRequest } from "../src/core/normalize.mjs";
import { DECISION, EFFECT, toDecision } from "../src/core/decisions.mjs";

const CWD = process.platform === "win32" ? "C:/workspace" : "/workspace";

function decide(source, call, ctx = {}) {
  const { rules } = compile(source, { cwd: CWD, origin: "test" });
  const normalized = normalize(call, { cwd: CWD, agent: "test", ...ctx });
  const result = evaluate(policyRequest(normalized), rules, { cwd: CWD });
  return result.decision ?? toDecision(result.verdict);
}

/* -------------------------------------------------------------------------- */
/*  The syntax from the specification                                          */
/* -------------------------------------------------------------------------- */

test("the specification's example compiles", () => {
  const { rules } = compile(
    `
allow:
  tool = git.status

allow:
  tool = filesystem.read
  path = ./src/**

deny:
  tool = shell.exec
  command = "rm -rf"

deny:
  network.destination = 169.254.169.254

require_approval:
  tool = database.write

require_approval:
  tool = shell.exec
  risk >= HIGH
`,
    { cwd: CWD, origin: "test" },
  );

  assert.equal(rules.length, 6);
  assert.equal(validateRules(rules).ok, true);
  assert.deepEqual(
    rules.map((r) => r.effect),
    [EFFECT.PERMIT, EFFECT.PERMIT, EFFECT.FORBID, EFFECT.FORBID, EFFECT.HOLD, EFFECT.HOLD],
  );
});

test("`risk >= HIGH` compiles to membership, not a new comparator", () => {
  // The Node and Python engines share a conformance fixture. Adding an operator
  // to one is how they drift.
  const { rules } = compile("require_approval:\n  tool = shell.exec\n  risk >= HIGH\n", { cwd: CWD });
  const condition = rules[0].when[0];
  assert.equal(condition.path, "risk");
  assert.equal(condition.op, "in");
  assert.deepEqual(condition.value, ["high", "critical"]);
});

test("every risk comparator produces the right subset", () => {
  const subset = (expr) =>
    compile(`deny:\n  tool = shell.exec\n  ${expr}\n`, { cwd: CWD }).rules[0].when[0].value;
  assert.deepEqual(subset("risk >= MEDIUM"), ["medium", "high", "critical"]);
  assert.deepEqual(subset("risk > MEDIUM"), ["high", "critical"]);
  assert.deepEqual(subset("risk <= MEDIUM"), ["low", "medium"]);
  assert.deepEqual(subset("risk < MEDIUM"), ["low"]);
  assert.deepEqual(subset("risk = CRITICAL"), ["critical"]);
  assert.deepEqual(subset("risk != CRITICAL"), ["low", "medium", "high"]);
});

test('`command = "rm -rf"` means contains, and crosses path separators', () => {
  // Compiled with a single `*`, this matched `rm -rf` and NOT `rm -rf /` —
  // the rule protecting against the canonical destructive command was the one
  // case it let through.
  const source = 'deny:\n  tool = shell.exec\n  command = "rm -rf"\n';
  assert.equal(decide(source, { tool: "shell_exec", arguments: { command: "rm -rf /" } }), DECISION.DENY);
  assert.equal(
    decide(source, { tool: "shell_exec", arguments: { command: "sudo rm -rf /var/lib/x" } }),
    DECISION.DENY,
  );
});

test("a destination match crosses separators too", () => {
  const source = "deny:\n  network.destination = 169.254.169.254\n";
  assert.equal(
    decide(source, {
      tool: "http_request",
      arguments: { url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/" },
    }),
    DECISION.DENY,
  );
});

/* -------------------------------------------------------------------------- */
/*  Aliases and anchoring                                                      */
/* -------------------------------------------------------------------------- */

test("filesystem.read and fs.read are the same rule", () => {
  const a = compile("allow:\n  tool = filesystem.read\n", { cwd: CWD }).rules[0];
  const b = compile("allow:\n  tool = fs.read\n", { cwd: CWD }).rules[0];
  assert.deepEqual(a.actions, b.actions);
});

test("a relative path anchors to the workspace", () => {
  const { rules } = compile("allow:\n  tool = filesystem.read\n  path = ./src/**\n", { cwd: CWD });
  assert.equal(rules[0].resources[0], `${CWD}/src/**`);
});

test("absolute paths and glob prefixes are left alone", () => {
  assert.equal(anchor("**/.env", CWD), "**/.env");
  assert.equal(anchor("/etc/passwd", CWD), "/etc/passwd");
  assert.equal(anchor("https://example.com/x", CWD), "https://example.com/x");
  assert.equal(anchor("~/.aws/credentials", CWD), "**/.aws/credentials");
});

test("an anchored rule matches a call inside the workspace", () => {
  const source = "allow:\n  tool = filesystem.read\n  path = ./src/**\n";
  assert.equal(
    decide(source, { tool: "read_file", arguments: { path: `${CWD}/src/deep/a.ts` } }),
    DECISION.ALLOW,
  );
  assert.equal(
    decide(source, { tool: "read_file", arguments: { path: `${CWD}/other/a.ts` } }),
    DECISION.DENY,
  );
});

/* -------------------------------------------------------------------------- */
/*  Precedence                                                                 */
/* -------------------------------------------------------------------------- */

test("deny beats allow regardless of order", () => {
  const denyFirst = "deny:\n  tool = filesystem.read\n  path = **/.env\nallow:\n  tool = filesystem.read\n";
  const allowFirst = "allow:\n  tool = filesystem.read\ndeny:\n  tool = filesystem.read\n  path = **/.env\n";
  const call = { tool: "read_file", arguments: { path: `${CWD}/.env` } };
  assert.equal(decide(denyFirst, call), DECISION.DENY);
  assert.equal(decide(allowFirst, call), DECISION.DENY);
});

test("require_approval outranks allow", () => {
  const source = "allow:\n  tool = database.write\nrequire_approval:\n  tool = database.write\n";
  assert.equal(decide(source, { tool: "database.write", arguments: {} }), DECISION.REQUIRE_APPROVAL);
});

test("sanitize outranks allow", () => {
  const source = "allow:\n  tool = network.request\nsanitize:\n  tool = network.request\n  targets = result\n";
  assert.equal(
    decide(source, { tool: "http_request", arguments: { url: "https://example.com/x" } }),
    DECISION.SANITIZE,
  );
});

test("a sanitizer alone does not authorize", () => {
  // Cleaning an authorized call is not the same as authorizing one.
  const source = "sanitize:\n  tool = network.request\n  targets = result\n";
  assert.equal(
    decide(source, { tool: "http_request", arguments: { url: "https://example.com/x" } }),
    DECISION.DENY,
  );
});

test("audit_only never authorizes", () => {
  const source = "audit_only:\n  tool = filesystem.read\n  path = **/.env\n";
  assert.equal(decide(source, { tool: "read_file", arguments: { path: `${CWD}/.env` } }), DECISION.DENY);
});

test("audit_only cannot punch through a deny", () => {
  const source =
    "deny:\n  tool = filesystem.read\n  path = **/.env\naudit_only:\n  tool = filesystem.read\n  path = **/.env\nallow:\n  tool = filesystem.read\n";
  assert.equal(decide(source, { tool: "read_file", arguments: { path: `${CWD}/.env` } }), DECISION.DENY);
});

/* -------------------------------------------------------------------------- */
/*  Errors                                                                     */
/* -------------------------------------------------------------------------- */

test("a block with no conditions is a compile error", () => {
  // It would match every call, which on an `allow` is catastrophic.
  assert.throws(() => compile("allow:\n  name = everything\n", { cwd: CWD }), PolicySyntaxError);
});

test("an unknown block is rejected with the list of valid ones", () => {
  assert.throws(() => compile("maybe:\n  tool = x\n", { cwd: CWD }), /Unknown block "maybe"/);
});

test("an unknown attribute is rejected", () => {
  assert.throws(() => compile("allow:\n  frobnicate = x\n", { cwd: CWD }), /Unknown attribute/);
});

test("an unknown risk level is rejected", () => {
  assert.throws(() => compile("deny:\n  tool = shell.exec\n  risk >= SPICY\n", { cwd: CWD }), /Unknown risk level/);
});

test("an attribute with no block above it is rejected", () => {
  assert.throws(() => compile("  tool = git.status\n", { cwd: CWD }), /no block above it/);
});

test("errors name the line", () => {
  try {
    compile("allow:\n  tool = git.status\n\nmaybe:\n  tool = x\n", { cwd: CWD });
    assert.fail("should have thrown");
  } catch (err) {
    assert.equal(err.line, 4);
  }
});

/* -------------------------------------------------------------------------- */
/*  Comments, quoting, tests                                                   */
/* -------------------------------------------------------------------------- */

test("comments and blank lines are ignored", () => {
  const { rules } = compile("# a comment\n\nallow:\n  # another\n  tool = git.status\n", { cwd: CWD });
  assert.equal(rules.length, 1);
});

test("a quoted value keeps its spaces and its hash", () => {
  const { rules } = compile('deny:\n  tool = shell.exec\n  command = "rm -rf # danger"\n', { cwd: CWD });
  assert.ok(rules[0].when[0].value.includes("# danger"));
});

test("an unquoted trailing comment is stripped", () => {
  const { rules } = compile("allow:\n  tool = git.status # read only\n", { cwd: CWD });
  assert.equal(rules[0].actions[0], "vcs.read");
});

test("test blocks compile into runnable cases", () => {
  const { tests } = compile(
    'test "dotenv is denied":\n  tool = filesystem.read\n  path = .env\n  expect deny\n',
    { cwd: CWD },
  );
  assert.equal(tests.length, 1);
  assert.equal(tests[0].name, "dotenv is denied");
  assert.equal(tests[0].expect, "deny");
  assert.equal(tests[0].call.tool, "filesystem.read");
});

test("a test with no expect is an error", () => {
  assert.throws(
    () => compile('test "x":\n  tool = filesystem.read\n', { cwd: CWD }),
    /has no `expect` line/,
  );
});

test("`expect` outside a test block is an error", () => {
  assert.throws(() => compile("allow:\n  tool = git.status\n  expect allow\n", { cwd: CWD }), /only valid inside/);
});

/* -------------------------------------------------------------------------- */
/*  Round trip                                                                 */
/* -------------------------------------------------------------------------- */

test("rules render back to source that compiles to the same rules", () => {
  const original = `
deny:
  tool = filesystem.read
  path = **/.env

require_approval:
  tool = shell.exec
  risk >= HIGH
  approvers = oncall

allow:
  tool = git.status
`;
  const first = compile(original, { cwd: CWD, origin: "a" }).rules;
  const rendered = toSource(first, { cwd: CWD });
  const second = compile(rendered, { cwd: CWD, origin: "b" }).rules;

  assert.deepEqual(
    second.map((r) => ({ effect: r.effect, actions: r.actions, resources: r.resources })),
    first.map((r) => ({ effect: r.effect, actions: r.actions, resources: r.resources })),
  );
});

/* -------------------------------------------------------------------------- */
/*  Names                                                                      */
/* -------------------------------------------------------------------------- */

test("rule names are generated and unique", () => {
  const { rules } = compile(
    "allow:\n  tool = git.status\nallow:\n  tool = git.status\nallow:\n  tool = git.status\n",
    { cwd: CWD },
  );
  const names = rules.map((r) => r.name);
  assert.equal(new Set(names).size, 3, "duplicate names make decision records ambiguous");
});

test("an explicit name wins", () => {
  const { rules } = compile("allow:\n  name = my-rule\n  tool = git.status\n", { cwd: CWD });
  assert.equal(rules[0].name, "my-rule");
});

/* -------------------------------------------------------------------------- */
/*  Validation                                                                 */
/* -------------------------------------------------------------------------- */

test("validation flags a duplicate rule name", () => {
  const result = validateRules([
    { name: "x", effect: "permit", actions: ["a"] },
    { name: "x", effect: "forbid", actions: ["b"] },
  ]);
  assert.equal(result.ok, false);
  assert.match(result.errors[0].message, /Duplicate rule name/);
});

test("validation warns about an unbounded permit", () => {
  const result = validateRules([{ name: "everything", effect: "permit" }]);
  assert.ok(result.warnings.some((w) => /every agent, action, and resource/.test(w.message)));
});

test("validation warns that audit_only authorizes nothing", () => {
  const result = validateRules([{ name: "watch", effect: "audit_only", actions: ["fs.read"] }]);
  assert.ok(result.warnings.some((w) => /never authorizes/.test(w.message)));
});

test("validation rejects an `in` with a non-array value", () => {
  const result = validateRules([
    { name: "x", effect: "permit", when: [{ path: "a", op: "in", value: "not-an-array" }] },
  ]);
  assert.equal(result.ok, false);
  assert.match(result.errors[0].message, /needs an array/);
});

/* -------------------------------------------------------------------------- */

test("parse separates rules from tests", () => {
  const { blocks, tests } = parse('allow:\n  tool = git.status\n\ntest "x":\n  tool = git.status\n  expect allow\n');
  assert.equal(blocks.length, 1);
  assert.equal(tests.length, 1);
});
