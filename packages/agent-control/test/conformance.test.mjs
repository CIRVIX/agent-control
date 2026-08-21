import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { evaluate } from "../src/core/policy.mjs";
import { intersectScopes, isNarrowing, scopePermits } from "../src/core/delegation.mjs";

/**
 * The shared conformance suite, run against the Node engine.
 *
 * `packages/cirvix-python` runs the same file against the Python engine. The
 * file is the contract; neither implementation is allowed a private copy of
 * it, because the entire value is that a case cannot be made to pass in one
 * language and quietly skipped in the other.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(HERE, "..", "..", "conformance", "policy-conformance.json");

const suite = JSON.parse(await readFile(FIXTURE, "utf8"));

test("the conformance fixture is present and non-trivial", () => {
  // A suite that silently loads zero cases passes forever.
  assert.equal(suite.version, 1);
  assert.ok(suite.cases.length >= 40, `only ${suite.cases.length} conformance cases`);
  const names = suite.cases.map((c) => c.name);
  assert.equal(new Set(names).size, names.length, "duplicate case names");
});

for (const testCase of suite.cases) {
  test(`conformance (node): ${testCase.name}`, () => {
    const decision = evaluate(
      {
        agent: testCase.request.agent,
        action: testCase.request.action,
        resource: testCase.request.resource,
        context: testCase.request.context ?? {},
      },
      testCase.rules,
      { cwd: testCase.cwd },
    );

    assert.equal(decision.verdict, testCase.expect.verdict, "verdict");
    assert.equal(decision.rule ?? null, testCase.expect.rule ?? null, "rule");

    // The five-outcome vocabulary. Asserted only when the case names it, so
    // the pre-existing cases keep testing exactly what they tested before.
    if (testCase.expect.decision !== undefined) {
      assert.equal(decision.decision, testCase.expect.decision, "decision");
    }

    if (testCase.expect.resource !== undefined) {
      assert.equal(decision.resource, testCase.expect.resource, "canonical resource");
    }
    if (testCase.expect.approvers !== undefined) {
      assert.deepEqual(decision.approvers ?? [], testCase.expect.approvers, "approvers");
    }
    if (testCase.expect.considered !== undefined) {
      assert.deepEqual(
        decision.considered.map((c) => ({ rule: c.rule, effect: c.effect, matched: c.matched })),
        testCase.expect.considered,
        "rule trace",
      );
    }
  });
}

/* ========================================================================== */
/*  Capabilities and the delegation section                                    */
/* ========================================================================== */

/**
 * An engine that implements a layer must run that layer's cases.
 *
 * The fixture declares which engines support which capability. Declaring is not
 * enough on its own — a declaration nobody checks is a comment — so each suite
 * asserts its own entry against what it can actually do. Node claims delegation
 * and therefore must run `delegationCases`; Python declares no delegation and
 * asserts the same thing from the other side.
 *
 * This closes the failure the cross-boundary suite found the hard way: a
 * capability that exists on one surface, is absent on another, and has nothing
 * anywhere that compares the two.
 */
test("the fixture declares which engines implement which capability", () => {
  assert.ok(Array.isArray(suite.capabilities?.policy), "policy capability must be declared");
  assert.ok(suite.capabilities.policy.includes("node"));
  assert.ok(
    suite.capabilities.delegation.includes("node"),
    "node implements delegation and must be listed as implementing it",
  );
  assert.ok(suite.delegationCases.length >= 20, `only ${suite.delegationCases?.length} delegation cases`);
});

for (const testCase of suite.delegationCases) {
  test(`conformance (node, delegation): ${testCase.name}`, () => {
    switch (testCase.op) {
      case "permits":
        assert.equal(scopePermits(testCase.scope, testCase.request), testCase.expect);
        break;

      case "narrows":
        assert.equal(isNarrowing(testCase.parent, testCase.child), testCase.expect);
        break;

      case "intersect": {
        // Probed rather than compared structurally: two correct engines may
        // represent the same authority differently, and only what the result
        // PERMITS has security meaning. See build-delegation-cases.mjs.
        const merged = intersectScopes(testCase.a, testCase.b);
        for (const probe of testCase.probes) {
          assert.equal(
            scopePermits(merged, { action: probe.action, resource: probe.resource }),
            probe.expect,
            `${probe.action} on ${probe.resource}`,
          );
        }
        if (testCase.symmetric) {
          const reversed = intersectScopes(testCase.b, testCase.a);
          for (const probe of testCase.probes) {
            assert.equal(
              scopePermits(reversed, { action: probe.action, resource: probe.resource }),
              probe.expect,
              `reversed: ${probe.action} on ${probe.resource}`,
            );
          }
        }
        break;
      }

      default:
        throw new Error(`unknown delegation op "${testCase.op}"`);
    }
  });
}
