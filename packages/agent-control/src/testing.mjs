/**
 * Policy testing.
 *
 * The point of this module is that a rule set is code, and code that decides
 * what an agent may do deserves unit tests that run in CI next to everything
 * else. `evaluate` is the same engine the gateway uses, called directly, with
 * the context filled in so a test states the one thing it is about:
 *
 *   test("production writes are held for a human", async () => {
 *     const decision = await evaluate({
 *       policyDir: "./policies",
 *       agent: "deploy-bot",
 *       action: "k8s.apply",
 *       resource: "production/checkout",
 *       context: { environment: "production" },
 *     });
 *     expect(decision.verdict).toBe("hold");
 *     expect(decision.approvers).toContain("platform-oncall");
 *   });
 *
 * The defaults matter. A test that has to spell out `path.insideWorkspace`
 * every time will stop spelling it out correctly, and a policy test that
 * passes because the context was wrong is worse than no test.
 */

import { readdir, readFile } from "node:fs/promises";
import { extname, join } from "node:path";

import { evaluate as evaluateRules, parseRules, STARTER_RULES } from "./core/policy.mjs";

/**
 * The context a call carries unless a test says otherwise.
 *
 * Chosen as the *permissive* baseline on purpose: inside the workspace, no
 * external egress, no secret touched. A test asserting that something is
 * denied should be denied by the rule it is testing, not by a restrictive
 * default that would have denied anything.
 */
const DEFAULT_CONTEXT = {
  environment: "local",
  path: { insideWorkspace: true },
  egress: { external: false, allowlisted: false },
  session: { touchedSecret: false },
};

/** Loads a rule set from a directory, a file, or an inline array. */
export async function loadPolicy({ rules, policy, policyFile, policyDir } = {}) {
  if (Array.isArray(rules)) return parseRules(rules);

  const file = policy ?? policyFile;
  if (file) return parseRules(JSON.parse(await readFile(file, "utf8")));

  if (policyDir) {
    const entries = await readdir(policyDir);
    const files = entries.filter((f) => [".json", ".policy"].includes(extname(f))).sort();
    if (files.length === 0) {
      throw new Error(`No policy files in ${policyDir}. Expected .json files.`);
    }
    const loaded = [];
    for (const name of files) {
      loaded.push(...parseRules(JSON.parse(await readFile(join(policyDir, name), "utf8"))));
    }
    // A duplicate name across files is a rule that silently shadows another,
    // which is exactly the bug a directory of policies invites.
    const seen = new Set();
    for (const rule of loaded) {
      if (seen.has(rule.name)) {
        throw new Error(`Duplicate rule "${rule.name}" across files in ${policyDir}.`);
      }
      seen.add(rule.name);
    }
    return loaded;
  }

  return STARTER_RULES;
}

/**
 * Evaluates one hypothetical call. Executes nothing.
 *
 * @returns {Promise<{verdict:string, rule:string|null, reason:string,
 *   remediation?:string, approvers?:string[], considered:Array, resource:string}>}
 */
export async function evaluate({
  rules,
  policy,
  policyFile,
  policyDir,
  agent = "test-agent",
  action,
  resource = "",
  context = {},
  cwd = process.cwd(),
} = {}) {
  if (!action) throw new Error("evaluate needs an action, e.g. \"fs.read\".");
  const ruleSet = await loadPolicy({ rules, policy, policyFile, policyDir });

  return evaluateRules(
    {
      agent,
      action,
      resource,
      context: {
        ...DEFAULT_CONTEXT,
        ...context,
        path: { ...DEFAULT_CONTEXT.path, ...(context.path ?? {}) },
        egress: { ...DEFAULT_CONTEXT.egress, ...(context.egress ?? {}) },
        session: { ...DEFAULT_CONTEXT.session, ...(context.session ?? {}) },
      },
    },
    ruleSet,
    { cwd },
  );
}

/**
 * Asserts a rule set does not permit more than it did.
 *
 * Point it at the calls you care about and it reports any that changed
 * verdict — the unit-test counterpart to `cirvix replay`, for a policy diff in
 * a pull request where there is no recorded run to replay against.
 */
export async function expectNoLoosening({ before, after, calls, cwd = process.cwd() }) {
  const previous = await loadPolicy(before);
  const candidate = await loadPolicy(after);

  const loosened = [];
  for (const call of calls) {
    const request = {
      agent: call.agent ?? "test-agent",
      action: call.action,
      resource: call.resource ?? "",
      context: { ...DEFAULT_CONTEXT, ...(call.context ?? {}) },
    };
    const was = evaluateRules(request, previous, { cwd }).verdict;
    const now = evaluateRules(request, candidate, { cwd }).verdict;
    // Only widening counts. A change that denies more is the direction a
    // security policy is allowed to move without a reviewer being surprised.
    const rank = { deny: 0, hold: 1, permit: 2 };
    if (rank[now] > rank[was]) loosened.push({ ...call, was, now });
  }
  return { loosened, ok: loosened.length === 0 };
}

export { STARTER_RULES, parseRules };
