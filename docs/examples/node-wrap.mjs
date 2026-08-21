/**
 * Governing a Node agent's tools.
 *
 * Run from the repository root:
 *   node docs/examples/node-wrap.mjs
 *
 * `guard.wrap` replaces each tool's callable with one that evaluates the call
 * first. It returns the same shape it was given, so this is a one-line change
 * at the executor boundary rather than a rewrite of how tools are registered.
 *
 * WHAT YOU GIVE UP versus the gateway: `wrap` governs the tools you hand it. A
 * tool the agent reaches directly is never evaluated. The gateway does not have
 * that limitation because it sits on the wire.
 */

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { guard, parseRules, CirvixDenied, CirvixHeld } from "../../packages/agent-control/src/index.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

/* The rule set is data. Load it however you like — this reads the file next
   door. `rules` is the option `wrap` understands; there is no `policyDir`. */
const rules = parseRules(JSON.parse(await readFile(join(HERE, "cirvix.policy.json"), "utf8")));

/* -------------------------------------------------------------------------- */
/*  The tools, ungoverned                                                      */
/* -------------------------------------------------------------------------- */

const rawTools = {
  async read_file({ path }) {
    return `<contents of ${path}>`;
  },
  async write_file({ path, content }) {
    return `wrote ${content.length} bytes to ${path}`;
  },
  async apply_manifest({ target }) {
    return `applied ${target}`;
  },
};

/* -------------------------------------------------------------------------- */
/*  The same tools, governed                                                   */
/* -------------------------------------------------------------------------- */

const tools = guard.wrap(rawTools, {
  agent: "pr-triage",
  environment: process.env.CIRVIX_ENV ?? "production",
  rules,
});

/* -------------------------------------------------------------------------- */

async function attempt(label, call) {
  try {
    const result = await call();
    console.log(`PERMIT  ${label}\n        ${result}\n`);
  } catch (err) {
    if (err instanceof CirvixHeld) {
      // A distinct type from a denial, because they call for different
      // behaviour: a denial means re-plan, a hold means this exact call may
      // still happen once somebody says yes.
      console.log(`HOLD    ${label}`);
      console.log(`        rule      ${err.policy}`);
      console.log(`        approvers ${err.approvers.join(", ")}\n`);
      return;
    }
    if (err instanceof CirvixDenied) {
      console.log(`DENY    ${label}`);
      console.log(`        rule   ${err.policy}`);
      console.log(`        reason ${err.reason}`);
      if (err.remediation) console.log(`        fix    ${err.remediation}`);
      console.log(`        why    cirvix why ${err.decisionId}\n`);
      return;
    }
    throw err;
  }
}

console.log("\n  agent: pr-triage · environment: production\n");

await attempt("read_file src/index.ts", () => tools.read_file({ path: "src/index.ts" }));
await attempt("read_file .env.production", () => tools.read_file({ path: ".env.production" }));
await attempt("write_file src/out.txt", () =>
  tools.write_file({ path: "src/out.txt", content: "hello" }),
);
await attempt("apply_manifest production/checkout", () =>
  tools.apply_manifest({ target: "production/checkout" }),
);

/* The tool name maps to a policy action by convention — `read_file` to
   `fs.read`, `apply_manifest` to `k8s.apply` — so one rule covers every tool
   that does the same thing. See docs/policy.md#actions. */
