/**
 * Consequence-based authorization.
 *
 * A consequence is what happens in the world if a call succeeds — not what the
 * call does to a file or process, but what it effects beyond the machine.
 *
 *   - deriveConsequence()  — deterministic derivation from a normalized call
 *   - policy matching      — `consequence = financial_transfer` as a rule condition
 *   - authority scoping    — missions/capabilities restricted by max consequence
 *   - delegation scoping   — delegations that narrow by consequence
 */

import test from "node:test";
import assert from "node:assert/strict";

import { deriveConsequence, canonicalActionLight, CONSEQUENCE, CONSEQUENCE_ORDER, consequenceAtLeast } from "../src/core/risk.mjs";
import { normalize, policyRequest, TAXONOMY } from "../src/core/normalize.mjs";
import { evaluate } from "../src/core/policy.mjs";
import { compile, toSource } from "../src/core/policy-dsl.mjs";
import { DECISION, EFFECT } from "../src/core/decisions.mjs";
import { MissionRegistry, assessAuthority, applyAuthority, lintMission, maxConsequenceKind } from "../src/core/authority.mjs";
import { DelegationBroker } from "../src/core/delegation.mjs";
import { Ed25519DelegationIssuer } from "../src/core/delegation-ed25519.mjs";
import { Pipeline } from "../src/core/pipeline.mjs";
import { Guard } from "../src/core/guard.mjs";
import { authorize as authorizeCanonical } from "../src/core/authorize.mjs";
import { test as runPolicyTest } from "../src/commands/policy.mjs";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const WORKSPACE = process.platform === "win32" ? "C:/workspace" : "/workspace";

/* ========================================================================== */
/*  1. Consequence derivation                                                 */
/* ========================================================================== */

test("deriveConsequence: reads are data_read", () => {
  assert.equal(
    deriveConsequence({ action: "fs.read", tool: "filesystem.read", resource: "/tmp/x.txt" }),
    CONSEQUENCE.DATA_READ,
  );
  assert.equal(
    deriveConsequence({ action: "db.query", tool: "database.query", resource: "orders" }),
    CONSEQUENCE.DATA_READ,
  );
  assert.equal(
    deriveConsequence({ action: "fs.list", tool: "filesystem.list", resource: "/tmp" }),
    CONSEQUENCE.DATA_READ,
  );
});

test("deriveConsequence: writes are data_write", () => {
  assert.equal(
    deriveConsequence({ action: "fs.write", tool: "filesystem.write", resource: "/tmp/x.txt" }),
    CONSEQUENCE.DATA_WRITE,
  );
  assert.equal(
    deriveConsequence({ action: "db.write", tool: "database.write", resource: "orders" }),
    CONSEQUENCE.DATA_WRITE,
  );
  assert.equal(
    deriveConsequence({ action: "fs.delete", tool: "filesystem.delete", resource: "/tmp/x.txt" }),
    CONSEQUENCE.DATA_WRITE,
  );
});

test("deriveConsequence: external HTTP requests are data_export", () => {
  assert.equal(
    deriveConsequence({
      action: "http.request",
      tool: "network.request",
      destination: "https://api.example.com/v1/data",
    }),
    CONSEQUENCE.DATA_EXPORT,
  );
  assert.equal(
    deriveConsequence({
      action: "http.request",
      tool: "network.request",
      destination: "https://evil.example/collect",
    }),
    CONSEQUENCE.DATA_EXPORT,
  );
});

test("deriveConsequence: internal destinations are not data_export", () => {
  // An internal network call is data_read or data_write, not export.
  assert.equal(
    deriveConsequence({
      action: "http.request",
      tool: "network.request",
      destination: "http://10.0.0.1/api",
    }),
    CONSEQUENCE.DATA_READ,
  );
});

test("deriveConsequence: shell execution is code_execution", () => {
  assert.equal(
    deriveConsequence({ action: "shell.exec", tool: "shell.exec", command: "npm test" }),
    CONSEQUENCE.CODE_EXECUTION,
  );
  assert.equal(
    deriveConsequence({ action: "shell.exec", tool: "shell.exec", command: "ls -la" }),
    CONSEQUENCE.CODE_EXECUTION,
  );
  assert.equal(
    deriveConsequence({ action: "pkg.install", tool: "package.install", command: "npm install" }),
    CONSEQUENCE.CODE_EXECUTION,
  );
});

test("deriveConsequence: secrets.get is credential_disclosure", () => {
  assert.equal(
    deriveConsequence({ action: "secrets.read", tool: "secrets.get", resource: "STRIPE_KEY" }),
    CONSEQUENCE.CREDENTIAL_DISCLOSURE,
  );
});

test("deriveConsequence: k8s.apply and db.migrate are infrastructure_change", () => {
  /* Deployments and migrations reconfigure systems; they do not decide who may
     act, which is what privilege_change means. Infrastructure change is a
     dominant kind, so a data_write-scoped mission still cannot migrate. */
  assert.equal(
    deriveConsequence({ action: "k8s.apply", tool: "deploy.apply", resource: "production/deploy" }),
    CONSEQUENCE.INFRASTRUCTURE_CHANGE,
  );
  assert.equal(
    deriveConsequence({ action: "db.migrate", tool: "database.migrate", resource: "schema" }),
    CONSEQUENCE.INFRASTRUCTURE_CHANGE,
  );
});

test("deriveConsequence: vcs writes and pushes", () => {
  assert.equal(
    deriveConsequence({ action: "vcs.write", tool: "git.commit", resource: "." }),
    CONSEQUENCE.DATA_WRITE,
  );
  assert.equal(
    deriveConsequence({ action: "vcs.push", tool: "git.push", resource: "." }),
    CONSEQUENCE.DATA_EXPORT,
  );
});

test("deriveConsequence: loose stems do not misfile benign tools", () => {
  /* Each of these once inherited a dominant consequence from a loose prefix —
     the false positives that get an otherwise-correct control switched off. */
  assert.equal(deriveConsequence({ action: "fs.move", tool: "transfer_files", resource: "/tmp/a" }), CONSEQUENCE.DATA_WRITE);
  assert.equal(deriveConsequence({ action: "fs.read", tool: "tokenize_text", resource: "/tmp/a" }), CONSEQUENCE.DATA_READ);
  assert.equal(deriveConsequence({ action: "fs.write", tool: "resize_image", resource: "/tmp/a.png" }), CONSEQUENCE.DATA_WRITE);
  assert.equal(deriveConsequence({ action: "fs.write", tool: "rotate_image", resource: "/tmp/a.png" }), CONSEQUENCE.DATA_WRITE);
  assert.equal(deriveConsequence({ action: "tool.square_root", tool: "square_root", resource: "x" }), CONSEQUENCE.NONE);
});

test("deriveConsequence: compounds still classify the real thing", () => {
  assert.equal(deriveConsequence({ action: "http.request", tool: "transfer_funds", destination: "https://bank.example/api" }), CONSEQUENCE.FINANCIAL_TRANSFER);
  assert.equal(deriveConsequence({ action: "secrets.read", tool: "token_store", resource: "STRIPE_KEY" }), CONSEQUENCE.CREDENTIAL_DISCLOSURE);
  assert.equal(deriveConsequence({ action: "tool.rotate", tool: "rotate_api_key", resource: "key-1" }), CONSEQUENCE.CREDENTIAL_DISCLOSURE);
  assert.equal(deriveConsequence({ action: "tool.terminate", tool: "terminate_instance", resource: "i-123" }), CONSEQUENCE.INFRASTRUCTURE_CHANGE);
  assert.equal(deriveConsequence({ action: "tool.scaleup", tool: "scale_up_cluster", resource: "prod" }), CONSEQUENCE.INFRASTRUCTURE_CHANGE);
  assert.equal(deriveConsequence({ action: "http.request", tool: "comment_add", destination: "https://api.example/comments" }), CONSEQUENCE.COMMUNICATION);
});

test("deriveConsequence: payment tools are financial_transfer", () => {
  assert.equal(
    deriveConsequence({ action: "http.request", tool: "stripe.charges.create", destination: "https://api.stripe.com/v1/charges" }),
    CONSEQUENCE.FINANCIAL_TRANSFER,
  );
  assert.equal(
    deriveConsequence({ action: "payment.send", tool: "payment.send", resource: "INV-482" }),
    CONSEQUENCE.FINANCIAL_TRANSFER,
  );
});

test("deriveConsequence: send_email is communication", () => {
  assert.equal(
    deriveConsequence({ action: "http.request", tool: "sendmail", destination: "https://api.email.example/send" }),
    CONSEQUENCE.COMMUNICATION,
  );
});

test("deriveConsequence: git.status is data_read (low-risk read)", () => {
  assert.equal(
    deriveConsequence({ action: "vcs.read", tool: "git.status", resource: "." }),
    CONSEQUENCE.DATA_READ,
  );
});

test("deriveConsequence: unknown tools are none", () => {
  assert.equal(
    deriveConsequence({ action: "custom.action", tool: "custom.tool", resource: "x" }),
    CONSEQUENCE.NONE,
  );
});

/* ========================================================================== */
/*  2. Consequence lattice                                                    */
/* ========================================================================== */

test("consequenceAtLeast: ordering within the lattice", () => {
  assert.ok(consequenceAtLeast(CONSEQUENCE.DATA_WRITE, CONSEQUENCE.DATA_READ));
  assert.ok(consequenceAtLeast(CONSEQUENCE.DATA_EXPORT, CONSEQUENCE.DATA_WRITE));
  assert.ok(consequenceAtLeast(CONSEQUENCE.DATA_EXPORT, CONSEQUENCE.DATA_READ));
  assert.ok(consequenceAtLeast(CONSEQUENCE.DATA_EXPORT, CONSEQUENCE.DATA_EXPORT));
  assert.ok(!consequenceAtLeast(CONSEQUENCE.DATA_READ, CONSEQUENCE.DATA_WRITE));
  assert.ok(!consequenceAtLeast(CONSEQUENCE.NONE, CONSEQUENCE.DATA_READ));
});

test("consequenceAtLeast: significant consequences are above data_export", () => {
  for (const sig of [
    CONSEQUENCE.CREDENTIAL_DISCLOSURE,
    CONSEQUENCE.PRIVILEGE_CHANGE,
    CONSEQUENCE.INFRASTRUCTURE_CHANGE,
    CONSEQUENCE.CODE_EXECUTION,
    CONSEQUENCE.IMPERSONATION,
    CONSEQUENCE.PROCESS_ADVANCE,
  ]) {
    assert.ok(consequenceAtLeast(sig, CONSEQUENCE.DATA_EXPORT), `${sig} should be >= data_export`);
  }
});

test("consequenceAtLeast: a kind is at least itself", () => {
  for (const kind of Object.values(CONSEQUENCE)) {
    assert.ok(consequenceAtLeast(kind, kind), `${kind} should be >= itself`);
  }
});

/* ========================================================================== */
/*  3. Policy matching on consequence                                         */
/* ========================================================================== */

test("policy: deny by consequence — financial_transfer is forbidden", () => {
  /* Rules come from the DSL so the consequence condition arrives in exactly the
     form an operator writes. Wildcard actions on purpose: the consequence is
     the discriminating axis, and tool names that mention "create" classify as
     writes anyway — matching on the action would miss them. */
  const { rules } = compile(
    `allow:
  name = allow-everything
  tool = *

deny:
  name = deny-financial
  tool = *
  consequence = financial_transfer
`,
    { cwd: WORKSPACE },
  );

  // A normal API read is allowed (consequence is data_export, not financial_transfer).
  const allowed = evaluate(
    policyRequest(normalize({ tool: "http_request", arguments: { url: "https://api.example.com/v1/status" } }, { cwd: WORKSPACE, agent: "bot" })),
    rules,
    { cwd: WORKSPACE },
  );
  assert.equal(allowed.verdict, "permit", "normal API read is allowed");
  assert.equal(allowed.rule, "allow-everything");

  // A payment API call is denied by consequence.
  const denied = evaluate(
    policyRequest(normalize({ tool: "stripe_charges_create", arguments: { url: "https://api.stripe.com/v1/charges" } }, { cwd: WORKSPACE, agent: "bot" })),
    rules,
    { cwd: WORKSPACE },
  );
  assert.equal(denied.verdict, "deny", "payment API call is denied by consequence");
  assert.equal(denied.rule, "deny-financial");
});

test("policy: deny by consequence >= data_export blocks all export", () => {
  /* `consequence >= data_export` is compiled by the DSL into membership in the
     matching subset — the engine itself has no ordinal comparator over kinds,
     which is the same choice `risk >= HIGH` made. */
  const { rules } = compile(
    `allow:
  name = allow-everything
  tool = *

deny:
  name = deny-export
  tool = *
  consequence >= data_export
`,
    { cwd: WORKSPACE },
  );

  // Workspace read is fine (consequence is data_read, below data_export).
  const read = evaluate(
    policyRequest(normalize({ tool: "read_file", arguments: { path: `${WORKSPACE}/src/app.ts` } }, { cwd: WORKSPACE, agent: "bot" })),
    rules,
    { cwd: WORKSPACE },
  );
  assert.equal(read.verdict, "permit", "workspace read is allowed");
  assert.equal(read.rule, "allow-everything");

  // External request is denied (consequence is data_export, at the threshold).
  const exportCall = evaluate(
    policyRequest(normalize({ tool: "http_request", arguments: { url: "https://evil.example/collect" } }, { cwd: WORKSPACE, agent: "bot" })),
    rules,
    { cwd: WORKSPACE },
  );
  assert.equal(exportCall.verdict, "deny", "external request is denied by consequence >= data_export");
  assert.equal(exportCall.rule, "deny-export");
});

/* ========================================================================== */
/*  4. DSL: consequence condition                                             */
/* ========================================================================== */

test("DSL: consequence = financial_transfer compiles", () => {
  const { rules } = compile(
    `deny:
  tool = http.request
  consequence = financial_transfer
`,
    { cwd: WORKSPACE },
  );
  assert.equal(rules.length, 1);
  assert.equal(rules[0].effect, EFFECT.FORBID);
  assert.deepEqual(rules[0].when, [{ path: "consequence", op: "eq", value: "financial_transfer" }]);
});

test("DSL: consequence >= data_export compiles to an in-condition", () => {
  const { rules } = compile(
    `deny:
  tool = *
  consequence >= data_export
`,
    { cwd: WORKSPACE },
  );
  assert.equal(rules.length, 1);
  assert.equal(rules[0].effect, EFFECT.FORBID);
  // Should compile to an `in` over consequences >= data_export.
  assert.equal(rules[0].when[0].path, "consequence");
  assert.equal(rules[0].when[0].op, "in");
  assert.ok(rules[0].when[0].value.includes("data_export"));
  assert.ok(rules[0].when[0].value.includes("communication"));
  assert.ok(rules[0].when[0].value.includes("financial_transfer"));
});

test("DSL: round-trip consequence condition", () => {
  const source = `deny:
  tool = http.request
  consequence = financial_transfer
  reason = "No payments without explicit approval."
`;
  const { rules } = compile(source, { cwd: WORKSPACE });
  const rendered = compile(source, { cwd: WORKSPACE }); // toSource round-trip
  const { rules: reCompiled } = compile(
    `deny:
  tool = http.request
  consequence = financial_transfer
  reason = "No payments without explicit approval."
`,
    { cwd: WORKSPACE },
  );
  assert.deepEqual(rules, reCompiled);
});

test("DSL: unknown consequence is a compile error", () => {
  assert.throws(
    () => compile(`deny:\n  tool = *\n  consequence = dragon_dust\n`, { cwd: WORKSPACE }),
    /Unknown consequence/,
  );
});

/* ========================================================================== */
/*  5. Authority: mission scoped by maxConsequence                           */
/* ========================================================================== */

test("authority: a mission with maxConsequence=data_write blocks financial_transfer", async () => {
  const registry = new MissionRegistry();
  const mission = registry.issue({
    name: "file-processing",
    agent: "worker",
    capabilities: [{ actions: ["*"], resources: ["*"] }],
    constraints: { maxConsequence: "data_write" },
  });

  // A file write is authorized.
  const writeAssessment = registry.get(mission.id);
  assert.ok(writeAssessment);

  // Use assessAuthority directly to check the constraint.
  const { evaluateConstraints } = await import("../src/core/authority.mjs");
  const call = {
    action: "http.request",
    tool: "stripe.charges.create",
    destination: "https://api.stripe.com/v1/charges",
    consequence: CONSEQUENCE.FINANCIAL_TRANSFER,
    resource: "https://api.stripe.com/v1/charges",
    environment: "production",
  };
  const result = evaluateConstraints(mission.constraints, call, mission);
  assert.ok(!result.ok, "financial_transfer exceeds data_write maxConsequence");
  assert.equal(result.violations[0].constraint, "maxConsequence");
});

test("authority: a mission with maxConsequence=financial_transfer allows data_write", async () => {
  const registry = new MissionRegistry();
  const mission = registry.issue({
    name: "payment-processing",
    agent: "worker",
    capabilities: [{ actions: ["*"], resources: ["*"] }],
    constraints: { maxConsequence: "financial_transfer" },
  });

  const { evaluateConstraints } = await import("../src/core/authority.mjs");
  const call = {
    action: "fs.write",
    tool: "filesystem.write",
    resource: "/tmp/invoice.txt",
    consequence: CONSEQUENCE.DATA_WRITE,
    environment: "production",
  };
  const result = evaluateConstraints(mission.constraints, call, mission);
  assert.ok(result.ok, "data_write is within financial_transfer maxConsequence");
});

/* ========================================================================== */
/*  6. Delegation: consequence narrowing                                     */
/* ========================================================================== */

test("delegation: a grant with maxConsequence narrows the delegate", () => {
  const broker = new DelegationBroker();
  broker.root("planner", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "financial_transfer" } });

  const root = broker.inventory().find((g) => g.subject === "planner");
  assert.ok(root);

  // Delegate to a worker with a narrower consequence boundary.
  const delegation = broker.delegate(root, "worker", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "data_write" } });
  assert.ok(delegation.ok, "delegation with narrower consequence should succeed");

  // The worker's grant carries the constraint.
  const workerGrant = broker.get(delegation.grant.id);
  assert.ok(workerGrant.constraints?.maxConsequence === "data_write");
});

test("delegation: a grant cannot widen consequence beyond its parent", () => {
  const broker = new DelegationBroker();
  broker.root("planner", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "data_write" } });

  const root = broker.inventory().find((g) => g.subject === "planner");
  assert.ok(root, "root grant exists");

  // Trying to delegate with a WIDER consequence (financial_transfer > data_write) should fail.
  const widened = broker.delegate(root, "worker", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "financial_transfer" } });
  assert.ok(!widened.ok, "cannot widen consequence beyond parent");
  assert.equal(widened.error, "widened");
});

test("delegation: a grant CAN narrow consequence below its parent", () => {
  const broker = new DelegationBroker();
  broker.root("planner", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "financial_transfer" } });

  const root = broker.inventory().find((g) => g.subject === "planner");
  assert.ok(root, "root grant exists");

  // Narrowing from financial_transfer to data_write is allowed.
  const narrowed = broker.delegate(root, "worker", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "data_write" } });
  assert.ok(narrowed.ok, "can narrow consequence below parent");
});

test("delegation: editing a grant's maxConsequence invalidates its signature", () => {
  /* Constraints narrow what a grant authorizes; they must be inside the
     signature or an in-memory tamper widens the consequence boundary freely. */
  const broker = new DelegationBroker();
  const planner = broker.root("planner", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "data_write" } });
  const toWorker = broker.delegate(planner, "worker", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "data_write" } });
  assert.ok(toWorker.ok);

  const tampered = { ...toWorker.grant, constraints: { maxConsequence: "financial_transfer" } };
  const resolved = broker.resolve(tampered, "worker");
  assert.equal(resolved.ok, false, "a tampered consequence boundary is not authority");
  assert.equal(resolved.error, "bad_signature");
});

test("delegation: a worker whose grant maxConsequence=data_write cannot effect financial_transfer", async () => {
  const broker = new DelegationBroker();
  const planner = broker.root("planner", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "financial_transfer" } });
  const delegation = broker.delegate(planner, "worker", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "data_write" } });

  // Simulate what applyDelegation does: evaluate the grant's constraints against the call.
  const { evaluateConstraints } = await import("../src/core/authority.mjs");
  const call = {
    action: "http.request",
    tool: "stripe.charges.create",
    destination: "https://api.stripe.com/v1/charges",
    consequence: CONSEQUENCE.FINANCIAL_TRANSFER,
    resource: "https://api.stripe.com/v1/charges",
    environment: "production",
    delegating: true,
  };

  // The worker's grant constraints should reject this.
  const resolved = broker.resolve(delegation.grant, "worker");
  assert.ok(resolved.ok);

  if (resolved.constraints?.length) {
    for (const link of resolved.constraints) {
      const outcome = evaluateConstraints(link.constraints, call, null);
      if (!outcome.ok) {
        assert.equal(outcome.violations[0].constraint, "maxConsequence");
        return; // test passes: constraint violation found
      }
    }
    assert.fail("expected a maxConsequence violation but none found");
  } else {
    assert.fail("expected constraints on the resolved grant but none found");
  }
});

/* ========================================================================== */
/*  7. End-to-end: the original user scenario                                 */
/* ========================================================================== */

test("e2e: creating a payment is OUTSIDE the delegated invoice-processing authority", async () => {
  /* This is the scenario from the original request:
   *   principal: "finance-team"
   *   agent: "ap-agent-7"
   *   delegated_authority: "invoice-processing-v3"
   *   action: "create_payment", target: "vendor_482", amount: 4200
   *   consequence: "external_funds_transfer"
   *
   * The human grants the accounts-payable agent its root authority (which
   * INCLUDES moving money). The invoice-processing delegation narrows that to
   * data work only. Creating a payment is a financial_transfer — outside the
   * consequence boundary of the delegated authority, so it must be refused
   * even though policy and the root would both allow it.
   */
  const broker = new DelegationBroker();

  // The finance team grants ap-agent-7 its base authority.
  const financeRoot = broker.root("ap-agent-7", { actions: ["*"], resources: ["*"] }, {
    tenant: "finance-team",
    constraints: { maxConsequence: "financial_transfer" },
  });

  // ap-agent-7 delegates the invoice-processing role to a worker, narrowing
  // the consequence boundary to data_write: invoice work moves data, not money.
  const invoiceDelegation = broker.delegate(financeRoot, "invoice-worker", {
    actions: ["fs.write", "fs.read", "db.query", "db.write"],
    resources: ["*"],
  }, {
    constraints: { maxConsequence: "data_write" },
    ttlMs: 15 * 60 * 1000,
  });

  assert.ok(invoiceDelegation.ok, "invoice processing delegation issued");

  // The worker tries to create a payment — consequence is financial_transfer.
  const paymentCall = {
    action: "http.request",
    tool: "stripe.charges.create",
    destination: "https://api.stripe.com/v1/charges",
    consequence: CONSEQUENCE.FINANCIAL_TRANSFER,
    resource: "https://api.stripe.com/v1/charges",
    environment: "production",
    delegating: true,
    arguments: {
      amount: 4200,
      currency: "usd",
      destination: "vendor_482",
    },
  };

  // Resolve the delegation.
  const resolved = broker.resolve(invoiceDelegation.grant, "invoice-worker");
  assert.ok(resolved.ok, "delegation resolves");

  // Evaluate the grant's constraints against the payment call.
  const { evaluateConstraints } = await import("../src/core/authority.mjs");
  let violated = false;
  if (resolved.constraints?.length) {
    for (const link of resolved.constraints) {
      const outcome = evaluateConstraints(link.constraints, paymentCall, null);
      if (!outcome.ok) {
        violated = true;
        assert.equal(outcome.violations[0].constraint, "maxConsequence",
          "payment creation exceeds the data_write consequence boundary of the invoice-processing delegation");
      }
    }
  }
  assert.ok(violated, "the payment call should be refused by the delegation's consequence constraint");
});

test("e2e: reading an invoice IS inside the delegated invoice-processing authority", async () => {
  const broker = new DelegationBroker();
  const financeRoot = broker.root("ap-agent-7", { actions: ["*"], resources: ["*"] }, {
    tenant: "finance-team",
    constraints: { maxConsequence: "financial_transfer" },
  });

  const invoiceDelegation = broker.delegate(financeRoot, "invoice-worker", {
    actions: ["fs.read", "db.query"],
    resources: ["*"],
  }, {
    constraints: { maxConsequence: "data_read" },
  });

  assert.ok(invoiceDelegation.ok);

  // Reading an invoice is data_read — within the delegation's consequence boundary.
  const readCall = {
    action: "fs.read",
    tool: "filesystem.read",
    resource: "/invoices/approved/482.pdf",
    consequence: CONSEQUENCE.DATA_READ,
    environment: "production",
    delegating: true,
  };

  const resolved = broker.resolve(invoiceDelegation.grant, "invoice-worker");
  assert.ok(resolved.ok);

  const { evaluateConstraints } = await import("../src/core/authority.mjs");
  if (resolved.constraints?.length) {
    for (const link of resolved.constraints) {
      const outcome = evaluateConstraints(link.constraints, readCall, null);
      assert.ok(outcome.ok, "reading an invoice is within the data_read consequence boundary");
    }
  }
});

/* ========================================================================== */
/*  8. Canonical-core integration: the REAL enforcement path                   */
/* ========================================================================== */

/*
 * Everything above can pass while the canonical core is silently inert: the
 * core builds its own call object and, until the fix, never derived
 * consequence at all — so consequence policy, mission constraints, and
 * delegation constraints fired for a caller that normalized the call itself
 * and fired NOWHERE on Guard, Pipeline, the gateway, or the socket. Each test
 * below drives a wired engine, which is the only proof that counts.
 */

const ENGINE_RULES = compile(
  `allow:
  name = allow-everything
  tool = *
`,
  { cwd: WORKSPACE },
).rules;

const PAYMENT_REQUEST = {
  tool: "stripe_charges_create",
  arguments: { url: "https://api.stripe.com/v1/charges", amount: 4200 },
};

/*
 * The adapters return different shapes — Pipeline.submit wraps the outcome in
 * `event`, Guard.authorize returns the decision directly — but both carry the
 * canonical decision fields. Normalizing here keeps the assertions about the
 * DECISION, not about which adapter produced it.
 *
 * The adapters also differ in where a PRESENTED delegation grant rides: the
 * local socket carries it on the trusted ctx (Pipeline reads ctx.delegation);
 * the MCP/SDK payload carries it with the call (Guard reads request.delegation
 * — the grant is signature-verified by the core either way). Normalizing that
 * channel here too keeps these tests about the decision, not the transport.
 */
async function runEngine(kind, engine, request, ctx = {}) {
  const { delegation, ...trusted } = ctx;
  const out =
    kind === "Pipeline"
      ? await engine.submit(request, ctx)
      : await engine.authorize(delegation !== undefined ? { ...request, delegation } : request, trusted);
  const d = kind === "Pipeline" ? out.event : out.decision;
  return { decision: d.decision ?? d.verdict, rule: d.policy ?? d.rule ?? null };
}

function makeEngine(kind, options) {
  return kind === "Pipeline" ? new Pipeline(options) : new Guard(options);
}

for (const kind of ["Pipeline", "Guard"]) {
  test(`${kind}: a policy deny on consequence fires through the canonical core`, async () => {
    const { rules } = compile(
      `allow:
  name = allow-everything
  tool = *

deny:
  name = deny-financial
  tool = *
  consequence = financial_transfer
`,
      { cwd: WORKSPACE },
    );
    const engine = makeEngine(kind, { rules, cwd: WORKSPACE, agent: "bot" });
    const denied = await runEngine(kind, engine, PAYMENT_REQUEST, { agent: "bot" });
    assert.equal(denied.decision, DECISION.DENY, "consequence deny must fire on the wired path");
    assert.equal(denied.rule, "deny-financial");

    // A data_export call is NOT denied by this rule.
    const allowed = await runEngine(
      kind,
      engine,
      { tool: "http_request", arguments: { url: "https://api.example.com/v1/status" } },
      { agent: "bot" },
    );
    assert.equal(allowed.decision, "allow", "data_export call passes the financial_transfer rule");
  });

  test(`${kind}: a mission maxConsequence=data_write refuses a payment through the canonical core`, async () => {
    const missions = new MissionRegistry();
    missions.issue({
      name: "invoice-processing",
      agent: "worker",
      capabilities: [{ actions: ["*"], resources: ["*"] }],
      constraints: { maxConsequence: "data_write" },
    });
    const engine = makeEngine(kind, { rules: ENGINE_RULES, cwd: WORKSPACE, agent: "worker", missions });
    const denied = await runEngine(kind, engine, PAYMENT_REQUEST, { agent: "worker" });
    assert.equal(denied.decision, DECISION.DENY, "payment exceeds the mission's consequence boundary");
    assert.match(String(denied.rule), /constraint/i);

    // The boundary permits what it names: a file write proceeds.
    const allowed = await runEngine(
      kind,
      engine,
      { tool: "write_file", arguments: { path: `${WORKSPACE}/out.txt`, content: "x" } },
      { agent: "worker" },
    );
    assert.equal(allowed.decision, "allow", "data_write is inside the mission's consequence boundary");
  });

  test(`${kind}: a delegation maxConsequence=data_write refuses a payment through the canonical core`, async () => {
    const broker = new DelegationBroker();
    const root = broker.root("planner", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "financial_transfer" } });
    const delegation = broker.delegate(root, "worker", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "data_write" } });
    assert.ok(delegation.ok);

    const engine = makeEngine(kind, { rules: ENGINE_RULES, cwd: WORKSPACE, agent: "worker", delegation: broker });
    const denied = await runEngine(kind, engine, PAYMENT_REQUEST, { agent: "worker", delegation: delegation.grant });
    assert.equal(denied.decision, DECISION.DENY, "payment exceeds the delegated consequence boundary");
    assert.equal(denied.rule, "delegation-constraint-violated");
  });
}

/* ========================================================================== */
/*  9. DSL operator discipline and alias conformance                           */
/* ========================================================================== */

test("DSL: consequence supports = and >= only — the other comparisons are compile errors", () => {
  /* They once compiled to CONSTANT predicates that matched every call —
     `deny: consequence <= data_write` denied everything while validating
     cleanly. Refusing beats compiling a rule that means something else. */
  /* `~`/`~=` join the refused set: they mean GLOB MATCH in the rest of this
     grammar, a glob can never name a kind, and `risk` already refuses them. */
  for (const op of [">", "<", "<=", "!=", "~", "~="]) {
    assert.throws(
      () => compile(`deny:\n  tool = *\n  consequence ${op} data_export\n`, { cwd: WORKSPACE }),
      /supports = and >= only/,
      `operator ${op} must be refused`,
    );
  }
});

test("DSL: a >= condition round-trips through toSource as the same set", () => {
  const { rules, } = compile(
    "deny:\n  tool = *\n  consequence >= data_export\n",
    { cwd: WORKSPACE },
  );
  const rendered = toSource(rules, { cwd: WORKSPACE });
  const second = compile(rendered, { cwd: WORKSPACE }).rules;
  assert.deepEqual(second[0].when, rules[0].when, "the rendered source must compile to the identical condition");
});

test("delegation: root refuses an unknown constraint kind at issue time", () => {
  const broker = new DelegationBroker();
  assert.throws(
    () => broker.root("agent", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequnce: "data_write" } }),
    /Unknown root constraint/,
  );
});

test("consequence: the light alias table agrees with normalize's canonicalAction", () => {
  /* Two alias tables that disagree are two policies. The light table exists
     only to break an import cycle; this pins it to the real one. */
  for (const entry of TAXONOMY) {
    assert.equal(canonicalActionLight(entry.tool), entry.action, `tool ${entry.tool}`);
    assert.equal(canonicalActionLight(entry.action), entry.action, `action ${entry.action}`);
  }
});

/* ========================================================================== */
/*  10. normalize derives consequence                                          */
/* ========================================================================== */

test("normalize: derives consequence on a normalized call", () => {
  const call = normalize(
    { tool: "read_file", arguments: { path: `${WORKSPACE}/src/app.ts` } },
    { cwd: WORKSPACE, agent: "test" },
  );
  assert.equal(call.consequence, CONSEQUENCE.DATA_READ);

  const writeCall = normalize(
    { tool: "write_file", arguments: { path: `${WORKSPACE}/src/app.ts`, content: "x" } },
    { cwd: WORKSPACE, agent: "test" },
  );
  assert.equal(writeCall.consequence, CONSEQUENCE.DATA_WRITE);

  const shellCall = normalize(
    { tool: "shell_exec", arguments: { command: "npm test" } },
    { cwd: WORKSPACE, agent: "test" },
  );
  assert.equal(shellCall.consequence, CONSEQUENCE.CODE_EXECUTION);

  const paymentCall = normalize(
    { tool: "stripe_charges_create", arguments: { url: "https://api.stripe.com/v1/charges" } },
    { cwd: WORKSPACE, agent: "test" },
  );
  assert.equal(paymentCall.consequence, CONSEQUENCE.FINANCIAL_TRANSFER);
});

/* ========================================================================== */
/*  11. Audit hardening: a consequence control that cannot be checked is not    */
/*      a control. Every case below was a live defect found by auditing the     */
/*      feature end to end.                                                    */
/* ========================================================================== */

test("maxConsequenceKind: one canonical spelling, and an unreadable value is null", () => {
  assert.equal(maxConsequenceKind("data_write"), "data_write");
  assert.equal(maxConsequenceKind("DATA_WRITE"), "data_write");
  assert.equal(maxConsequenceKind({ max: "data_write" }), "data_write");
  for (const bad of ["data_writ", "", null, undefined, 42, {}, { max: "nope" }, ["data_write"]]) {
    assert.equal(maxConsequenceKind(bad), null, `${JSON.stringify(bad)} is not a consequence`);
  }
});

test("delegation (HMAC): the object form of maxConsequence narrows instead of breaking the comparison", () => {
  /* Before: `{max:"data_write"}` was accepted by the evaluator and signed, but
     the narrowing check compared the raw values — so a child carrying the SAME
     ceiling was refused as a widening "from [object Object] to [object Object]".
     Fail-closed, but the feature did not work in the spelling the evaluator
     accepts. */
  const broker = new DelegationBroker();
  const root = broker.root("planner", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: { max: "data_write" } } });
  assert.equal(root.constraints.maxConsequence, "data_write", "the signed grant carries the canonical kind");

  const same = broker.delegate(root, "worker", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: { max: "data_write" } } });
  assert.ok(same.ok, "the same ceiling in the object spelling is not a widening");
  assert.equal(same.grant.constraints.maxConsequence, "data_write");

  const uppers = broker.delegate(root, "worker2", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "DATA_WRITE" } });
  assert.ok(uppers.ok, "case is a spelling, not a different kind");
  assert.equal(uppers.grant.constraints.maxConsequence, "data_write");

  const wider = broker.delegate(root, "worker3", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "financial_transfer" } });
  assert.equal(wider.ok, false);
  assert.equal(wider.error, "widened", "a wider ceiling is still refused across spellings");
});

test("delegation (HMAC): a misspelled maxConsequence is refused where it is signed", () => {
  const broker = new DelegationBroker();
  assert.throws(
    () => broker.root("planner", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "data_writ" } }),
    /not a consequence this build derives/,
  );

  const root = broker.root("planner2", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "data_write" } });
  const child = broker.delegate(root, "worker", { actions: ["*"], resources: ["*"] }, { constraints: { maxConsequence: "data_writ" } });
  assert.equal(child.ok, false);
  assert.equal(child.error, "unknown_constraint");
});

test("delegation (Ed25519): a child cannot WIDEN its parent's maxConsequence", async () => {
  /* The live/CLI path. It checked only that the child kept the parent's
     constraint KEY, so `data_write` could become `financial_transfer` — widening
     the exact axis the ceiling exists to bound, by the grant a worker asks for. */
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-consequence-"));
  const issuer = await new Ed25519DelegationIssuer({ stateDir }).init();
  const WIDE = { actions: ["*"], resources: ["*"] };
  const root = await issuer.root({ agent: "planner", scope: WIDE, constraints: { maxConsequence: "data_write" } });
  assert.equal(root.grant.constraints.maxConsequence, "data_write");

  await assert.rejects(
    () => issuer.delegate({ parent: root.grant, subject: "worker", scope: WIDE, constraints: { maxConsequence: "financial_transfer" } }),
    (e) => e.code === "widened" && /maxConsequence/.test(e.message),
    "a wider ceiling must be refused at issue time",
  );

  const narrowed = await issuer.delegate({ parent: root.grant, subject: "worker", scope: WIDE, constraints: { maxConsequence: { max: "data_read" } } });
  assert.equal(narrowed.grant.constraints.maxConsequence, "data_read", "a narrower ceiling is issued in canonical form");

  await assert.rejects(
    () => issuer.delegate({ parent: narrowed.grant, subject: "helper", scope: WIDE, constraints: { maxConsequence: "data_write" } }),
    (e) => e.code === "widened",
    "a grandchild cannot widen back past its own ceiling",
  );
});

test("delegation (Ed25519): a misspelled maxConsequence is refused where it is issued", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-consequence-"));
  const issuer = await new Ed25519DelegationIssuer({ stateDir }).init();
  const WIDE = { actions: ["*"], resources: ["*"] };
  await assert.rejects(
    () => issuer.root({ agent: "planner", scope: WIDE, constraints: { maxConsequence: "data_writ" } }),
    (e) => e.code === "unknown_constraint",
  );
});

test("authority: a misspelled maxConsequence refuses rather than restricting nothing", () => {
  const mission = {
    name: "typo-mission",
    agent: "ap-agent-7",
    capabilities: [{ name: "pay", actions: ["*"], resources: ["*"] }],
    constraints: { maxConsequence: "data_writ" },
    status: "active",
    issuedAt: Date.now(),
  };
  const assessment = assessAuthority(
    { agent: "ap-agent-7", action: "payments.create", resource: "stripe", consequence: CONSEQUENCE.FINANCIAL_TRANSFER },
    mission,
  );
  assert.equal(assessment.authorized, false, "an unreadable ceiling is not a satisfied constraint");
  assert.match(assessment.reason, /not a consequence this build derives/);

  const lint = lintMission(mission);
  assert.ok(
    lint.findings.some((f) => f.code === "unreadable_consequence"),
    `expected an unreadable_consequence finding, got ${JSON.stringify(lint.findings)}`,
  );
});

test("authority: lintMission also lints a capability's own conditions", () => {
  const lint = lintMission({
    name: "cap-conditions",
    agent: "bot",
    capabilities: [
      { name: "writer", actions: ["*"], resources: ["*"], conditions: { maxConsequence: "data_writ", netwrok: { deny: ["*"] } } },
    ],
    status: "active",
  });
  assert.ok(lint.findings.some((f) => f.code === "unreadable_consequence" && f.capability === "writer"));
  assert.ok(lint.findings.some((f) => f.code === "unknown_constraint" && f.capability === "writer"));
});

test("authority: an unknown constraint key is RECORDED, not silently dropped", () => {
  const mission = {
    name: "unknown-key",
    agent: "bot",
    capabilities: [{ name: "any", actions: ["*"], resources: ["*"] }],
    constraints: { netwrok: { deny: ["*"] } },
    status: "active",
    issuedAt: Date.now(),
  };
  const assessment = assessAuthority(
    { agent: "bot", action: "fs.read", resource: "/tmp/x", consequence: CONSEQUENCE.DATA_READ },
    mission,
  );
  const context = applyAuthority({ decision: DECISION.ALLOW, verdict: "permit" }, assessment);
  assert.deepEqual(context.constraints.unknown, ["netwrok"], "the record must say the restriction was never evaluated");
});

for (const kind of ["Pipeline", "Guard"]) {
  test(`${kind}: the derived consequence reaches the decision and the record`, async () => {
    const engine = makeEngine(kind, { rules: ENGINE_RULES, cwd: WORKSPACE, agent: "bot" });
    if (kind === "Pipeline") {
      const out = await engine.submit(PAYMENT_REQUEST, { agent: "bot" });
      assert.equal(out.decision.consequence, CONSEQUENCE.FINANCIAL_TRANSFER, "the decision names what was enforced");
      assert.equal(out.event.consequence, CONSEQUENCE.FINANCIAL_TRANSFER, "the socket event carries it");
    } else {
      const out = await engine.authorize(PAYMENT_REQUEST, { agent: "bot" });
      assert.equal(out.decision.consequence, CONSEQUENCE.FINANCIAL_TRANSFER);
      assert.equal(out.record.consequence, CONSEQUENCE.FINANCIAL_TRANSFER, "the MCP record carries it");
    }
  });
}

test("canonical core: the evidence carries the consequence the rule fired on", async () => {
  /* The evidence is the canonical audit shape every surface renders from. A
     rule that fired on `consequence` must be explainable after the fact from
     the record alone — and this is the ONLY place the derivation is visible to
     somebody who did not run the transport. */
  const out = await authorizeCanonical(
    { tool: PAYMENT_REQUEST.tool, arguments: PAYMENT_REQUEST.arguments, agent: "bot" },
    { surface: "cli", principal: "bot" },
    { rules: ENGINE_RULES, cwd: WORKSPACE },
  );
  assert.equal(out.evidence.consequence, CONSEQUENCE.FINANCIAL_TRANSFER);
  assert.equal(out.evidence.risk, "high");
  assert.equal(out.decision.consequence, CONSEQUENCE.FINANCIAL_TRANSFER);
});

test("policy test: a test case that names consequence ASSERTS the derived kind", async () => {
  /* The `consequence` attribute in a test block compiled to nothing, so the
     assertion could not fail even when the derivation changed under it. */
  const dir = await mkdtemp(join(tmpdir(), "cirvix-policy-"));
  const path = join(dir, "cirvix.policy");
  await writeFile(
    path,
    [
      "allow:",
      "  name = allow-everything",
      "  tool = *",
      "",
      'test "a payment is a financial transfer":',
      "  tool = stripe_charges_create",
      "  url = https://api.stripe.com/v1/charges",
      "  consequence = financial_transfer",
      "  expect allow",
      "",
      'test "the same payment is NOT a read":',
      "  tool = stripe_charges_create",
      "  url = https://api.stripe.com/v1/charges",
      "  consequence = data_read",
      "  expect allow",
      "",
    ].join("\n"),
    "utf8",
  );

  const { result, code } = await runPolicyTest({ path, cwd: dir, json: true });
  const good = result.cases.find((c) => c.name.startsWith("a payment"));
  const wrong = result.cases.find((c) => c.name.startsWith("the same payment"));
  assert.equal(good.passed, true);
  assert.equal(good.consequence, CONSEQUENCE.FINANCIAL_TRANSFER);
  assert.equal(wrong.passed, false, "declaring the wrong consequence must fail the test");
  assert.equal(wrong.consequenceMismatch, true);
  assert.equal(code, 1);
});

test("policy test: a test case naming an unknown consequence is a compile error", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-policy-"));
  const path = join(dir, "cirvix.policy");
  await writeFile(
    path,
    ["allow:", "  name = allow-everything", "  tool = *", "", 'test "typo":', "  tool = read_file", "  consequence = data_writ", "  expect allow", ""].join("\n"),
    "utf8",
  );
  await assert.rejects(() => runPolicyTest({ path, cwd: dir, json: true }), /Unknown consequence/);
});

test("consequence kinds: the documented vocabulary is the derived vocabulary", () => {
  assert.deepEqual(
    [...CONSEQUENCE_ORDER],
    [
      "none", "data_read", "data_write", "data_export", "communication", "financial_transfer",
      "credential_disclosure", "privilege_change", "infrastructure_change", "code_execution",
      "impersonation", "process_advance",
    ],
    "docs/policy.md lists these twelve, in this order",
  );
});

test("deriveConsequence: the tool's OWN name counts, not just the canonical action", () => {
  /* normalize() rewrites `create_payment` to `filesystem.write` and
     `send_email` to `tool.send_email`, so reading only the canonical name lost
     the only signal those tools have — the name a human gave them. The
     delegated-authority question is asked about exactly these calls. */
  const cases = [
    ["create_payment", CONSEQUENCE.FINANCIAL_TRANSFER],
    ["process_refund", CONSEQUENCE.FINANCIAL_TRANSFER],
    ["pay_invoice", CONSEQUENCE.FINANCIAL_TRANSFER],
    ["send_email", CONSEQUENCE.COMMUNICATION],
    ["rotate_api_key", CONSEQUENCE.CREDENTIAL_DISCLOSURE],
    ["grant_role", CONSEQUENCE.PRIVILEGE_CHANGE],
    ["terraform_apply", CONSEQUENCE.INFRASTRUCTURE_CHANGE],
    ["approve_invoice", CONSEQUENCE.PROCESS_ADVANCE],
    /* …and the benign spellings stay benign. That is the half that keeps a
       consequence ceiling from blocking ordinary work. */
    ["transfer_files", CONSEQUENCE.DATA_READ],
    ["create_file", CONSEQUENCE.DATA_WRITE],
    ["list_payments", CONSEQUENCE.DATA_READ],
    ["tokenize_text", CONSEQUENCE.NONE],
    ["payload_send", CONSEQUENCE.NONE],
  ];
  for (const [tool, expected] of cases) {
    const call = normalize({ tool, arguments: {} }, { cwd: WORKSPACE, agent: "test" });
    assert.equal(call.consequence, expected, `${tool} derives ${expected}`);
  }
});

test("e2e: create_payment under an invoice-processing mission is refused by consequence alone", async () => {
  /* The original scenario, end to end and with NO URL anywhere in the call: a
     money-moving tool named in plain English must not pass a data_write
     ceiling just because the classifier filed it as a file write. */
  const missions = new MissionRegistry();
  missions.issue({
    name: "invoice-processing-v3",
    agent: "ap-agent-7",
    capabilities: [{ actions: ["*"], resources: ["*"] }],
    constraints: { maxConsequence: "data_write" },
  });

  const out = await authorizeCanonical(
    { tool: "create_payment", arguments: { vendor: "vendor_482", amount: 4200 }, agent: "ap-agent-7" },
    { surface: "cli", principal: "ap-agent-7" },
    { rules: ENGINE_RULES, cwd: WORKSPACE, missions },
  );

  assert.equal(out.decision.verdict, "deny", "money must not move outside the delegated ceiling");
  assert.match(String(out.decision.rule), /constraint/i);
  assert.equal(out.evidence.consequence, CONSEQUENCE.FINANCIAL_TRANSFER);
});

test("journal: the record's consequence is filterable and rendered", async () => {
  /* The field exists so an operator can answer "what did this agent effect?"
     after the fact. A field nobody can filter or read is a comment. */
  const { query, renderTree } = await import("../src/core/journal.mjs");
  const records = [
    { request_id: "req_1", decision: "deny", tool: "create_payment", risk: "high", consequence: "financial_transfer", policy: "deny-money-movement" },
    { request_id: "req_2", decision: "allow", tool: "read_file", risk: "low", consequence: "data_read", policy: "allow-everything" },
    { request_id: "req_3", decision: "allow", tool: "legacy", risk: "low", policy: "allow-everything" },
  ];
  assert.deepEqual(
    query(records, { consequence: "financial_transfer" }).map((r) => r.request_id),
    ["req_1"],
  );
  assert.deepEqual(
    query(records, { consequence: "DATA_READ" }).map((r) => r.request_id),
    ["req_2"],
    "the kind is matched case-insensitively",
  );
  assert.deepEqual(
    query(records, { consequence: "data_read" }).map((r) => r.request_id),
    ["req_2"],
    "an exact kind, not a floor: financial_transfer does not match data_read",
  );
  const tree = renderTree(records[0]);
  assert.match(tree, /Consequence\s+financial_transfer/);
});
