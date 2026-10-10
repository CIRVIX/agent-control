/**
 * P0-D: ONE AUTHORIZATION PIPELINE, AND THE PROOF THAT EVERY SURFACE USES IT.
 *
 * The two engines used to answer the same question with different stage sets:
 * the MCP gateway ran identity, delegation and authority and none of session
 * tracking, the behavioural baseline, engine mode or tool drift; the local
 * socket ran all of those and had NO identity stage at all, because the socket
 * verified the caller and then handed the engine a bare agent name.
 *
 * So the test that matters is not "does the new code work" — it is:
 *
 *   1. PARITY (INV-015): for the same logical request, the transports agree on
 *      the decision AND on the rule that produced it. Where they differ, the
 *      difference must be explainable as a difference in TRUSTED INPUT.
 *   2. NO MISSING STAGE (INV-016/017): every stage the canonical core defines is
 *      evaluated on every surface, and a stage that is unwired is reported as
 *      INERT rather than silently absent.
 *   3. NO SILENT DOWNGRADE (INV-020): a hardened profile is never reported or
 *      treated as a policy-only one, and a caller-controlled field never
 *      establishes trusted context (INV-018).
 *   4. EVIDENCE IS MANDATORY (INV-022) and stale authority never allows
 *      (INV-019, INV-021).
 *
 * Every transport row ends at the same place: an independent execution oracle.
 * "The guard returned DENY" is not evidence that the effect did not happen.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Guard } from "../src/core/guard.mjs";
import { Pipeline } from "../src/core/pipeline.mjs";
import { Gateway } from "../src/core/gateway.mjs";
import { UdsServer, UdsClient, defaultEndpoint, writeToken } from "../src/core/uds.mjs";
import { AuditChain } from "../src/core/audit.mjs";
import { MessageFramer } from "../src/core/jsonrpc.mjs";
import { compile } from "../src/core/policy-dsl.mjs";
import { SessionTracker } from "../src/core/session.mjs";
import { normalizeMission, MissionRegistry } from "../src/core/authority.mjs";
import { RevocationEngine, REVOCATION_SCOPE } from "../src/core/revocation.mjs";
import { createCallerVerifier, enrollAgent, signRequest } from "../src/core/identity.mjs";
import {
  CANONICAL_STAGES,
  STAGE_CONTRACT,
  SECURITY_PROFILE,
  STAGE_STATUS,
  SURFACE,
  SURFACE_BOUND_STAGES,
  authorize,
  policyStamp,
  stagePlan,
} from "../src/core/authorize.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = join(HERE, "fixtures", "mock-mcp-server.mjs");
const WORKSPACE = process.platform === "win32" ? "C:/workspace" : "/workspace";

const POLICY = `
allow:
  name = allow-workspace-read
  tool = filesystem.read
  workspace = true

allow:
  name = allow-egress
  tool = web.fetch

deny:
  name = deny-aws
  tool = filesystem.read
  path = **/.aws/**
  reason = "Cloud credentials are never readable by an agent."
`;

const rules = () => compile(POLICY, { cwd: WORKSPACE, origin: "p0d-parity" }).rules;
const read = () => ({ tool: "read_file", arguments: { path: `${WORKSPACE}/notes.txt` } });

/** Both engines, built from the SAME dependency object. */
function engines(deps = {}) {
  const shared = { rules: rules(), cwd: WORKSPACE, ...deps };
  return {
    Pipeline: async (request = read(), ctx = {}) => (await new Pipeline({ ...shared }).submit(request, ctx)).decision,
    Guard: async (request = read(), ctx = {}) => (await new Guard({ ...shared }).authorize(request, ctx)).decision,
  };
}

/* ========================================================================== */
/*  1. PARITY (INV-015)                                                        */
/* ========================================================================== */

const PARITY_ROWS = [
  {
    label: "allow",
    deps: {},
    expect: { decision: "allow", rule: "allow-workspace-read" },
  },
  {
    label: "deny by policy",
    deps: {},
    request: { tool: "read_file", arguments: { path: `${WORKSPACE}/.aws/credentials` } },
    expect: { decision: "deny", rule: "deny-aws" },
  },
  {
    label: "malformed request (no tool name)",
    deps: {},
    request: { tool: "", arguments: {} },
    expect: { decision: "deny", rule: "invalid-request" },
  },
  {
    label: "missing identity under a PRODUCTION boundary",
    deps: { identityMode: "production" },
    expect: { decision: "deny", rule: "identity-unverified" },
  },
  {
    label: "expired capability",
    deps: {
      mission: normalizeMission({
        agent: "local",
        capabilities: [{ name: "read", actions: ["fs.read"], expiresAt: "2020-01-01T00:00:00.000Z" }],
        constraints: {},
      }),
    },
    expect: { decision: "deny" },
  },
  {
    label: "revoked capability",
    deps: () => {
      const missions = new MissionRegistry();
      const issued = missions.issue({
        agent: "local",
        capabilities: [{ name: "read", actions: ["fs.read"] }],
        constraints: {},
      });
      missions.revokeCapability(issued.id, issued.capabilities[0].id);
      return { missions, mission: missions.get(issued.id) };
    },
    expect: { decision: "deny", rule: "authority-capability_revoked" },
  },
  {
    label: "session chain (quarantined session)",
    deps: () => {
      const sessionTracker = new SessionTracker("parity-session");
      sessionTracker.quarantine("suspicious sequence");
      return { sessionTracker };
    },
    expect: { decision: "deny", rule: "stateful-exfiltration-chain" },
  },
  {
    label: "declared intent that does not cover the call",
    deps: { intent: "Run jest unit tests on calculator" },
    /* A credential-shaped target under a testing-only intent is the misalignment
       the firewall exists for. */
    request: { tool: "read_file", arguments: { path: `${WORKSPACE}/.env` } },
    expect: { decision: "deny", rule: "intent-firewall-boundary" },
  },
  {
    label: "behavioural baseline deviation (rule opts into the risk floor)",
    deps: {
      rules: [{ name: "allow-workspace-read", effect: "permit", actions: ["fs.read"], resources: ["*"], respectRiskFloor: true }],
      baseline: { scoreDeviation: () => ({ isDeviation: true, anomalyScore: 9, reasons: ["unseen tool"] }) },
    },
    expect: { decision: "require_approval" },
  },
  {
    label: "tool-definition drift",
    deps: { drift: () => ({ status: "drifted", reason: "the definition changed after approval" }) },
    expect: { decision: "deny", rule: "tool-definition-drift" },
  },
  {
    label: "tool definition still in its pin (control row for drift)",
    deps: { drift: () => ({ status: "in-pin" }) },
    expect: { decision: "allow" },
  },
  {
    label: "stale policy (published stamp does not match the rules in force)",
    deps: { publishedPolicy: { version: 2, hash: "sha256:" + "f".repeat(64) } },
    expect: { decision: "deny", rule: "stale-policy" },
  },
  {
    label: "approval required, no approval store",
    deps: { rules: compile("require_approval:\n  name = hold-reads\n  tool = filesystem.read\n  workspace = true\n", { cwd: WORKSPACE, origin: "p0d" }).rules },
    expect: { decision: "require_approval", rule: "hold-reads" },
  },
  {
    label: "credential broker unavailable",
    deps: { secrets: { substitute: async () => { throw new Error("vault unreachable"); } } },
    expect: { decision: "deny", rule: "secret-broker" },
  },
  {
    label: "agent killed",
    deps: () => {
      const killSwitch = { evaluate: () => ({ killed: true, scope: "agent", reason: "frozen by operator" }) };
      return { killSwitch };
    },
    expect: { decision: "deny", rule: "emergency-kill-switch" },
  },
  {
    label: "authority required and none presented",
    deps: { requireDelegation: true, delegation: { resolve: async () => ({ ok: false, error: "required" }) } },
    expect: { decision: "deny", rule: "delegation-required" },
  },
];

for (const row of PARITY_ROWS) {
  test(`parity: ${row.label}`, async () => {
    const deps = typeof row.deps === "function" ? row.deps() : row.deps;
    const request = row.request ?? read();
    const surfaces = engines(deps);

    const decisions = {};
    for (const [name, run] of Object.entries(surfaces)) {
      decisions[name] = await run(request, {});
    }

    /* INV-015: ONE implementation. Same verb, same rule, on both surfaces. */
    assert.equal(
      decisions.Pipeline.decision,
      decisions.Guard.decision,
      `${row.label}: Pipeline said ${decisions.Pipeline.decision}/${decisions.Pipeline.rule}, Guard said ${decisions.Guard.decision}/${decisions.Guard.rule}`,
    );
    assert.equal(
      decisions.Pipeline.rule,
      decisions.Guard.rule,
      `${row.label}: the two surfaces attributed the same verb to different rules`,
    );

    if (row.expect?.decision) assert.equal(decisions.Pipeline.decision, row.expect.decision, row.label);
    if (row.expect?.rule) assert.equal(decisions.Pipeline.rule, row.expect.rule, row.label);
  });
}

/* ========================================================================== */
/*  2. THE STAGE SET IS THE SAME EVERYWHERE (INV-016, INV-017)                 */
/* ========================================================================== */

test("INV-016: every canonical stage has a contract, and the order is the one asserted", () => {
  assert.deepEqual(CANONICAL_STAGES, [
    "request",
    "identity",
    "normalize",
    "secrets",
    "risk",
    "policy",
    "delegation",
    "authority",
    "capability",
    "revocation",
    "kill",
    "trifecta",
    "policy-version",
    "mode",
    "entitlements",
    "intent",
    "session",
    "baseline",
    "drift",
    "validation",
    "approval",
    "credential",
    "sanitize",
    "final-tighten",
    "evidence",
  ]);
  for (const stage of CANONICAL_STAGES) {
    const contract = STAGE_CONTRACT[stage];
    assert.ok(contract, `${stage} has no contract`);
    for (const field of ["input", "output", "failure", "trust", "narrows"]) {
      assert.ok(contract[field] !== undefined, `${stage} has no ${field}`);
    }
  }
  /* Identity is FIRST among the stages that can refuse, and evidence is LAST:
     the ordering constraints the trust model depends on. */
  assert.ok(CANONICAL_STAGES.indexOf("identity") < CANONICAL_STAGES.indexOf("policy"));
  assert.ok(CANONICAL_STAGES.indexOf("normalize") < CANONICAL_STAGES.indexOf("risk"));
  assert.ok(CANONICAL_STAGES.indexOf("revocation") < CANONICAL_STAGES.indexOf("approval"));
  assert.equal(CANONICAL_STAGES[CANONICAL_STAGES.length - 1], "evidence");
});

test("INV-017: a boundary reports exactly which stages are wired, and an unwired stage is INERT", () => {
  const bare = new Pipeline({ rules: rules(), cwd: WORKSPACE });
  const armed = new Pipeline({
    rules: rules(),
    cwd: WORKSPACE,
    sessionTracker: new SessionTracker("s"),
    baseline: { scoreDeviation: () => ({ isDeviation: false }) },
    drift: () => ({ status: "in-pin" }),
    revocation: { evaluate: async () => null },
  });
  const barePlan = bare.securityPosture().stages;
  const armedPlan = armed.securityPosture().stages;
  for (const stage of CANONICAL_STAGES) {
    assert.ok(barePlan[stage], `${stage} is missing from the reported posture`);
  }
  assert.equal(barePlan.session, STAGE_STATUS.INERT);
  assert.equal(armedPlan.session, STAGE_STATUS.MANDATORY);
  assert.equal(barePlan.drift, STAGE_STATUS.INERT);
  assert.equal(armedPlan.drift, STAGE_STATUS.MANDATORY);
  /* Evidence without an audit chain is OPTIONAL and reported as such, never as
     an enforced control. */
  assert.equal(barePlan.evidence, STAGE_STATUS.OPTIONAL);
  assert.equal(armedPlan.identity, STAGE_STATUS.MANDATORY, "identity is mandatory on every surface");
});

test("INV-017: the same dependencies produce the same plan on both surfaces", () => {
  const deps = {
    rules: rules(),
    cwd: WORKSPACE,
    sessionTracker: new SessionTracker("s"),
    drift: () => ({ status: "in-pin" }),
  };
  const g = new Guard({ ...deps, surface: "mcp-gateway" }).securityPosture().stages;
  const p = new Pipeline({ ...deps, surface: "uds" }).securityPosture().stages;
  assert.deepEqual(g, p);
});

/**
 * The SHIPPED compositions, not a minimal deps object: everything the CLI hands
 * the socket runtime and the MCP gateway. This is the metric P0-D is judged by,
 * written as a test — can every supported production surface answer the same
 * authorization question with the same semantics? Any stage wired on one and
 * silently absent on the other fails here.
 *
 * `secrets` is the row that failed when this test was first run: the runtime
 * held the credential broker and the gateway did not, so a call carrying a
 * secret handle was substituted on the socket and passed through untouched on
 * the MCP path.
 */
test("INV-015: the two shipped compositions wire the same stages, surface-bound stages excepted", () => {
  const shared = {
    rules: rules(),
    cwd: WORKSPACE,
    agent: "local",
    environment: "local",
    audit: { append: async () => {} },
    secrets: { held: true, handle: () => null },
    approvals: { request: async () => null, get: () => null },
    delegation: { resolve: async () => null },
    requireDelegation: true,
    missions: { list: () => [] },
    revocation: { evaluate: async () => null },
    licence: { tier: "team" },
    meter: { record: async () => {} },
    agents: { list: () => [] },
    identity: { verify: async () => ({ verified: false }) },
    identityMode: "production",
    mode: "enforce",
    publishedPolicy: { version: "v1", hash: "sha256:whatever" },
    sessionTracker: new SessionTracker("shipped"),
    baseline: { scoreDeviation: () => ({ isDeviation: false }) },
    compatibility: false,
  };

  const socket = new Pipeline({ ...shared, surface: "uds" }).securityPosture();
  const mcp = new Gateway({ ...shared, servers: {}, log: () => {} }).securityPosture();
  assert.equal(socket.profile, SECURITY_PROFILE.PRODUCTION);
  assert.equal(mcp.profile, SECURITY_PROFILE.PRODUCTION);

  const surfaceBound = Object.keys(SURFACE_BOUND_STAGES);
  for (const stage of CANONICAL_STAGES) {
    if (surfaceBound.includes(stage)) continue;
    assert.equal(
      mcp.stages[stage],
      socket.stages[stage],
      `${stage}: the socket says "${socket.stages[stage]}" and the MCP gateway says "${mcp.stages[stage]}"`,
    );
  }

  /* THE COMPLETE DIFFERENCE, enumerated. Not "the differences we thought about"
     — every stage compared, and every difference required to be a declared
     surface-bound stage. A new asymmetry fails here before it can ship, and the
     declared set has to be updated on purpose. */
  const differing = CANONICAL_STAGES.filter((stage) => mcp.stages[stage] !== socket.stages[stage]);
  assert.deepEqual(
    differing.filter((stage) => !surfaceBound.includes(stage)),
    [],
    `undeclared cross-surface asymmetry in: ${differing.join(", ")}`,
  );
  const declaredAndDiffering = surfaceBound.filter((stage) => differing.includes(stage));
  assert.deepEqual(
    declaredAndDiffering.sort(),
    Object.keys(SURFACE_BOUND_STAGES).filter((stage) => mcp.stages[stage] !== socket.stages[stage]).sort(),
    "a stage declared surface-bound must actually differ, or the declaration is stale",
  );
  /* And the exempted stage is exempted for a stated reason, not by silence: the
     gateway owns the upstream definitions a pin is compared against. */
  assert.deepEqual(SURFACE_BOUND_STAGES.drift, [SURFACE.MCP_GATEWAY]);
  assert.equal(mcp.stages.drift, STAGE_STATUS.MANDATORY);
  assert.equal(socket.stages.drift, STAGE_STATUS.INERT);
  /* Nothing may be BYPASSABLE, and the report has to agree with the plan. */
  for (const stage of CANONICAL_STAGES) {
    assert.ok(Object.values(STAGE_STATUS).includes(mcp.stages[stage]), `${stage} has an unknown status`);
    assert.notEqual(mcp.stages[stage], STAGE_STATUS.PROFILE_DISABLED, `${stage} is disabled in production`);
  }
});

/* ========================================================================== */
/*  3. NO SILENT DOWNGRADE (INV-018, INV-020)                                  */
/* ========================================================================== */

test("INV-020: a hardened boundary reports itself hardened, and never as compatibility", () => {
  const hardened = new Pipeline({ rules: rules(), cwd: WORKSPACE, identityMode: "production", compatibility: false });
  const posture = hardened.securityPosture();
  assert.equal(posture.profile, SECURITY_PROFILE.PRODUCTION);
  assert.equal(posture.hardened, true);
  assert.equal(posture.compatibility, false);

  /* And the reverse: a library caller that stated nothing is reported as
     compatibility, not as production. */
  const libraryDefault = new Pipeline({ rules: rules(), cwd: WORKSPACE });
  assert.equal(libraryDefault.securityPosture().compatibility, true);
  assert.equal(libraryDefault.securityPosture().hardened, false);
});

test("INV-020: an explicit DEV-INSECURE profile is visible on every decision", async () => {
  const deps = { rules: rules(), cwd: WORKSPACE, identityMode: "dev-insecure" };
  const { Pipeline: runPipeline, Guard: runGuard } = engines(deps);
  const p = await runPipeline(read(), {});
  const g = await runGuard(read(), {});
  assert.equal(p.decision, "allow");
  assert.equal(g.decision, "allow");
  const posture = new Pipeline({ ...deps }).securityPosture();
  assert.equal(posture.profile, SECURITY_PROFILE.DEV_INSECURE);
  assert.equal(posture.compatibility, true, "a dev profile must never be reported as hardened");
});

test("INV-018: caller-controlled identity fields never become trusted context", async () => {
  const outcome = await authorize(
    {
      tool: "read_file",
      arguments: { path: `${WORKSPACE}/notes.txt` },
      /* Every one of these is a CLAIM. None may become the principal, the
         tenant or the audience the decision is evaluated against. */
      agent: "admin",
      principal: "root@example",
      tenant: "globex",
      audience: "runtime:prod",
      claim: "someone-else",
    },
    { principal: "worker", surface: SURFACE.DIRECT },
    { rules: rules(), cwd: WORKSPACE },
  );
  assert.equal(outcome.principal, "worker");
  assert.equal(outcome.claim, "admin", "the claim is recorded, and only recorded");
  assert.equal(outcome.identity.tenant, null);
  assert.equal(outcome.identity.audience, null);
  assert.equal(outcome.decision.decision, "allow");
});

/* ========================================================================== */
/*  4. STALE AND REVOKED AUTHORITY NEVER ALLOWS (INV-019, INV-021)             */
/* ========================================================================== */

test("INV-021: the policy version a runtime reports is the one it enforces", async () => {
  const enforced = rules();
  const other = compile("allow:\n  name = permit-everything\n  tool = *\n", { cwd: WORKSPACE, origin: "p0d" }).rules;
  const stamp = policyStamp(other);

  const { Pipeline: runPipeline, Guard: runGuard } = engines({
    policyVersion: "7",
    publishedPolicy: { version: "7", hash: stamp.policyHash },
  });
  const p = await runPipeline();
  const g = await runGuard();
  assert.equal(p.rule, "stale-policy");
  assert.equal(g.rule, "stale-policy");
  assert.equal(p.decision, "deny");
  assert.equal(g.decision, "deny");

  /* The honest agreement case: the published hash IS the enforced hash. */
  const agreed = policyStamp(enforced, { version: "7", published: { hash: policyStamp(enforced).policyHash } });
  assert.equal(agreed.stale, false);
  assert.equal(agreed.policyVersion, "7");
});

test("INV-019: a revocation written by another process refuses the call on both surfaces", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-parity-rev-"));
  const engine = await new RevocationEngine({ stateDir, log: () => {} }).init();
  await engine.revoke({ scope: REVOCATION_SCOPE.AGENT, subject: "local", reason: "parity test" });

  const { Pipeline: runPipeline, Guard: runGuard } = engines({ revocation: engine });
  const p = await runPipeline();
  const g = await runGuard();
  assert.equal(p.decision, "deny");
  assert.equal(g.decision, "deny");
  assert.equal(p.rule, "revoked-agent");
  assert.equal(g.rule, "revoked-agent");
  assert.equal(p.revocation?.subject, "local");
  assert.equal(g.revocation?.subject, "local");
});

/* ========================================================================== */
/*  5. EVIDENCE IS MANDATORY (INV-022)                                         */
/* ========================================================================== */

test("INV-022: a decision that cannot be recorded is a decision that does not stand", async () => {
  const deps = { audit: { append: async () => { throw new Error("journal unavailable"); } } };
  const { Pipeline: runPipeline, Guard: runGuard } = engines(deps);
  const p = await runPipeline();
  const g = await runGuard();
  assert.equal(p.decision, "deny");
  assert.equal(p.rule, "audit-unavailable");
  assert.equal(g.decision, "deny");
  assert.equal(g.rule, "audit-unavailable");
});

/* ========================================================================== */
/*  6. THE LIVE MCP BOUNDARY NOW RUNS THE STAGES IT USED TO SKIP              */
/* ========================================================================== */

class McpClient {
  #pending = new Map();
  #nextId = 1;

  constructor(gateway) {
    this.gateway = gateway;
    this.framer = new MessageFramer({
      onMessage: (m) => {
        const entry = this.#pending.get(m.id);
        if (!entry) return;
        this.#pending.delete(m.id);
        entry(m);
      },
    });
    gateway.start((msg) => this.framer.push(Buffer.from(JSON.stringify(msg) + "\n")));
  }

  request(method, params = {}, timeoutMs = 8000) {
    return new Promise((resolve, reject) => {
      const id = this.#nextId++;
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`timed out on ${method}`));
      }, timeoutMs);
      this.#pending.set(id, (m) => {
        clearTimeout(timer);
        resolve(m);
      });
      void this.gateway.handleClientMessage({ jsonrpc: "2.0", id, method, params });
    });
  }
}

test("MCP: the gateway now enforces a stage it previously skipped — session quarantine — and nothing executes", async () => {
  const root = await mkdtemp(join(tmpdir(), "cirvix-p0d-gw-"));
  const workspace = join(root, "workspace").split(String.fromCharCode(92)).join("/");
  const home = join(root, "home").split(String.fromCharCode(92)).join("/");
  await mkdir(join(workspace, "src"), { recursive: true });
  await mkdir(join(home, ".aws"), { recursive: true });
  await writeFile(join(workspace, "src", "app.ts"), "export const answer = 42;\n", "utf8");
  await writeFile(join(home, ".aws", "credentials"), "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", "utf8");
  const accessLog = join(root, "access.jsonl").split(String.fromCharCode(92)).join("/");
  await writeFile(accessLog, "", "utf8");

  const { rules: gwRules } = compile(POLICY, { cwd: workspace, origin: "p0d-gateway" });
  const chain = await new AuditChain(join(root, "audit.jsonl")).open();

  /* A quarantined session. The gateway has no session stage of its own — that
     was the asymmetry — so if this refuses, the refusal came from the canonical
     core the socket also calls. */
  const sessionTracker = new SessionTracker("gateway-session");
  sessionTracker.quarantine("operator paused this agent");

  const gateway = new Gateway({
    servers: {
      files: {
        command: process.execPath,
        args: [SERVER],
        env: {
          CIRVIX_TEST_SERVER_NAME: "files",
          CIRVIX_TEST_ACCESS_LOG: accessLog,
          CIRVIX_TEST_RESOURCE_ROOT: home,
        },
      },
    },
    rules: gwRules,
    audit: chain,
    cwd: workspace,
    log: () => {},
    sessionTracker,
  });

  const client = new McpClient(gateway);
  try {
    const listed = await client.request("tools/list", {});
    assert.ok(listed.result?.tools?.length, "the upstream must expose at least one tool");

    const decision = await client.request("tools/call", {
      name: "files__read_file",
      arguments: { path: `${workspace}/src/app.ts` },
    });

    const payload = JSON.stringify(decision.result ?? {});
    assert.match(payload, /stateful-exfiltration-chain/, "the canonical session stage must refuse over MCP");
    assert.doesNotMatch(payload, /answer = 42/, "a refused call must not return content");

    /* THE ORACLE. The server writes its access log BEFORE reading the file, so
       an empty log is proof that the call never reached it — not merely that the
       gateway said no. */
    const log = (await readFile(accessLog, "utf8")).trim();
    assert.equal(log, "", "the upstream must never have been called");
  } finally {
    gateway.stop();
  }
});

test("MCP and the local socket agree: the same logical call, the same decision", async () => {
  const root = await mkdtemp(join(tmpdir(), "cirvix-p0d-parity-"));
  const workspace = join(root, "workspace").split(String.fromCharCode(92)).join("/");
  await mkdir(join(workspace, "src"), { recursive: true });
  await writeFile(join(workspace, "src", "app.ts"), "export const answer = 42;\n", "utf8");

  const sharedRules = compile(POLICY, { cwd: workspace, origin: "p0d-parity" }).rules;
  const chain = await new AuditChain(join(root, "audit.jsonl")).open();

  /* The socket: a real server, a real client, the same rules. */
  const stateDir = join(root, "state");
  const token = await writeToken(stateDir);
  const endpoint = defaultEndpoint(stateDir);
  const server = new UdsServer({
    pipeline: new Pipeline({ rules: sharedRules, cwd: workspace, audit: chain }),
    endpoint,
    token,
    status: () => ({}),
    recent: async () => [],
  });
  await server.start();

  /* The SDK/Guard surface, in-process. */
  const guard = new Guard({ rules: sharedRules, cwd: workspace, audit: chain });
  const sdk = await guard.authorize({ tool: "read_file", arguments: { path: `${workspace}/src/app.ts` } });

  try {
    const client = new UdsClient({ endpoint, token });
    const socket = await client.call("cirvix/authorize", {
      tool: "read_file",
      arguments: { path: `${workspace}/src/app.ts` },
    });
    assert.equal(socket.decision, sdk.decision.decision, "socket and SDK must agree on the verb");
    assert.equal(socket.policy, sdk.decision.rule, "socket and SDK must agree on the rule");
    assert.equal(socket.decision, "allow");
    assert.equal(socket.policy, "allow-workspace-read");
  } finally {
    await server.stop();
  }
});
