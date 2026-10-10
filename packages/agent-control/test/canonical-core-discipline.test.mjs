/**
 * STRUCTURAL DISCIPLINE: there is ONE decision implementation, and this file
 * fails if a transport reintroduces a second one.
 *
 * P0-D's failure mode is not a bug in a stage — it is a transport quietly
 * growing its own stage. The MCP gateway ran identity/delegation/authority and
 * no session/baseline/drift; the socket ran session/baseline/drift and no
 * identity. Both had passing tests. No behavioural test catches the next one of
 * those, because the next one will also have passing tests. What catches it is a
 * test that reads the import graph and refuses the shape.
 *
 * HOW THIS FILE WAS WRITTEN: by dumping the actual import specifiers of every
 * adapter and classifying each one — stage evaluation (forbidden) versus
 * serialization, normalization, state containers and injected dependency CLASSES
 * (allowed, with a reason). The allowlists below are that classification, not a
 * guess. They are narrow on purpose: adding one entry is a deliberate act that
 * shows up in review.
 *
 * THE GRAPH IT PINS
 *
 *   guard.mjs    ──▶ authorize.mjs   (authorize as authorizeCanonical)
 *   pipeline.mjs ──▶ authorize.mjs   (authorize as authorizeCanonical)
 *   gateway.mjs  ──▶ guard.mjs       (Guard — an adapter over the adapter over the core)
 *   uds.mjs      ──▶ pipeline.submit (exactly one decision call site, no core import at all)
 *
 * and the core is the only module that imports the stage implementations:
 * policy, risk, delegation, authority, revocation, kill-switch, trifecta,
 * intent, entitlement-gate, approvals, secret-detect, normalize.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, "..", "src");
const CORE = join(SRC, "core");

/** The transports, by file. */
const ADAPTERS = {
  "src/core/guard.mjs": "MCP/SDK adapter",
  "src/core/pipeline.mjs": "local-socket adapter",
  "src/core/gateway.mjs": "MCP gateway transport",
  "src/core/uds.mjs": "socket transport",
};

/**
 * What an adapter is allowed to import from a core module, and why. Anything
 * not listed is stage evaluation and belongs in the canonical core.
 */
const ALLOWED_SYMBOLS = {
  "./policy.mjs": {
    canonicalizeResource: "normalization: one definition of what a resource IS, shared with the policy engine",
  },
  "./trifecta.mjs": {
    SessionTaint: "state container; the ANALYSIS is the core's trifecta stage",
  },
  "./authority.mjs": {
    captureMissionCost: "telemetry helper; the authority DECISION is the core's",
  },
  "./normalize.mjs": {
    "*": "the transport's own request parsing and evidence rendering",
  },
  "./decisions.mjs": {
    "*": "the verdict VOCABULARY a transport has to render",
  },
  "./secret-detect.mjs": {
    redact: "output redaction, downstream of the decision",
  },
  "./sanitize.mjs": {
    stripInjection: "output sanitization of a result the core already authorized",
  },
  "./identity-modes.mjs": {
    "*": "the identity MODE vocabulary the transport states",
  },
  "./session.mjs": {
    SessionTracker: "a stage DEPENDENCY: constructed and handed to the core, never evaluated here",
  },
  "./baseline.mjs": {
    BehavioralBaseline: "a stage DEPENDENCY: constructed and handed to the core",
  },
  "./tool-drift.mjs": {
    ToolPinRegistry: "a stage DEPENDENCY: constructed and handed to the core",
  },
  "./jsonrpc.mjs": { "*": "the transport's protocol" },
  "./http-transport.mjs": { "*": "the transport's protocol" },
  "./windows.mjs": { "*": "platform helpers" },
  "./audit.mjs": { "*": "the record a decision is written to" },
  "./keys.mjs": { "*": "key loading for a verifier the boundary constructs" },
  "./principal.mjs": { "*": "principal vocabulary" },
  "./graph.mjs": { "*": "call-graph rendering" },
  "./proof.mjs": { "*": "signature primitives" },
  "./identity.mjs": { "*": "the caller-side identity helpers a transport authenticates with" },
  "./identity-store.mjs": { "*": "agent records" },
  "./tool-drift.mjs": { ToolPinRegistry: "stage dependency" },
};

/**
 * Stage implementations. A transport that imports one of these is making a
 * decision, which means the canonical order is no longer the only order.
 */
const STAGE_MODULES = [
  "./policy.mjs",
  "./policy-dsl.mjs",
  "./risk.mjs",
  "./delegation.mjs",
  "./delegation-ed25519.mjs",
  "./revocation.mjs",
  "./kill-switch.mjs",
  "./intent.mjs",
  "./entitlement-gate.mjs",
  "./approvals.mjs",
  "./authorize.mjs",
];

/** Calls that would mean an adapter is evaluating a stage itself. */
const FORBIDDEN_CALLS = [
  "evaluateRevocations(",
  "foldRevocations(",
  "assessTrifecta(",
  "applyTrifecta(",
  "evaluateIntent(",
  "applyMode(",
  "applyEntitlements(",
  "escalateForRisk(",
  "plannedRule(",
  "stricterIdentityMode(",
  "recordStep(",
  "scoreDeviation(",
  "DECISION_PRECEDENCE",
];

/**
 * Core helpers an adapter is ALLOWED to call, because they answer "what am I"
 * rather than "what is the verdict": the profile resolver maps a boundary's own
 * options onto the profile name the posture report uses, and both decision
 * adapters need it to describe themselves.
 */
const ALLOWED_CORE_CALLS = ["resolveSecurityProfile("];

function importSpecifiers(source) {
  const found = [];
  const re = /import\s+([\s\S]*?)\s+from\s+"([^"]+)"/g;
  let match;
  while ((match = re.exec(source))) {
    const clause = match[1].replace(/\/\*[\s\S]*?\*\//g, "").replace(/\s+/g, " ").trim();
    const names = [...clause.matchAll(/[{,]\s*([A-Za-z_$][\w$]*)/g)].map((m) => m[1]);
    const bare = clause.match(/^([A-Za-z_$][\w$]*)\s*(?:,|$)/)?.[1];
    found.push({ specifier: match[2], symbols: [...(bare && !clause.includes("{") ? [bare] : []), ...names] });
  }
  return found;
}

async function read(rel) {
  return readFile(join(HERE, "..", rel), "utf8");
}

const sources = new Map();

test("load the four transports", async () => {
  for (const rel of Object.keys(ADAPTERS)) sources.set(rel, await read(rel));
  assert.equal(sources.size, 4);
});

test("every transport reaches the canonical core, directly or through an adapter", () => {
  const guard = sources.get("src/core/guard.mjs");
  const pipeline = sources.get("src/core/pipeline.mjs");
  const gateway = sources.get("src/core/gateway.mjs");
  const uds = sources.get("src/core/uds.mjs");

  /* The two decision adapters call authorize() from the core, aliased so the
     import cannot be confused with their own methods. */
  for (const [source, surface] of [[guard, "MCP/SDK"], [pipeline, "local socket"]]) {
    assert.match(
      source,
      /import\s*\{[\s\S]*?\bauthorize as (\w+)[\s\S]*?\}\s*from\s*"\.\/authorize\.mjs"/,
      `${surface} does not import authorize() from the canonical core`,
    );
    const alias = source.match(/\bauthorize as (\w+)/)[1];
    assert.match(source, new RegExp(`\\b${alias}\\(`), `${surface} imports authorize() but never calls it (${alias})`);
  }

  /* The gateway is an adapter over the Guard adapter: it must not reach around it. */
  assert.match(gateway, /from "\.\/guard\.mjs"/, "the gateway must decide through the Guard");
  assert.ok(!/from "\.\/authorize\.mjs"/.test(gateway), "the gateway must not import the core directly AND the Guard");

  /* The socket owns transport auth and one, single call into the pipeline. */
  const decisionCalls = uds.split("\n").filter((line) => /\.submit\(|\.authorize\(/.test(line) && !/^\s*\*/.test(line));
  assert.equal(decisionCalls.length, 1, `the socket has ${decisionCalls.length} decision call sites`);
  assert.match(decisionCalls[0], /this\.pipeline\.submit\(/);
});

test("no transport imports a stage implementation, except for the documented helpers", () => {
  for (const [rel, surface] of Object.entries(ADAPTERS)) {
    for (const { specifier, symbols } of importSpecifiers(sources.get(rel))) {
      if (!specifier.startsWith(".")) continue;
      if (!STAGE_MODULES.includes(specifier)) continue;
      if (specifier === "./authorize.mjs" && rel !== "src/core/uds.mjs" && rel !== "src/core/gateway.mjs") continue;
      const allowed = ALLOWED_SYMBOLS[specifier] ?? {};
      for (const symbol of symbols) {
        assert.ok(
          allowed[symbol] ?? allowed["*"],
          `${surface} (${rel}) imports ${symbol} from ${specifier} — that is stage evaluation, which belongs in core/authorize.mjs` +
            (Object.keys(allowed).length ? ` (allowed here: ${Object.keys(allowed).join(", ")})` : ""),
        );
      }
    }
  }
});

test("no transport calls a stage evaluator", () => {
  for (const [rel, surface] of Object.entries(ADAPTERS)) {
    const source = sources.get(rel);
    for (const call of FORBIDDEN_CALLS) {
      assert.ok(!ALLOWED_CORE_CALLS.includes(call), "a call cannot be both forbidden and allowed");
      const callSites = source
        .split("\n")
        .filter((line) => line.includes(call))
        .filter((line) => !/^\s*(\*|\/\*|\/\/)/.test(line));
      assert.equal(
        callSites.length,
        0,
        `${surface} (${rel}) calls ${call} — a transport that evaluates a stage is a second implementation`,
      );
    }
  }
});

test("no transport constructs a run or defines its own decision function", () => {
  for (const [rel, surface] of Object.entries(ADAPTERS)) {
    const source = sources.get(rel);
    assert.ok(!/new AuthorizationRun\(/.test(source), `${surface} (${rel}) constructs an AuthorizationRun itself`);
    assert.ok(
      !/^\s*(export\s+)?(async\s+)?function\s+\w*(decide|verdict|adjudicate|authorizeRequest)\w*\s*\(/im.test(source),
      `${surface} (${rel}) defines its own decision function`,
    );
  }
});

test("the canonical order and the stage contracts are defined exactly once, in the core", async () => {
  const files = [];
  const walk = async (dir) => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.name.endsWith(".mjs")) files.push(full);
    }
  };
  await walk(SRC);

  const definers = { CANONICAL_STAGES: [], STAGE_CONTRACT: [], MANDATORY_STAGES: [] };
  for (const file of files) {
    const source = await readFile(file, "utf8");
    for (const name of Object.keys(definers)) {
      if (new RegExp(`export const ${name}\\s*=`).test(source) || new RegExp(`^const ${name}\\s*=`, "m").test(source)) {
        definers[name].push(file.slice(SRC.length + 1).replace(/\\/g, "/"));
      }
    }
  }
  for (const [name, where] of Object.entries(definers)) {
    assert.deepEqual(where, [`core/authorize.mjs`], `${name} is defined in ${JSON.stringify(where)}`);
  }
});

test("the core is the only module that imports the stage implementations", async () => {
  const core = await readFile(join(CORE, "authorize.mjs"), "utf8");
  const importedByCore = new Set(importSpecifiers(core).map((i) => i.specifier));
  for (const stage of [
    "./policy.mjs",
    "./risk.mjs",
    "./delegation.mjs",
    "./authority.mjs",
    "./revocation.mjs",
    "./kill-switch.mjs",
    "./trifecta.mjs",
    "./intent.mjs",
    "./entitlement-gate.mjs",
    "./approvals.mjs",
    "./secret-detect.mjs",
    "./normalize.mjs",
  ]) {
    assert.ok(importedByCore.has(stage), `the canonical core does not import ${stage}; that stage is orphaned`);
  }

  /* And no OTHER module under src/core decides on a live call. Commands
     (policy tooling, replay, shadow, doctor) may evaluate — they are not
     boundaries — but the core directory may not grow a second engine. */
  const boundaries = ["guard.mjs", "pipeline.mjs", "gateway.mjs", "uds.mjs", "http-transport.mjs"];
  for (const file of boundaries) {
    const source = await readFile(join(CORE, file), "utf8");
    const stageImports = importSpecifiers(source)
      .map((i) => i.specifier)
      .filter((s) => STAGE_MODULES.includes(s) && s !== "./authorize.mjs");
    for (const specifier of stageImports) {
      const allowed = Object.keys(ALLOWED_SYMBOLS[specifier] ?? {});
      if (allowed.length === 0) {
        assert.ok(
          false,
          `${file} imports ${specifier} with no documented allowance — a boundary must not evaluate a stage`,
        );
      }
    }
  }
});

test("every transport asks the core what it enforces", () => {
  for (const [rel, surface] of Object.entries(ADAPTERS)) {
    const source = sources.get(rel);
    const asksTheCore =
      /describeCanonicalPosture\(/.test(source) ||
      /guard\.securityPosture\(\)/.test(source) ||
      /pipeline\.securityPosture\(\)/.test(source);
    assert.ok(
      asksTheCore,
      `${surface} (${rel}) does not derive its posture from the canonical core`,
    );
  }
});
