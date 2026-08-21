/**
 * The consistency oracle — can Cirvix be made to lie?
 *
 * Every other test asks whether a decision is correct. This asks something
 * harder and more important: whether the three things Cirvix tells you about a
 * call agree with each other.
 *
 *   INPUT  ──▶  DECISION  ──▶  ACTUAL EXECUTION  ──▶  AUDIT RECORD
 *
 * A security product is exposed at exactly the seams between those. The failure
 * modes are not "wrong decision" — they are:
 *
 *   · It says DENY and the operation happens anyway.
 *   · It says SANITIZE and the *unsanitized* form is what executes.
 *   · It says ALLOW and the audit record describes a different call.
 *   · It says REQUIRE_APPROVAL and there is a path that executes first.
 *   · It executes correctly and records nothing, so the history is a lie by
 *     omission.
 *
 * Each of those is invisible to a test that checks only the returned verdict,
 * because in every one of them the verdict is *right*. What is wrong is that
 * something else disagreed with it.
 *
 * HOW GROUND TRUTH IS ESTABLISHED
 *
 * Not from Cirvix. The MCP server is a real subprocess that really opens files
 * and really records, to a side-channel file, every operation it attempted —
 * written BEFORE the attempt, so a crash mid-read still leaves the receipt.
 * That log is the only witness this oracle trusts. Everything else is the
 * defendant's own testimony.
 */

import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { AuditChain } from "../../src/core/audit.mjs";
import { Gateway } from "../../src/core/gateway.mjs";
import { MessageFramer } from "../../src/core/jsonrpc.mjs";
import { compile } from "../../src/core/policy-dsl.mjs";
import { DECISION, toDecision } from "../../src/core/decisions.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = join(HERE, "..", "fixtures", "mock-mcp-server.mjs");

/* -------------------------------------------------------------------------- */
/*  The world under test                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Builds a real workspace, a real gateway, and a real MCP server subprocess.
 *
 * Returns handles for the three witnesses the oracle cross-examines:
 *   `call()`      what Cirvix said
 *   `accesses()`  what the server actually did
 *   `records()`   what the audit chain claims happened
 */
export async function createWorld({ policy } = {}) {
  const root = await mkdtemp(join(tmpdir(), "cirvix-oracle-"));
  const workspace = join(root, "workspace").replace(/\\/g, "/");
  const home = join(root, "home").replace(/\\/g, "/");

  await mkdir(join(workspace, "src"), { recursive: true });
  await mkdir(join(home, ".aws"), { recursive: true });
  await writeFile(join(workspace, "src", "app.ts"), "export const answer = 42;\n", "utf8");
  await writeFile(join(workspace, "src", "notes.md"), "Nothing secret here.\n", "utf8");
  await writeFile(
    join(home, ".aws", "credentials"),
    "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n",
    "utf8",
  );

  const accessLog = join(root, "access.jsonl").replace(/\\/g, "/");
  await writeFile(accessLog, "", "utf8");

  const source = policy ?? DEFAULT_POLICY;
  const { rules } = compile(source, { cwd: workspace, origin: "oracle" });
  const chain = await new AuditChain(join(root, "audit.jsonl")).open();

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
    rules,
    audit: chain,
    cwd: workspace,
    log: () => {},
  });
  gateway.agentName = "claude-code";

  /* A real MCP client over the real framer. */
  const pending = new Map();
  let nextId = 1;
  const framer = new MessageFramer({ onMessage: (m) => pending.get(m.id)?.(m) });
  gateway.start((msg) => framer.push(Buffer.from(JSON.stringify(msg) + "\n")));

  const request = (method, params, timeoutMs = 8000) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`timed out on ${method}`));
      }, timeoutMs);
      pending.set(id, (m) => {
        clearTimeout(timer);
        pending.delete(id);
        resolve(m);
      });
      void gateway.handleClientMessage({ jsonrpc: "2.0", id, method, params });
    });

  return {
    root,
    workspace,
    home,
    gateway,
    chain,
    request,
    credentialUri: pathToFileURL(`${home}/.aws/credentials`).href,

    /** Every operation the server actually attempted. The only ground truth. */
    async accesses() {
      const text = await readFile(accessLog, "utf8");
      return text.split("\n").filter(Boolean).map((l) => JSON.parse(l));
    },

    async records() {
      return chain.read();
    },

    stop() {
      gateway.stop();
    },
  };
}

const DEFAULT_POLICY = `
deny:
  name = deny-credentials
  tool = filesystem.read
  path = **/.aws/**
  reason = "Cloud credentials are never readable by an agent."

deny:
  name = deny-destructive
  tool = shell.exec
  command = "rm -rf"

deny:
  name = deny-critical-shell
  tool = shell.exec
  risk >= CRITICAL

require_approval:
  name = approve-shell
  tool = shell.exec
  risk >= HIGH
  approvers = oncall

sanitize:
  name = sanitize-fetched
  tool = network.request
  targets = result

allow:
  name = allow-workspace-read
  tool = filesystem.read
  workspace = true

allow:
  name = allow-safe-shell
  tool = shell.exec
  risk <= MEDIUM

allow:
  name = allow-network
  tool = network.request
`;

/* -------------------------------------------------------------------------- */
/*  The oracle                                                                 */
/* -------------------------------------------------------------------------- */

/** The secrets that must never appear anywhere Cirvix reports. */
export const PLANTED_SECRETS = [
  "AKIAIOSFODNN7EXAMPLE",
  "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
];

/**
 * Reads a decision out of an MCP tool result.
 *
 * The gateway reports a refusal as a tool result with `_meta`, not as a
 * transport error, so this is where the claimed decision lives.
 */
export function decisionOf(response) {
  const meta = response?.result?._meta ?? {};
  const verdict = meta["cirvix/verdict"];
  if (verdict) return toDecision(verdict);
  if (response?.error) return DECISION.DENY;
  // No refusal metadata and no error: the call was forwarded.
  return DECISION.ALLOW;
}

/** True when the server's log shows it touched `needle`. */
export function touched(accesses, needle) {
  return accesses.some((a) => String(a.target).replace(/\\/g, "/").includes(needle));
}

/**
 * Cross-examines one call.
 *
 * @param {object} evidence
 * @param {object} evidence.response   what Cirvix returned to the agent
 * @param {Array}  evidence.accesses   what the server actually attempted
 * @param {Array}  evidence.records    what the audit chain claims
 * @param {string} [evidence.target]   substring identifying the sensitive resource
 * @param {number} [evidence.accessesBefore] log length before this call
 * @returns {string[]} inconsistencies, empty when the three witnesses agree
 */
export function crossExamine({ response, accesses, records, target, accessesBefore = 0 }) {
  const problems = [];
  const decision = decisionOf(response);
  const newAccesses = accesses.slice(accessesBefore);

  /* ---------------------------------------------------------- 1. execution */

  if (decision === DECISION.DENY) {
    // The central claim. A denial that still executes is the failure that
    // makes every other guarantee worthless.
    if (target && touched(newAccesses, target)) {
      problems.push(
        `DENY but the server attempted it: ${JSON.stringify(newAccesses.map((a) => a.target))}`,
      );
    }
    if (!target && newAccesses.length > 0) {
      problems.push(`DENY but the server performed ${newAccesses.length} operation(s)`);
    }
  }

  if (decision === DECISION.REQUIRE_APPROVAL) {
    // There must be no execution-before-approval path. If the call reached the
    // server while it was still pending, the approval is decoration.
    if (newAccesses.length > 0) {
      problems.push(
        `REQUIRE_APPROVAL but the server already executed: ${JSON.stringify(newAccesses.map((a) => a.target))}`,
      );
    }
    const text = response?.result?.content?.[0]?.text ?? "";
    if (text.includes("EXECUTED")) {
      problems.push("REQUIRE_APPROVAL but the response carries an execution result");
    }
  }

  /* ------------------------------------------------------------- 2. record */

  // Every call must produce exactly one decision record. Zero is a history
  // that omits what happened; more than one makes "why" ambiguous.
  const forThisCall = records.filter((r) => r.decision_id === response?.result?._meta?.["cirvix/decision_id"]);
  if (response?.result?._meta?.["cirvix/decision_id"] && forThisCall.length !== 1) {
    problems.push(`expected exactly 1 audit record for this decision, found ${forThisCall.length}`);
  }

  const last = records[records.length - 1];
  if (!last) {
    problems.push("no audit record was written at all");
  } else {
    const recorded = last.decision ?? toDecision(last.verdict);
    if (recorded !== decision) {
      problems.push(`told the agent ${decision} but recorded ${recorded}`);
    }
    if (last.verdict === "permit" && decision === DECISION.DENY) {
      problems.push("recorded a permit for a call it refused");
    }
  }

  /* ------------------------------------------------------------ 3. secrets */

  // No surface Cirvix produces may contain planted credential material —
  // not the response, not the record.
  const surfaces = { response: JSON.stringify(response ?? {}), audit: JSON.stringify(records ?? []) };
  for (const [where, text] of Object.entries(surfaces)) {
    for (const secret of PLANTED_SECRETS) {
      if (text.includes(secret)) problems.push(`planted secret leaked into the ${where}`);
    }
  }

  return problems;
}

/**
 * Verifies the audit chain still verifies, and that it covers every call.
 *
 * Separated from `crossExamine` because it is a property of the run rather than
 * of one call: a chain that verifies but is missing entries is a chain that
 * proves nobody edited the lies it does contain.
 */
export async function auditIsComplete(world, expectedCalls) {
  const problems = [];
  const verification = await world.chain.verify();
  if (!verification.ok) {
    problems.push(`audit chain broken at record ${verification.brokenAt}: ${verification.reason}`);
  }
  const records = await world.records();
  if (records.length !== expectedCalls) {
    problems.push(`expected ${expectedCalls} audit records, found ${records.length}`);
  }
  return problems;
}
