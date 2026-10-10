/**
 * The Claude Code hook's failure posture, resolved in ONE place.
 *
 * A hook runs BEFORE the boundary it protects, so there is a set of inputs it
 * cannot evaluate: unparseable payload, no runtime token, a runtime that is not
 * listening, no identity material on the host. Whatever it does then IS a
 * security posture — there is no "no posture" — and it is the posture nobody
 * reads, because the hook is a two-line entry in a settings file.
 *
 * What this module exists to prevent: a hook that ALLOWS an unevaluated
 * consequential call (a shell command, a write, a fetch) without anybody having
 * chosen that. The previous revision defaulted to allow and documented the
 * default as fail-closed, which is the worst of both — an operator reading the
 * header believed Bash was governed while it was not.
 *
 * THE RULES
 *
 *   1. The default is ENFORCING. An unevaluated CONSEQUENTIAL call is denied.
 *   2. Compatibility (allow unevaluated) exists only when SELECTED, by
 *      `CIRVIX_HOOK_FAIL=open` or by an explicit dev profile
 *      (`CIRVIX_IDENTITY_MODE=dev-insecure|bootstrap`).
 *   3. An unrecognised value for `CIRVIX_HOOK_FAIL` is ENFORCING. A typo must
 *      never open the boundary.
 *   4. Whatever was decided is written down, and `doctor` and `status` read it.
 *
 * WHY THE HOOK KEEPS ITS OWN AUDIT CHAIN. The runtime owns
 * `<state>/audit.jsonl`, and an AuditChain is a per-process chain: each writer
 * caches its sequence and previous hash in memory. Two processes appending to
 * one file interleave those sequences and produce a chain that fails
 * verification on the next start — which the runtime treats as "refusing to
 * extend it", i.e. every decision becomes `audit-unavailable`. So the hook's
 * unevaluated-call record is its own append-only chain
 * (`<state>/claude-code-hook.jsonl`), tamper-evident in the same way, and the
 * decision trail stays owned by the boundary that took the decisions.
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { AuditChain } from "./audit.mjs";

export const HOOK_POSTURE = Object.freeze({
  /** Unevaluated consequential calls are refused. */
  ENFORCING: "enforcing",
  /** Unevaluated calls are allowed, on purpose, and recorded as such. */
  COMPATIBILITY: "compatibility",
});

export const HOOK_DECISION = Object.freeze({ ALLOW: "allow", DENY: "deny" });

export const UNEVALUATED_REASON = Object.freeze({
  MALFORMED_PAYLOAD: "malformed-payload",
  NO_RUNTIME: "runtime-not-initialized",
  UNREACHABLE: "runtime-unreachable",
  NO_IDENTITY: "no-identity-enrolled",
  STATE_UNREADABLE: "security-state-unreadable",
});

/**
 * Claude Code's built-in tools that CHANGE something outside the conversation:
 * they execute, persist, or reach the network. An unevaluated call to one of
 * these is the case the hook must never wave through.
 *
 * Read-only built-ins are NOT in this set, so a stopped runtime does not brick
 * reading a file — but they are still marked and recorded, never silently
 * allowed. An unknown tool name is treated as consequential: policy is what
 * decides unknown tools, and an unevaluated unknown is exactly what policy
 * would have refused.
 */
export const CONSEQUENTIAL_TOOLS = new Set([
  "Bash",
  "BashOutput",
  "KillShell",
  "Write",
  "Edit",
  "MultiEdit",
  "NotebookEdit",
  "WebFetch",
  "WebSearch",
  "Task",
]);

export function isConsequentialTool(name) {
  if (typeof name !== "string" || !name) return true;
  if (CONSEQUENTIAL_TOOLS.has(name)) return true;
  /* A tool nobody has classified is not assumed harmless. */
  return !["Read", "Glob", "Grep", "LS", "TodoWrite", "NotebookRead", "ListMcpResources"].includes(name);
}

const COMPAT_VALUES = new Set(["open", "compat", "compatibility", "insecure"]);
const COMPAT_MODES = new Set(["dev-insecure", "bootstrap", "compat"]);

/**
 * Resolves the posture from the environment. Pure: no disk, no clock, so every
 * branch below is directly testable and the hook cannot be the only place the
 * rule is implemented.
 */
export function resolveHookPosture({ fail = null, identityMode = null } = {}) {
  const requested = typeof fail === "string" ? fail.trim().toLowerCase() : "";
  const mode = typeof identityMode === "string" ? identityMode.trim().toLowerCase() : "";

  if (requested === "closed") {
    return { posture: HOOK_POSTURE.ENFORCING, explicit: true, source: "CIRVIX_HOOK_FAIL=closed" };
  }
  if (COMPAT_VALUES.has(requested)) {
    return {
      posture: HOOK_POSTURE.COMPATIBILITY,
      explicit: true,
      source: `CIRVIX_HOOK_FAIL=${requested}`,
      note: "unevaluated calls are allowed because this shell asked for it",
    };
  }
  if (requested) {
    return {
      posture: HOOK_POSTURE.ENFORCING,
      explicit: true,
      source: `CIRVIX_HOOK_FAIL=${requested}`,
      note: `"${requested}" is not a recognised posture; an unreadable setting must not open the boundary`,
    };
  }
  if (COMPAT_MODES.has(mode)) {
    return {
      posture: HOOK_POSTURE.COMPATIBILITY,
      explicit: true,
      source: `CIRVIX_IDENTITY_MODE=${mode}`,
      note: "the developer profile is selected explicitly",
    };
  }
  return { posture: HOOK_POSTURE.ENFORCING, explicit: false, source: "hardened default" };
}

/**
 * What the hook does when it cannot reach a decision.
 *
 * @returns {{decision: string, why: string}}
 */
export function unevaluatedOutcome({ posture, tool, reason }) {
  const consequential = isConsequentialTool(tool);
  if (posture === HOOK_POSTURE.COMPATIBILITY) {
    return { decision: HOOK_DECISION.ALLOW, consequential, why: `${reason} (compatibility posture)` };
  }
  if (consequential) {
    return { decision: HOOK_DECISION.DENY, consequential, why: `${reason} (enforcing posture)` };
  }
  return {
    decision: HOOK_DECISION.ALLOW,
    consequential,
    why: `${reason} (enforcing posture, read-only tool: allowed and recorded)`,
  };
}

export function hookStatePath(stateDir) {
  return join(stateDir, "claude-code-hook.json");
}

export function hookAuditPath(stateDir) {
  return join(stateDir, "claude-code-hook.jsonl");
}

/** The last observed posture, written by the hook so the CLI can report it. */
export async function readHookState(stateDir) {
  try {
    const raw = await readFile(hookStatePath(stateDir), "utf8");
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

async function writeHookState(stateDir, state) {
  await mkdir(stateDir, { recursive: true });
  await writeFile(hookStatePath(stateDir), JSON.stringify(state, null, 2), "utf8");
}

/**
 * Records one unevaluated call: a tamper-evident line in the hook's own chain,
 * plus the posture snapshot `doctor` and `status` read.
 *
 * Best-effort by design. If even this fails the hook still returns an answer,
 * because refusing to answer because the record could not be written is a
 * denial of service an attacker could trigger by filling the disk.
 */
export async function recordUnevaluatedCall({
  stateDir,
  posture,
  postureSource,
  tool,
  reason,
  decision,
  consequential,
  now = new Date(),
}) {
  if (!stateDir) return null;
  const record = {
    ts: now.toISOString(),
    kind: "hook-unevaluated-call",
    tool: tool ?? null,
    reason,
    consequential: consequential === true,
    decision,
    posture: posture.posture,
    postureSource: posture.source,
    postureExplicit: posture.explicit === true,
    agent: process.env.CIRVIX_AGENT ?? null,
    pid: process.pid,
  };
  try {
    const chain = await new AuditChain(hookAuditPath(stateDir)).open();
    await chain.append(record, now.toISOString());
  } catch {
    /* Recorded below in the posture snapshot even when the chain cannot be
       extended; a counter in a JSON file is weaker evidence than a chain, but
       it is not nothing, and it is not a reason to fail the call. */
  }
  try {
    const previous = (await readHookState(stateDir)) ?? {};
    await writeHookState(stateDir, {
      v: 1,
      posture: posture.posture,
      source: postureSource ?? posture.source,
      explicit: posture.explicit === true,
      note: posture.note ?? null,
      updatedAt: now.toISOString(),
      unevaluatedCalls: (previous.unevaluatedCalls ?? 0) + 1,
      unevaluatedAllowed: (previous.unevaluatedAllowed ?? 0) + (decision === HOOK_DECISION.ALLOW ? 1 : 0),
      unevaluatedDenied: (previous.unevaluatedDenied ?? 0) + (decision === HOOK_DECISION.DENY ? 1 : 0),
      lastUnevaluated: { at: now.toISOString(), tool: tool ?? null, reason, decision, consequential: consequential === true },
    });
  } catch {
    /* Reported by `doctor` as "the hook has never recorded anything", which is
       the truth and is visible. */
  }
  return record;
}
