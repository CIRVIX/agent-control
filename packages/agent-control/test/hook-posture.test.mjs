/**
 * The hook's failure posture is a SECURITY POSTURE, and these are its rules.
 *
 * Every branch of `resolveHookPosture` and `unevaluatedOutcome` is asserted
 * here, including the one that matters most in practice: an unrecognised
 * `CIRVIX_HOOK_FAIL` value must not open the boundary. A typo in a settings file
 * is the most likely way an operator would accidentally run a fail-open hook,
 * so it is the case with an explicit test.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  HOOK_DECISION,
  HOOK_POSTURE,
  UNEVALUATED_REASON,
  hookAuditPath,
  hookStatePath,
  isConsequentialTool,
  readHookState,
  recordUnevaluatedCall,
  resolveHookPosture,
  unevaluatedOutcome,
} from "../src/core/hook-posture.mjs";

test("posture: the default is ENFORCING, and it is not an explicit selection", () => {
  const resolved = resolveHookPosture({});
  assert.equal(resolved.posture, HOOK_POSTURE.ENFORCING);
  assert.equal(resolved.explicit, false);
});

test("posture: compatibility requires an explicit selection", () => {
  for (const value of ["open", "OPEN", "compat", "insecure"]) {
    const resolved = resolveHookPosture({ fail: value });
    assert.equal(resolved.posture, HOOK_POSTURE.COMPATIBILITY, `${value} selects compatibility`);
    assert.equal(resolved.explicit, true);
  }
  for (const mode of ["dev-insecure", "bootstrap"]) {
    const resolved = resolveHookPosture({ identityMode: mode });
    assert.equal(resolved.posture, HOOK_POSTURE.COMPATIBILITY, `${mode} selects compatibility`);
    assert.equal(resolved.explicit, true);
    assert.match(resolved.source, new RegExp(mode));
  }
});

test("posture: matching is case-insensitive, so an operator writing Open gets compatibility", () => {
  const resolved = resolveHookPosture({ fail: "Open" });
  assert.equal(resolved.posture, HOOK_POSTURE.COMPATIBILITY);
  assert.equal(resolved.explicit, true);
});

test("posture: an UNRECOGNISED value is ENFORCING, because a typo must not open the boundary", () => {
  for (const value of ["opne", "yes", "1", "false", "disabled", "quiet"]) {
    const resolved = resolveHookPosture({ fail: value });
    assert.equal(resolved.posture, HOOK_POSTURE.ENFORCING, `"${value}" must not select compatibility`);
    assert.match(resolved.note ?? "", /not a recognised posture/);
  }
});

test("posture: an explicit closed wins over a dev profile", () => {
  const resolved = resolveHookPosture({ fail: "closed", identityMode: "dev-insecure" });
  assert.equal(resolved.posture, HOOK_POSTURE.ENFORCING);
});

test("posture: the production identity profile is never compatibility", () => {
  const resolved = resolveHookPosture({ identityMode: "production" });
  assert.equal(resolved.posture, HOOK_POSTURE.ENFORCING);
  assert.equal(resolved.explicit, false);
});

test("consequential tools include the ones that execute, persist or reach out", () => {
  for (const tool of ["Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch", "Task"]) {
    assert.equal(isConsequentialTool(tool), true, `${tool} is consequential`);
  }
  for (const tool of ["Read", "Glob", "Grep"]) {
    assert.equal(isConsequentialTool(tool), false, `${tool} is read-only`);
  }
  /* An unclassified tool is NOT assumed harmless. */
  assert.equal(isConsequentialTool("SomeFutureTool"), true);
  assert.equal(isConsequentialTool(null), true);
});

test("outcome: enforcing denies a consequential call it could not evaluate", () => {
  for (const reason of Object.values(UNEVALUATED_REASON)) {
    const outcome = unevaluatedOutcome({ posture: HOOK_POSTURE.ENFORCING, tool: "Bash", reason });
    assert.equal(outcome.decision, HOOK_DECISION.DENY, `${reason} must deny a shell command`);
    assert.equal(outcome.consequential, true);
  }
});

test("outcome: enforcing allows a read-only call, and says so out loud", () => {
  const outcome = unevaluatedOutcome({
    posture: HOOK_POSTURE.ENFORCING,
    tool: "Read",
    reason: UNEVALUATED_REASON.UNREACHABLE,
  });
  assert.equal(outcome.decision, HOOK_DECISION.ALLOW);
  assert.equal(outcome.consequential, false);
  assert.match(outcome.why, /read-only tool: allowed and recorded/);
});

test("outcome: compatibility allows what enforcing denies, and never claims to be hardening", () => {
  const outcome = unevaluatedOutcome({
    posture: HOOK_POSTURE.COMPATIBILITY,
    tool: "Bash",
    reason: UNEVALUATED_REASON.UNREACHABLE,
  });
  assert.equal(outcome.decision, HOOK_DECISION.ALLOW);
  assert.match(outcome.why, /compatibility posture/);
});

test("recording: an unevaluated call lands in the hook's own chain and in the posture snapshot", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "cirvix-hookstate-"));
  try {
    const posture = resolveHookPosture({});
    await recordUnevaluatedCall({
      stateDir,
      posture,
      tool: "Bash",
      reason: UNEVALUATED_REASON.UNREACHABLE,
      decision: HOOK_DECISION.DENY,
      consequential: true,
    });
    const state = await readHookState(stateDir);
    assert.equal(state.posture, HOOK_POSTURE.ENFORCING);
    assert.equal(state.unevaluatedCalls, 1);
    assert.equal(state.unevaluatedDenied, 1);
    assert.equal(state.unevaluatedAllowed, 0);
    assert.equal(state.lastUnevaluated.tool, "Bash");

    const chained = (await readFile(hookAuditPath(stateDir), "utf8")).trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    assert.equal(chained.length, 1, "the call is on a chain, not in a loose file");
    assert.equal(chained[0].seq, 1);
    assert.ok(chained[0].hash, "the record is chained");
    assert.equal(chained[0].kind, "hook-unevaluated-call");

    /* A second call extends the same chain and the same counters. */
    await recordUnevaluatedCall({
      stateDir,
      posture: resolveHookPosture({ fail: "open" }),
      tool: "Read",
      reason: UNEVALUATED_REASON.UNREACHABLE,
      decision: HOOK_DECISION.ALLOW,
      consequential: false,
    });
    const after = await readHookState(stateDir);
    assert.equal(after.unevaluatedCalls, 2);
    assert.equal(after.unevaluatedAllowed, 1);
    assert.equal(after.posture, HOOK_POSTURE.COMPATIBILITY, "the snapshot reports the latest posture");
    const lines = (await readFile(hookAuditPath(stateDir), "utf8")).trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    assert.equal(lines.length, 2);
    assert.equal(lines[1].seq, 2, "the chain continues rather than restarting");
    assert.equal(lines[1].prev_hash, lines[0].hash, "and it is linked to the record before it");
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

test("recording: no state directory is not an exception", async () => {
  await assert.doesNotReject(() =>
    recordUnevaluatedCall({
      stateDir: null,
      posture: resolveHookPosture({}),
      tool: "Bash",
      reason: UNEVALUATED_REASON.MALFORMED_PAYLOAD,
      decision: HOOK_DECISION.DENY,
      consequential: true,
    }),
  );
});

test("paths: the hook never writes into the runtime's decision trail", () => {
  const stateDir = join("some", "state");
  assert.notEqual(hookAuditPath(stateDir), join(stateDir, "audit.jsonl"));
  assert.equal(hookStatePath(stateDir).endsWith("claude-code-hook.json"), true);
});
