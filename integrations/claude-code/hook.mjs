#!/usr/bin/env node
/**
 * Claude Code `PreToolUse` hook → Cirvix.
 *
 * Governs Claude Code's BUILT-IN tools (Bash, Write, Edit, WebFetch, …), which
 * the MCP gateway never sees because they are not MCP calls. Without this,
 * "Cirvix is protecting Claude Code" is true of the MCP half and false of the
 * half that runs shell commands — and the shell half is the one that matters.
 *
 * PROTOCOL
 *
 * Claude Code writes a JSON object on stdin and reads one on stdout. Exit 0 with
 * `permissionDecision: "deny"` blocks the call and hands the model the reason;
 * exit 0 with `"allow"` lets it through.
 *
 * WHEN THE CALL CANNOT BE EVALUATED
 *
 * Three things can stop an evaluation before it happens: unparseable input, no
 * runtime token in the state directory, and a runtime that is not listening. In
 * each of them a POSTURE decides — and the posture is ENFORCING unless somebody
 * explicitly selected compatibility (core/hook-posture.mjs owns the rule, so the
 * hook cannot be the only place it is implemented):
 *
 *   unset (default)                      ENFORCING      deny unevaluated consequential calls
 *   CIRVIX_HOOK_FAIL=closed              ENFORCING
 *   CIRVIX_HOOK_FAIL=open                COMPATIBILITY  allow, recorded, marked
 *   CIRVIX_IDENTITY_MODE=dev-insecure    COMPATIBILITY  allow, recorded, marked
 *   CIRVIX_HOOK_FAIL=<anything else>     ENFORCING      a typo never opens the boundary
 *
 * "Consequential" means the tool executes, persists or reaches the network
 * (Bash, Write, Edit, WebFetch, an unknown tool name). Read-only built-ins
 * (Read, Glob, Grep) are allowed and RECORDED rather than denied, so a stopped
 * runtime does not brick reading a file — but nothing is ever allowed silently:
 * every unevaluated call is written to the hook's own append-only chain
 * (`<state>/claude-code-hook.jsonl`) and counted in `<state>/claude-code-hook.json`,
 * which `cirvix doctor` and `cirvix status` read. `doctor` reports the posture in
 * plain words and warns when unevaluated calls are being allowed.
 *
 * IDENTITY IS PRESENTED, NOT CLAIMED
 *
 * The hook loads the agent identity enrolled on this host (core/identity.mjs
 * `loadCallerIdentity`) and attaches the credential plus a signature over the
 * exact params it sends, so the SOCKET decides who the caller is — through the
 * same identity stage, the same production refusal and the same evidence every
 * other surface uses. No enrolment is a state this hook REPORTS, not one it
 * papers over.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { UdsClient, defaultEndpoint, tokenPath } from "../../packages/agent-control/src/core/uds.mjs";
import { loadCallerIdentity } from "../../packages/agent-control/src/core/identity.mjs";
import {
  HOOK_DECISION,
  HOOK_POSTURE,
  UNEVALUATED_REASON,
  resolveHookPosture,
  recordUnevaluatedCall,
  unevaluatedOutcome,
} from "../../packages/agent-control/src/core/hook-posture.mjs";

const METHOD = "cirvix/authorize";

/** Claude Code's built-in tool names → the arguments Cirvix reads. */
function toCall(input) {
  const name = input.tool_name ?? input.toolName ?? "";
  const args = input.tool_input ?? input.toolInput ?? {};

  switch (name) {
    case "Bash":
      return { tool: "shell.exec", arguments: { command: args.command ?? "" } };
    case "Read":
      return { tool: "filesystem.read", arguments: { path: args.file_path ?? args.path ?? "" } };
    case "Write":
      return { tool: "filesystem.write", arguments: { path: args.file_path ?? args.path ?? "" } };
    case "Edit":
    case "NotebookEdit":
      return { tool: "filesystem.write", arguments: { path: args.file_path ?? args.notebook_path ?? "" } };
    case "Glob":
      return { tool: "filesystem.list", arguments: { path: args.path ?? args.pattern ?? "" } };
    case "Grep":
      return { tool: "filesystem.search", arguments: { path: args.path ?? "" } };
    case "WebFetch":
      return { tool: "network.request", arguments: { url: args.url ?? "" } };
    case "WebSearch":
      return { tool: "network.request", arguments: { url: "https://search.invalid/" } };
    default:
      // An unrecognised built-in keeps its own identity rather than being
      // guessed into a bucket. Policy must name it explicitly.
      return { tool: name, arguments: args };
  }
}

function reply(decision, reason) {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: decision,
        permissionDecisionReason: reason,
      },
    }) + "\n",
  );
}

/** The posture this invocation ran under, resolved once. */
const resolvedPosture = resolveHookPosture({
  fail: process.env.CIRVIX_HOOK_FAIL ?? null,
  identityMode: process.env.CIRVIX_IDENTITY_MODE ?? null,
});

/** How to change the posture, in the message the model and the operator read. */
function postureRemedy() {
  return resolvedPosture.posture === HOOK_POSTURE.ENFORCING
    ? "Set CIRVIX_HOOK_FAIL=open only if you intend unevaluated tool calls to be allowed."
    : `Compatibility posture is in force (${resolvedPosture.source}): unevaluated calls are ALLOWED. Unset it to enforce.`;
}

/**
 * The single place an unevaluated call is answered, so every failure branch is
 * recorded and every branch follows the resolved posture. `tool` is the Claude
 * Code tool name (which is what "consequential" is defined over).
 */
async function answerUnevaluated({ stateDir, tool, reason, detail }) {
  /* `posture` here is the resolved OBJECT; `unevaluatedOutcome` takes the
     posture NAME. Passing the object was a real bug that this file's own tests
     caught: every branch fell through to the enforcing case, so compatibility
     was reported in the message and denied in the decision. */
  const { decision, consequential, why } = unevaluatedOutcome({
    posture: resolvedPosture.posture,
    tool,
    reason,
  });
  await recordUnevaluatedCall({
    stateDir,
    posture: resolvedPosture,
    postureSource: resolvedPosture.source,
    tool,
    reason,
    decision,
    consequential,
  });
  const lines = [
    detail,
    decision === HOOK_DECISION.DENY
      ? `Cirvix refused this call because it could not be evaluated (${why}). Nothing was executed.`
      : `This call was NOT evaluated by Cirvix (${why}).`,
    consequential ? "" : "This tool is read-only, so the call was not blocked.",
  ].filter(Boolean);
  lines.push(postureRemedy());
  process.stderr.write(`[cirvix] ${lines[0]} ${postureRemedy()}\n`);
  reply(decision, lines.join("\n"));
  return 0;
}

async function main() {
  /* The state directory is resolved first, because it is where the posture and
     the unevaluated calls are recorded — including for a malformed payload,
     where every other field is unavailable. */
  let input = null;
  let malformed = null;
  try {
    const raw = readFileSync(0, "utf8") || "{}";
    input = JSON.parse(raw);
    if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("hook payload must be a JSON object");
  } catch (err) {
    malformed = err;
  }

  const stateDir = process.env.CIRVIX_STATE ?? join(input?.cwd ?? process.cwd(), ".cirvix");

  if (malformed) {
    return answerUnevaluated({
      stateDir,
      tool: null,
      reason: UNEVALUATED_REASON.MALFORMED_PAYLOAD,
      detail: "Cirvix could not parse the hook payload, so the call was not evaluated.",
    });
  }

  const toolName = input.tool_name ?? input.toolName ?? null;
  const call = toCall(input);

  let token;
  try {
    token = readFileSync(tokenPath(stateDir), "utf8").trim();
  } catch {
    return answerUnevaluated({
      stateDir,
      tool: toolName,
      reason: UNEVALUATED_REASON.NO_RUNTIME,
      detail: `Cirvix runtime is not initialized in ${stateDir}. Run \`cirvix init\` then \`cirvix runtime\`.`,
    });
  }

  /* WHO IS CALLING. The enrolled agent on this host, named explicitly when
     several exist. Resolved BEFORE the call is built, because the proof covers
     the params actually sent: signing a body and then changing it is the
     classic way to have a boundary refuse a request for "not matching what
     arrived", with nothing in the message pointing at the cause. */
  let identity = null;
  try {
    identity = await loadCallerIdentity({ stateDir, agentId: process.env.CIRVIX_AGENT ?? null });
  } catch (err) {
    process.stderr.write(`[cirvix] could not read the enrolled identity: ${err.message}\n`);
  }

  const params = {
    ...call,
    /* No `agent` claim is sent without an identity behind it. At a boundary
       that requires proof, a claim is exactly what gets refused, and at one
       that does not, a claim would be recorded as though it meant something. */
    ...(identity ? { agent: identity.agentId } : {}),
    source: "hook",
  };
  if (identity) params._meta = { cirvix: identity.meta(params, METHOD) };

  try {
    const client = new UdsClient({ endpoint: defaultEndpoint(stateDir), token, timeoutMs: 3000 });
    const result = await client.call(METHOD, params);

    if (result.allowed) {
      reply("allow", `${result.policy ?? "policy"} · risk ${String(result.risk).toUpperCase()} · ${result.latency_ms}ms`);
      return 0;
    }

    // The refusal the model reads. Carrying the remediation is what lets it
    // re-plan rather than retry the same call, and carrying the IDENTITY
    // evidence is what lets an operator tell "the policy said no" from "this
    // host never proved who was calling" without reading the audit trail.
    const lines = [
      `Blocked by Cirvix policy: ${result.policy ?? "default-deny"}`,
      result.reason,
      result.remediation ? `Try instead: ${result.remediation}` : null,
      result.approval_id ? `Waiting on approval ${result.approval_id}` : null,
      identity
        ? `Identity: ${result.identity?.verified ? `verified as ${result.identity.agentId ?? identity.agentId}` : "NOT verified"}`
        : `Identity: none presented — no agent is enrolled in ${stateDir}. Run \`cirvix enroll claude-code\` to give this surface a verified identity.`,
      `Request id: ${result.request_id}`,
    ].filter(Boolean);

    reply("deny", lines.join("\n"));
    return 0;
  } catch (err) {
    return answerUnevaluated({
      stateDir,
      tool: toolName,
      reason: UNEVALUATED_REASON.UNREACHABLE,
      detail: `Cirvix runtime unreachable (${err.message}).`,
    });
  }
}

main().then((code) => process.exit(code));
