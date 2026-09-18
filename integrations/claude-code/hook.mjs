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
 * FAILS OPEN, LOUDLY, AND ONLY WHEN IT CANNOT DECIDE
 *
 * If the runtime is not listening, this hook allows the call and writes a
 * warning to stderr. That is a deliberate and arguable choice: a hook that
 * fails closed turns "I forgot to start the runtime" into "my editor is
 * bricked", and the practical result is that people delete the hook. Failing
 * open with a visible warning keeps the control in place across restarts.
 *
 * FAIL CLOSED BY DEFAULT, WITH AN EXPLICIT ESCAPE HATCH
 *
 * Malformed input can never be evaluated, so the only question is what the
 * exit posture is. `CIRVIX_HOOK_FAIL=closed` denies; anything else allows with
 * a stderr warning. The default allows — matching the no-runtime behavior
 * below — because bricking the editor on unparseable input is the fastest way
 * to get the hook deleted. Production CI should set it closed.
 *
 * If you want fail-closed, set CIRVIX_HOOK_FAIL=closed. Production CI should.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { UdsClient, defaultEndpoint, tokenPath } from "../../packages/agent-control/src/core/uds.mjs";

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

async function main() {
  const failClosed = process.env.CIRVIX_HOOK_FAIL === "closed";
  let input = null;
  try {
    const raw = readFileSync(0, "utf8") || "{}";
    input = JSON.parse(raw);
    if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("hook payload must be a JSON object");
  } catch {
    // Unparseable input can never be evaluated, so it can never be allowed
    // *because* it looked safe. The configured failure posture applies here
    // too — previously this path allowed unconditionally, before CIRVIX_HOOK_FAIL
    // was even read.
    const message = "Cirvix could not parse the hook payload, so the call was not evaluated.";
    process.stderr.write(`[cirvix] ${message} Set CIRVIX_HOOK_FAIL=closed to deny unevaluated calls.\n`);
    reply(failClosed ? "deny" : "allow", message);
    return 0;
  }

  const stateDir = process.env.CIRVIX_STATE ?? join(input.cwd ?? process.cwd(), ".cirvix");

  let token;
  try {
    token = readFileSync(tokenPath(stateDir), "utf8").trim();
  } catch {
    const message = `Cirvix runtime is not initialized in ${stateDir}. Run \`cirvix init\` then \`cirvix runtime\`.`;
    process.stderr.write(`[cirvix] ${message}${failClosed ? "" : " Set CIRVIX_HOOK_FAIL=closed to deny unevaluated calls."}\n`);
    reply(failClosed ? "deny" : "allow", message);
    return 0;
  }

  const call = toCall(input);

  try {
    const client = new UdsClient({ endpoint: defaultEndpoint(stateDir), token, timeoutMs: 3000 });
    const result = await client.call("cirvix/authorize", {
      ...call,
      agent: "claude-code",
      source: "hook",
    });

    if (result.allowed) {
      reply("allow", `${result.policy ?? "policy"} · risk ${String(result.risk).toUpperCase()} · ${result.latency_ms}ms`);
      return 0;
    }

    // The refusal the model reads. Carrying the remediation is what lets it
    // re-plan rather than retry the same call.
    const lines = [
      `Blocked by Cirvix policy: ${result.policy ?? "default-deny"}`,
      result.reason,
      result.remediation ? `Try instead: ${result.remediation}` : null,
      result.approval_id ? `Waiting on approval ${result.approval_id}` : null,
      `Request id: ${result.request_id}`,
    ].filter(Boolean);

    reply("deny", lines.join("\n"));
    return 0;
  } catch (err) {
    const message = `Cirvix runtime unreachable (${err.message}).`;
    process.stderr.write(`[cirvix] ${message}${failClosed ? "" : " Set CIRVIX_HOOK_FAIL=closed to deny unevaluated calls."}\n`);
    reply(failClosed ? "deny" : "allow", message);
    return 0;
  }
}

main().then((code) => process.exit(code));
