import { evaluate, STARTER_RULES } from "../core/policy.mjs";
import { bold, dim, green, red, amber } from "../core/format.mjs";

/**
 * `cirvix console` — non-interactive evaluation preview.
 *
 * Existing full-screen TUI in interactive.mjs remains the interactive path.
 * This helper answers one question without executing anything:
 * "what would policy decide for this hypothetical call?"
 *
 * Never touches the network, the audit chain, the vault, approvals, or the
 * upstream tool. Prints a human summary, or JSON with --json.
 */
export function parseEvalInput(raw) {
  if (raw === undefined || raw === null) return { ok: false, error: "--eval needs a value." };
  const text = String(raw).trim();
  if (!text) return { ok: false, error: "--eval needs a value." };
  // Accepted shapes: "tool resource" | "action=.. resource=.." | JSON
  if (text.startsWith("{")) {
    try {
      const parsed = JSON.parse(text);
      const tool = parsed.tool ?? parsed.action ?? "";
      const resource = parsed.resource ?? parsed.path ?? parsed.command ?? parsed.url ?? "";
      if (!tool || !resource) return { ok: false, error: "--eval JSON needs tool/action and resource/path." };
      return { ok: true, tool: String(tool), resource: String(resource) };
    } catch {
      return { ok: false, error: "--eval JSON did not parse." };
    }
  }
  const pairs = {};
  for (const part of text.split(/\s+/)) {
    const eq = part.indexOf("=");
    if (eq > 0) pairs[part.slice(0, eq)] = part.slice(eq + 1);
  }
  if (pairs.tool || pairs.action || pairs.resource || pairs.path || pairs.command || pairs.url) {
    const tool = pairs.tool ?? pairs.action ?? "";
    const resource = pairs.resource ?? pairs.path ?? pairs.command ?? pairs.url ?? "";
    if (!tool || !resource) return { ok: false, error: "--eval needs both a tool/action and a resource." };
    return { ok: true, tool, resource };
  }
  const [tool, ...rest] = text.split(/\s+/);
  const resource = rest.join(" ");
  if (!tool || !resource) return { ok: false, error: '--eval needs "<tool> <resource>".' };
  return { ok: true, tool, resource };
}

export async function consolePreview({ cwd = process.cwd(), json = false, evalInput = null, policy = null, agent = "local", env = "local" } = {}) {
  const parsed = parseEvalInput(evalInput);
  if (!parsed.ok) return { code: 2, output: null, error: parsed.error };
  let rules = STARTER_RULES;
  if (policy) {
    const { loadPolicyFile } = await import("./policy.mjs");
    rules = (await loadPolicyFile(policy, { cwd })).rules;
  }
  const decision = evaluate(
    {
      agent,
      action: parsed.tool,
      resource: parsed.resource,
      context: {
        environment: env,
        path: { insideWorkspace: false },
        egress: { external: false, allowlisted: false },
        session: { touchedSecret: false },
      },
    },
    rules,
    { cwd },
  );
  if (json) return { code: 0, output: JSON.stringify({ preview: true, tool: parsed.tool, resource: parsed.resource, decision }, null, 2) };
  const tone = decision.verdict === "permit" ? green : decision.verdict === "hold" ? amber : red;
  const output = [
    "",
    `  ${bold("CONSOLE PREVIEW")}  ${dim("hypothetical — nothing executed, nothing recorded")}`,
    `  ${tone(bold(decision.verdict.toUpperCase()))}  ${dim(parsed.tool)} ${parsed.resource}`,
    `  ${dim("rule")}    ${decision.rule ?? dim("— no rule matched (default deny)")}`,
    `  ${dim("reason")}  ${decision.reason}`,
    "",
  ].join("\n");
  return { code: 0, output };
}
