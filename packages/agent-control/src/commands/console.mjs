import { evaluate, STARTER_RULES } from "../core/policy.mjs";
import { bold, dim, green, red, amber, blue, cyan, gray, stripAnsi } from "../core/format.mjs";
import { boxChars, glyphs, padVisible, wordWrap, renderCard } from "../core/ui/theme.mjs";

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

/**
 * Render a polished authorization card preview.
 */
export function renderAuthPreviewCard({
  tool,
  resource,
  agent = "local",
  decision,
  width = 62,
  verbose = false,
  env = "local",
}) {
  const ch = boxChars();
  const g = glyphs();
  const termCols = (process.stdout && process.stdout.columns) ? process.stdout.columns : 80;
  const W = Math.max(48, Math.min(width, Math.max(48, termCols - 4)));
  const innerW = W - 4;
  const innerCardW = Math.max(36, innerW - 4);

  const verdict = String(decision.verdict ?? "deny").toLowerCase();
  const isAllow = verdict === "permit" || verdict === "allow";
  const isHold = verdict === "hold" || verdict === "require_approval";
  const isSanitize = verdict === "sanitize";
  const isDeny = !isAllow && !isHold && !isSanitize;

  const tone = isAllow ? green : isHold ? amber : isSanitize ? blue : red;
  const badgeLabel = isAllow
    ? "ALLOW"
    : isHold
      ? "APPROVAL REQUIRED"
      : isSanitize
        ? "CONTENT SANITIZED"
        : "BLOCKED (DENY)";
  const icon = isAllow ? g.check : isHold ? g.pause : isSanitize ? (g.recycle ?? g.info) : g.cross;

  // Determine risk level
  let risk = (decision.risk ?? "").toUpperCase();
  if (!risk || risk === "—") {
    if (isDeny) risk = "HIGH";
    else if (isHold) risk = "MEDIUM";
    else risk = "LOW";
  }
  const rTone = risk === "CRITICAL" ? red : risk === "HIGH" ? amber : risk === "MEDIUM" ? blue : dim;

  // Human-readable action description
  let actionDesc = "The agent requested:";
  let execStatus = "Safe to execute.";
  if (isDeny) {
    actionDesc = "The agent tried to read:";
    execStatus = "No action was executed.";
  } else if (isHold) {
    actionDesc = "The agent requested:";
    execStatus = "Operation held. Requires human review.";
  } else if (isSanitize) {
    actionDesc = "Untrusted instructions detected inside:";
    execStatus = "Content sanitized. Request not blocked.";
  }

  // Human-readable reason
  let reason = decision.reason;
  if (!reason) {
    if (isDeny) reason = "No rule permits this call. The policy set is default-deny: an action must be explicitly allowed.";
    else if (isAllow) reason = "Call matches an explicit allow rule.";
    else if (isHold) reason = "Operation requires manual authorization.";
    else if (isSanitize) reason = "Fetched content is data. Instructions inside it are not addressed to the model.";
  }

  // Inner decision card lines
  const badgeText = `${icon} ${badgeLabel}`;
  const centeredBadge = " ".repeat(Math.max(0, Math.floor((innerCardW - 2 - stripAnsi(badgeText).length) / 2))) + tone(bold(badgeText));

  const innerLines = [
    "",
    centeredBadge,
    "",
    ` ${dim(actionDesc)}`,
    ` ${cyan(bold(resource))} ${dim(`(${tool})`)}`,
    "",
    ` ${bold("Why:")}`,
  ];

  const wrappedReason = wordWrap(reason, innerCardW - 6);
  if (wrappedReason.length > 0) {
    for (const wr of wrappedReason) {
      innerLines.push(`   ${wr}`);
    }
  }

  innerLines.push("");
  innerLines.push(` ${bold("Rule:")}    ${decision.rule ?? dim("— no rule matched (default deny)")}`);
  innerLines.push(` ${bold("Risk:")}    ${rTone(risk)}`);
  innerLines.push("");
  innerLines.push(` ${dim("Status:")}  ${dim(execStatus)}`);

  // Inner card box
  const innerBoxTop = `  ${gray(ch.tl + ch.h)} ${bold("POLICY DECISION")} ${gray(ch.h.repeat(Math.max(0, innerCardW - 19)) + ch.tr)}`;
  const innerBoxBottom = `  ${gray(ch.bl + ch.h.repeat(innerCardW) + ch.br)}`;
  const renderedInnerBox = [
    innerBoxTop,
    ...innerLines.map((l) => `  ${gray(ch.v)} ${padVisible(l, innerCardW - 2)} ${gray(ch.v)}`),
    `  ${gray(ch.v)} ${" ".repeat(innerCardW - 2)} ${gray(ch.v)}`,
    innerBoxBottom,
  ];

  // Check remediation
  let remediation = null;
  if (isDeny && (resource.includes(".env") || decision.rule?.includes("dotenv"))) {
    remediation = 'secrets.get("STRIPE_KEY")';
  } else if (isHold) {
    remediation = "cirvix approvals --review";
  }

  const lines = [
    `  ${bold("REQUEST")}`,
    `  ${dim(g.treeBranch)} ${dim("Agent".padEnd(10))} ${agent}`,
    `  ${dim(g.treeBranch)} ${dim("Action".padEnd(10))} ${cyan(tool)}`,
    `  ${dim(g.treeLast)} ${dim("Resource".padEnd(10))} ${resource}`,
    "",
    ...renderedInnerBox,
  ];

  if (remediation) {
    lines.push("");
    lines.push(`  ${cyan(g.arrow)} ${bold("Suggested path")}`);
    lines.push(`    ${dim(remediation)}`);
  }

  if (verbose) {
    lines.push("");
    lines.push(`  ${dim("─".repeat(innerW))}`);
    lines.push(`  ${bold("FORENSIC DETAILS")}`);
    lines.push(`  ${dim("Identity:")}     ${agent}`);
    lines.push(`  ${dim("Tool:")}         ${tool}`);
    lines.push(`  ${dim("Target:")}       ${resource}`);
    lines.push(`  ${dim("Rule ID:")}      ${decision.rule ?? "default-deny"}`);
    lines.push(`  ${dim("Environment:")}  ${env}`);
    lines.push(`  ${dim("Execution:")}    preview (unexecuted)`);
    lines.push(`  ${dim("Audit Log:")}    bypassed (unrecorded)`);
  }

  const title = `${bold("CIRVIX")} ${dim("/")} ${bold("CONSOLE PREVIEW")}`;
  const footer = `  ${cyan(g.info)} ${dim("Preview only — nothing executed, nothing recorded.")}`;

  return renderCard({
    title,
    headerRight: dim("AUTHORIZATION PREVIEW"),
    lines,
    footer,
    width: W,
    borderColor: gray,
  });
}

export function isInsideWorkspace(cwd, resource) {
  if (!resource) return false;
  const norm = (s) => s.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  const a = norm(cwd);
  const resolved = resource.startsWith("/") || /^[A-Za-z]:/.test(resource)
    ? resource
    : `${cwd}/${resource}`;
  const b = norm(resolved.replace(/\/\.\//g, "/"));
  const parts = [];
  for (const seg of b.split("/")) {
    if (seg === "..") parts.pop();
    else if (seg !== ".") parts.push(seg);
  }
  const flat = parts.join("/");
  return flat === a || flat.startsWith(a + "/");
}

export async function consolePreview({
  cwd = process.cwd(),
  json = false,
  evalInput = null,
  policy = null,
  agent = "local",
  env = "local",
  verbose = false,
} = {}) {
  const parsed = parseEvalInput(evalInput);
  if (!parsed.ok) return { code: 2, output: null, error: parsed.error };
  let rules = STARTER_RULES;
  if (policy) {
    const { loadPolicyFile } = await import("./policy.mjs");
    rules = (await loadPolicyFile(policy, { cwd })).rules;
  }
  const inside = isInsideWorkspace(cwd, parsed.resource);
  const decision = evaluate(
    {
      agent,
      action: parsed.tool,
      resource: parsed.resource,
      context: {
        environment: env,
        path: { insideWorkspace: inside },
        egress: { external: false, allowlisted: false },
        session: { touchedSecret: false },
      },
    },
    rules,
    { cwd },
  );
  if (json) return { code: 0, output: JSON.stringify({ preview: true, tool: parsed.tool, resource: parsed.resource, decision }, null, 2) };

  const output = "\n" + renderAuthPreviewCard({
    tool: parsed.tool,
    resource: parsed.resource,
    agent,
    decision,
    verbose,
    env,
  }) + "\n";

  return { code: 0, output };
}
