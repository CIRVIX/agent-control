/**
 * Cirvix TUI cards — every tool call rendered as a visual object.
 *
 * Pure functions: (data) → string. No console writes, no engine imports.
 * The same functions back the interactive console, `cirvix logs --tree`,
 * and the future React/Ink port (one card = one component).
 *
 * Accessibility rule: icon + color + WORD. A ✓/✕ alone is never the only
 * signal — every card prints ALLOWED / SANITIZED / BLOCKED / HELD as text.
 */

import { style, bold, dim, roleForDecision, roleForRisk, badgeForDecision } from "../core/theme.mjs";

/* ------------------------------------------------------------------ */
/*  Box primitives                                                     */
/* ------------------------------------------------------------------ */

function width() {
  return Math.max(40, Math.min(process.stdout.columns ?? 80, 100));
}

function rule(char = "─") {
  return dim(char.repeat(Math.max(0, width() - 2)));
}

function frame(title, lines, { tone = "border" } = {}) {
  const W = Math.max(40, width() - 6);
  const top = style(`┌─ ${title} ${"─".repeat(Math.max(0, W - title.length - 4))}┐`, tone);
  const bottom = style(`└${"─".repeat(W)}┘`, tone);
  const body = lines.map((l) => {
    const plain = stripAnsi(l);
    const pad = " ".repeat(Math.max(0, W - 2 - plain.length));
    return `${style("│", tone)} ${l}${pad} ${style("│", tone)}`;
  });
  return [top, ...body, bottom].join("\n");
}

function stripAnsi(s) {
  return String(s).replace(/\x1b\[[0-9;]*m/g, "");
}

function kv(key, value, { keyWidth = 12 } = {}) {
  return `${dim(String(key).padEnd(keyWidth))} ${value}`;
}

/* ------------------------------------------------------------------ */
/*  Header                                                             */
/* ------------------------------------------------------------------ */

export function header({ mode = "PROTECTED", version = "" } = {}) {
  const dot = mode === "PROTECTED" ? style("●", "allow") : style("○", "warning");
  const title = `${bold("◆ CIRVIX")}  ${dim("Runtime Authorization")}`;
  const right = `${dot} ${bold(mode)}${version ? dim(`  v${version}`) : ""}`;
  return `${title}${" ".repeat(Math.max(2, width() - stripAnsi(title).length - stripAnsi(right).length))}${right}\n${rule()}`;
}

/* ------------------------------------------------------------------ */
/*  Policy decision card — the ALLOWED shape                           */
/* ------------------------------------------------------------------ */

export function policyCard({ action, risk, policy, identity, reason, latencyMs } = {}) {
  const badge = badgeForDecision("allow");
  const lines = [
    `${style(`✓ ${badge.label}`, "allow")}`,
    ``,
    kv("Action", bold(action ?? "—")),
    kv("Risk", style(String(risk ?? "—").toUpperCase(), roleForRisk(risk))),
    kv("Policy", policy ?? dim("default-deny")),
    kv("Identity", identity ?? dim("agent:local")),
    ...(reason ? [kv("Reason", dim(truncate(reason, 60)))] : []),
    ...(latencyMs !== undefined ? [kv("Latency", dim(`${latencyMs}ms`))] : []),
  ];
  return frame("POLICY DECISION", lines, { tone: "border" });
}

/* ------------------------------------------------------------------ */
/*  Tool card — full lifecycle: identity → policy checks → decision    */
/* ------------------------------------------------------------------ */

export function toolCard({ tool, risk, identity, detail, checks = [], decision, policy, reason } = {}) {
  const badge = badgeForDecision(decision);
  const role = roleForDecision(decision);
  const lines = [
    ``,
    kv("Risk", style(String(risk ?? "—").toUpperCase(), roleForRisk(risk))),
    kv("Identity", identity ?? dim("agent:local")),
    ...(detail ? [kv(detailLabel(tool), truncate(detail, 64))] : []),
    ``,
    dim("Policy evaluation"),
    ...checks.map((c) => `  ${c.ok ? style("✓", "allow") : style("✕", "block")} ${dim(c.label)}`),
    ``,
    kv("Decision", style(`${badge.icon} ${badge.label}`, role)),
    ...(policy ? [kv("Policy", policy)] : []),
    ...(reason ? [kv("Why", dim(truncate(reason, 64)))] : []),
  ];
  const title = String(tool ?? "TOOL").toUpperCase().replace(/__/g, " · ");
  return frame(title, lines, { tone: role === "block" ? "block" : "border" });
}

function detailLabel(tool) {
  const t = String(tool ?? "");
  if (/http|egress|fetch|request/i.test(t)) return "URL";
  if (/read|write|file/i.test(t)) return "Path";
  if (/shell|exec|command/i.test(t)) return "Command";
  if (/sql|db|query/i.test(t)) return "Query";
  return "Target";
}

/* ------------------------------------------------------------------ */
/*  Blocked card — the dangerous shape. Human first, fields second.    */
/* ------------------------------------------------------------------ */

export function blockedCard({ tool, target, policy, reason, detail } = {}) {
  const lines = [
    style(`🔴 HIGH-RISK ACTION — BLOCKED`, "block"),
    ``,
    bold(tool ?? "unknown tool"),
    ...(target ? [dim(truncate(target, 72))] : []),
    ``,
    ...(policy ? [kv("Policy", policy)] : []),
    ...(reason ? [kv("Reason", truncate(reason, 72))] : []),
    ...(detail ? [dim(truncate(detail, 72))] : []),
    ``,
    dim("Action was NOT executed. No side effects occurred."),
  ];
  return frame("BLOCKED", lines, { tone: "block" });
}

export function heldCard({ tool, target, approvers = [], reason } = {}) {
  const lines = [
    `${style("◷ HELD FOR APPROVAL", "hold")}`,
    ``,
    bold(tool ?? "unknown tool"),
    ...(target ? [dim(truncate(target, 72))] : []),
    ``,
    kv("Waits on", approvers.length ? approvers.join(", ") : dim("a human approver")),
    ...(reason ? [kv("Reason", dim(truncate(reason, 68)))] : []),
    ``,
    dim("The call is suspended. Approve it with `cirvix approvals`."),
  ];
  return frame("APPROVAL", lines, { tone: "hold" });
}

/* ------------------------------------------------------------------ */
/*  Human-readable explanation — security product, not infra dump      */
/* ------------------------------------------------------------------ */

export function explainDecision(event = {}) {
  const decision = event.decision ?? event.verdict ?? "deny";
  const badge = badgeForDecision(decision);
  const role = roleForDecision(decision);
  const title = style(`${badge.icon} ${badge.label}`, role);

  if (decision === "deny") {
    return [
      title,
      ``,
      `Cirvix stopped this request${event.policy ? ` because policy ${bold(`"${event.policy}"`)} matched` : ""}.`,
      ...(event.resource || event.destination
        ? [``, `Target:`, `  ${truncate(event.resource || event.destination, 76)}`]
        : []),
      ...(event.reason ? [``, dim(wrap(event.reason, 76))] : []),
      ``,
      dim("No network request was sent. No file was read. No command ran."),
      ``,
      `${dim("[Why?]")} ${dim("cirvix logs --tree " + (event.request_id ?? event.decision_id ?? "<id>"))}   ${dim("[Policy]")} cirvix policy list`,
    ].join("\n");
  }

  if (decision === "sanitize") {
    return [
      title,
      ``,
      `Cirvix forwarded this call after cleaning it.`,
      ...(event.reason ? [``, dim(wrap(event.reason, 76))] : []),
      ``,
      dim("The agent received a safe version — the original never left the runtime."),
    ].join("\n");
  }

  if (decision === "require_approval") {
    return [
      title,
      ``,
      `This call needs a human before it runs.`,
      ...(event.reason ? [``, dim(wrap(event.reason, 76))] : []),
    ].join("\n");
  }

  return [
    title,
    ...(event.reason ? [``, dim(wrap(event.reason, 76))] : []),
  ].join("\n");
}

/* ------------------------------------------------------------------ */
/*  Transcript rows                                                    */
/* ------------------------------------------------------------------ */

export function userRow(text) {
  return `${bold("You")}\n${dim("─".repeat(27))}\n${text}`;
}

export function cirvixRow(text) {
  return `${bold("CIRVIX")}\n${dim("─".repeat(27))}\n${text}`;
}

/* ------------------------------------------------------------------ */
/*  Small helpers                                                      */
/* ------------------------------------------------------------------ */

export function spinnerFrame(i) {
  return ["◐", "◓", "◑", "◒"][i % 4];
}

function truncate(s, n) {
  const v = String(s ?? "");
  return v.length <= n ? v : `…${v.slice(-(n - 1))}`;
}

function wrap(text, w) {
  const words = String(text).split(/\s+/);
  const lines = [];
  let line = "";
  for (const word of words) {
    if ((line + " " + word).trim().length > w) {
      lines.push(line.trim());
      line = word;
    } else line += " " + word;
  }
  if (line.trim()) lines.push(line.trim());
  return lines.join("\n");
}

export { frame, rule, width };
