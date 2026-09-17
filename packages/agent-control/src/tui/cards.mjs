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

function width(value = Math.min(process.stdout.columns ?? 80, 100)) {
  return Number.isFinite(value) ? Math.max(1, Math.floor(value)) : 80;
}

function rule(char = "─", options = {}) {
  const budget = Math.max(0, width(options.width) - 2);
  const cells = displayWidth(char);
  return dim(cells ? clipText(String(char).repeat(Math.ceil(budget / cells)), budget) : "");
}

function frameWidth(options) {
  const columns = width(options.width);
  return Math.min(columns, Math.max(4, columns - 4));
}

function cardBudget(options, limit, keyed = false) {
  return Math.max(0, Math.min(limit, frameWidth(options) - 4 - (keyed ? 13 : 0)));
}

function frame(title, lines, options = {}) {
  const { tone = "border" } = options;
  const size = frameWidth(options);
  if (size < 5) return [title, ...lines].map((line) => wrapText(line, size)).join("\n");
  const inner = size - 4;
  const label = clipText(title, Math.max(0, size - 5));
  const top = style(`┌─ ${label} ${"─".repeat(Math.max(0, size - displayWidth(label) - 5))}┐`, tone);
  const bottom = style(`└${"─".repeat(size - 2)}┘`, tone);
  const body = lines.flatMap((line) => wrapText(line, inner).split("\n")).map((line) => {
    const pad = " ".repeat(Math.max(0, inner - displayWidth(line)));
    return `${style("│", tone)} ${line}${pad} ${style("│", tone)}`;
  });
  return [top, ...body, bottom].join("\n");
}

function kv(key, value, { keyWidth = 12 } = {}) {
  return `${dim(String(key).padEnd(keyWidth))} ${value}`;
}

/* ------------------------------------------------------------------ */
/*  Header                                                             */
/* ------------------------------------------------------------------ */

export function header({ mode = "PROTECTED", version = "", preview = false, width: columns } = {}) {
  const budget = width(columns);
  if (preview) mode = "AUTHORIZATION PREVIEW";
  const dot = mode === "PROTECTED" ? style("●", "allow") : style("○", "warning");
  const title = `${bold("◆ CIRVIX")}  ${dim("Runtime Authorization")}`;
  const right = `${dot} ${bold(mode)}${version ? dim(`  v${version}`) : ""}`;
  const gap = budget - displayWidth(title) - displayWidth(right);
  return `${wrapText(gap >= 2 ? title + " ".repeat(gap) + right : title + "\n" + right, budget)}\n${rule("─", { width: budget })}`;
}

/* ------------------------------------------------------------------ */
/*  Policy decision card — the ALLOWED shape                           */
/* ------------------------------------------------------------------ */

export function policyCard({ action, risk, policy, identity, reason, latencyMs, decision = "allow" } = {}, options = {}) {
  const badge = badgeForDecision(decision);
  const lines = [
    style(options.preview ? previewDecision(decision) : `${badge.icon} ${badge.label}`, roleForDecision(decision)),
    ``,
    kv("Action", bold(action ?? "—")),
    kv("Risk", style(String(risk ?? "—").toUpperCase(), roleForRisk(risk))),
    kv("Policy", policy ?? dim("default-deny")),
    kv("Identity", identity ?? dim("agent:local")),
    ...(reason ? [kv("Reason", dim(truncateReason(reason, cardBudget(options, 60, true))))] : []),
    ...(!options.preview && latencyMs !== undefined ? [kv("Latency", dim(`${latencyMs}ms`))] : []),
    ...(options.preview ? [dim("No action executed by preview.")] : []),
  ];
  return frame("POLICY DECISION", lines, options);
}

/* ------------------------------------------------------------------ */
/*  Tool card — full lifecycle: identity → policy checks → decision    */
/* ------------------------------------------------------------------ */

export function toolCard({ tool, risk, identity, detail, checks = [], decision, policy, reason } = {}, options = {}) {
  const badge = badgeForDecision(decision);
  const role = roleForDecision(decision);
  const lines = [
    ``,
    kv("Risk", style(String(risk ?? "—").toUpperCase(), roleForRisk(risk))),
    kv("Identity", identity ?? dim("agent:local")),
    ...(detail ? [kv(detailLabel(tool), truncate(detail, cardBudget(options, 64, true)))] : []),
    ``,
    dim("Policy evaluation"),
    ...checks.map((c) => `  ${c.ok ? style("✓", "allow") : style("✕", "block")} ${dim(c.label)}`),
    ``,
    kv("Decision", style(options.preview ? previewDecision(decision) : `${badge.icon} ${badge.label}`, role)),
    ...(policy ? [kv("Policy", policy)] : []),
    ...(reason ? [kv("Why", dim(truncateReason(reason, cardBudget(options, 64, true))))] : []),
    ...(options.preview ? [dim("No action executed by preview.")] : []),
  ];
  const title = String(tool ?? "TOOL").split(/(\x1b\[[0-9;:]*m)/).map((part, index) => index % 2 ? part : part.toUpperCase()).join("").replace(/__/g, " · ");
  return frame(title, lines, { ...options, tone: role === "block" ? "block" : "border" });
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

export function blockedCard({ tool, target, policy, reason, detail } = {}, options = {}) {
  const lines = [
    style(options.preview ? "Would block" : "\u{1f534} HIGH-RISK ACTION — BLOCKED", "block"),
    ``,
    bold(tool ?? "unknown tool"),
    ...(target ? [dim(truncate(target, cardBudget(options, 72)))] : []),
    ``,
    ...(policy ? [kv("Policy", policy)] : []),
    ...(reason ? [kv("Reason", truncateReason(reason, cardBudget(options, 72, true)))] : []),
    ...(detail ? [dim(truncateReason(detail, cardBudget(options, 72)))] : []),
    ``,
    dim(options.preview ? "No action executed by preview." : "Action was NOT executed. No side effects occurred."),
  ];
  return frame(options.preview ? "AUTHORIZATION PREVIEW" : "BLOCKED", lines, { ...options, tone: "block" });
}

export function heldCard({ tool, target, approvers = [], reason } = {}, options = {}) {
  const lines = [
    style(options.preview ? "Would require approval" : "◷ HELD FOR APPROVAL", "hold"),
    ``,
    bold(tool ?? "unknown tool"),
    ...(target ? [dim(truncate(target, cardBudget(options, 72)))] : []),
    ``,
    kv(options.preview ? "Approvers" : "Waits on", approvers.length ? approvers.join(", ") : dim("a human approver")),
    ...(reason ? [kv("Reason", dim(truncateReason(reason, cardBudget(options, 68, true))))] : []),
    ``,
    dim(options.preview ? "No action executed by preview. No approval created." : "The call is suspended. Approve it with `cirvix approvals`."),
  ];
  return frame(options.preview ? "AUTHORIZATION PREVIEW" : "APPROVAL", lines, { ...options, tone: "hold" });
}

/* ------------------------------------------------------------------ */
/*  Human-readable explanation — security product, not infra dump      */
/* ------------------------------------------------------------------ */

export function explainDecision(event = {}, { policyFilePresent = null, preview = false, width: columns } = {}) {
  const budget = width(columns);
  const decision = event.decision ?? event.verdict ?? "deny";
  const badge = badgeForDecision(decision);
  const role = roleForDecision(decision);
  const title = style(preview ? previewDecision(decision) : `${badge.icon} ${badge.label}`, role);
  const reason = event.reason ? [``, dim(event.reason)] : [];
  const remediation = event.remediation ? [``, `Remediation: ${event.remediation}`] : [];
  const render = (lines) => wrapText(lines.join("\n"), budget);

  if (decision === "deny") {
    return render([
      title,
      ``,
      `${preview ? "Cirvix would block" : "Cirvix stopped"} this request${event.policy ? ` because policy ${bold(`"${event.policy}"`)} matched` : ""}.`,
      ...(event.resource || event.destination
        ? [``, `Target:`, `  ${truncate(event.resource || event.destination, Math.max(0, Math.min(76, budget - 2)))}`]
        : []),
      ...reason,
      ...(policyFilePresent === false && event.explicit === false && event.policy == null
        ? [``, "No policy file found. Run `cirvix init` in this workspace to create one, then retry."]
        : []),
      ...remediation,
      ``,
      dim(preview ? "No action executed by preview." : "No network request was sent. No file was read. No command ran."),
      ``,
      ...(preview ? [`${dim("[Policy]")} cirvix policy list`] : [
        `${dim("[Why?]")} ${dim("cirvix logs --tree " + (event.request_id ?? event.decision_id ?? "<id>"))}   ${dim("[Policy]")} cirvix policy list`,
      ]),
    ]);
  }

  if (preview) return render([
    title,
    ...reason,
    ...remediation,
    ``,
    dim("No action executed by preview."),
    ...(decision === "require_approval" ? [dim("No approval created.")] : []),
  ]);

  if (decision === "sanitize") {
    return render([
      title,
      ``,
      `Cirvix forwarded this call after cleaning it.`,
      ...reason,
      ``,
      dim("The agent received a safe version — the original never left the runtime."),
    ]);
  }

  if (decision === "require_approval") {
    return render([title, ``, `This call needs a human before it runs.`, ...reason]);
  }

  return render([title, ...reason]);
}

/* ------------------------------------------------------------------ */
/*  Transcript rows                                                    */
/* ------------------------------------------------------------------ */

export function userRow(text, options = {}) {
  return wrapText(`${bold("You")}\n${dim("─".repeat(Math.min(27, width(options.width))))}\n${text}`, width(options.width));
}

export function cirvixRow(text, options = {}) {
  return wrapText(`${bold("CIRVIX")}\n${dim("─".repeat(Math.min(27, width(options.width))))}\n${text}`, width(options.width));
}

/* ------------------------------------------------------------------ */
/*  Small helpers                                                      */
/* ------------------------------------------------------------------ */

export function spinnerFrame(i) {
  return ["◐", "◓", "◑", "◒"][i % 4];
}

const segmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });
const sgr = /\x1b\[[0-9;:]*m/g;

function cellWidth(cluster) {
  const base = cluster.replace(/[\p{Mark}\p{Default_Ignorable_Code_Point}\p{Control}]/gu, "");
  if (!base) return 0;
  if (/\p{Emoji_Presentation}/u.test(cluster) || /\p{Extended_Pictographic}.*\uFE0F/u.test(cluster) || /[0-9#*]\uFE0F?\u20E3/u.test(cluster)) return 2;
  const cp = base.codePointAt(0);
  return cp >= 0x1100 && (
    cp <= 0x115f || cp === 0x2329 || cp === 0x232a ||
    (cp >= 0x2e80 && cp <= 0xa4cf && cp !== 0x303f) ||
    (cp >= 0xac00 && cp <= 0xd7a3) || (cp >= 0xf900 && cp <= 0xfaff) ||
    (cp >= 0xfe10 && cp <= 0xfe19) || (cp >= 0xfe30 && cp <= 0xfe6f) ||
    (cp >= 0xff01 && cp <= 0xff60) || (cp >= 0xffe0 && cp <= 0xffe6) ||
    (cp >= 0x16fe0 && cp <= 0x18dff) || (cp >= 0x1aff0 && cp <= 0x1b2ff) ||
    (cp >= 0x20000 && cp <= 0x3fffd)
  ) ? 2 : 1;
}

function units(text) {
  const value = String(text ?? "");
  const escapes = new Map();
  let plain = "";
  let offset = 0;
  for (const match of value.matchAll(sgr)) {
    plain += value.slice(offset, match.index).replace(/[\x00-\x09\x0b-\x1f\x7f-\x9f]/g, " ");
    escapes.set(plain.length, (escapes.get(plain.length) ?? "") + match[0]);
    offset = match.index + match[0].length;
  }
  plain += value.slice(offset).replace(/[\x00-\x09\x0b-\x1f\x7f-\x9f]/g, " ");
  const result = [];
  for (const { segment, index } of segmenter.segment(plain)) {
    let raw = "";
    for (let i = index; i < index + segment.length; i++) raw += (escapes.get(i) ?? "") + plain[i];
    result.push({ text: segment, raw, cells: cellWidth(segment) });
  }
  if (escapes.has(plain.length)) result.push({ text: "", raw: escapes.get(plain.length), cells: 0 });
  return result;
}

function renderUnits(tokens, start = 0, end = tokens.length) {
  const prefix = tokens.slice(0, start).map((t) => (t.raw.match(sgr) ?? []).join("")).join("");
  const text = prefix + tokens.slice(start, end).map((t) => t.raw).join("");
  return text + (text.includes("\x1b[") ? "\x1b[0m" : "");
}

export function displayWidth(text) {
  return units(text).reduce((sum, token) => sum + token.cells, 0);
}

export function clipText(text, budget, { tail = false, ellipsis = "…" } = {}) {
  const tokens = units(String(text ?? "").replace(/\n/g, " "));
  const limit = Math.max(0, Math.floor(budget));
  if (!limit) return "";
  if (tokens.reduce((sum, t) => sum + t.cells, 0) <= limit) return renderUnits(tokens);
  const marker = displayWidth(ellipsis) <= limit ? ellipsis : "";
  const available = limit - displayWidth(marker);
  let used = 0;
  if (tail) {
    let start = tokens.length;
    while (start > 0 && used + tokens[start - 1].cells <= available) used += tokens[--start].cells;
    return marker + renderUnits(tokens, start);
  }
  let end = 0;
  while (end < tokens.length && used + tokens[end].cells <= available) used += tokens[end++].cells;
  return renderUnits(tokens, 0, end) + marker;
}

export function wrapText(text, budget) {
  const limit = Math.max(1, Math.floor(budget));
  const tokens = units(text);
  const lines = [];
  let start = 0;
  while (start < tokens.length) {
    let end = start;
    let used = 0;
    let space = -1;
    while (end < tokens.length && tokens[end].text !== "\n" && used + tokens[end].cells <= limit) {
      if (tokens[end].text === " " && used > 0) space = end;
      used += tokens[end++].cells;
    }
    if (end === start && tokens[end].text !== "\n") {
      lines.push(" ");
      start++;
    } else if (end < tokens.length && tokens[end].text !== "\n" && space > start) {
      lines.push(renderUnits(tokens, start, space));
      start = space + 1;
    } else {
      lines.push(renderUnits(tokens, start, end));
      start = end + (tokens[end]?.text === "\n" ? 1 : 0);
    }
  }
  if (!tokens.length || tokens.at(-1).text === "\n") lines.push("");
  return lines.join("\n");
}

export function previewDecision(decision) {
  return { allow: "Would allow", deny: "Would block", sanitize: "Would sanitize", require_approval: "Would require approval", audit_only: "Would evaluate in audit mode" }[decision] ?? "Unknown preview decision";
}

function truncate(s, n) {
  return clipText(s, n, { tail: true });
}

function truncateReason(s, n) {
  return clipText(s, n);
}

export { frame, rule, width };
