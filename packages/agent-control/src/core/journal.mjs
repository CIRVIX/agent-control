/**
 * The execution journal — reading the audit chain back.
 *
 * `audit.mjs` writes an immutable, hash-linked record of every decision. This
 * reads it: filter, group into runs, render as an execution tree, and re-decide
 * a recorded call under a candidate policy.
 *
 *   cirvix logs
 *   cirvix logs --last 50
 *   cirvix logs --risk high
 *   cirvix replay req_8a91
 *
 * IMMUTABLE HISTORY FIRST, TIME TRAVEL NEVER
 *
 * `replay` re-evaluates and does not re-execute. It answers "what would today's
 * rules have decided about that call" — the question you have at 2am — and it
 * cannot undo the call's effects, because nothing in a userspace policy engine
 * can un-send an HTTP request or un-drop a table.
 *
 * That distinction is stated in the output of the command itself, not only
 * here, because "time-travel rollback" is a thing security products claim and
 * an operator who believes it will not take the backup.
 *
 * WHY THIS READS THE FILE EVERY TIME
 *
 * No index, no cache, no daemon. The journal is a JSONL file that a developer
 * can `tail`, `grep`, and diff — and at the volume one machine produces, a
 * linear scan of a few megabytes is faster than the code that would avoid it.
 * When the file gets large enough to matter, it belongs in the control plane,
 * which has a database.
 */

import { readFile } from "node:fs/promises";

import { evaluate } from "./policy.mjs";
import { DECISION, toDecision } from "./decisions.mjs";
import { RISK_ORDER, riskRank } from "./risk.mjs";
import { normalize, policyRequest } from "./normalize.mjs";
import { amber, blue, bold, dim, green, red } from "./format.mjs";

/* -------------------------------------------------------------------------- */
/*  Reading                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Reads every record.
 *
 * A malformed line is returned as `{ malformed: true }` rather than skipped.
 * Silently dropping it would let someone corrupt one line to make a record
 * disappear from `cirvix logs` while the chain still verifies over the rest.
 */
export async function read(path) {
  let text = "";
  try {
    text = await readFile(path, "utf8");
  } catch {
    return [];
  }
  return text
    .split("\n")
    .filter(Boolean)
    .map((line, i) => {
      try {
        return JSON.parse(line);
      } catch {
        return { malformed: true, line: i + 1, raw: line.slice(0, 200) };
      }
    });
}

/**
 * @typedef {object} Query
 * @property {number} [last]        most recent N
 * @property {string} [risk]        minimum risk level
 * @property {string} [decision]    exact decision
 * @property {string} [agent]
 * @property {string} [tool]        substring match
 * @property {string} [run]         run id
 * @property {string} [since]       ISO timestamp
 * @property {boolean} [deniedOnly]
 */

/** Filters records. Ordering is preserved; `last` is applied at the end. */
export function query(records, q = {}) {
  let out = records.filter((r) => !r.malformed);

  if (q.risk) {
    const floor = riskRank(q.risk);
    out = out.filter((r) => riskRank(r.risk) >= floor);
  }
  if (q.decision) {
    const want = String(q.decision).toLowerCase();
    out = out.filter((r) => (r.decision ?? toDecision(r.verdict)) === want);
  }
  if (q.deniedOnly) {
    out = out.filter((r) => (r.decision ?? toDecision(r.verdict)) === DECISION.DENY);
  }
  if (q.agent) out = out.filter((r) => r.agent === q.agent);
  if (q.tool) {
    const needle = String(q.tool).toLowerCase();
    out = out.filter((r) => `${r.tool ?? ""} ${r.action ?? ""}`.toLowerCase().includes(needle));
  }
  if (q.run) out = out.filter((r) => r.run_id === q.run || r.runId === q.run);
  if (q.since) {
    const t = new Date(q.since).getTime();
    out = out.filter((r) => new Date(r.ts ?? r.timestamp ?? 0).getTime() >= t);
  }
  if (q.last) out = out.slice(-Number(q.last));

  return out;
}

/** One record by request id or decision id. */
export function find(records, id) {
  return (
    records.find((r) => r.request_id === id || r.decision_id === id || r.decisionId === id) ?? null
  );
}

/* -------------------------------------------------------------------------- */
/*  Summaries                                                                  */
/* -------------------------------------------------------------------------- */

/** Counts and latency percentiles over a record set. */
export function summarize(records) {
  const counts = { allow: 0, deny: 0, require_approval: 0, sanitize: 0, audit_only: 0 };
  const risks = { low: 0, medium: 0, high: 0, critical: 0 };
  const latencies = [];
  const agents = new Set();
  const rules = new Map();

  for (const r of records) {
    if (r.malformed) continue;
    const d = r.decision ?? toDecision(r.verdict);
    if (d in counts) counts[d]++;
    if (r.risk in risks) risks[r.risk]++;
    if (typeof r.latency_ms === "number") latencies.push(r.latency_ms);
    if (r.agent) agents.add(r.agent);
    if (r.policy ?? r.rule) {
      const key = r.policy ?? r.rule;
      rules.set(key, (rules.get(key) ?? 0) + 1);
    }
  }

  latencies.sort((a, b) => a - b);
  const at = (q) => (latencies.length ? latencies[Math.min(latencies.length - 1, Math.floor(q * latencies.length))] : 0);

  return {
    records: records.length,
    counts,
    risks,
    agents: [...agents],
    topRules: [...rules.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10),
    latency: {
      p50: Number(at(0.5).toFixed(3)),
      p95: Number(at(0.95).toFixed(3)),
      p99: Number(at(0.99).toFixed(3)),
      max: Number((latencies[latencies.length - 1] ?? 0).toFixed(3)),
      samples: latencies.length,
    },
  };
}

/** Groups records into the runs they belong to. Loose records get one bucket. */
export function byRun(records) {
  const runs = new Map();
  for (const r of records) {
    if (r.malformed) continue;
    const key = r.run_id ?? r.runId ?? "(no run)";
    if (!runs.has(key)) runs.set(key, []);
    runs.get(key).push(r);
  }
  return runs;
}

/* -------------------------------------------------------------------------- */
/*  Rendering                                                                  */
/* -------------------------------------------------------------------------- */

const TONE = {
  [DECISION.ALLOW]: green,
  [DECISION.SANITIZE]: blue,
  [DECISION.AUDIT_ONLY]: dim,
  [DECISION.REQUIRE_APPROVAL]: amber,
  [DECISION.DENY]: red,
};

const RISK_TONE = { low: dim, medium: blue, high: amber, critical: red };

function toneFor(record) {
  return TONE[record.decision ?? toDecision(record.verdict)] ?? dim;
}

/** `2026-08-12T09:14:02.113Z` → `09:14:02`. */
function clock(ts) {
  const s = String(ts ?? "");
  const m = s.match(/T(\d{2}:\d{2}:\d{2})/);
  return m ? m[1] : s.slice(0, 8).padEnd(8);
}

/** One record, one line. The shape `cirvix logs` prints. */
export function renderLine(record) {
  if (record.malformed) {
    return `  ${dim(String(record.line).padStart(4))}  ${red("malformed record")} ${dim(record.raw.slice(0, 60))}`;
  }
  const decision = record.decision ?? toDecision(record.verdict);
  const tone = toneFor(record);
  const risk = RISK_TONE[record.risk] ?? dim;

  return [
    `  ${dim(clock(record.ts ?? record.timestamp))}`,
    tone(String(decision).toUpperCase().padEnd(16)),
    risk(String(record.risk ?? "—").toUpperCase().padEnd(8)),
    String(record.tool ?? record.action ?? "—").padEnd(20),
    dim(truncate(record.resource ?? record.command ?? "", 44).padEnd(44)),
    dim(String(record.policy ?? record.rule ?? "default-deny").padEnd(24)),
    dim(`${record.latency_ms ?? "—"}ms`),
  ].join(" ");
}

/**
 * The execution tree.
 *
 *   claude-code
 *    └── filesystem.read
 *         ├── input      ./src/app.ts
 *         ├── risk       LOW
 *         ├── policy     allow-workspace-read
 *         ├── decision   ALLOW
 *         ├── latency    0.41ms
 *         └── result     forwarded
 *
 * Deliberately one call per tree rather than a whole run in one: an operator
 * reading this is looking at a specific decision, and a hundred-node tree
 * scrolls the interesting node off the screen.
 */
export function renderTree(record, { indent = "  " } = {}) {
  const decision = record.decision ?? toDecision(record.verdict);
  const tone = toneFor(record);
  const risk = RISK_TONE[record.risk] ?? dim;

  const rows = [
    ["input", truncate(record.resource || record.command || "(no resource)", 70)],
    ["risk", risk(String(record.risk ?? "unknown").toUpperCase()) + (record.risk_signals?.length ? dim(`  ${record.risk_signals.join(", ")}`) : "")],
    ["policy", record.policy ?? record.rule ?? dim("— no rule matched (default deny)")],
    ["decision", tone(String(decision).toUpperCase()) + (record.enforced === false ? dim("  (not enforced — audit mode)") : "")],
    ["latency", `${record.latency_ms ?? "—"}ms`],
  ];

  if (record.would_have) {
    rows.push(["would have", red(String(record.would_have.decision).toUpperCase()) + dim(` by ${record.would_have.rule ?? "default-deny"}`)]);
  }
  if (record.approval_id) rows.push(["approval", blue(record.approval_id)]);
  if (record.secrets_brokered?.length) rows.push(["secrets", `${record.secrets_brokered.join(", ")} ${dim("(brokered — the agent never held the value)")}`]);
  if (record.secrets_detected?.length) {
    rows.push(["detected", record.secrets_detected.map((s) => `${s.detector} ${dim(s.masked)}`).join(", ")]);
  }
  if (record.sanitized?.arguments?.length) {
    rows.push(["sanitized", `${record.sanitized.arguments.length} value(s) stripped from arguments`]);
  }
  if (record.observed_by?.length) rows.push(["observed", dim(record.observed_by.join(", "))]);
  rows.push(["result", decision === DECISION.DENY ? red("not forwarded") : decision === DECISION.REQUIRE_APPROVAL ? amber("held") : green("forwarded")]);

  const width = Math.max(...rows.map(([k]) => k.length));
  const lines = [
    `${indent}${bold(record.agent ?? "agent")}  ${dim(record.request_id ?? "")}`,
    `${indent} └── ${bold(record.tool ?? record.action ?? "tool")}`,
  ];
  rows.forEach(([key, value], i) => {
    const branch = i === rows.length - 1 ? "└──" : "├──";
    lines.push(`${indent}      ${branch} ${dim(key.padEnd(width))}  ${value}`);
  });

  if (record.reason) {
    lines.push("");
    lines.push(`${indent}      ${dim(wrap(record.reason, 84, `${indent}      `))}`);
  }
  return lines.join("\n");
}

function truncate(value, n) {
  const s = String(value ?? "");
  return s.length <= n ? s : `…${s.slice(-(n - 1))}`;
}

function wrap(text, width, prefix) {
  const words = String(text).split(/\s+/);
  const lines = [];
  let line = "";
  for (const w of words) {
    if ((line + " " + w).trim().length > width) {
      lines.push(line.trim());
      line = w;
    } else line += " " + w;
  }
  if (line.trim()) lines.push(line.trim());
  return lines.join("\n" + prefix);
}

/* -------------------------------------------------------------------------- */
/*  Replay                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Re-decides recorded calls under a candidate rule set.
 *
 * A record is replayable when it carries enough to reconstruct the request:
 * an action and a resource. Older records, and records from a version that did
 * not write those fields, are reported as not replayable rather than silently
 * counted as unchanged — a diff that quietly omits what it could not evaluate
 * is a diff that says "no change" when it means "did not look".
 *
 * NOTHING IS EXECUTED. Not the permitted calls, not the previously denied ones.
 *
 * @returns {{steps:Array, changed:number, replayable:number, caveat:string}}
 */
export function replay(records, rules, { cwd = process.cwd() } = {}) {
  const steps = [];
  let changed = 0;
  let replayable = 0;

  for (const record of records) {
    if (record.malformed) continue;

    const before = {
      decision: record.decision ?? toDecision(record.verdict),
      rule: record.policy ?? record.rule ?? null,
      risk: record.risk ?? null,
    };

    if (!record.action && !record.tool) {
      steps.push({
        request_id: record.request_id ?? null,
        ts: record.ts ?? record.timestamp,
        replayable: false,
        reason: "Record carries no action; there is nothing to re-evaluate.",
        before,
      });
      continue;
    }

    replayable++;

    // Rebuilt from the record rather than re-derived from arguments: the
    // arguments are not retained (they can contain secret material), so the
    // recorded action and canonicalized resource are the inputs.
    const request = {
      agent: record.agent ?? "unknown",
      action: record.action ?? record.tool,
      resource: record.resource ?? "",
      context: {
        environment: record.environment ?? "local",
        path: { insideWorkspace: record.inside_workspace ?? true },
        egress: {
          external: record.egress === "external",
          allowlisted: false,
          destination: record.destination ?? null,
        },
        session: { touchedSecret: false },
        mcp: { server: record.server ?? null, tool: record.tool ?? null },
        risk: record.risk ?? null,
        command: record.command ?? null,
        secrets: { detected: record.secrets_detected?.length ?? 0 },
      },
    };

    const result = evaluate(request, rules, { cwd });
    const after = {
      decision: result.decision ?? toDecision(result.verdict),
      rule: result.rule,
      reason: result.reason,
    };

    const didChange = after.decision !== before.decision || after.rule !== before.rule;
    if (didChange) changed++;

    steps.push({
      request_id: record.request_id ?? record.decision_id ?? null,
      ts: record.ts ?? record.timestamp,
      action: record.action ?? record.tool,
      resource: record.resource ?? "",
      risk: record.risk,
      replayable: true,
      changed: didChange,
      before,
      after,
    });
  }

  return {
    steps,
    changed,
    replayable,
    caveat:
      "Replay re-evaluates recorded decisions. It does not re-execute calls and cannot undo their effects. Session-dependent context (secret taint, allowlists) is not reconstructed, so a decision that depended on it may differ here.",
  };
}

/** A single call, re-decided. Used by `cirvix replay <request-id>`. */
export function replayOne(record, rules, options) {
  const result = replay([record], rules, options);
  return result.steps[0] ?? null;
}

/**
 * Re-runs a *live* call description through normalization and policy.
 *
 * This is what `cirvix check` uses: it takes a tool and arguments rather than a
 * historical record, so the risk classification is recomputed from the real
 * inputs instead of read back from the log.
 */
export function decideNow({ tool, server = null, args = {}, agent = "local", environment = "local", rules, cwd = process.cwd() }) {
  const call = normalize({ tool, server, arguments: args }, { agent, environment, cwd });
  const decision = evaluate(policyRequest(call), rules, { cwd });
  decision.decision = decision.decision ?? toDecision(decision.verdict);
  return { call, decision };
}

export { RISK_ORDER };
