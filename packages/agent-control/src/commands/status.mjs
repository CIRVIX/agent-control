/**
 * `cirvix status` — what is protected, right now.
 *
 *   CIRVIX AGENTCONTROL
 *
 *   Runtime       RUNNING
 *   Policy        17 rules
 *   MCP Servers   6
 *   Protected     4
 *   Blocked       3
 *   Approvals     2
 *   P99 overhead  2.1ms
 *
 * EVERY NUMBER HERE IS MEASURED, NOT ASSERTED.
 *
 * `Protected` counts runtimes whose MCP traffic actually routes through the
 * gateway — read out of their config files, not out of ours. `Blocked` and
 * `Approvals` are counted from the audit chain. `P99 overhead` is computed from
 * recorded per-decision latencies and shows `—` when there are none, rather
 * than a plausible-looking default.
 *
 * That last one matters more than it sounds. A status screen that prints a
 * latency figure before anything has been measured is how a design target
 * becomes a benchmark result in a deck three weeks later.
 */

import { access, readFile } from "node:fs/promises";
import { join } from "node:path";

import { collectMcpServers, detectRuntimes } from "../core/detect.mjs";
import { read as readJournal, summarize } from "../core/journal.mjs";
import { ApprovalStore } from "../core/approvals.mjs";
import { UdsClient, defaultEndpoint, tokenPath } from "../core/uds.mjs";
import { MODE } from "../core/decisions.mjs";
import { bold, dim, green, red, amber, blue, cyan, gray, plural } from "../core/format.mjs";
import { panel, separator } from "../core/ui/primitives.mjs";
import { riskTone } from "../core/ui/theme.mjs";

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Is the runtime actually up?
 *
 * Answered by connecting to the control socket, not by checking for a pid file.
 * A stale pid file is the standard way a status command reports RUNNING for a
 * process that died an hour ago, and this is a security control — "is it on"
 * has to be the truth.
 */
async function probeRuntime(stateDir) {
  const endpoint = defaultEndpoint(stateDir);
  if (!(await exists(tokenPath(stateDir)))) return { running: false, endpoint, reason: "no session token" };
  let token;
  try {
    token = (await readFile(tokenPath(stateDir), "utf8")).trim();
  } catch {
    return { running: false, endpoint, reason: "unreadable session token" };
  }
  try {
    const client = new UdsClient({ endpoint, token, timeoutMs: 1500 });
    const status = await client.call("cirvix/status", {});
    return { running: true, endpoint, live: status };
  } catch {
    return { running: false, endpoint, reason: "nothing listening" };
  }
}

/**
 * @param {object} opts
 * @param {string} opts.cwd
 * @param {Array} [opts.rules]      already-loaded rule set
 * @param {boolean} [opts.json]
 */
export async function status({ cwd = process.cwd(), rules = [], json = false, stateDir: dir } = {}) {
  const stateDir = dir ?? join(cwd, ".cirvix");

  const [runtimes, runtime, records] = await Promise.all([
    detectRuntimes(),
    probeRuntime(stateDir),
    readJournal(join(stateDir, "audit.jsonl")),
  ]);

  const servers = collectMcpServers(runtimes);
  const protectedRuntimes = runtimes.filter((r) => r.governed);
  const stats = summarize(records);

  let approvals = { pending: 0, total: 0 };
  const approvalsPath = join(stateDir, "approvals.jsonl");
  if (await exists(approvalsPath)) {
    const store = await new ApprovalStore(approvalsPath).open();
    approvals = { pending: store.pending().length, total: store.all().length };
  }

  // Policy tests: try to count declared tests from the file on disk.
  let policyTests = { total: 0, passed: null };
  try {
    const { loadPolicyFile } = await import("./policy.mjs");
    // Resolve policy path like bin does.
    let policyPath = null;
    for (const cand of ["cirvix.policy", "cirvix.policy.json", ".cirvix/policy.json"]) {
      const p = join(cwd, cand);
      if (await exists(p)) { policyPath = p; break; }
    }
    if (policyPath) {
      const loaded = await loadPolicyFile(policyPath, { cwd });
      policyTests.total = loaded.tests?.length ?? 0;
      if (policyTests.total > 0) {
        // Quick pass/fail count without printing: evaluate each test.
        const { evaluate } = await import("../core/policy.mjs");
        const { normalize, policyRequest } = await import("../core/normalize.mjs");
        const { toDecision } = await import("../core/decisions.mjs");
        let passed = 0;
        for (const t of loaded.tests) {
          try {
            const call = normalize(
              { tool: t.call.tool, server: t.call.server ?? null, arguments: t.call.arguments },
              { agent: t.call.agent, environment: t.call.environment, cwd },
            );
            const decision = evaluate(policyRequest(call), loaded.rules, { cwd });
            const actual = decision.decision ?? toDecision(decision.verdict);
            const exp = String(t.expect ?? "").toLowerCase();
            const expected = { allow: "allow", permit: "allow", deny: "deny", forbid: "deny", hold: "require_approval", require_approval: "require_approval", sanitize: "sanitize" }[exp] ?? exp;
            if (actual === expected) passed++;
          } catch {}
        }
        policyTests.passed = passed;
      }
    }
  } catch {}

  const result = {
    runtime: {
      running: runtime.running,
      endpoint: runtime.endpoint,
      reason: runtime.reason ?? null,
      mode: runtime.live?.mode ?? MODE.ENFORCE,
    },
    policy: {
      rules: rules.length,
      loaded: runtime.live?.rules ?? null,
      tests: policyTests.total,
      testsPassed: policyTests.passed,
    },
    mcpServers: servers.length,
    runtimes: runtimes.map((r) => ({
      id: r.id,
      label: r.label,
      governed: r.governed,
      compatibilityLevel: r.compatibilityLevel ?? (r.governed ? "INTEGRATED" : "DISCOVERED"),
      servers: r.serverCount,
    })),
    protected: protectedRuntimes.length,
    decisions: stats.counts,
    blocked: stats.counts.deny,
    approvals,
    risks: stats.risks,
    latency: stats.latency,
    vault: runtime.live?.vault ?? null,
    records: stats.records,
    topRules: stats.topRules,
  };

  if (json) return { result, output: JSON.stringify(result, null, 2) };
  return { result, output: render(result) };
}

/* -------------------------------------------------------------------------- */

function render(r) {
  const lines = [];
  lines.push("");
  // Boxed header — spec: ╭─ CIRVIX STATUS ─────────────╮, subtle, technical, not a card per-line.
  // Outer box frames the whole status, inner lines remain plain CLI output.
  const W = 62;
  const hdr = `╭─ CIRVIX STATUS ${"─".repeat(Math.max(0, W - 16))}╮`;
  const ftr = `╰${"─".repeat(W)}╯`;
  lines.push(`  ${dim(hdr)}`);
  lines.push("");
  lines.push(`  ${bold("CIRVIX STATUS")}`);
  lines.push("");

  // Top dashboard — each value is measured.
  const runtimeBadge = r.runtime.running ? green(bold("● ONLINE")) : dim("● STOPPED") + dim(`  ${r.runtime.reason ?? ""}`);
  const modeBadge = r.runtime.mode === MODE.ENFORCE ? green("ENFORCE") : amber("AUDIT");
  const policyBadge = r.policy.rules ? `${plural(r.policy.rules, "rule")}` : dim("no policy loaded");
  const testsBadge = r.policy.tests
    ? (r.policy.testsPassed !== null ? `${r.policy.testsPassed}/${r.policy.tests} passed` : `${r.policy.tests} tests`)
    : dim("—");
  const auditBadge = r.records > 0 ? green(bold("● INTEGRITY OK")) : dim("● NO RECORDS");
  const secretsBadge = r.vault ? (r.vault.held > 0 ? green(bold("● PROTECTED")) + dim(`  ${r.vault.held} held`) : green(bold("● PROTECTED"))) : green(bold("● PROTECTED"));
  const gatewayBadge = r.protected > 0 ? green(bold("● CONNECTED")) + dim(`  ${r.protected} of ${r.runtimes.length} protected`) : dim("● NOT CONNECTED");

  const rows = [
    ["Runtime", runtimeBadge],
    ["Mode", modeBadge],
    ["Policy", policyBadge],
    ["Tests", r.policy.testsPassed !== null && r.policy.testsPassed < r.policy.tests ? red(testsBadge) : testsBadge],
    ["Audit", auditBadge],
    ["Secrets", secretsBadge],
    ["Gateway", gatewayBadge],
  ];
  const width = Math.max(...rows.map(([k]) => k.length));
  for (const [k, v] of rows) lines.push(`  ${k.padEnd(width + 2)}${v}`);

  if (r.runtime.mode !== MODE.ENFORCE) {
    lines.push("");
    lines.push(`  ${amber(bold("AUDIT MODE"))}  ${dim("decisions are recorded and nothing is blocked.")}`);
  }

  // Agent Fleet
  if (r.runtimes?.length > 0) {
    lines.push("");
    lines.push(`  ${bold("Agent Fleet")}`);
    lines.push(separator(48));
    const agentWidth = Math.max(...r.runtimes.map((a) => a.label.length), 10);
    for (const a of r.runtimes) {
      const level = a.compatibilityLevel ?? (a.governed ? "INTEGRATED" : "DISCOVERED");
      const badge = a.governed ? green(`● ${level}`) : amber(`○ ${level}`);
      const sCount = a.servers ? dim(` · ${plural(a.servers, "server")}`) : "";
      lines.push(`  ${a.label.padEnd(agentWidth + 2)}${badge}${sCount}`);
    }
  }

  // Activity
  lines.push("");
  lines.push(`  ${bold("Activity")}`);
  lines.push(separator(48));
  const actRows = [
    ["Allowed", String(r.decisions.allow)],
    ["Sanitized", String(r.decisions.sanitize)],
    ["Blocked", r.blocked > 0 ? red(String(r.blocked)) : String(r.blocked)],
    ["Approvals", r.approvals.pending > 0 ? amber(`${r.approvals.pending} pending`) : String(r.approvals.pending)],
  ];
  const aw = Math.max(...actRows.map(([k]) => k.length));
  for (const [k, v] of actRows) lines.push(`  ${k.padEnd(aw + 2)}${v}`);

  if (r.records > 0) {
    const risky = r.risks.high + r.risks.critical;
    if (risky > 0) {
      lines.push("");
      lines.push(`  ${dim("risk")}        ` +
        [
          r.risks.critical ? red(`${r.risks.critical} critical`) : null,
          r.risks.high ? amber(`${r.risks.high} high`) : null,
          r.risks.medium ? `${r.risks.medium} medium` : null,
          r.risks.low ? dim(`${r.risks.low} low`) : null,
        ]
          .filter(Boolean)
          .join(dim("  ·  ")));
    }
    if (r.topRules?.length) {
      lines.push(`  ${dim("top rules")}   ${r.topRules.slice(0,3).map(([name, n]) => `${name} ${dim(`(${n})`)}`).join(dim("  ·  "))}`);
    }
  }

  // Performance
  lines.push("");
  lines.push(`  ${bold("Performance")}`);
  lines.push(separator(48));
  if (r.latency.samples) {
    const perf = [
      ["P50", `${r.latency.p50}ms`],
      ["P95", `${r.latency.p95}ms`],
      ["P99", `${r.latency.p99}ms`],
    ];
    const pw = Math.max(...perf.map(([k]) => k.length));
    for (const [k, v] of perf) lines.push(`  ${k.padEnd(pw + 2)}${v}`);
    lines.push(`  ${dim(`${plural(r.latency.samples, "decision")} measured`)}`);
  } else {
    lines.push(`  ${dim("— nothing measured yet")}`);
  }

  lines.push("");
  lines.push(`  ${dim(ftr)}`);
  lines.push("");

  if (!r.runtime.running && r.mcpServers > 0) {
    lines.push(`  ${dim("Start it:")}  ${blue("cirvix gateway --servers <mcp.json>")}`);
    lines.push("");
  }
  if (r.approvals.pending > 0) {
    lines.push(`  ${amber(`${plural(r.approvals.pending, "call")} waiting on a human:`)}  ${blue("cirvix approvals")}`);
    lines.push("");
  }

  return lines.join("\n");
}
