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
import { bold, dim, green, red, amber, blue, plural } from "../core/format.mjs";

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

  const result = {
    runtime: {
      running: runtime.running,
      endpoint: runtime.endpoint,
      reason: runtime.reason ?? null,
      mode: runtime.live?.mode ?? MODE.ENFORCE,
    },
    policy: {
      rules: rules.length,
      // A live runtime is the authority on how many rules are actually loaded;
      // the file on disk may have been edited since it started.
      loaded: runtime.live?.rules ?? null,
    },
    mcpServers: servers.length,
    runtimes: runtimes.map((r) => ({
      id: r.id,
      label: r.label,
      governed: r.governed,
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
  const rows = [
    ["Runtime", r.runtime.running ? green(bold("RUNNING")) : dim("STOPPED") + dim(`  ${r.runtime.reason ?? ""}`)],
    ["Policy", r.policy.rules ? `${plural(r.policy.rules, "rule")}` : dim("no policy loaded")],
    ["MCP Servers", String(r.mcpServers)],
    [
      "Protected",
      r.protected === 0 && r.runtimes.length > 0
        ? amber(String(r.protected)) + dim(`  of ${r.runtimes.length} — nothing is routed through the gateway yet`)
        : `${r.protected}` + dim(r.runtimes.length ? `  of ${r.runtimes.length}` : ""),
    ],
    ["Blocked", r.blocked > 0 ? red(String(r.blocked)) : String(r.blocked)],
    ["Approvals", r.approvals.pending > 0 ? amber(`${r.approvals.pending} pending`) : String(r.approvals.pending)],
    [
      "P99 overhead",
      r.latency.samples
        ? `${r.latency.p99}ms` + dim(`  over ${plural(r.latency.samples, "decision")}`)
        : dim("— nothing measured yet"),
    ],
  ];

  const width = Math.max(...rows.map(([k]) => k.length));
  const lines = ["", `  ${bold("CIRVIX AGENTCONTROL")}`, ""];
  for (const [key, value] of rows) lines.push(`  ${key.padEnd(width + 2)}${value}`);

  if (r.runtime.mode !== MODE.ENFORCE) {
    lines.push("");
    lines.push(`  ${amber(bold("AUDIT MODE"))}  ${dim("decisions are recorded and nothing is blocked.")}`);
  }

  if (r.records > 0) {
    lines.push("");
    lines.push(`  ${dim("decisions")}   ` +
      [
        green(`${r.decisions.allow} allowed`),
        r.decisions.sanitize ? blue(`${r.decisions.sanitize} sanitized`) : null,
        r.decisions.require_approval ? amber(`${r.decisions.require_approval} held`) : null,
        r.decisions.deny ? red(`${r.decisions.deny} denied`) : null,
        r.decisions.audit_only ? dim(`${r.decisions.audit_only} audit-only`) : null,
      ]
        .filter(Boolean)
        .join(dim("  ·  ")));

    const risky = r.risks.high + r.risks.critical;
    if (risky > 0) {
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
  }

  if (r.vault) {
    lines.push(`  ${dim("vault")}       ${r.vault.held} held` + (r.vault.unscoped ? amber(`  ${r.vault.unscoped} unscoped`) : ""));
  }

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
