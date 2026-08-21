/**
 * `cirvix scan` — the free, read-only inventory.
 *
 * This is the command the whole funnel rests on, so it has one job: tell a
 * developer something true about their machine that they did not already
 * know, in under five seconds, without an account and without sending
 * anything anywhere.
 *
 * It writes nothing and opens no sockets.
 */

import {
  collectMcpServers,
  detectCredentials,
  detectFrameworks,
  detectRuntimes,
} from "../core/detect.mjs";
import { bold, dim, green, red, amber, blue, plural } from "../core/format.mjs";

export async function scan({ cwd = process.cwd(), json = false, deep = false } = {}) {
  const runtimes = await detectRuntimes();
  const frameworks = await detectFrameworks(cwd);
  const servers = collectMcpServers(runtimes);
  const credentials = await detectCredentials(cwd);

  const findings = buildFindings({ runtimes, frameworks, servers, credentials });
  const counts = tally(findings);

  const result = {
    scannedAt: new Date().toISOString(),
    cwd,
    runtimes: runtimes.map(({ servers: _s, ...r }) => r),
    frameworks,
    mcpServers: servers,
    credentials: credentials.map(({ keys: _k, ...c }) => c),
    findings,
    counts,
  };

  if (json) return { result, output: JSON.stringify(result, null, 2) };
  return { result, output: render(result, { deep }) };
}

/* -------------------------------------------------------------------------- */

function buildFindings({ runtimes, frameworks, servers, credentials }) {
  const findings = [];

  for (const r of runtimes) {
    if (!r.governed) {
      findings.push({
        severity: "high",
        code: "runtime-ungoverned",
        subject: r.label,
        detail: `Tool calls from ${r.label} are not routed through a control plane. Anything it can reach, it can reach unchecked.`,
        fix: `cirvix gateway --servers ${r.path}`,
      });
    }
  }

  for (const f of frameworks) {
    findings.push({
      severity: "medium",
      code: "framework-uninstrumented",
      subject: f.label,
      detail: `${f.label} detected in this project with no Cirvix middleware on its tool boundary.`,
      fix: "Wrap the executor boundary: guard.wrap(tools, { agent, rules })",
    });
  }

  for (const s of servers) {
    if (s.scope?.broad) {
      findings.push({
        severity: "high",
        code: "mcp-broad-scope",
        subject: s.name,
        detail: `Exposes ${s.scope.widest} to any agent that can call it — far wider than a workspace.`,
        fix: "Narrow the server's path arguments, or scope it per-agent through the gateway.",
      });
    }
    if (s.envKeys.length > 0) {
      findings.push({
        severity: "medium",
        code: "mcp-inline-secrets",
        subject: s.name,
        detail: `Configuration carries ${plural(s.envKeys.length, "environment value")} inline (${s.envKeys.slice(0, 3).join(", ")}${s.envKeys.length > 3 ? "…" : ""}). These sit in a plaintext config file.`,
        fix: "Move to secret handles brokered at the boundary.",
      });
    }
    if (s.runtimes.length > 1) {
      findings.push({
        severity: "low",
        code: "mcp-duplicated",
        subject: s.name,
        detail: `Configured separately in ${s.runtimes.join(" and ")} — one trust boundary with ${s.runtimes.length} doors, each updated independently.`,
        fix: "Register once and route both runtimes through the gateway.",
      });
    }
  }

  for (const c of credentials) {
    findings.push({
      severity: c.severity,
      code: c.kind === "dotenv" ? "env-readable" : "credential-readable",
      subject: c.label,
      detail: c.detail,
      fix: "Route agents through cirvix gateway — the starter policy already denies reads of this path.",
    });
  }

  const order = { high: 0, medium: 1, low: 2 };
  return findings.sort((a, b) => order[a.severity] - order[b.severity]);
}

function tally(findings) {
  return findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] ?? 0) + 1 }),
    { high: 0, medium: 0, low: 0 },
  );
}

/* -------------------------------------------------------------------------- */

function render(r, { deep }) {
  const L = [];
  // padEnd does nothing when the string already exceeds the column, which
  // collides the label with the next field. Always guarantee one space.
  const pad = (s, n) => {
    const v = String(s);
    return v.length >= n ? v + " " : v.padEnd(n);
  };

  L.push("");
  L.push(`  ${bold("Cirvix scan")} ${dim("· read-only · nothing was changed or sent")}`);
  L.push("");

  // Runtimes
  L.push(`  ${bold("runtimes")}${dim(pad("", 12))}${r.runtimes.length ? plural(r.runtimes.length, "found") : dim("none detected")}`);
  for (const rt of r.runtimes) {
    const state = rt.governed ? green("governed") : red("ungoverned");
    L.push(`    ${pad(rt.label, 18)}${dim(shorten(rt.path))}`);
    L.push(`    ${pad("", 18)}${state}${dim(` · ${plural(rt.serverCount, "MCP server")}`)}`);
  }
  if (r.frameworks.length) {
    for (const f of r.frameworks) {
      L.push(`    ${pad(f.label, 18)}${dim(f.via)}`);
      L.push(`    ${pad("", 18)}${amber("uninstrumented")}`);
    }
  }
  L.push("");

  // MCP servers
  L.push(`  ${bold("mcp servers")}${dim(pad("", 9))}${r.mcpServers.length ? plural(r.mcpServers.length, "configured") : dim("none")}`);
  for (const s of r.mcpServers) {
    const flags = [];
    if (s.scope?.broad) flags.push(red("broad scope"));
    if (s.envKeys.length) flags.push(amber("inline secrets"));
    if (s.runtimes.length > 1) flags.push(dim(`×${s.runtimes.length} runtimes`));
    L.push(`    ${pad(s.name, 18)}${pad(s.transport, 8)}${flags.join(dim(" · "))}`);
    if (deep && s.command) L.push(`    ${pad("", 18)}${dim(s.command + " " + s.args.join(" "))}`);
  }
  L.push("");

  // Credentials
  L.push(`  ${bold("credentials")}${dim(pad("", 9))}${r.credentials.length ? `${plural(r.credentials.length, "path")} reachable from agent context` : dim("none reachable")}`);
  for (const c of r.credentials) {
    L.push(`    ${pad(c.label, 18)}${dim(c.detail)}`);
  }
  L.push("");

  // Findings
  const { high, medium, low } = r.counts;
  const summary = [
    high ? red(`${high} high`) : null,
    medium ? amber(`${medium} medium`) : null,
    low ? dim(`${low} low`) : null,
  ]
    .filter(Boolean)
    .join(dim(" · "));

  L.push(`  ${bold("findings")}${dim(pad("", 12))}${summary || green("nothing ungoverned")}`);
  L.push("");

  for (const f of r.findings.slice(0, 12)) {
    const mark = f.severity === "high" ? red("▲") : f.severity === "medium" ? amber("▲") : dim("▪");
    L.push(`    ${mark} ${bold(f.subject)} ${dim(`(${f.code})`)}`);
    L.push(`      ${f.detail}`);
    L.push(`      ${dim("fix:")} ${blue(f.fix)}`);
    L.push("");
  }
  if (r.findings.length > 12) {
    L.push(`    ${dim(`…and ${r.findings.length - 12} more. Run with --json for the full list.`)}`);
    L.push("");
  }

  if (r.findings.length > 0) {
    L.push(`  ${dim("Nothing was changed. To see how a call would be decided:")}`);
    L.push(`    ${blue("cirvix check --action fs.read --resource .env")}`);
  } else {
    L.push(`  ${green("No ungoverned surfaces found on this machine.")}`);
  }
  L.push("");

  return L.join("\n");
}

function shorten(p) {
  const home = process.env.HOME || process.env.USERPROFILE || "";
  return home && p.startsWith(home) ? "~" + p.slice(home.length) : p;
}
