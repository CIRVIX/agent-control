#!/usr/bin/env node
/**
 * Cirvix AgentControl CLI.
 *
 * Zero runtime dependencies, by design: this binary runs on developer
 * machines and in CI, and a security tool that drags in a transitive
 * dependency tree is asking to become the supply-chain incident it exists to
 * prevent.
 */

import { access, mkdir, readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { evaluate, parseRules, STARTER_RULES } from "../src/core/policy.mjs";
import { AuditChain } from "../src/core/audit.mjs";
import { Daemon } from "../src/core/daemon.mjs";
import { Gateway } from "../src/core/gateway.mjs";
import { MessageFramer, serialize } from "../src/core/jsonrpc.mjs";
import { scan } from "../src/commands/scan.mjs";
import { bold, dim, green, red, amber, blue, plural } from "../src/core/format.mjs";

import { MODE, DECISION } from "../src/core/decisions.mjs";
import { Pipeline } from "../src/core/pipeline.mjs";
import { Vault } from "../src/core/vault.mjs";
import { ApprovalStore } from "../src/core/approvals.mjs";
import { UdsServer, defaultEndpoint, writeToken } from "../src/core/uds.mjs";
import * as journal from "../src/core/journal.mjs";
import * as policyCmd from "../src/commands/policy.mjs";
import { init as initCmd } from "../src/commands/init.mjs";
import { status as statusCmd } from "../src/commands/status.mjs";
import { upgrade as upgradeCmd } from "../src/commands/upgrade.mjs";
import { AgentRegistry, Meter, readLicence } from "../src/core/meter.mjs";
import { commercialNotices } from "../src/core/notices.mjs";
import { demo as demoCmd } from "../src/commands/demo.mjs";

/**
 * Read from the manifest, never written down twice.
 *
 * It was a hardcoded `"0.2.0"` while `package.json` said `0.1.0`, so a clean
 * `npm install -g` produced a binary that reported a version npm had never
 * published. The first bug report would cite a release that does not exist, and
 * the two numbers had no reason to ever converge again.
 *
 * Synchronous and at startup because every other path here is async and a
 * version string is not worth an await in `--version`.
 */
const VERSION = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
).version;

const HELP = `
  ${bold("cirvix")} ${dim("· runtime governance for AI agents")}

  ${bold("USAGE")}
    cirvix <command> [options]

  ${bold("GETTING STARTED")}
    init                  Detect agents and MCP servers, write a policy, start protecting
    status                Runtime, policy, servers, blocked, approvals, P99 overhead
    upgrade               Today's usage against your plan, and what lifts the limit
    demo                  Watch an injected exfiltration attempt get stopped, live
    scan                  Inventory what is ungoverned on this machine

  ${bold("ENFORCEMENT")}
    gateway               Run the MCP gateway — intercepts and enforces
    runtime               Run the local control socket — any agent, any language
    daemon                Run the endpoint service — policy sync + telemetry

  ${bold("POLICY")}
    policy check          Parse and validate the rule set
    policy test           Run the test cases the policy declares
    policy explain        Why would this call be decided that way
    policy list           Show the active rules
    check                 Evaluate a single tool call against the policy set

  ${bold("HISTORY")}
    logs                  Recent decisions
    logs --last 50        The last N
    logs --risk high      Only high and critical
    logs --tree <id>      One decision, as an execution tree
    replay <id>           Re-decide a recorded call under a candidate policy
    why <decision-id>     Explain one decision from the control plane
    audit verify          Recompute the decision chain and report any break

  ${bold("APPROVALS & SECRETS")}
    approvals             Calls waiting on a human
    approve <id> --by <who>
    deny <id> --by <who>
    vault load            Move credential env vars behind handles

  ${bold("OPTIONS")}
    --json                Machine-readable output
    --sarif <file>        Write SARIF 2.1.0 for code-scanning upload
    --deep                Include MCP command lines in scan output
    --policy <file>       Rule set to evaluate against ${dim("(default ./cirvix.policy)")}
    --cwd <dir>           Workspace root (default: current directory)
    --state <dir>         State directory ${dim("(default ./.cirvix)")}
    --fail-on <level>     Exit non-zero at high|medium|low findings
    --mode <enforce|audit>  audit records decisions and blocks nothing

  ${bold("GATEWAY / DAEMON")}
    --servers <file>      MCP server map (same shape as an editor's mcp.json)
    --api <url>           Control-plane URL
    --key <cvx_…>         API key ${dim("(or set CIRVIX_API_KEY)")}

  ${bold("EXAMPLES")}
    ${dim("$")} cirvix init
    ${dim("$")} cirvix demo
    ${dim("$")} cirvix policy test
    ${dim("$")} cirvix policy explain --tool shell.exec --command "rm -rf /"
    ${dim("$")} cirvix gateway --servers ~/.cursor/mcp.json
    ${dim("$")} cirvix logs --risk high --last 20
    ${dim("$")} cirvix replay req_8a91 --policy policies/proposed.policy
    ${dim("$")} cirvix audit verify --file .cirvix/audit.jsonl
`;

/**
 * A read against the control plane.
 *
 * `why` and `replay` are the two commands that need one — everything else in
 * this CLI works offline, because enforcement has to. These do not: they ask
 * about something that was already recorded somewhere else.
 */
async function controlPlane(flags) {
  const apiUrl = flags.api ?? process.env.CIRVIX_API_URL;
  const apiKey = flags.key ?? process.env.CIRVIX_API_KEY;
  if (!apiUrl || !apiKey) {
    throw new Error(
      "This command reads from a control plane. Pass --api <url> and --key <cvx_…>, or set CIRVIX_API_URL and CIRVIX_API_KEY.",
    );
  }
  const base = String(apiUrl).replace(/\/$/, "");
  return async (method, path, body) => {
    const res = await fetch(base + path, {
      method,
      headers: {
        authorization: `Bearer ${apiKey}`,
        ...(body ? { "content-type": "application/json" } : {}),
        // A one-shot CLI has no use for a pooled socket, and leaving one open
        // holds the event loop past the last line of output — on Windows that
        // surfaced as a libuv assertion and exit code 127 on a command that
        // had already printed the right answer. The exit code is the contract
        // for CI, so it has to be the one we chose.
        connection: "close",
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(20_000),
    });
    const payload = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(payload.error ?? `${method} ${path} → ${res.status}`);
    return payload;
  };
}

/* -------------------------------------------------------------------------- */

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) flags[key] = true;
      else {
        flags[key] = next;
        i++;
      }
    } else positional.push(a);
  }
  return { positional, flags };
}

async function fileExists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolves which policy file to use.
 *
 * An explicit `--policy` always wins. Otherwise the workspace's own
 * `cirvix.policy` (what `init` writes), then `cirvix.policy.json` for
 * deployments that predate the DSL, then the built-in starter rules.
 *
 * Order matters: a project that has written its own policy must never silently
 * run under the defaults because the lookup missed its file.
 */
async function resolvePolicyPath(flag, cwd) {
  if (typeof flag === "string") return flag;
  for (const candidate of ["cirvix.policy", "cirvix.policy.json", ".cirvix/policy.json"]) {
    const path = join(cwd, candidate);
    if (await fileExists(path)) return path;
  }
  return null;
}

/** Loads rules from either the DSL or the JSON shape, or the starter set. */
async function loadRules(file, cwd = process.cwd()) {
  const path = await resolvePolicyPath(file, cwd);
  if (!path) return STARTER_RULES;
  const loaded = await policyCmd.loadPolicyFile(path, { cwd });
  return loaded.rules;
}

/** Same, but keeps the tests and the path — for the policy subcommands. */
async function loadPolicy(file, cwd = process.cwd()) {
  const path = await resolvePolicyPath(file, cwd);
  if (!path) {
    return { rules: STARTER_RULES, tests: [], format: "builtin", path: null };
  }
  return policyCmd.loadPolicyFile(path, { cwd });
}

function stateDirFor(flags, cwd) {
  return String(flags.state ?? join(cwd, ".cirvix"));
}

/** Parses `--arg key=value` pairs plus the convenience flags into call args. */
function callArgsFrom(flags) {
  const args = {};
  if (typeof flags.path === "string") args.path = flags.path;
  if (typeof flags.resource === "string" && !args.path) args.path = flags.resource;
  if (typeof flags.url === "string") args.url = flags.url;
  if (typeof flags.command === "string") args.command = flags.command;
  if (typeof flags.sql === "string") args.sql = flags.sql;
  for (const pair of [].concat(flags.arg ?? [])) {
    if (typeof pair !== "string") continue;
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    args[pair.slice(0, eq)] = pair.slice(eq + 1);
  }
  return args;
}

/**
 * Reads an MCP server map. Accepts an editor's config verbatim — `mcpServers`
 * (Claude Code, Cursor, Windsurf) or `servers` (VS Code) — so a user points at
 * the file they already have rather than authoring a new format. Cirvix's own
 * entry is skipped, otherwise pointing the gateway at a governed config would
 * make it proxy itself.
 */
async function loadServers(file) {
  if (!file) return {};
  const raw = JSON.parse(await readFile(String(file), "utf8"));
  const map = raw.mcpServers ?? raw.servers ?? raw;
  const out = {};
  for (const [name, spec] of Object.entries(map)) {
    if (name === "cirvix") continue;

    // Hosted servers are named by `url`, local ones by `command`. Both are
    // governed; skipping the HTTP ones left exactly the servers a company did
    // not write and cannot audit outside the control plane.
    if (spec?.url) {
      out[name] = {
        url: spec.url,
        headers: spec.headers ?? {},
        ...(spec.timeoutMs ? { timeoutMs: spec.timeoutMs } : {}),
      };
      continue;
    }
    if (!spec?.command) continue;
    out[name] = { command: spec.command, args: spec.args ?? [], env: spec.env ?? {} };
  }
  return out;
}

/* -------------------------------------------------------------------------- */

async function main() {
  const { positional, flags } = parseArgs(process.argv.slice(2));
  const command = positional[0] ?? "help";
  const sub = positional[1];
  const cwd = flags.cwd ? String(flags.cwd) : process.cwd();

  if (flags.version || command === "version") {
    process.stdout.write(VERSION + "\n");
    return 0;
  }

  switch (command) {
    case "scan": {
      const { result, output } = await scan({
        cwd,
        json: Boolean(flags.json),
        deep: Boolean(flags.deep),
      });

      // Written before the exit-code gate below, so a failing scan still
      // produces the artifact CI is about to upload. Emitting it only on
      // success would mean the runs that matter most report nothing.
      if (typeof flags.sarif === "string") {
        const { toSarif } = await import("../src/commands/sarif.mjs");
        const { writeFile } = await import("node:fs/promises");
        await writeFile(flags.sarif, JSON.stringify(toSarif(result, { root: cwd }), null, 2), "utf8");
      }

      process.stdout.write(output + "\n");

      const gate = flags["fail-on"];
      if (typeof gate === "string") {
        const levels = { high: ["high"], medium: ["high", "medium"], low: ["high", "medium", "low"] };
        const watch = levels[gate];
        if (!watch) {
          process.stderr.write(red(`  Unknown --fail-on level "${gate}". Use high, medium, or low.\n`));
          return 2;
        }
        const hit = watch.reduce((n, l) => n + (result.counts[l] ?? 0), 0);
        if (hit > 0) return 1;
      }
      return 0;
    }

    case "gateway": {
      // stdio transport: the agent owns stdout, so every diagnostic goes to
      // stderr. One stray console.log here corrupts the JSON-RPC stream and
      // the agent sees a protocol error it cannot explain.
      const log = (m) => process.stderr.write(`[cirvix] ${m}\n`);
      const servers = await loadServers(flags.servers);
      if (Object.keys(servers).length === 0) {
        process.stderr.write(
          red("  No upstream MCP servers configured. Pass --servers <file>.\n"),
        );
        return 2;
      }

      const rules = await loadRules(flags.policy, cwd);
      const stateDir = String(flags.state ?? join(cwd, ".cirvix"));
      await mkdir(stateDir, { recursive: true }).catch(() => {});
      const chain = await new AuditChain(join(stateDir, "audit.jsonl")).open();

      // If a control plane is configured, the daemon supplies policy and
      // receives telemetry. Without one the gateway still enforces, from the
      // local rule set — the product is useful before you have an account.
      let daemon = null;
      const apiUrl = flags.api ?? process.env.CIRVIX_API_URL;
      const apiKey = flags.key ?? process.env.CIRVIX_API_KEY;
      if (apiUrl && apiKey) {
        daemon = new Daemon({ apiUrl: String(apiUrl), apiKey: String(apiKey), stateDir, log });
        await daemon.start();
      }

      const agentName = String(flags.agent ?? "local");
      const environment = String(flags.env ?? "local");

      // Metered on the same terms as the local socket. The gateway is the path
      // most Free-tier traffic actually takes, and it was the one measuring
      // nothing.
      const gwLicence = readLicence(cwd);
      const gwMeter = new Meter({ cwd });
      // stdout is the MCP wire on this path. Notices go to stderr or they
      // corrupt protocol frames.
      const gwNotice = commercialNotices({
        licence: gwLicence,
        meter: gwMeter,
        write: (s) => process.stderr.write(s),
      });
      const gw = new Gateway({
        servers,
        rules: daemon?.currentRules().length ? daemon.currentRules() : rules,
        audit: chain,
        cwd,
        environment: String(flags.env ?? "local"),
        licence: gwLicence,
        meter: gwMeter,
        agents: new AgentRegistry(),
        log,
        onDecision: (d) => {
          if (d.kind === "decision") gwNotice(d);
          if (daemon && d.kind === "decision") void daemon.record(d);
        },
      });

      gw.agentName = agentName;
      // Announce the agent so it appears in the fleet inventory alongside its
      // decisions, rather than the console reporting calls from nobody. Then
      // open the run every decision in this session will belong to.
      if (daemon) {
        await daemon.registerAgent({ name: agentName, framework: "mcp-gateway", environment });
        gw.runId = await daemon.openRun({ agent: agentName, environment });
      }
      gw.start((msg) => process.stdout.write(serialize(msg)));

      // `--http` serves the same gateway over Streamable HTTP for agents that
      // connect to a URL rather than spawning a subprocess. stdio keeps working
      // alongside it; the two are transports for one decision path.
      let httpServer = null;
      if (flags.http) {
        const { HttpGatewayServer } = await import("../src/core/http-transport.mjs");
        try {
          httpServer = await new HttpGatewayServer({
            gateway: gw,
            host: String(flags.host ?? "127.0.0.1"),
            port: Number(flags.port ?? 8787),
            token: typeof flags.token === "string" ? flags.token : null,
            log,
          }).start();
        } catch (err) {
          process.stderr.write(red(`  ${err.message}\n`));
          gw.stop();
          return 2;
        }
      }

      const framer = new MessageFramer({
        onMessage: (m) => void gw.handleClientMessage(m),
        onInvalid: (line) => log(`client sent unparseable frame: ${line.slice(0, 120)}`),
      });
      process.stdin.on("data", (c) => framer.push(c));

      log(
        `gateway up · ${Object.keys(servers).length} upstream · ` +
          `${(daemon?.currentRules().length || rules.length)} rules` +
          (daemon ? ` · synced with ${apiUrl}` : " · local policy"),
      );

      await new Promise((resolve) => {
        let closing = false;
        const shutdown = async () => {
          // Guard against stdin 'end' and SIGTERM both firing — a double
          // shutdown would drain the spool twice and double-report.
          if (closing) return;
          closing = true;
          log(
            `stopping · ${gw.stats.calls} calls · ${gw.stats.permitted} permitted · ` +
              `${gw.stats.denied} denied · ${gw.stats.held} held`,
          );
          gw.stop();
          if (httpServer) await httpServer.stop();
          // Flush telemetry before exiting. A short-lived run would otherwise
          // leave its decisions spooled on disk until some later daemon start.
          if (daemon) {
            await daemon.shutdown();
            // Closed after the flush, so the run's counts and its decisions
            // arrive in that order and a reader never sees a finished run
            // whose steps have not landed yet.
            await daemon.closeRun({
              calls: gw.stats.calls,
              permitted: gw.stats.permitted,
              denied: gw.stats.denied,
              held: gw.stats.held,
              leaks: gw.stats.leaks,
            });
          }
          resolve();
        };
        process.stdin.on("end", () => void shutdown());
        process.on("SIGINT", () => void shutdown());
        process.on("SIGTERM", () => void shutdown());
      });
      return 0;
    }

    case "daemon": {
      const apiUrl = flags.api ?? process.env.CIRVIX_API_URL;
      const apiKey = flags.key ?? process.env.CIRVIX_API_KEY;
      if (!apiUrl || !apiKey) {
        process.stderr.write(
          red("  daemon needs --api <url> and --key <cvx_…> (or CIRVIX_API_URL / CIRVIX_API_KEY).\n"),
        );
        return 2;
      }
      const stateDir = String(flags.state ?? join(cwd, ".cirvix"));
      const daemon = new Daemon({
        apiUrl: String(apiUrl),
        apiKey: String(apiKey),
        stateDir,
        intervalMs: Number(flags.interval ?? 30000),
        log: (m) => process.stdout.write(`[cirvix] ${m}\n`),
      });
      await daemon.start();

      await new Promise((resolve) => {
        let closing = false;
        const shutdown = async () => {
          if (closing) return;
          closing = true;
          await daemon.shutdown();
          resolve();
        };
        process.on("SIGINT", () => void shutdown());
        process.on("SIGTERM", () => void shutdown());
      });
      return 0;
    }

    case "check": {
      const rules = await loadRules(flags.policy, cwd);
      const action = String(flags.action ?? "");
      const resource = String(flags.resource ?? "");
      if (!action || !resource) {
        process.stderr.write(red("  check needs --action and --resource.\n"));
        return 2;
      }

      const decision = evaluate(
        {
          agent: String(flags.agent ?? "local"),
          action,
          resource,
          context: {
            environment: String(flags.env ?? "local"),
            path: { insideWorkspace: isInsideWorkspace(cwd, resource) },
            egress: { external: false, allowlisted: false },
            session: { touchedSecret: false },
          },
        },
        rules,
        { cwd },
      );

      if (flags.json) {
        process.stdout.write(JSON.stringify(decision, null, 2) + "\n");
      } else {
        const tone =
          decision.verdict === "permit" ? green : decision.verdict === "hold" ? amber : red;
        process.stdout.write(
          [
            "",
            `  ${tone(bold(decision.verdict.toUpperCase()))}  ${dim(action)} ${decision.resource}`,
            `  ${dim("rule")}    ${decision.rule ?? dim("— no rule matched (default deny)")}`,
            `  ${dim("reason")}  ${decision.reason}`,
            decision.remediation ? `  ${dim("fix")}     ${blue(decision.remediation)}` : "",
            decision.approvers?.length
              ? `  ${dim("waits")}   ${decision.approvers.join(", ")}`
              : "",
            "",
            `  ${dim("considered")}`,
            ...decision.considered.map(
              (c) =>
                `    ${c.matched ? bold("→") : dim(" ")} ${dim(c.effect.padEnd(7))} ${c.matched ? c.rule : dim(c.rule)}`,
            ),
            "",
          ]
            .filter(Boolean)
            .join("\n") + "\n",
        );
      }
      return decision.verdict === "deny" ? 1 : 0;
    }

    case "why": {
      const decisionId = sub;
      if (!decisionId) {
        process.stderr.write(red("  why needs a decision id.\n"));
        return 2;
      }
      const api = await controlPlane(flags);
      const d = await api("GET", `/v1/decisions/${encodeURIComponent(decisionId)}`);

      if (flags.json) {
        process.stdout.write(JSON.stringify(d, null, 2) + "\n");
        return d.verdict === "deny" ? 1 : 0;
      }

      const tone = d.verdict === "permit" ? green : d.verdict === "hold" ? amber : red;
      process.stdout.write(
        [
          "",
          `  ${tone(bold(String(d.verdict).toUpperCase()))}  ${dim(d.action ?? d.tool ?? "")} ${d.resource ?? ""}`,
          `  ${dim("rule")}    ${d.rule ?? dim("— no rule matched (default deny)")}`,
          `  ${dim("reason")}  ${d.reason ?? dim("—")}`,
          `  ${dim("agent")}   ${d.agent ?? dim("—")}`,
          `  ${dim("when")}    ${d.ts}`,
          // The whole point of this command in an incident: it hands you the
          // thread to pull, not just the one bead you arrived holding.
          `  ${dim("run")}     ${d.runId ? blue(d.runId) : dim("— recorded outside a run")}`,
          "",
          ...(d.considered?.length
            ? [
                `  ${dim("considered")}`,
                ...d.considered.map(
                  (c) =>
                    `    ${c.matched ? bold("→") : dim(" ")} ${dim(String(c.effect).padEnd(7))} ${c.matched ? c.rule : dim(c.rule)}`,
                ),
                "",
              ]
            : []),
          d.runId ? `  ${dim(`cirvix replay ${d.runId} --diff`)}` : "",
          "",
        ]
          .filter((l) => l !== "")
          .join("\n") + "\n",
      );
      return d.verdict === "deny" ? 1 : 0;
    }

    case "replay": {
      const runId = sub;
      if (!runId) {
        process.stderr.write(red("  replay needs a run id.\n"));
        return 2;
      }
      const api = await controlPlane(flags);
      // No --policy replays against whatever is live, which answers "would
      // today's rules have stopped this" — the question after an incident.
      const rules = flags.policy ? await loadRules(String(flags.policy)) : undefined;
      const result = await api("POST", `/v1/runs/${encodeURIComponent(runId)}/replay`, { rules });

      if (flags.json) {
        process.stdout.write(JSON.stringify(result, null, 2) + "\n");
        return result.changed > 0 ? 1 : 0;
      }

      const shown = flags.diff ? result.steps.filter((s) => s.changed) : result.steps;
      const t0 = result.steps.length ? new Date(result.steps[0].ts).getTime() : 0;
      const offset = (ts) => ((new Date(ts).getTime() - t0) / 1000).toFixed(3).padStart(6, "0");

      process.stdout.write(
        [
          "",
          `  ${bold(result.runId)}   ${dim("agent")} ${result.agent ?? "—"}   ${result.calls} calls`,
          "",
          `  ${bold("changed decisions")}${" ".repeat(Math.max(1, 34 - 17))}${result.changed} of ${result.replayable}`,
          "",
          ...shown.flatMap((s) => {
            if (!s.replayable) {
              return [`  ${offset(s.ts)}  ${dim(`${s.action ?? ""} ${s.resource ?? ""} — not replayable`)}`];
            }
            const tone = (v) => (v === "permit" ? green : v === "hold" ? amber : red);
            const lines = [`  ${offset(s.ts)}  ${s.action ?? ""}  ${dim(s.resource ?? "")}`];
            if (s.changed) {
              lines.push(`          ${dim("was")}  ${tone(s.before.verdict)(s.before.verdict.toUpperCase().padEnd(6))} ${s.before.rule ?? "—"}`);
              lines.push(`          ${dim("now")}  ${tone(s.after.verdict)(s.after.verdict.toUpperCase().padEnd(6))} ${s.after.rule ?? "—"}`);
              if (s.after.reason) lines.push(`          ${dim("→")} ${dim(s.after.reason)}`);
            } else {
              lines.push(
                `          ${dim("was")}  ${tone(s.before.verdict)(s.before.verdict.toUpperCase().padEnd(6))} ${s.before.rule ?? "—"}      ${dim("(unchanged)")}`,
              );
            }
            return lines;
          }),
          "",
          `  ${dim("No side effects were executed.")}`,
          `  ${dim(result.caveat)}`,
          "",
        ].join("\n") + "\n",
      );
      // Non-zero when the policy would have behaved differently, so this works
      // as a gate in CI against a candidate rule set.
      return result.changed > 0 ? 1 : 0;
    }

    case "audit": {
      if (sub !== "verify") {
        process.stderr.write(red("  Only `audit verify` is available.\n"));
        return 2;
      }
      const file = String(flags.file ?? ".cirvix/audit.jsonl");
      const chain = new AuditChain(file);
      const res = await chain.verify();
      if (flags.json) {
        process.stdout.write(JSON.stringify(res, null, 2) + "\n");
        return res.ok ? 0 : 1;
      }
      process.stdout.write(
        res.ok
          ? `\n  ${green(bold("chain intact"))}  ${dim(`${res.records} records verified`)}\n\n  ${dim("Verification proves records were not altered after they were written.\n  It does not attest to their content.")}\n\n`
          : `\n  ${red(bold("chain broken"))}  ${dim(`at record ${res.brokenAt} of ${res.records}`)}\n  ${res.reason}\n\n`,
      );
      return res.ok ? 0 : 1;
    }

    case "policy": {
      const loaded = await loadPolicy(flags.policy, cwd);

      switch (sub ?? "list") {
        case "check": {
          if (!loaded.path) {
            process.stderr.write(
              red("  No policy file found. Run `cirvix init`, or pass --policy <file>.\n"),
            );
            return 2;
          }
          const { output, code } = await policyCmd.check({
            path: loaded.path,
            cwd,
            json: Boolean(flags.json),
            strict: Boolean(flags.strict),
          });
          process.stdout.write(output + "\n");
          return code;
        }

        case "test": {
          if (!loaded.path) {
            process.stderr.write(
              red("  No policy file found. Run `cirvix init`, or pass --policy <file>.\n"),
            );
            return 2;
          }
          const { output, code } = await policyCmd.test({
            path: loaded.path,
            cwd,
            json: Boolean(flags.json),
            filter: typeof flags.filter === "string" ? flags.filter : null,
          });
          process.stdout.write(output + "\n");
          return code;
        }

        case "explain": {
          const tool = flags.tool ?? flags.action;
          if (typeof tool !== "string") {
            process.stderr.write(red("  explain needs --tool <name>.\n"));
            return 2;
          }
          const { output, code } = await policyCmd.explain({
            path: loaded.path,
            // The starter set has no file, so explain against the rules directly.
            rules: loaded.path ? null : loaded.rules,
            cwd,
            json: Boolean(flags.json),
            tool,
            args: callArgsFrom(flags),
            agent: String(flags.agent ?? "local"),
            environment: String(flags.env ?? "local"),
          });
          process.stdout.write(output + "\n");
          return code;
        }

        case "list":
        default: {
          const { output, code } = policyCmd.list(loaded.rules, {
            json: Boolean(flags.json),
            source: Boolean(flags.source),
            cwd,
          });
          process.stdout.write(output + "\n");
          return code;
        }
      }
    }

    /* ---------------------------------------------------------------- init */
    case "init": {
      const { result, output } = await initCmd({
        cwd,
        json: Boolean(flags.json),
        force: Boolean(flags.force),
      });
      process.stdout.write(output + "\n");
      return result.ok ? 0 : 1;
    }

    /* -------------------------------------------------------------- status */
    case "upgrade": {
      // `positional` already has the command at [0]; the rest are the
      // tier and any flags the command parses itself.
      const rest = positional.slice(1);
      if (flags.seats) rest.push("--seats", String(flags.seats));
      await upgradeCmd(rest, { cwd });
      return 0;
    }

    case "status": {
      const rules = await loadRules(flags.policy, cwd);
      const { output } = await statusCmd({
        cwd,
        rules,
        json: Boolean(flags.json),
        stateDir: stateDirFor(flags, cwd),
      });
      process.stdout.write(output + "\n");
      return 0;
    }

    /* ---------------------------------------------------------------- demo */
    case "demo": {
      const rules = flags.policy ? await loadRules(flags.policy, cwd) : null;
      const { output } = await demoCmd({
        cwd,
        rules,
        json: Boolean(flags.json),
        stateDir: stateDirFor(flags, cwd),
        // `--fast` for CI and for anyone who has seen it once.
        pace: flags.fast ? 0 : Number(flags.pace ?? 700),
      });
      if (output) process.stdout.write(output + "\n");
      return 0;
    }

    /* ---------------------------------------------------------------- logs */
    case "logs": {
      const stateDir = stateDirFor(flags, cwd);
      const file = String(flags.file ?? join(stateDir, "audit.jsonl"));
      const records = await journal.read(file);

      // `--tree <id>` prints one decision in full rather than the list.
      const treeId = typeof flags.tree === "string" ? flags.tree : sub;
      if (flags.tree || (sub && sub !== "list")) {
        const record = journal.find(records, treeId);
        if (!record) {
          process.stderr.write(red(`  No decision with id ${treeId} in ${file}.\n`));
          return 2;
        }
        if (flags.json) {
          process.stdout.write(JSON.stringify(record, null, 2) + "\n");
          return record.decision === DECISION.DENY ? 1 : 0;
        }
        process.stdout.write("\n" + journal.renderTree(record) + "\n\n");
        return record.decision === DECISION.DENY ? 1 : 0;
      }

      const selected = journal.query(records, {
        last: flags.last ? Number(flags.last) : 25,
        risk: typeof flags.risk === "string" ? flags.risk : undefined,
        decision: typeof flags.decision === "string" ? flags.decision : undefined,
        agent: typeof flags.agent === "string" ? flags.agent : undefined,
        tool: typeof flags.tool === "string" ? flags.tool : undefined,
        run: typeof flags.run === "string" ? flags.run : undefined,
        since: typeof flags.since === "string" ? flags.since : undefined,
        deniedOnly: Boolean(flags.denied),
      });

      if (flags.json) {
        process.stdout.write(JSON.stringify(selected, null, 2) + "\n");
        return 0;
      }

      if (selected.length === 0) {
        process.stdout.write(
          `\n  ${dim("no matching decisions")}  ${dim(`in ${file}`)}\n\n  ${dim("Run `cirvix demo` to produce some, or start the gateway.")}\n\n`,
        );
        return 0;
      }

      const stats = journal.summarize(selected);
      process.stdout.write("\n");
      for (const record of selected) process.stdout.write(journal.renderLine(record) + "\n");
      process.stdout.write("\n");
      process.stdout.write(
        `  ${dim(plural(stats.records, "decision"))}  ` +
          [
            stats.counts.allow ? green(`${stats.counts.allow} allowed`) : null,
            stats.counts.sanitize ? blue(`${stats.counts.sanitize} sanitized`) : null,
            stats.counts.require_approval ? amber(`${stats.counts.require_approval} held`) : null,
            stats.counts.deny ? red(`${stats.counts.deny} denied`) : null,
            stats.counts.audit_only ? dim(`${stats.counts.audit_only} audit-only`) : null,
          ]
            .filter(Boolean)
            .join(dim("  ·  ")) +
          dim(`   P99 ${stats.latency.p99}ms`) +
          "\n\n",
      );
      return 0;
    }

    /* ------------------------------------------------------------ approvals */
    case "approvals": {
      const store = await new ApprovalStore(join(stateDirFor(flags, cwd), "approvals.jsonl")).open();
      const pending = flags.all ? store.all() : store.pending();

      if (flags.json) {
        process.stdout.write(JSON.stringify(pending, null, 2) + "\n");
        return 0;
      }
      if (!pending.length) {
        process.stdout.write(`\n  ${dim("nothing waiting on a human")}\n\n`);
        return 0;
      }

      process.stdout.write("\n  " + bold(plural(pending.length, "call")) + dim(" waiting\n\n"));
      for (const a of pending) {
        const riskTone = { low: dim, medium: blue, high: amber, critical: red }[a.risk] ?? dim;
        process.stdout.write(
          `    ${bold(a.id)}  ${riskTone(String(a.risk ?? "").toUpperCase().padEnd(9))}${a.tool ?? "—"}  ${dim(a.resource ?? "")}\n`,
        );
        process.stdout.write(`      ${dim(a.reason ?? "")}\n`);
        process.stdout.write(
          `      ${dim("agent")} ${a.agent ?? "—"}   ${dim("rule")} ${a.rule ?? "—"}   ${dim("waits on")} ${(a.approvers ?? []).join(", ") || dim("nobody in particular")}\n`,
        );
        if (a.state !== "pending") {
          process.stdout.write(`      ${dim("state")} ${a.state}${a.decidedBy ? dim(` by ${a.decidedBy}`) : ""}\n`);
        }
        process.stdout.write("\n");
      }
      process.stdout.write(
        `  ${dim("Decide one:")}  ${blue(`cirvix approve ${pending[0].id} --by you@example.com`)}\n\n`,
      );
      return 0;
    }

    case "approve":
    case "deny": {
      const id = sub;
      const by = flags.by ?? process.env.CIRVIX_APPROVER;
      if (!id) {
        process.stderr.write(red(`  ${command} needs an approval id.\n`));
        return 2;
      }
      if (typeof by !== "string" || !by) {
        // Never defaulted. An approval whose record says "approved by unknown"
        // is not evidence of anything.
        process.stderr.write(
          red("  --by <who> is required. An approval has to name the person accountable for it.\n"),
        );
        return 2;
      }
      const store = await new ApprovalStore(join(stateDirFor(flags, cwd), "approvals.jsonl")).open();
      try {
        const record = await store.decide(
          id,
          command === "approve" ? "approved" : "denied",
          String(by),
          typeof flags.note === "string" ? flags.note : null,
        );
        const tone = command === "approve" ? green : red;
        process.stdout.write(
          `\n  ${tone(bold(record.state.toUpperCase()))}  ${record.tool ?? "—"} ${dim(record.resource ?? "")}\n  ${dim(`by ${by} at ${record.decidedAt}`)}\n\n`,
        );
        return 0;
      } catch (err) {
        process.stderr.write(red(`  ${err.message}\n`));
        return 1;
      }
    }

    /* --------------------------------------------------------------- vault */
    case "vault": {
      const vault = new Vault();
      const loadedEnv = vault.loadFromEnv({ replaceEnv: false });
      const loadedFile = flags.file ? await vault.loadFromFile(String(flags.file)) : [];
      const all = [...loadedEnv, ...loadedFile];

      if (flags.json) {
        process.stdout.write(JSON.stringify({ loaded: vault.inventory() }, null, 2) + "\n");
        return 0;
      }
      if (!all.length) {
        process.stdout.write(
          `\n  ${dim("nothing to vault")}  ${dim("no credential-shaped environment variables in this shell.")}\n\n`,
        );
        return 0;
      }
      process.stdout.write("\n  " + bold(plural(all.length, "secret")) + dim(" behind handles\n\n"));
      for (const entry of vault.inventory()) {
        process.stdout.write(
          `    ${blue(entry.handle.padEnd(16))} ${entry.name}${entry.destinations.length ? dim(`   scoped to ${entry.destinations.join(", ")}`) : amber("   unscoped")}\n`,
        );
      }
      process.stdout.write(
        `\n  ${dim("The value is never printed, never written to the audit chain, and never")}\n  ${dim("reaches the agent. Pass the handle where you would have passed the key.")}\n\n`,
      );
      return 0;
    }

    /* ------------------------------------------------------------- runtime */
    case "runtime": {
      const stateDir = stateDirFor(flags, cwd);
      await mkdir(stateDir, { recursive: true }).catch(() => {});

      const rules = await loadRules(flags.policy, cwd);
      const chain = await new AuditChain(join(stateDir, "audit.jsonl")).open();
      const approvals = await new ApprovalStore(join(stateDir, "approvals.jsonl")).open();
      const vault = new Vault({ log: (m) => process.stderr.write(`[cirvix] ${m}\n`) });
      if (flags.vault) vault.loadFromEnv();

      const mode = flags.mode === "audit" ? MODE.AUDIT : MODE.ENFORCE;
      // The commercial gate needs all three, and it silently does nothing
      // without them. This is the long-running enforcement path — if the
      // published Free limits are enforced anywhere, it is here.
      const runtimeLicence = readLicence(cwd);
      const runtimeMeter = new Meter({ cwd });
      const notice = commercialNotices({
        licence: runtimeLicence,
        meter: runtimeMeter,
        write: (s) => process.stderr.write(s),
      });
      const pipeline = new Pipeline({
        rules,
        cwd,
        agent: String(flags.agent ?? "local"),
        environment: String(flags.env ?? "local"),
        mode,
        audit: chain,
        secrets: vault.held ? vault : null,
        approvals,
        licence: runtimeLicence,
        meter: runtimeMeter,
        agents: new AgentRegistry(),
        onEvent: (e) => {
          if (e.kind === "decision") notice(e);
        },
        log: (m) => process.stderr.write(`[cirvix] ${m}\n`),
      });

      const token = await writeToken(stateDir);
      const endpoint = defaultEndpoint(stateDir);
      const server = new UdsServer({
        pipeline,
        endpoint,
        token,
        log: (m) => process.stdout.write(`[cirvix] ${m}\n`),
        status: () => ({
          mode: pipeline.mode,
          rules: pipeline.rules.length,
          calls: pipeline.stats.calls,
          denied: pipeline.stats.denied,
          approvals: approvals.pending().length,
          latency: pipeline.percentiles(),
          vault: { held: vault.held, unscoped: vault.inventory().filter((v) => !v.destinations.length).length },
        }),
        recent: async ({ limit, risk }) =>
          journal.query(await journal.read(join(stateDir, "audit.jsonl")), { last: limit, risk }),
      });
      await server.start();

      process.stdout.write(
        `\n  ${green(bold("runtime up"))}  ${dim(`${plural(rules.length, "rule")} · ${mode} · ${endpoint}`)}\n` +
          `  ${dim(`token in ${join(stateDir, "socket.token")}`)}\n\n`,
      );
      if (mode === MODE.AUDIT) {
        process.stdout.write(
          `  ${amber(bold("AUDIT MODE"))} ${dim("— decisions are recorded and nothing is blocked.")}\n\n`,
        );
      }

      await new Promise((resolve) => {
        let closing = false;
        const shutdown = async () => {
          if (closing) return;
          closing = true;
          vault.forget();
          await server.stop();
          resolve();
        };
        process.on("SIGINT", () => void shutdown());
        process.on("SIGTERM", () => void shutdown());
      });
      return 0;
    }

    case "help":
    default:
      process.stdout.write(HELP + "\n");
      return command === "help" ? 0 : 2;
  }
}

function isInsideWorkspace(cwd, resource) {
  // Kept local to the CLI: the engine takes this as context so it stays pure.
  const path = new URL(`file://${process.platform === "win32" ? "/" : ""}`);
  void path;
  const resolved = resource.startsWith("/") || /^[A-Za-z]:/.test(resource)
    ? resource
    : `${cwd}/${resource}`;
  const norm = (s) => s.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  const a = norm(cwd);
  const b = norm(resolved.replace(/\/\.\//g, "/"));
  // Collapse traversal before comparing — the whole point of the check.
  const parts = [];
  for (const seg of b.split("/")) {
    if (seg === "..") parts.pop();
    else if (seg !== ".") parts.push(seg);
  }
  const flat = parts.join("/");
  return flat === a || flat.startsWith(a + "/");
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`\n  ${red("error")}  ${err.message}\n\n`);
    process.exit(2);
  });
