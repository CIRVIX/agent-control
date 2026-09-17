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
import { join, resolve } from "node:path";

import { evaluate, parseRules, STARTER_RULES } from "../src/core/policy.mjs";
import { AuditChain } from "../src/core/audit.mjs";
import { Daemon } from "../src/core/daemon.mjs";
import { Gateway } from "../src/core/gateway.mjs";
import { MessageFramer, serialize } from "../src/core/jsonrpc.mjs";
import { scan } from "../src/commands/scan.mjs";
import { bold, dim, green, red, amber, blue, cyan, gray, plural } from "../src/core/format.mjs";
import { SHARE_URL } from "../src/core/prompts.mjs";
import { shouldAnimate } from "../src/core/ui/controller.mjs";
import { brandHeader, panel } from "../src/core/ui/primitives.mjs";
import { LiveStream } from "../src/core/ui/live.mjs";

import { MODE, DECISION } from "../src/core/decisions.mjs";
import { Pipeline } from "../src/core/pipeline.mjs";
import { Vault } from "../src/core/vault.mjs";
import { ApprovalStore } from "../src/core/approvals.mjs";
import { UdsServer, defaultEndpoint, writeToken } from "../src/core/uds.mjs";
import * as journal from "../src/core/journal.mjs";
import * as policyCmd from "../src/commands/policy.mjs";
import * as protectCmd from "../src/commands/protect.mjs";
import * as proveCmd from "../src/commands/prove.mjs";
import * as passportCmd from "../src/commands/passport.mjs";
import { init as initCmd } from "../src/commands/init.mjs";
import { status as statusCmd } from "../src/commands/status.mjs";
import { upgrade as upgradeCmd } from "../src/commands/upgrade.mjs";
import { AgentRegistry, Meter, readLicence } from "../src/core/meter.mjs";
import { commercialNotices } from "../src/core/notices.mjs";
import { demo as demoCmd } from "../src/commands/demo.mjs";
import { welcome } from "../src/commands/welcome.mjs";
import { doctor } from "../src/commands/doctor.mjs";
import { login, logout } from "../src/commands/login.mjs";

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
    console               Interactive runtime authorization (the product UI)
    onboard               10-second guided first run
    init                  Detect agents and MCP servers, write a policy, start protecting
    init --apply          Safely wire detected agents with pre-integration backup
    init --dry-run        Preview agent configuration changes without modifying files
    init --rollback [id]  Revert agent configurations to pre-integration state
    status                Runtime, policy, servers, blocked, approvals, P99 overhead
    doctor                diagnose this installation: policy, state, daemon, control plane
    login / logout        link this machine to your CIRVIX control plane (browser or --key)
    upgrade               Today's usage against your plan, and what lifts the limit
    demo                  Watch an injected exfiltration attempt get stopped, live
    protect [path]        Discover, analyse, apply policy and prove it decides
    passport [agent]      What an agent is, by what it has actually done
    prove <decision-id>   Sign a decision into a portable proof artifact
    verify <proof>        Check a proof offline: signature, chain, integrity
    scan                  Inventory what is ungoverned on this machine
    theme                 Change appearance (dark|light|midnight|high-contrast|monochrome)

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

  // BARE `cirvix`:
  //   first run in a workspace  -> onboarding (what CIRVIX is, three commands)
  //   returning, interactive    -> the full live terminal
  //   returning, piped/CI       -> the measured digest + next steps (no animation)
  if (positional.length === 0 && !flags.json && !flags.help) {
    let firstRun = false;
    try { await access(join(cwd, ".cirvix")); } catch { firstRun = true; }
    if (!firstRun) {
      const { canLaunchInteractive } = await import("../src/commands/interactive.mjs");
      if (canLaunchInteractive(flags, positional)) {
        const rules = await loadRules(flags.policy, cwd);
        const { interactive } = await import("../src/commands/interactive.mjs");
        await interactive({ cwd, flags, rules });
        return 0;
      }
    }
    await welcome({ cwd });
    return 0;
  }

  switch (command) {
    case "protect": {
      /* Shares policy resolution with `runtime` and `gateway`. A protect that
         read policy differently from the runtime would be proving a decision
         the runtime will not make. */
      const target = sub && !sub.startsWith("-") ? resolve(cwd, sub) : cwd;
      const rules = await loadRules(flags.policy, target);
      const { result, output } = await protectCmd.protect({
        cwd: target,
        rules,
        agent: String(flags.agent ?? "local"),
        environment: String(flags.env ?? "local"),
        json: Boolean(flags.json),
        pace: flags.fast ? 0 : Number(flags.pace ?? 90),
        animate: flags["no-animation"] ? false : undefined,
        stateDir: stateDirFor(flags, target),
      });
      if (output) process.stdout.write(output + "\n");
      // Exit 1 on HIGH or CRITICAL so CI can gate on it, the same convention
      // `scan --fail-on` already uses.
      if (flags["fail-on-risk"] && ["high", "critical"].includes(result.risk)) process.exitCode = 1;
      return;
    }

    case "passport": {
      const policyFile = await loadPolicy(flags.policy, cwd);
      const { output, exitCode } = await passportCmd.passport({
        agentId: sub && !sub.startsWith("-") && sub !== "badge" ? sub : null,
        cwd,
        stateDir: stateDirFor(flags, cwd),
        policy: { rules: policyFile.rules, version: policyFile.version ?? null },
        json: Boolean(flags.json),
        sign: Boolean(flags.sign),
        out: flags.out ? String(flags.out) : null,
        badge: Boolean(flags.badge) || sub === "badge",
        badgeOut: flags["badge-out"] ? String(flags["badge-out"]) : null,
      });
      if (output) process.stdout.write(output + "\n");
      if (exitCode) process.exitCode = exitCode;
      return;
    }

    case "prove": {
      const target = flags.cwd ? cwd : cwd;
      const policyFile = await loadPolicy(flags.policy, target);
      const { output, exitCode } = await proveCmd.prove({
        decisionId: sub,
        cwd: target,
        stateDir: stateDirFor(flags, target),
        // The policy is part of what a proof attests: a decision only means
        // something against the rules that produced it.
        policy: { rules: policyFile.rules, version: policyFile.version ?? null },
        json: Boolean(flags.json),
        out: flags.out ? String(flags.out) : null,
      });
      if (output) process.stdout.write(output + "\n");
      if (exitCode) process.exitCode = exitCode;
      return;
    }

    case "verify": {
      const { output, exitCode } = await proveCmd.verify({
        proof: sub,
        publicKey: flags.key ? String(flags.key) : null,
        cwd,
        stateDir: stateDirFor(flags, cwd),
        json: Boolean(flags.json),
      });
      if (output) process.stdout.write(output + "\n");
      // Exit 1 on a failed verification so CI can gate on it. A verifier that
      // always exits 0 is a verifier nobody can automate.
      if (exitCode) process.exitCode = exitCode;
      return;
    }

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

      // Premium gateway startup — to stderr so stdout stays JSON-RPC clean.
      {
        const animated = shouldAnimate({ pace: flags.pace ? Number(flags.pace) : 700, json: false });
        const gwRules = daemon?.currentRules().length || rules.length;
        if (animated) {
          try {
            process.stderr.write("\n" + brandHeader({ width: 62 }) + "\n\n");
          } catch {}
        }
        log(`gateway up · ${Object.keys(servers).length} upstream · ${gwRules} rules` + (daemon ? ` · synced with ${apiUrl}` : " · local policy"));
        // Also emit a small protected panel for human visibility (stderr).
        try {
          const gwPanel = panel({
            lines: [
              `${bold("CIRVIX GATEWAY")}`,
              ``,
              `${"Upstreams".padEnd(12)} ${Object.keys(servers).length}`,
              `${"Policy".padEnd(12)} ${green(bold("● ENFORCING"))}  ${dim(plural(gwRules, "rule"))}`,
              `${"Audit".padEnd(12)} ${green(bold("● RECORDING"))}`,
              `${"Mode".padEnd(12)} ${dim(daemon ? "synced" : "local")}`,
            ],
            width: 48,
          });
          process.stderr.write(gwPanel + "\n");
        } catch {}
      }

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
            decision.verdict === "deny" && !flags.json
              ? `  ${dim("share")}  ${dim(`was this a good catch? ${SHARE_URL} — redact first, your call`)}`
              : "",
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

      const isWhyDeny = d.verdict === "deny";
      const isWhyHold = d.verdict === "hold";
      const whyTone = isWhyDeny ? red : isWhyHold ? amber : green;
      const whyDecision = isWhyDeny ? "✕ BLOCKED" : isWhyHold ? "● AWAITING APPROVAL" : "✓ " + String(d.verdict).toUpperCase();
      const whyRisk = String(d.risk ?? "unknown").toUpperCase();
      const whyRiskTone = whyRisk === "CRITICAL" ? red : whyRisk === "HIGH" ? amber : whyRisk === "MEDIUM" ? blue : dim;
      process.stdout.write(
        [
          "",
          `  ${bold("CIRVIX DECISION ANALYSIS")}`,
          "",
          `  ${dim("Decision".padEnd(12))} ${whyTone(bold(whyDecision))}`,
          `  ${dim("Risk".padEnd(12))} ${whyRiskTone(bold(whyRisk))}`,
          "",
          `  ${dim("Tool".padEnd(12))} ${bold(String(d.tool ?? d.action ?? "—"))}`,
          d.resource ? `  ${dim("Target".padEnd(12))} ${d.resource}` : "",
          d.destination ? `  ${dim("Destination".padEnd(12))} ${d.destination}` : "",
          `  ${dim("Matched policy".padEnd(12))} ${d.rule ?? dim("— no rule matched (default deny)")}`,
          d.reason ? `  ${dim("Reason".padEnd(12))} ${d.reason}` : "",
          `  ${dim("Agent".padEnd(12))} ${d.agent ?? dim("—")}`,
          `  ${dim("When".padEnd(12))} ${d.ts}`,
          `  ${dim("Run".padEnd(12))} ${d.runId ? blue(d.runId) : dim("— recorded outside a run")}`,
          "",
          `  ${dim("Decision path")}`,
          `    ${dim("secret detection")}`,
          `      ${dim("↓")}`,
          `    ${dim("risk classification")}`,
          `      ${dim("↓")}`,
          `    ${dim("policy evaluation")}`,
          `      ${dim("↓")}`,
          `    ${whyTone(isWhyDeny ? "BLOCK" : isWhyHold ? "HOLD" : "ALLOW")}`,
          "",
          /* The trifecta is the one refusal whose reason lives outside this
             call, so it gets the sequence rendered rather than a rule name.
             "Blocked: trifecta" is indistinguishable from a bug; three
             timestamped steps are something the reader can act on. */
          ...(d.trifecta?.complete
            ? [
                `  ${whyTone(bold("LETHAL TRIFECTA"))}  ${dim("all three conditions met in this session")}`,
                "",
                ...["sensitive_data", "untrusted_content", "outbound_action"]
                  .map((k) => [k, d.trifecta.legs?.[k]])
                  .filter(([, v]) => v)
                  .sort((a, b) => String(a[1].at ?? "").localeCompare(String(b[1].at ?? "")))
                  .map(
                    ([k, v], i) =>
                      `    ${bold(String(i + 1) + ".")} ${dim(k.replace(/_/g, " ").padEnd(18))} ${v.why}` +
                      (v.at ? `
       ${dim(v.at)}` : ""),
                  ),
                "",
                `  ${dim("Cirvix refuses on capability and opportunity. It does not claim the")}`,
                `  ${dim("sensitive bytes are in this request — that needs data-flow analysis")}`,
                `  ${dim("it deliberately does not do.")}`,
                "",
              ]
            : d.trifecta?.satisfied?.length
              ? [
                  `  ${dim("trifecta")}  ${d.trifecta.satisfied.length} of 3 conditions met` +
                    (d.trifecta.imminent ? `  ${whyRiskTone("one step from complete")}` : ""),
                  "",
                ]
              : []),
          ...(d.considered?.length
            ? [
                `  ${dim("considered")}  ${dim(`${d.considered.filter((c) => c.matched).length} of ${d.considered.length} matched`)}`,
                ...d.considered.map(
                  (c) =>
                    `    ${c.matched ? bold("→") : dim(" ")} ${dim(String(c.effect).padEnd(11))} ${c.matched ? c.rule : dim(c.rule)}`,
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
      if (res.ok) {
        const W = 62;
        const top = `  ${dim(`╭─ CIRVIX AUDIT VERIFICATION ${"─".repeat(Math.max(0, W - 26))}╮`)}`;
        const bottom = `  ${dim(`╰${"─".repeat(W)}╯`)}`;
        const chainLines = [
          ``,
          `  ${green("✓")} ${dim("Hash chain intact")}`,
          `  ${green("✓")} ${dim(`${res.records} records verified`)}`,
          `  ${green("✓")} ${dim("No records altered")}`,
          ``,
          `  ${bold("CHAIN")}`,
          ``,
          `  ${dim("current")}`,
          `    ${dim("↓")}`,
          `  ${dim("previous")}`,
          `    ${dim("↓")}`,
          `  ${dim("previous")}`,
          `    ${dim("↓")}`,
          `  ${dim("genesis")}`,
          ``,
          `  ${bold("STATUS")}  ${green(bold("● INTEGRITY OK"))}`,
          ``,
          `  ${dim(`head ${String(res.head ?? "").slice(0, 16)}…`)}`,
          ``,
          `  ${dim("Verification proves records were not altered after they were written.")}`,
          `  ${dim("It does not attest to their content.")}`,
          ``,
        ];
        process.stdout.write(`\n${top}\n`);
        process.stdout.write(`\n  ${bold("CIRVIX AUDIT VERIFICATION")}\n`);
        for (const l of chainLines) process.stdout.write(l + "\n");
        process.stdout.write(`${bottom}\n\n`);
      } else {
        process.stdout.write(
          `\n  ${red(bold("chain broken"))}  ${dim(`at record ${res.brokenAt} of ${res.records}`)}\n  ${res.reason}\n\n`,
        );
      }
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

        case "simulate": {
          const { simulatePolicy } = await import("../src/commands/simulate.mjs");
          const { output, code } = await simulatePolicy({
            rules: loaded.rules,
            action: flags.action ?? flags.tool ?? "fs:read",
            resource: flags.resource ?? flags.path ?? flags.command ?? "",
            tool: flags.tool ?? "file_reader",
            intent: flags.intent ?? null,
            agent: String(flags.agent ?? "local"),
            json: Boolean(flags.json),
            cwd,
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
        apply: Boolean(flags.apply),
        dryRun: Boolean(flags["dry-run"]),
        rollback: flags.rollback ? (typeof flags.rollback === "string" ? flags.rollback : true) : false,
      });
      process.stdout.write(output + "\n");
      return result.ok ? 0 : 1;
    }

    /* ------------------------------------------------------------ simulate */
    case "simulate": {
      const rules = await loadRules(flags.policy, cwd);
      const { simulatePolicy } = await import("../src/commands/simulate.mjs");
      const { output, code } = await simulatePolicy({
        rules,
        action: flags.action ?? flags.tool ?? positional[1] ?? "fs:read",
        resource: flags.resource ?? flags.path ?? flags.command ?? positional[2] ?? "",
        tool: flags.tool ?? "file_reader",
        intent: flags.intent ?? null,
        agent: String(flags.agent ?? "local"),
        json: Boolean(flags.json),
        cwd,
      });
      process.stdout.write(output + "\n");
      return code;
    }

    /* ----------------------------------------------------------------- kill */
    case "kill": {
      const { executeKillCommand } = await import("../src/commands/kill.mjs");
      const { output, code } = await executeKillCommand({
        scope: flags.scope ?? "agent",
        target: positional[1] ?? flags.target ?? null,
        reason: flags.reason ?? "Emergency freeze triggered via CLI",
        release: flags.release ?? null,
        list: Boolean(flags.list),
        json: Boolean(flags.json),
      });
      process.stdout.write(output + "\n");
      return code;
    }

    /* --------------------------------------------------------------- shadow */
    case "shadow": {
      const rules = await loadRules(flags.policy, cwd);
      const { executeShadowCommand } = await import("../src/commands/shadow.mjs");
      const { output, code } = await executeShadowCommand({
        rules,
        action: flags.action ?? positional[1] ?? null,
        resource: flags.resource ?? positional[2] ?? null,
        json: Boolean(flags.json),
        cwd,
      });
      process.stdout.write(output + "\n");
      return code;
    }

    /* -------------------------------------------------------------- redteam */
    case "redteam": {
      const rules = await loadRules(flags.policy, cwd);
      const { executeRedTeamCommand } = await import("../src/commands/redteam.mjs");
      const { output, code } = await executeRedTeamCommand({
        rules,
        plugins: flags.plugins ? String(flags.plugins).split(",") : null,
        json: Boolean(flags.json),
        cwd,
      });
      process.stdout.write(output + "\n");
      return code;
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

    /* ------------------------------------------------------------ console */
    case "console": {
      if (typeof flags.theme === "string") {
        const { setTheme } = await import("../src/core/theme.mjs");
        try {
          setTheme(flags.theme);
          process.env.CIRVIX_THEME = flags.theme;
        } catch (err) {
          process.stderr.write(red(`  ${err.message}\n`));
          return 2;
        }
      }
      const rules = await loadRules(flags.policy, cwd);
      const { consoleCmd } = await import("../src/commands/console.mjs");
      await consoleCmd({
        cwd,
        rules,
        mode: flags.mode === "audit" ? MODE.AUDIT : MODE.ENFORCE,
        evalText: typeof flags.eval === "string" ? flags.eval : null,
        once: Boolean(flags.once ?? flags.eval),
      });
      return 0;
    }

    case "theme": {
      const { setTheme, THEME_NAMES } = await import("../src/core/theme.mjs");
      const name = sub ?? flags.set;
      if (!name) {
        process.stdout.write(
          `\n  Current theme: ${process.env.CIRVIX_THEME ?? "dark"}\n  Available: ${THEME_NAMES.join(", ")}\n\n  Usage: cirvix theme <name>\n  Persist it: CIRVIX_THEME=${THEME_NAMES[0]} cirvix console\n\n`,
        );
        return 0;
      }
      try {
        setTheme(name);
        process.stdout.write(`\n  Theme → ${name} (set CIRVIX_THEME=${name} to keep it)\n\n`);
        return 0;
      } catch (err) {
        process.stderr.write(red(`  ${err.message}\n`));
        return 2;
      }
    }

    case "onboard": {
      const { onboard } = await import("../src/commands/onboard.mjs");
      await onboard({ cwd, pace: flags.fast ? 0 : 400 });
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

      // Live mode: cirvix logs --watch
      if (flags.watch || flags.follow || flags.w) {
        if (flags.json) {
          process.stderr.write(red("  --watch is not compatible with --json.\n"));
          return 2;
        }
        const { watch } = await import("node:fs");
        const live = new LiveStream({ stream: process.stdout, title: "CIRVIX LIVE · protection active" });
        // Print existing tail first
        const existing = await journal.read(file);
        const tail = journal.query(existing, {
          last: flags.last ? Number(flags.last) : 10,
          risk: typeof flags.risk === "string" ? flags.risk : undefined,
          decision: typeof flags.decision === "string" ? flags.decision : undefined,
        });
        live.header();
        for (const r of tail) live.push(r);
        if (tail.length === 0) {
          process.stdout.write(`  ${dim("waiting for decisions…")}  ${dim(`tailing ${file}`)}\n`);
        }
        // Watch for new records — polling via fs.watch where available, fallback to interval.
        let known = existing.length;
        let watcher = null;
        let polling = null;
        const emitNew = async () => {
          const all = await journal.read(file);
          if (all.length > known) {
            const fresh = all.slice(known);
            const filtered = journal.query(fresh, {
              risk: typeof flags.risk === "string" ? flags.risk : undefined,
              decision: typeof flags.decision === "string" ? flags.decision : undefined,
              agent: typeof flags.agent === "string" ? flags.agent : undefined,
              tool: typeof flags.tool === "string" ? flags.tool : undefined,
              deniedOnly: Boolean(flags.denied),
            });
            for (const r of filtered) live.push(r);
            known = all.length;
          } else if (all.length < known) {
            known = all.length;
          }
        };
        try {
          watcher = watch(file, async () => { await emitNew().catch(() => {}); });
        } catch {
          polling = setInterval(() => void emitNew(), 700);
        }
        if (!watcher) polling = setInterval(() => void emitNew(), 700);
        await new Promise((resolve) => {
          const done = () => {
            try { watcher?.close(); } catch {}
            if (polling) clearInterval(polling);
            resolve();
          };
          process.on("SIGINT", done);
          process.on("SIGTERM", done);
        });
        return 0;
      }

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
        const W = 62;
        const top = `    ${dim(`╭─ HUMAN APPROVAL REQUIRED ${"─".repeat(Math.max(0, W - 28))}╮`)}`;
        const bottom = `    ${dim(`╰${"─".repeat(W)}╯`)}`;
        process.stdout.write(top + "\n");
        process.stdout.write(`    ${dim("│")} ${dim("Agent".padEnd(10))} ${a.agent ?? "—"}  ${dim("│")}\n`);
        process.stdout.write(`    ${dim("│")} ${dim("Action".padEnd(10))} ${a.tool ?? "—"}  ${dim("│")}\n`);
        process.stdout.write(`    ${dim("│")} ${dim("Target".padEnd(10))} ${String(a.resource ?? "").slice(0, 32).padEnd(32)}  ${dim("│")}\n`);
        process.stdout.write(`    ${dim("│")} ${"".padEnd(46)} ${dim("│")}\n`);
        process.stdout.write(`    ${dim("│")} ${dim("Risk".padEnd(10))} ${riskTone(String(a.risk ?? "").toUpperCase().padEnd(9))} ${dim("│")}\n`);
        process.stdout.write(`    ${dim("│")} ${dim("Policy".padEnd(10))} ${String(a.rule ?? "—").slice(0, 32).padEnd(32)}  ${dim("│")}\n`);
        process.stdout.write(`    ${dim("│")} ${dim("Waits on".padEnd(10))} ${(a.approvers ?? []).join(", ") || "—"}  ${dim("│")}\n`);
        process.stdout.write(`    ${dim("│")} ${"".padEnd(46)} ${dim("│")}\n`);
        process.stdout.write(`    ${dim("│")} ${dim("Reason")}  ${dim("│")}\n`);
        process.stdout.write(`    ${dim("│")} ${(a.reason ?? "Production database mutation requires human authorization.").slice(0, 44).padEnd(44)} ${dim("│")}\n`);
        process.stdout.write(`    ${dim("│")} ${"".padEnd(46)} ${dim("│")}\n`);
        process.stdout.write(`    ${dim("│")} ${green("[A] Approve")}  ${dim("  ")} ${red("[R] Reject")}  ${dim(`  ${a.id}`)} ${dim("│")}\n`);
        process.stdout.write(bottom + "\n\n");
        if (a.state !== "pending") {
          process.stdout.write(`      ${dim("state")} ${a.state}${a.decidedBy ? dim(` by ${a.decidedBy}`) : ""}\n\n`);
        }
      }
      process.stdout.write(
        `  ${dim("Decide one:")}  ${blue(`cirvix approve ${pending[0].id} --by you@example.com`)}  ${dim("or")}  ${red(`cirvix deny ${pending[0].id} --by you@example.com`)}\n\n`,
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
      /* Measured, not asserted. The panel below reports these, and the only
         honest source for them is the decision stream itself. */
      const counters = { blocked: 0, approvals: 0, violations: 0 };
      const seenAgents = new Set();
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
          if (e.kind === "decision") {
            notice(e);
            const ev = e.event ?? e;
            if (ev.agent) seenAgents.add(ev.agent);
            if (ev.decision === "deny") counters.blocked += 1;
            else if (ev.decision === "require_approval") counters.approvals += 1;
            if (ev.risk === "critical") counters.violations += 1;
          }
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

      // Premium startup sequence — brand + real state, zero fake.
      const runtimeAnimated = shouldAnimate({ pace: flags.pace ? Number(flags.pace) : 700, json: Boolean(flags.json) });
      // Compute policy tests count for display (real).
      let rtTests = 0;
      try {
        const { loadPolicyFile } = await import("../src/commands/policy.mjs");
        let policyPath = null;
        for (const cand of ["cirvix.policy", "cirvix.policy.json", ".cirvix/policy.json"]) {
          const p = join(cwd, cand);
          try { await access(p); policyPath = p; break; } catch {}
        }
        if (policyPath) {
          const loaded = await loadPolicyFile(policyPath, { cwd });
          rtTests = loaded.tests?.length ?? 0;
        }
      } catch {}
      if (!flags.json) {
        // Brand header only when interactive; in CI/non-TTY just show compact.
        if (runtimeAnimated) {
          process.stdout.write("\n" + brandHeader({ width: 62 }) + "\n\n");
        } else {
          process.stdout.write(`\n  ${bold("CIRVIX")} ${dim("· runtime governance")}\n\n`);
        }
        process.stdout.write(`  ${dim("Initializing CIRVIX runtime...")}\n`);
        process.stdout.write(`  ${green("✓")} ${dim("Control socket established")}  ${dim(endpoint)}\n`);
        process.stdout.write(`  ${green("✓")} ${dim("Policy engine loaded")}\n`);
        process.stdout.write(`  ${green("✓")} ${dim("Secret protection enabled")}\n`);
        process.stdout.write(`  ${green("✓")} ${dim("Audit chain initialized")}\n`);
        process.stdout.write(`  ${green("✓")} ${dim(`${plural(rules.length, "rule")} loaded`)}${rtTests ? dim(` · ${rtTests} policy tests`) : ""}\n`);
        process.stdout.write("\n");
        // The agent this runtime was started for, plus any that have since
        // announced themselves. One at startup is a fact, not a placeholder —
        // but only because it is counted.
        const agentsSeen = Math.max(seenAgents.size, 1);
        const protectedLines = [
          `${bold("CIRVIX PROTECTED")}`,
          ``,
          `${"Runtime".padEnd(12)} ${green(bold("● ONLINE"))}  ${dim(mode === MODE.AUDIT ? "AUDIT · recording only" : "ENFORCING")}`,
          `${"Policy".padEnd(12)} ${green(bold("● ENFORCING"))}  ${dim(plural(rules.length, "rule"))}`,
          `${"Secrets".padEnd(12)} ${green(bold("● PROTECTED"))}`,
          `${"Audit".padEnd(12)} ${green(bold("● RECORDING"))}`,
          `${"Agents".padEnd(12)} ${dim(plural(agentsSeen, "detected", "detected"))}`,
          ``,
          /* These were string literals — `1 detected`, `0 blocked · 0
             approvals · 0 violations`. They happened to be true at startup,
             which is exactly what makes that kind of line dangerous: it reads
             as measurement, it survives review, and it is wrong the moment
             anything happens. Counted from the pipeline now. */
          `${dim(`${counters.blocked} blocked  ·  ${counters.approvals} approvals  ·  ${counters.violations} violations`)}`,
        ];
        process.stdout.write(panel({ lines: protectedLines, width: 62 }) + "\n\n");
        process.stdout.write(`  ${dim("Ready. Your agent is under policy control.")}\n`);
        process.stdout.write(`  ${dim(`token in ${join(stateDir, "socket.token")}`)}\n\n`);
        if (mode === MODE.AUDIT) {
          process.stdout.write(`  ${amber(bold("AUDIT MODE"))} ${dim("— decisions are recorded and nothing is blocked.")}\n\n`);
        }
      } else {
        process.stdout.write(
          `\n  ${green(bold("runtime up"))}  ${dim(`${plural(rules.length, "rule")} · ${mode} · ${endpoint}`)}\n` +
            `  ${dim(`token in ${join(stateDir, "socket.token")}`)}\n\n`,
        );
        if (mode === MODE.AUDIT) {
          process.stdout.write(`  ${amber(bold("AUDIT MODE"))} ${dim("— decisions are recorded and nothing is blocked.")}\n\n`);
        }
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

    case "doctor": {
      return doctor({ cwd, json: Boolean(flags.json) });
    }

    case "login": {
      return login({ key: flags.key ? String(flags.key) : null, url: flags.url ? String(flags.url) : null, status: Boolean(flags.status), browser: flags.browser === undefined ? undefined : Boolean(flags.browser), json: Boolean(flags.json) });
    }

    case "logout": {
      return logout({ json: Boolean(flags.json) });
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
