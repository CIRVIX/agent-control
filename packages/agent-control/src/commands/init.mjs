/**
 * `cirvix init` — from nothing to protected, in one command.
 *
 *   ✓ Cirvix runtime installed
 *   ✓ MCP servers detected          6 servers across 2 runtimes
 *   ✓ Agent configuration detected  Claude Code, Cursor
 *   ✓ Security policy initialized   cirvix.policy · 17 rules
 *   ✓ Secret protection enabled     4 credential sources vaulted
 *   ✓ Audit logging enabled         .cirvix/audit.jsonl
 *
 *   Cirvix is protecting your agent.
 *
 * WHAT IT WILL AND WILL NOT TOUCH
 *
 * `init` writes inside the workspace and nowhere else: a `.cirvix/` state
 * directory and a `cirvix.policy` file. It does NOT edit the user's editor
 * configuration, because rewriting `~/.cursor/mcp.json` on their behalf is
 * precisely the kind of unrequested action this product exists to prevent an
 * agent from taking. The command that would do it prints the exact change for
 * the operator to apply, and `--wire` performs it only when they ask.
 *
 * `init` is also idempotent and never destructive. An existing policy file is
 * kept, reported as kept, and never overwritten — the second run of a setup
 * command must not silently discard the rules somebody wrote after the first.
 */

import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import {
  collectMcpServers,
  detectCredentials,
  detectFrameworks,
  detectRuntimes,
} from "../core/detect.mjs";
import { compile } from "../core/policy-dsl.mjs";
import { writeToken, defaultEndpoint, tokenPath } from "../core/uds.mjs";
import { UdsClient } from "../core/uds.mjs";
import { bold, dim, green, red, amber, blue, cyan, gray, plural } from "../core/format.mjs";
import { shouldAnimate } from "../core/ui/controller.mjs";
import { brandHeader, panel } from "../core/ui/primitives.mjs";
import { ConfigBackupManager, validateMcpServersMap } from "../core/config-store.mjs";
import { detectFleet, generateFleetPlan } from "../adapters/index.mjs";

const STARTER_POLICY = `# Cirvix policy
#
# Ordered rules, evaluated most-authoritative-first:
#   deny  always wins        — a permit can never punch through it
#   require_approval         — outranks allow; a human decides
#   sanitize                 — outranks allow; the call proceeds, cleaned
#   allow                    — permits
#   audit_only               — records a match, authorizes nothing
#
# Anything no rule permits is denied. That is the point.
#
# Check it:  cirvix policy check
# Test it:   cirvix policy test
# Explain:   cirvix policy explain --tool shell.exec --command "rm -rf /"

# ---------------------------------------------------------------- prohibited

deny:
  name = deny-credential-files
  tool = filesystem.read
  path = **/.env
  reason = "Reading .env is the shortest path from a prompt injection to a live credential."
  remediation = "Request the value as a handle: secrets.get(\\"NAME\\")"

# .env.production and friends hold the credentials that matter most, and the
# pattern above does not cover them: a glob ending in ".env" does not match
# ".env.production". The adversarial corpus caught this as a live bypass.
#
# The variants are named individually rather than matched with a wildcard.
# ".env.example", ".env.sample", and ".env.template" are committed to source
# control by design, hold placeholder values, and are read constantly during
# setup — denying them is the kind of false positive that gets a security tool
# switched off. A deny always wins, so an exemption cannot be expressed as an
# allow; it has to be expressed as a narrower deny.
deny:
  name = deny-dotenv-production
  tool = filesystem.read
  path = **/.env.production
  reason = "Production credentials."
  remediation = "Request the value as a handle: secrets.get(\\"NAME\\")"

deny:
  name = deny-dotenv-local
  tool = filesystem.read
  path = **/.env.local
  reason = "Local credentials, which are real credentials."

deny:
  name = deny-dotenv-development
  tool = filesystem.read
  path = **/.env.development
  reason = "Development credentials are still credentials."

deny:
  name = deny-dotenv-staging
  tool = filesystem.read
  path = **/.env.staging
  reason = "Staging credentials are still credentials."

deny:
  name = deny-dotenv-test-env
  tool = filesystem.read
  path = **/.env.test
  reason = "Test environments hold real keys more often than anyone admits."

deny:
  name = deny-credential-directories
  tool = filesystem.read
  path = **/.aws/**
  reason = "Cloud credentials are never readable by an agent."

deny:
  name = deny-ssh-keys
  tool = filesystem.read
  path = **/.ssh/**
  reason = "SSH private keys are never readable by an agent."

deny:
  name = deny-cloud-metadata
  network.destination = 169.254.169.254
  reason = "The cloud instance-metadata endpoint returns live role credentials to anything that can reach it."

deny:
  name = deny-metadata-hostname
  network.destination = metadata.google.internal
  reason = "Cloud metadata by hostname resolves to the same link-local address."

# The rest of the metadata endpoints. Every cloud has one, and a policy that
# blocks only AWS's leaves the same attack working on three other providers —
# which the generated corpus demonstrated by simply trying them.
deny:
  name = deny-metadata-goog-short
  network.destination = metadata.goog
  reason = "The short form of the Google metadata endpoint."

deny:
  name = deny-metadata-alibaba
  network.destination = 100.100.100.200
  reason = "The same instance-metadata attack, on Alibaba Cloud."

deny:
  name = deny-metadata-ecs-task
  network.destination = 169.254.170.2
  reason = "ECS task metadata returns the task role's credentials."

deny:
  name = deny-link-local
  network.destination = 169.254.
  reason = "The whole link-local range exists for host-local services that were never designed to authenticate."

deny:
  name = deny-destructive-shell
  tool = shell.exec
  command = "rm -rf"
  reason = "Recursive force-delete destroys state rather than changing it."

# The blanket rule, and the most important line in this file.
#
# Anything the risk engine calls CRITICAL — remote code execution, disk
# overwrite, privilege escalation, force-push, DROP TABLE, history wipe,
# reading a credential through a shell — is denied outright rather than held.
# Without this, each of those needed its own named rule, and the corpus found
# six that had none.
deny:
  name = deny-critical-shell
  tool = shell.exec
  risk >= CRITICAL
  reason = "A CRITICAL command must be permitted by a rule that names it, never held for a rubber stamp."
  remediation = "If this specific command is intended, add an explicit allow rule naming it."

deny:
  name = deny-remote-code-execution
  tool = shell.exec
  command = "curl"
  risk >= CRITICAL
  reason = "Downloading code and executing it in one step means nothing inspects it in between."

deny:
  name = deny-workspace-escape
  tool = filesystem.write
  workspace = false
  reason = "Writes outside the workspace root are outside what this run was scoped to change."

# An agent may reach the network. It may not put a credential in the request.
# This is the rule that turns "read the secret, then post it somewhere" from two
# individually-plausible calls into a blocked one.
deny:
  name = deny-egress-carrying-secrets
  tool = network.request
  secrets >= 1
  reason = "This request carries credential material. Send a scoped handle instead — the broker substitutes it on the wire and the value never enters the model's context."
  remediation = "secrets.get(\\"NAME\\") returns a handle. Pass the handle where you would have passed the key."

deny:
  name = deny-egress-after-secret-read
  tool = network.request
  touched_secret = true
  reason = "This session read secret-shaped material, so outbound requests are blocked for the remainder of it."

deny:
  name = deny-write-ci-config
  tool = filesystem.write
  path = ./.github/workflows/**
  reason = "A workflow file is code that runs in CI with CI's credentials, reviewed by nobody before it runs."

deny:
  name = deny-write-git-internals
  tool = filesystem.write
  path = ./.git/**
  reason = "Writing into .git rewrites history without a commit, so nothing in the log reflects the change."

# ------------------------------------------------------------------ approval
#
# An agent that can rewrite its own instructions, its own tool list, or its own
# policy is not governed by any of them. Held rather than denied, because
# changing them is legitimate — with a person watching.

require_approval:
  name = approve-policy-change
  tool = filesystem.write
  path = ./cirvix.policy
  approvers = platform-oncall
  reason = "This is the policy governing the agent. An agent that can edit it is not governed by it."

require_approval:
  name = approve-mcp-config-change
  tool = filesystem.write
  path = ./.mcp.json
  approvers = developer
  reason = "This file decides which tools the agent can reach at all."

require_approval:
  name = approve-agent-instructions-change
  tool = filesystem.write
  path = ./CLAUDE.md
  approvers = developer
  reason = "This file instructs the agent. Changing it changes what future runs believe they were told."

require_approval:
  name = approve-agents-md-change
  tool = filesystem.write
  path = ./AGENTS.md
  approvers = developer
  reason = "This file instructs the agent."

require_approval:
  name = approve-claude-dir-change
  tool = filesystem.write
  path = ./.claude/**
  approvers = developer
  reason = "Agent configuration. Changing it changes what future runs are allowed to do."

require_approval:
  name = approve-cursorrules-change
  tool = filesystem.write
  path = ./.cursorrules
  approvers = developer
  reason = "Cursor instructions. Changing it changes what future runs believe they were told."

require_approval:
  name = approve-cursor-dir-change
  tool = filesystem.write
  path = ./.cursor/**
  approvers = developer
  reason = "Cursor agent configuration."

require_approval:
  name = approve-windsurfrules-change
  tool = filesystem.write
  path = ./.windsurfrules
  approvers = developer
  reason = "Windsurf instructions. Changing it changes what future runs believe they were told."

require_approval:
  name = approve-codeium-dir-change
  tool = filesystem.write
  path = ./.codeium/**
  approvers = developer
  reason = "Windsurf agent configuration."

require_approval:
  name = approve-clinerules-change
  tool = filesystem.write
  path = ./.clinerules
  approvers = developer
  reason = "Cline instructions. Changing it changes what future runs believe they were told."

require_approval:
  name = approve-roomodes-change
  tool = filesystem.write
  path = ./.roomodes
  approvers = developer
  reason = "Roo Code agent configuration."

require_approval:
  name = approve-codex-config-change
  tool = filesystem.write
  path = ./codex.json
  approvers = developer
  reason = "Codex agent configuration."

require_approval:
  name = approve-gemini-config-change
  tool = filesystem.write
  path = ./gemini.json
  approvers = developer
  reason = "Gemini agent configuration."

require_approval:
  name = approve-database-write
  tool = database.write
  approvers = platform-oncall
  reason = "Mutates persistent state that other systems read."

require_approval:
  name = approve-high-risk-shell
  tool = shell.exec
  risk >= HIGH
  approvers = platform-oncall
  reason = "Arbitrary command execution reaches past every per-tool rule."

require_approval:
  name = approve-production-deploy
  tool = deploy.apply
  env = production
  approvers = platform-oncall
  reason = "Changes what is serving live traffic."

# ----------------------------------------------------------------- sanitize

sanitize:
  name = sanitize-fetched-content
  tool = network.request
  targets = result
  reason = "Fetched content is data. Instructions inside it are not addressed to the model."

# -------------------------------------------------------------------- allow

allow:
  name = allow-version-control-read
  tool = git.status

allow:
  name = allow-git-log
  tool = git.log

allow:
  name = allow-git-diff
  tool = git.diff

allow:
  name = allow-git-branch
  tool = git.branch

allow:
  name = allow-workspace-read
  tool = filesystem.read
  workspace = true

allow:
  name = allow-workspace-list
  tool = filesystem.list
  workspace = true

allow:
  name = allow-workspace-search
  tool = filesystem.search
  workspace = true

allow:
  name = allow-workspace-write
  tool = filesystem.write
  workspace = true

allow:
  name = allow-shell-low-risk
  tool = shell.exec
  risk <= MEDIUM

allow:
  name = allow-database-read
  tool = database.query

# Outbound requests are permitted and their results are sanitized on the way
# back. What stops exfiltration is not blocking the network — it is the two
# deny rules above, which forbid a request that carries a secret and any
# request at all once the session has touched one.
allow:
  name = allow-network-request
  tool = network.request

# ---------------------------------------------------------------- test cases
#
# These run under \`cirvix policy test\`. A policy file that ships its own tests
# is one an operator can change safely.

test "a workspace file is readable":
  tool = filesystem.read
  path = ./src/app.ts
  expect allow

test "dotenv is not readable":
  tool = filesystem.read
  path = .env
  expect deny

test "aws credentials are not readable":
  tool = filesystem.read
  path = ~/.aws/credentials
  expect deny

test "cloud metadata is unreachable":
  tool = network.request
  url = http://169.254.169.254/latest/meta-data/
  expect deny

test "recursive delete is denied":
  tool = shell.exec
  command = rm -rf /
  expect deny

test "running tests is allowed":
  tool = shell.exec
  command = npm test
  expect allow

test "git status is allowed":
  tool = git.status
  expect allow

test "a database write waits for a human":
  tool = database.write
  expect require_approval

test "fetching a page is allowed, and sanitized":
  tool = network.request
  url = https://docs.example.com/guide
  expect sanitize

test "writing outside the workspace is denied":
  tool = filesystem.write
  path = /etc/hosts
  expect deny

test "cursor rules modification requires approval":
  tool = filesystem.write
  path = ./.cursorrules
  expect require_approval

test "cline rules modification requires approval":
  tool = filesystem.write
  path = ./.clinerules
  expect require_approval
`;

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function probeRuntime(stateDir) {
  const endpoint = defaultEndpoint(stateDir);
  try {
    await access(tokenPath(stateDir));
  } catch {
    return { running: false, endpoint, reason: "no session token" };
  }
  let token;
  try {
    token = (await readFile(tokenPath(stateDir), "utf8")).trim();
  } catch {
    return { running: false, endpoint, reason: "unreadable session token" };
  }
  try {
    const client = new UdsClient({ endpoint, token, timeoutMs: 1200 });
    const status = await client.call("cirvix/status", {});
    return { running: true, endpoint, live: status };
  } catch {
    return { running: false, endpoint, reason: "nothing listening" };
  }
}

/**
 * @param {object} opts
 * @param {string} opts.cwd
 * @param {boolean} [opts.json]
 * @param {boolean} [opts.force]     overwrite an existing policy file
 * @param {boolean} [opts.apply]     apply integration plans to detected agents
 * @param {boolean} [opts.dryRun]    preview integration plans without modifying files
 * @param {boolean|string} [opts.rollback] rollback to previous configuration
 * @param {number} [opts.pace]       animation pace; 0 disables
 * @returns {Promise<{result:object, output:string}>}
 */
export async function init({
  cwd = process.cwd(),
  json = false,
  force = false,
  apply = false,
  dryRun = false,
  rollback = false,
  pace,
} = {}) {
  const stateDir = join(cwd, ".cirvix");
  const policyPath = join(cwd, "cirvix.policy");

  if (dryRun) {
    if (apply || force || rollback) {
      const result = { ok: false, error: "--dry-run cannot be combined with --apply, --force, or --rollback." };
      return { result, output: json ? JSON.stringify(result) : result.error };
    }
    const plans = await generateFleetPlan(cwd, { stateDir });
    const result = {
      ok: true,
      dryRun: true,
      fleetPlans: plans.map(({ adapterId, targetFile, canIntegrate }) => ({ adapterId, targetFile, canIntegrate })),
    };
    return { result, output: json ? JSON.stringify(result, null, 2) : `Integration preview: ${plans.length} plans. No files modified.` };
  }

  /* ------------------------------------------------------------ 0. rollback */
  if (rollback) {
    const backupManager = new ConfigBackupManager({ stateDir });
    try {
      const backupId = typeof rollback === "string" ? rollback : null;
      const res = await backupManager.rollback(backupId);
      const safe = {
        ok: true,
        action: "rollback",
        backupId: res.backupId,
        restored: res.restored,
        removed: res.removed,
      };
      const output = json
        ? JSON.stringify(safe, null, 2)
        : [
            "",
            `  ${green(bold("✓ Configuration rolled back successfully"))}`,
            `  ${dim("Backup ID:")} ${res.backupId}`,
            `  ${dim("Restored:")}  ${res.restored.length ? res.restored.join(", ") : "none"}`,
            `  ${dim("Removed:")}   ${res.removed.length ? res.removed.join(", ") : "none"}`,
            "",
          ].join("\n");
      return { result: safe, output };
    } catch (err) {
      const safe = { ok: false, action: "rollback", error: err.message };
      const output = json
        ? JSON.stringify(safe, null, 2)
        : `\n  ${red(bold("✗ Rollback failed:"))} ${err.message}\n`;
      return { result: safe, output };
    }
  }

  const steps = [];

  /* ------------------------------------------------------------ 1. runtime */
  await mkdir(stateDir, { recursive: true });
  const token = await exists(tokenPath(stateDir))
    ? (await readFile(tokenPath(stateDir), "utf8")).trim()
    : await writeToken(stateDir);
  const endpoint = defaultEndpoint(stateDir);
  steps.push({
    id: "runtime",
    label: "Cirvix runtime installed",
    ok: true,
    detail: `state in ./.cirvix · control socket ${endpoint}`,
  });

  /* -------------------------------------------------------- 2. MCP servers */
  let fleet = await detectFleet(cwd, { stateDir });
  let runtimes = fleet.runtimes;
  const servers = fleet.mcpServers;
  steps.push({
    id: "mcp",
    label: "MCP servers detected",
    ok: servers.length > 0,
    detail: servers.length
      ? `${plural(servers.length, "server")} across ${plural(runtimes.length, "runtime")}`
      : "none found — the gateway will govern whatever you point it at",
  });

  /* ------------------------------------------------------------- 3. agents */
  const frameworks = fleet.frameworks?.length ? fleet.frameworks : await detectFrameworks(cwd);
  const agentNames = [...runtimes.map((r) => r.label), ...frameworks.map((f) => f.label)];
  steps.push({
    id: "agents",
    label: "Agent configuration detected",
    ok: agentNames.length > 0,
    detail: agentNames.length ? agentNames.join(", ") : "none found in this workspace",
  });

  /* ------------------------------------------------------------- 4. policy */
  const policyExisted = await exists(policyPath);
  if (!policyExisted || force) {
    await writeFile(policyPath, STARTER_POLICY, "utf8");
  }
  const source = await readFile(policyPath, "utf8");
  let ruleCount = 0;
  let testCount = 0;
  let policyError = null;
  try {
    const compiled = compile(source, { cwd, origin: "cirvix.policy" });
    ruleCount = compiled.rules.length;
    testCount = compiled.tests.length;
  } catch (err) {
    policyError = err.message;
  }
  steps.push({
    id: "policy",
    label: "Security policy initialized",
    ok: !policyError,
    detail: policyError
      ? policyError
      : `cirvix.policy · ${plural(ruleCount, "rule")}, ${plural(testCount, "test")}` +
        (policyExisted && !force ? " (existing file kept)" : ""),
  });

  /* ------------------------------------------------------------ 5. secrets */
  const credentials = await detectCredentials(cwd);
  steps.push({
    id: "secrets",
    label: "Secret protection enabled",
    ok: true,
    detail: credentials.length
      ? `${plural(credentials.length, "credential source")} found and covered by deny rules; run \`cirvix vault load\` to broker them as handles`
      : "no credential files in this workspace; detection is active on every call",
  });

  /* -------------------------------------------------------------- 6. audit */
  const auditPath = join(stateDir, "audit.jsonl");
  if (!(await exists(auditPath))) await writeFile(auditPath, "", "utf8");
  steps.push({
    id: "audit",
    label: "Audit logging enabled",
    ok: true,
    detail: ".cirvix/audit.jsonl · hash-chained, verify with `cirvix audit verify`",
  });

  /* --------------------------------------------------- 7. fleet integration */
  const fleetPlans = await generateFleetPlan(cwd, { stateDir });
  const unintegratedPlans = fleetPlans.filter((p) => {
    const rt = runtimes.find((r) => r.id === p.adapterId);
    return rt && !rt.isIntegrated && p.canIntegrate;
  });

  let integrationBackup = null;
  let appliedCount = 0;

  if (apply && unintegratedPlans.length > 0) {
    const backupManager = new ConfigBackupManager({ stateDir });
    const targetFiles = unintegratedPlans.map((p) => p.targetFile);
    integrationBackup = await backupManager.createBackup(targetFiles, "cirvix init --apply");

    for (const plan of unintegratedPlans) {
      const targetPath = plan.targetFile;
      await mkdir(dirname(targetPath), { recursive: true });
      await writeFile(targetPath, JSON.stringify(plan.plan, null, 2), "utf8");
      appliedCount++;
    }

    // Refresh detection after integration
    fleet = await detectFleet(cwd, { stateDir });
    runtimes = fleet.runtimes;

    steps.push({
      id: "integration",
      label: "Fleet integration applied",
      ok: true,
      detail: `${plural(appliedCount, "agent")} wired into CIRVIX · backup ${integrationBackup.backupId}`,
    });
  } else if (dryRun) {
    steps.push({
      id: "integration",
      label: "Fleet integration (dry run)",
      ok: true,
      detail: `${plural(unintegratedPlans.length, "agent")} ready to wire (no files modified)`,
    });
  } else {
    steps.push({
      id: "integration",
      label: "Fleet integration plan",
      ok: true,
      detail: unintegratedPlans.length
        ? `${plural(unintegratedPlans.length, "agent")} ready for automatic integration (use --apply)`
        : "no safe automatic integration available; verify gateway-only routing manually",
    });
  }

  // Probe whether a runtime is actually reachable.
  const runtimeProbe = await probeRuntime(stateDir);

  const result = {
    ok: steps.every((s) => s.ok || s.id === "mcp" || s.id === "agents" || s.id === "integration"),
    cwd,
    stateDir,
    policyPath,
    endpoint,
    tokenPath: join(stateDir, "socket.token"),
    rules: ruleCount,
    tests: testCount,
    mcpServers: servers.length,
    runtimes: runtimes.map((r) => ({
      id: r.id,
      label: r.label,
      governed: r.governed,
      compatibilityLevel: r.compatibilityLevel,
      path: r.path,
    })),
    credentials: credentials.length,
    steps,
    runtime: runtimeProbe,
    fleetPlans: unintegratedPlans.map((p) => ({
      adapterId: p.adapterId,
      label: p.label,
      targetFile: p.targetFile,
      snippet: p.snippet,
    })),
    appliedCount,
    backupId: integrationBackup?.backupId ?? null,
    // Never printed, never logged — returned so a caller that just created the
    // session can use it without reading the file back.
    token,
  };

  if (json) {
    const { token: _hidden, ...safe } = result;
    return { result: safe, output: JSON.stringify(safe, null, 2) };
  }
  return {
    result,
    output: render(result, { runtimes, runtimeProbe, appliedCount, backupId: integrationBackup?.backupId, dryRun }),
  };
}

/* -------------------------------------------------------------------------- */

function render(result, { runtimes, runtimeProbe, appliedCount = 0, backupId = null, dryRun = false }) {
  const lines = [];
  lines.push("");
  lines.push(brandHeader({ width: 62 }));
  lines.push("");

  // Initialization steps — premium checkmarks, real data.
  lines.push(`  ${dim("Initializing CIRVIX runtime...")}`);
  const width = Math.max(...result.steps.map((s) => s.label.length));
  for (const step of result.steps) {
    const tick = step.ok ? green("✓") : amber("○");
    lines.push(`  ${tick} ${step.label.padEnd(width)}   ${dim(step.detail)}`);
  }
  lines.push("");

  // Protected panel
  const isOnline = Boolean(runtimeProbe?.running);
  const runtimeLabel = isOnline ? green(bold("● ONLINE")) : cyan(bold("● CONFIGURED"));
  const runtimeDetail = isOnline ? dim("control socket reachable") : dim("state configured — start runtime to go ONLINE");
  const policyDetail = `${result.rules} rules loaded`;
  const testsDetail = `${result.tests} policy tests`;
  const secretsDetail = result.credentials ? `${result.credentials} credential sources` : "active";

  const panelLines = [
    `${bold("CIRVIX CONFIGURATION")}`,
    ``,
    `${"Runtime".padEnd(12)} ${runtimeLabel}  ${runtimeDetail}`,
    `${"Policy".padEnd(12)} ${result.ok ? cyan("CONFIGURED") : red("INVALID")}  ${dim(policyDetail)}`,
    `${"Secrets".padEnd(12)} ${cyan("DETECTED")}  ${dim(secretsDetail)}`,
    `${"Audit".padEnd(12)} ${cyan("CONFIGURED")}  ${dim(".cirvix/audit.jsonl")}`,
    `${"Agents".padEnd(12)} ${String(runtimes.length)} detected`,
  ];

  if (runtimes.length > 0) {
    panelLines.push(``);
    for (const rt of runtimes) {
      const badge = rt.governed ? green(bold("● " + (rt.compatibilityLevel ?? "INTEGRATED"))) : amber("○ " + (rt.compatibilityLevel ?? "CONFIGURABLE"));
      panelLines.push(`  ${rt.label.padEnd(16)} ${badge}`);
    }
  }

  panelLines.push(``);
  panelLines.push(dim("Configuration is not evidence of executed tool calls."));

  lines.push(panel({ lines: panelLines, width: 62 }));
  lines.push("");

  if (appliedCount > 0) {
    lines.push(`  ${green(bold(`✓ Successfully wired ${appliedCount} agent(s) into CIRVIX gateway.`))}`);
    if (backupId) {
      lines.push(`  ${dim(`Safe backup saved as: ${backupId}`)}`);
      lines.push(`  ${dim("To undo this change at any time, run:")} ${blue("cirvix init --rollback")}`);
    }
    lines.push("");
  } else {
    lines.push(`  ${dim("Start the runtime or gateway and verify a routed tool call before relying on enforcement.")}`);
    lines.push("");
  }

  // Integration guidance
  const ungoverned = runtimes.filter((r) => !r.governed);
  if (ungoverned.length && !appliedCount) {
    const warnLines = [
      `${amber(bold("⚠ INTEGRATION ACTION AVAILABLE"))}`,
      ``,
      `${plural(ungoverned.length, "agent")} detected but not yet routed through`,
      `the CIRVIX gateway:`,
      ``,
      ...ungoverned.map((u) => `  • ${u.label} (${u.compatibilityLevel ?? "CONFIGURABLE"})`),
      ``,
      `Automatic non-destructive integration:`,
      `  ${blue("cirvix init --apply")}       ${dim("(creates pre-modification backup)")}`,
      `  ${blue("cirvix init --dry-run")}     ${dim("(preview configuration without writing)")}`,
      `  ${blue("cirvix init --rollback")}    ${dim("(revert to pre-integration state)")}`,
      ``,
      `Or manually run:`,
      `  ${blue(`cirvix gateway --servers ${ungoverned[0].path}`)}`,
    ];
    lines.push(panel({ lines: warnLines, width: 62, heavy: true }));
    lines.push("");
  }

  lines.push(`  ${dim("Next")}`);
  lines.push(`    ${blue("cirvix policy test")}    ${dim("run the policy's own test cases")}`);
  lines.push(`    ${blue("cirvix scan")}           ${dim("full inventory of runtimes, MCP servers & secrets")}`);
  lines.push(`    ${blue("cirvix demo")}           ${dim("watch an injected exfiltration attempt get stopped")}`);
  lines.push(`    ${blue("cirvix status")}         ${dim("what is protected right now")}`);
  lines.push("");

  return lines.join("\n");
}

export { STARTER_POLICY };
