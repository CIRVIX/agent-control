import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { renderAuthPreviewCard, consolePreview } from "../src/commands/console.mjs";
import { stripAnsi, visibleWidth } from "../src/core/format.mjs";

const exec = promisify(execFile);
const cli = fileURLToPath(new URL("../bin/cirvix.mjs", import.meta.url));

async function workspace(t) {
  const cwd = await mkdtemp(join(tmpdir(), "cirvix-ux-test-"));
  t.after(() => rm(cwd, { recursive: true, force: true }));
  return cwd;
}

async function runCli(cwd, args, extraEnv = {}) {
  const env = { ...process.env, HOME: cwd, USERPROFILE: cwd, CI: "1", ...extraEnv };
  delete env.CIRVIX_API_URL;
  delete env.CIRVIX_API_KEY;
  try {
    return { ...(await exec(process.execPath, [cli, ...args], { cwd, env, timeout: 20000 })), code: 0 };
  } catch (error) {
    if (typeof error.code !== "number") throw error;
    return { stdout: error.stdout, stderr: error.stderr, code: error.code };
  }
}

test("authorization preview: DENY card renders rule, risk, reason, remediation and preview notice", () => {
  const card = renderAuthPreviewCard({
    tool: "fs.read",
    resource: ".env.production",
    agent: "local",
    decision: {
      verdict: "deny",
      rule: "deny-dotenv-read",
      risk: "high",
      reason: "Reading .env files is denied outside an approved secrets flow.",
    },
    width: 60,
  });

  const plain = stripAnsi(card);
  assert.match(plain, /DENY/);
  assert.match(plain, /deny-dotenv-read/);
  assert.match(plain, /HIGH/);
  assert.match(plain, /Reading \.env files is denied/);
  assert.match(plain, /Suggested path/);
  assert.match(plain, /secrets\.get\("STRIPE_KEY"\)/);
  assert.match(plain, /Preview only — nothing executed, nothing recorded/);
  assert.match(plain, /fs\.read/);
  assert.match(plain, /\.env\.production/);
});

test("authorization preview: ALLOW card renders cleanly with green badge and low risk", () => {
  const card = renderAuthPreviewCard({
    tool: "read_file",
    resource: "README.md",
    agent: "local",
    decision: {
      verdict: "permit",
      rule: "allow-workspace-read",
      risk: "low",
      reason: "Read inside workspace root.",
    },
    width: 60,
  });

  const plain = stripAnsi(card);
  assert.match(plain, /ALLOW/);
  assert.match(plain, /allow-workspace-read/);
  assert.match(plain, /LOW/);
  assert.match(plain, /Read inside workspace root/);
  assert.match(plain, /Preview only/);
});

test("authorization preview: APPROVAL REQUIRED card renders with amber badge", () => {
  const card = renderAuthPreviewCard({
    tool: "shell.exec",
    resource: "deploy.sh",
    agent: "ci-agent",
    decision: {
      verdict: "hold",
      rule: "require-approval-deploy",
      risk: "high",
      reason: "Production deployment requires manual authorization.",
    },
    width: 60,
  });

  const plain = stripAnsi(card);
  assert.match(plain, /APPROVAL REQUIRED/);
  assert.match(plain, /require-approval-deploy/);
  assert.match(plain, /HIGH/);
  assert.match(plain, /cirvix approvals --review/);
});

test("authorization preview: responsive to narrow terminals without horizontal blowout", () => {
  const cardNarrow = renderAuthPreviewCard({
    tool: "fs.read",
    resource: ".env.production",
    agent: "local",
    decision: {
      verdict: "deny",
      rule: "deny-dotenv-read",
      risk: "high",
      reason: "Reading .env files is denied outside an approved secrets flow.",
    },
    width: 48,
  });

  const lines = cardNarrow.split("\n");
  for (const line of lines) {
    assert.ok(visibleWidth(line) <= 54, "Line exceeds target width: " + visibleWidth(line) + " > 54: " + line);
  }
});

test("authorization preview: NO_COLOR suppresses all ANSI escape codes", async (t) => {
  const cwd = await workspace(t);
  const result = await runCli(cwd, ["console", "--eval", "fs.read .env.production"], { NO_COLOR: "1" });
  assert.equal(result.code, 0);
  assert.equal(stripAnsi(result.stdout), result.stdout, "Output contains ANSI escapes despite NO_COLOR=1");
  assert.match(result.stdout, /DENY/);
  assert.match(result.stdout, /Preview only/);
});

test("authorization preview: --json emits pure machine-readable JSON", async (t) => {
  const cwd = await workspace(t);
  const result = await runCli(cwd, ["console", "--eval", "fs.read .env.production", "--json"]);
  assert.equal(result.code, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.preview, true);
  assert.equal(parsed.tool, "fs.read");
  assert.equal(parsed.resource, ".env.production");
  assert.equal(parsed.decision.verdict, "deny");
  assert.equal(parsed.decision.rule, "deny-dotenv-read");
});

test("onboarding: first run displays concise product overview, workspace, protection status, and starting actions", async (t) => {
  const cwd = await workspace(t);
  const result = await runCli(cwd, []);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /CIRVIX/);
  assert.match(result.stdout, /Runtime authorization for AI agents/);
  assert.match(result.stdout, /Workspace:/);
  assert.match(result.stdout, /Protection:\s+NOT ACTIVE/);
  assert.match(result.stdout, /GET STARTED/);
  assert.match(result.stdout, /1\s+cirvix init/);
  assert.match(result.stdout, /2\s+cirvix demo/);
  assert.match(result.stdout, /3\s+cirvix console/);
  assert.match(result.stdout, /4\s+cirvix status/);
  assert.match(result.stdout, /5\s+cirvix --help/);
  assert.match(result.stdout, /Help:\s+cirvix --help/);
});

test("help: structured sections are visually grouped and scannable with preview guidance", async (t) => {
  const cwd = await workspace(t);
  const result = await runCli(cwd, ["--help"]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /CIRVIX/);
  assert.match(result.stdout, /USAGE/);
  assert.match(result.stdout, /GET STARTED/);
  assert.match(result.stdout, /PROTECT/);
  assert.match(result.stdout, /POLICY/);
  assert.match(result.stdout, /HISTORY/);
  assert.match(result.stdout, /APPROVALS \/ SECRETS/);
  assert.match(result.stdout, /ADVANCED/);
  assert.match(result.stdout, /OPTIONS/);
  assert.match(result.stdout, /TRY IT \(PREVIEW ONLY\)/);
  assert.match(result.stdout, /cirvix console --eval "fs\.read README\.md"/);
  assert.match(result.stdout, /console --eval previews the authorization decision/);
});

test("authorization preview: --verbose reveals forensic details", async (t) => {
  const cwd = await workspace(t);
  const result = await runCli(cwd, ["console", "--eval", "fs.read .env.production", "--verbose"]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /FORENSIC DETAILS/);
  assert.match(result.stdout, /Identity:\s+local/);
  assert.match(result.stdout, /Tool:\s+fs\.read/);
  assert.match(result.stdout, /Rule ID:\s+deny-dotenv-read/);
  assert.match(result.stdout, /Execution:\s+preview \(unexecuted\)/);
});

test("demo: runs concisely and ends with unmistakable DEMO COMPLETE summary", async (t) => {
  const cwd = await workspace(t);
  const result = await runCli(cwd, ["demo", "--fast"]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /ACT I\s+Untrusted content reaches the agent/);
  assert.match(result.stdout, /Prompt injection detected/);
  assert.match(result.stdout, /ACT II\s+Cirvix evaluates the resulting actions/);
  assert.match(result.stdout, /CONTENT SANITIZED/);
  assert.match(result.stdout, /BLOCKED — Credential access/);
  assert.match(result.stdout, /ACT III\s+Legitimate work continues normally/);
  assert.match(result.stdout, /DEMO COMPLETE/);
  assert.match(result.stdout, /Dangerous actions stopped:/);
  assert.match(result.stdout, /Legitimate work:/);
  assert.match(result.stdout, /No dangerous action was executed/);
  assert.match(result.stdout, /Audit Trail:/);
});

test("demo: --verbose reveals raw attack payload and telemetry", async (t) => {
  const cwd = await workspace(t);
  const result = await runCli(cwd, ["demo", "--fast", "--verbose"]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /Full raw fetched page:/);
  assert.match(result.stdout, /Telemetry:\s+P50/);
});

test("eval: fs.read README.md is ALLOWED inside workspace root", async (t) => {
  const cwd = await workspace(t);
  const result = await runCli(cwd, ["console", "--eval", "fs.read README.md"]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /ALLOW/);
  assert.match(result.stdout, /allow-workspace-read/);
  assert.match(result.stdout, /Safe to execute/);
  assert.match(result.stdout, /Preview only — nothing executed, nothing recorded/);
});

test("eval: fs.read .env.production is BLOCKED even inside workspace", async (t) => {
  const cwd = await workspace(t);
  const result = await runCli(cwd, ["console", "--eval", "fs.read .env.production"]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /BLOCKED \(DENY\)/);
  assert.match(result.stdout, /deny-dotenv-read/);
  assert.match(result.stdout, /No action was executed/);
});

test("bare cirvix in initialized directory still renders home screen and does not force TUI", async (t) => {
  const cwd = await workspace(t);
  // Create .cirvix state directory
  const { mkdir } = await import("node:fs/promises");
  await mkdir(join(cwd, ".cirvix"), { recursive: true });
  const result = await runCli(cwd, []);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /CIRVIX/);
  assert.match(result.stdout, /GET STARTED/);
  assert.match(result.stdout, /3\s+cirvix console/);
});
