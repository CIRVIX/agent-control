import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { toSarif } from "../src/commands/sarif.mjs";

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const REPORTER = join(HERE, "..", "action", "report.mjs");

const RESULT = {
  scannedAt: "2026-08-07T00:00:00.000Z",
  cwd: "/repo",
  findings: [
    {
      severity: "high",
      code: "runtime-ungoverned",
      subject: "Claude Code",
      detail: "Tool calls are not routed through a control plane.",
      fix: "cirvix gateway --servers ~/.claude/settings.json",
    },
    {
      severity: "high",
      code: "env-readable",
      subject: ".env.production",
      detail: "4 secret-shaped keys readable from agent context.",
      fix: "cirvix gateway --servers ~/.claude/settings.json",
      path: "/repo/.env.production",
    },
    {
      severity: "medium",
      code: "server-inline-secrets",
      subject: "github-mcp",
      detail: "Configuration carries 2 environment values inline.",
      fix: "cirvix gateway --servers ~/.claude/settings.json",
    },
    {
      severity: "low",
      code: "server-duplicated",
      subject: "filesystem-mcp",
      detail: "Configured separately in Claude Code and Cursor.",
      fix: "cirvix gateway --servers ~/.claude/settings.json",
    },
  ],
  counts: { high: 2, medium: 1, low: 1 },
};

/* -------------------------------------------------------------------------- */
/*  SARIF                                                                      */
/* -------------------------------------------------------------------------- */

test("the SARIF log has the shape code scanning requires", () => {
  const sarif = toSarif(RESULT, { root: "/repo" });

  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].tool.driver.name, "Cirvix AgentControl");
  assert.equal(sarif.runs[0].results.length, 4);

  // One rule per code, not per result — a rule per finding makes GitHub's
  // rule filter useless.
  const ruleIds = sarif.runs[0].tool.driver.rules.map((r) => r.id).sort();
  assert.deepEqual(ruleIds, [
    "env-readable",
    "runtime-ungoverned",
    "server-duplicated",
    "server-inline-secrets",
  ]);

  // GitHub sorts and filters on security-severity and shows nothing useful
  // without it.
  for (const rule of sarif.runs[0].tool.driver.rules) {
    assert.ok(rule.properties["security-severity"], `${rule.id} has no security-severity`);
    assert.ok(rule.help.text.length > 20, `${rule.id} has no actionable help`);
  }
});

test("severities map onto the three levels SARIF actually has", () => {
  const results = toSarif(RESULT, { root: "/repo" }).runs[0].results;
  assert.equal(results.find((r) => r.ruleId === "runtime-ungoverned").level, "error");
  assert.equal(results.find((r) => r.ruleId === "server-inline-secrets").level, "warning");
  assert.equal(results.find((r) => r.ruleId === "server-duplicated").level, "note");
});

test("fingerprints are stable, so a dismissal sticks", () => {
  // Without this GitHub treats every scan as fresh findings, and anything a
  // human triaged reappears on the next push until the feature is noise.
  const first = toSarif(RESULT, { root: "/repo" });
  const second = toSarif({ ...RESULT, scannedAt: "2026-09-09T00:00:00.000Z" }, { root: "/repo" });
  assert.deepEqual(
    first.runs[0].results.map((r) => r.partialFingerprints.cirvixFindingV1),
    second.runs[0].results.map((r) => r.partialFingerprints.cirvixFindingV1),
  );

  // Rewording a detail must not resurrect a dismissed finding.
  const reworded = toSarif(
    {
      ...RESULT,
      findings: RESULT.findings.map((f) => ({ ...f, detail: `${f.detail} (rephrased)` })),
    },
    { root: "/repo" },
  );
  assert.deepEqual(
    first.runs[0].results.map((r) => r.partialFingerprints.cirvixFindingV1),
    reworded.runs[0].results.map((r) => r.partialFingerprints.cirvixFindingV1),
  );
});

test("paths are repository-relative, and anything outside falls back to the root", () => {
  // An absolute path from the scanning machine points at nothing on GitHub's
  // side: the upload succeeds and the finding attaches to no file at all.
  const sarif = toSarif(RESULT, { root: "/repo" });
  const inRepo = sarif.runs[0].results.find((r) => r.ruleId === "env-readable");
  assert.equal(inRepo.locations[0].physicalLocation.artifactLocation.uri, ".env.production");

  const outside = toSarif(
    {
      ...RESULT,
      findings: [{ ...RESULT.findings[1], path: "/home/dev/.ssh/id_rsa" }],
    },
    { root: "/repo" },
  );
  assert.equal(outside.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, ".");
});

test("a clean scan produces a valid, empty log rather than nothing", () => {
  const sarif = toSarif({ scannedAt: "2026-08-07T00:00:00.000Z", findings: [], counts: {} });
  assert.equal(sarif.runs[0].results.length, 0);
  assert.deepEqual(sarif.runs[0].tool.driver.rules, []);
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true);
});

test("the CLI writes SARIF where it is told", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-sarif-"));
  const out = join(dir, "scan.sarif");
  const cli = join(HERE, "..", "bin", "cirvix.mjs");

  // A scan of an empty directory: no findings expected, but the artifact must
  // exist and parse — CI uploads it either way.
  await run(process.execPath, [cli, "scan", "--json", "--sarif", out, "--cwd", dir]).catch(
    (err) => err,
  );
  const written = JSON.parse(await readFile(out, "utf8"));
  assert.equal(written.version, "2.1.0");
  assert.ok(Array.isArray(written.runs[0].results));
});

/* -------------------------------------------------------------------------- */
/*  The Action's reporter                                                      */
/* -------------------------------------------------------------------------- */

async function report(result, env = {}) {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-action-"));
  const resultPath = join(dir, "scan.json");
  const summaryPath = join(dir, "summary.md");
  const outputPath = join(dir, "output.txt");
  await writeFile(resultPath, JSON.stringify(result), "utf8");
  await writeFile(summaryPath, "", "utf8");
  await writeFile(outputPath, "", "utf8");

  const { stdout } = await run(process.execPath, [REPORTER, resultPath], {
    cwd: dir,
    env: {
      ...process.env,
      GITHUB_STEP_SUMMARY: summaryPath,
      GITHUB_OUTPUT: outputPath,
      ...env,
    },
  });

  return {
    stdout,
    summary: await readFile(summaryPath, "utf8"),
    outputs: parseOutputs(await readFile(outputPath, "utf8")),
  };
}

/**
 * Parses GitHub's `name<<DELIM\nvalue\nDELIM` output file the way the runner
 * does — a value ends at a line that is exactly the delimiter, and nowhere
 * else. Parsing it loosely here would make the injection test below pass
 * without proving anything.
 */
function parseOutputs(text) {
  const outputs = {};
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const header = lines[i].match(/^(\w+)<<(\S+)$/);
    if (!header) continue;
    const [, name, delimiter] = header;
    const value = [];
    for (i += 1; i < lines.length && lines[i] !== delimiter; i += 1) value.push(lines[i]);
    outputs[name] = value.join("\n");
  }
  return outputs;
}

test("the job summary says what was found, and how much of it blocks", async () => {
  const { summary } = await report(RESULT, { CIRVIX_FAIL_ON: "high" });

  assert.match(summary, /## Cirvix AgentControl/);
  assert.match(summary, /\*\*2\*\* findings at or above \*\*high\*\*/);
  assert.match(summary, /Claude Code/);
  assert.match(summary, /cirvix gateway/);
  // The honesty line: a scan reports reachability, not wrongdoing.
  assert.match(summary, /\*could\* reach, not what one has done/);
  assert.match(summary, /Nothing was executed and no code was sent anywhere/);
});

test("only blocking findings are annotated onto the diff", async () => {
  // Annotating every low finding on every pull request is how a team learns
  // to scroll past the annotations.
  const { stdout } = await report(RESULT, { CIRVIX_FAIL_ON: "high" });
  const annotations = stdout.split("\n").filter((l) => l.startsWith("::"));

  assert.equal(annotations.length, 2);
  assert.ok(annotations.every((a) => a.startsWith("::error")));
  assert.ok(annotations.some((a) => a.includes("Claude Code")));
  assert.ok(!stdout.includes("filesystem-mcp"), "a low finding was annotated under fail-on high");
});

test("lowering the gate annotates more, and raising it annotates none", async () => {
  const low = await report(RESULT, { CIRVIX_FAIL_ON: "low" });
  assert.equal(low.stdout.split("\n").filter((l) => l.startsWith("::")).length, 4);
  assert.equal(low.outputs.passed, "false");

  const never = await report(RESULT, { CIRVIX_FAIL_ON: "never" });
  assert.equal(never.stdout.split("\n").filter((l) => l.startsWith("::")).length, 0);
  // "never" is for the first run on an existing repository: report the
  // baseline without blocking a merge on it.
  assert.equal(never.outputs.passed, "true");
});

test("the counts a workflow can branch on are exposed as outputs", async () => {
  const { outputs } = await report(RESULT, { CIRVIX_FAIL_ON: "medium" });
  assert.equal(outputs.high, "2");
  assert.equal(outputs.medium, "1");
  assert.equal(outputs.low, "1");
  assert.equal(outputs.passed, "false");
  assert.equal(JSON.parse(outputs.findings).counts.high, 2);
});

test("a finding containing the output delimiter cannot inject a workflow output", async () => {
  // Multi-line outputs use a delimiter form, and a value containing a
  // predictable delimiter would let scanned content set arbitrary outputs.
  const hostile = {
    ...RESULT,
    findings: [
      {
        severity: "high",
        code: "runtime-ungoverned",
        subject: "evil",
        detail: "EOF\npasted=1\nEOF",
        fix: "x",
      },
    ],
    counts: { high: 1 },
  };
  const { outputs } = await report(hostile, { CIRVIX_FAIL_ON: "high" });
  assert.equal(outputs.pasted, undefined, "scanned content set a workflow output");
  assert.equal(outputs.high, "1");
});

test("a clean repository reports clean rather than silently passing", async () => {
  const { summary, stdout, outputs } = await report(
    { scannedAt: "2026-08-07T00:00:00.000Z", cwd: "/repo", findings: [], counts: {} },
    { CIRVIX_FAIL_ON: "high" },
  );
  assert.match(summary, /Nothing ungoverned found/);
  assert.equal(outputs.passed, "true");
  assert.equal(stdout.split("\n").filter((l) => l.startsWith("::")).length, 0);
});
