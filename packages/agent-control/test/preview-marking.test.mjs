/**
 * PREVIEW MARKING (P0-D exit gate — "no unexplained asymmetry" includes
 * surfaces that DECIDE LESS than the boundary). simulate/console/shadow/
 * policy-test evaluate policy/risk/intent directly; each must label its output
 * as a preview and disclose the stages it did not evaluate, so a preview
 * verdict can never be quoted as the boundary's answer.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CANONICAL_STAGES } from "../src/core/authorize.mjs";
import { PREVIEW_BANNER, PREVIEW_EVALUATED_STAGES, previewScope } from "../src/core/preview-scope.mjs";

const POLICY = "allow:\n  name = allow-read\n  tool = filesystem.read\n  workspace = true\n";

test("the preview scope is derived from the canonical stage list, not hand-maintained", () => {
  const scope = previewScope();
  assert.deepEqual(scope.evaluated, [...PREVIEW_EVALUATED_STAGES]);
  const expectedOmitted = CANONICAL_STAGES.filter((s) => !PREVIEW_EVALUATED_STAGES.includes(s));
  assert.deepEqual(scope.omitted, expectedOmitted);
  assert.ok(scope.omitted.includes("identity"));
  assert.ok(scope.omitted.includes("delegation"));
  assert.ok(scope.omitted.includes("revocation"));
  assert.ok(scope.omitted.includes("credential"));
  assert.ok(scope.omitted.includes("session"));
  assert.ok(scope.omitted.includes("evidence"));
  assert.ok(!scope.omitted.includes("policy"));
});

test("the console preview marks its JSON and its rendered card", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-preview-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeFile(join(dir, "cirvix.policy"), POLICY, "utf8");

  const { consolePreview } = await import("../src/commands/console.mjs");
  const jsonRun = await consolePreview({ cwd: dir, json: true, evalInput: "filesystem.read notes.txt" });
  const parsed = JSON.parse(jsonRun.output);
  assert.equal(parsed.preview, true);
  assert.equal(parsed.previewScope.kind, "preview");
  assert.ok(parsed.previewScope.omitted.includes("revocation"));

  const rendered = await consolePreview({ cwd: dir, json: false, evalInput: "filesystem.read notes.txt" });
  assert.match(rendered.output, /PREVIEW — NOT AN AUTHORIZATION DECISION/);
  assert.match(rendered.output, /NOT evaluated/);
  assert.match(rendered.output, /revocation/);
});

test("the policy simulator marks its JSON and its text output", async (t) => {
  const { simulatePolicy } = await import("../src/commands/simulate.mjs");
  const jsonRun = await simulatePolicy({ rules: [], json: true });
  const parsed = JSON.parse(jsonRun.output);
  assert.equal(parsed.preview.kind, "preview");
  assert.ok(parsed.preview.omitted.length > 0);

  const textRun = await simulatePolicy({ rules: [], json: false });
  assert.match(textRun.output, /PREVIEW — policy\/risk\/intent only/);
});

test("shadow mode marks its summary as policy-only", async (t) => {
  const { executeShadowCommand } = await import("../src/commands/shadow.mjs");
  const run = await executeShadowCommand({ cwd: process.cwd(), json: false });
  assert.match(run.output, /PREVIEW/);

  const jsonRun = await executeShadowCommand({ cwd: process.cwd(), json: true });
  const parsed = JSON.parse(jsonRun.output);
  assert.equal(parsed.preview.kind, "preview");
});

test("policy test marks its report as policy-only", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-preview-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const policyPath = join(dir, "cirvix.policy");
  await writeFile(
    policyPath,
    POLICY + '\ntest "read is allowed":\n  tool = filesystem.read\n  path = notes.txt\n  expect allow\n',
    "utf8",
  );

  const { test: policyTest } = await import("../src/commands/policy.mjs");
  const run = await policyTest({ path: policyPath, cwd: dir, json: true });
  const parsed = JSON.parse(run.output);
  assert.equal(parsed.preview.kind, "preview");
  assert.ok(parsed.preview.omitted.includes("authority"));
});
