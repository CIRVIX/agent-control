/**
 * The gate is wired to the paths a customer actually uses.
 *
 * WHY THIS FILE EXISTS
 *
 * `entitlements.test.mjs` proves the arithmetic: 100 decisions on Free, an
 * exhausted quota denies, the numbers match the pricing page. Every one of
 * those tests passed while the Free tier was, in practice, unlimited.
 *
 * They passed because they tested `checkQuota` and `Pipeline` in isolation.
 * Nothing tested that the shipped CLI hands a Pipeline a licence and a meter —
 * and it did not. `Meter` was constructed in exactly one place, `cirvix
 * upgrade`, the command that *reports* usage. The enforcement paths built
 * their Pipeline and Gateway without one, so `if (this.licence && this.meter)`
 * was false on every call and the gate was dead code in production.
 *
 * `Guard` was worse: it had no gate at all. Since `guard.wrap()` and the MCP
 * gateway both go through `Guard` rather than `Pipeline`, an SDK user and an
 * MCP user were unmetered even if the CLI had been wired correctly.
 *
 * The measured effect, before the fix: 150 decisions through the CLI's own
 * Pipeline configuration produced zero quota denials. The same 150 with a
 * licence and meter supplied denied from call 101 exactly.
 *
 * So this file tests two things unit tests structurally cannot:
 *
 *   1. Both decision cores apply the same gate, and reach the same verdict on
 *      the same input. One core growing a rule the other lacks is the recurring
 *      defect in this codebase.
 *   2. The CLI actually passes the three arguments. That is a source-level
 *      assertion on purpose — the failure mode is a dropped argument, which is
 *      invisible to any behavioural test that constructs its own Pipeline.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { Pipeline } from "../src/core/pipeline.mjs";
import { Guard } from "../src/core/guard.mjs";
import { Meter } from "../src/core/meter.mjs";
import { STARTER_RULES } from "../src/core/policy.mjs";
import { TIERS } from "../src/core/entitlements.mjs";
import { commercialNotices } from "../src/core/notices.mjs";
import { NUDGE_AT } from "../src/core/prompts.mjs";

const HERE = join(fileURLToPath(import.meta.url), "..");
const FREE_ALLOWANCE = TIERS.free.decisionsPerDay;
const LICENCE = { tier: "free" };

function workspace() {
  return mkdtempSync(join(tmpdir(), "cirvix-wiring-"));
}

/** `submit()` nests the verdict; reading the top level silently sees no denial. */
const verdictOf = (res) => (res && res.decision) || res;

test("Pipeline: a supplied licence and meter deny the call after the allowance", async () => {
  const cwd = workspace();
  const pipeline = new Pipeline({
    rules: STARTER_RULES,
    cwd,
    agent: "probe",
    licence: LICENCE,
    meter: new Meter({ cwd }),
  });

  let firstDenied = null;
  for (let i = 1; i <= FREE_ALLOWANCE + 5; i++) {
    const d = verdictOf(
      await pipeline.submit({ agent: "probe", action: "http.get", resource: `https://example.com/${i}` }),
    );
    if (d.rule === "quota-exhausted" && firstDenied === null) firstDenied = i;
  }

  assert.equal(firstDenied, FREE_ALLOWANCE + 1, "the first refusal must land one past the allowance");
  rmSync(cwd, { recursive: true, force: true });
});

test("Guard: the same licence and meter deny at the same point", async () => {
  const cwd = workspace();
  const guard = new Guard({
    rules: STARTER_RULES,
    cwd,
    agent: "probe",
    licence: LICENCE,
    meter: new Meter({ cwd }),
  });

  let firstDenied = null;
  for (let i = 1; i <= FREE_ALLOWANCE + 5; i++) {
    const { decision } = await guard.authorize({ tool: "fetch_url", args: { url: `https://example.com/${i}` } });
    if (decision.rule === "quota-exhausted" && firstDenied === null) firstDenied = i;
  }

  assert.equal(
    firstDenied,
    FREE_ALLOWANCE + 1,
    "Guard backs guard.wrap() and the MCP gateway; if it does not meter, neither do they",
  );
  rmSync(cwd, { recursive: true, force: true });
});

test("neither core meters when no licence or meter is supplied", async () => {
  const cwd = workspace();
  const pipeline = new Pipeline({ rules: STARTER_RULES, cwd, agent: "probe" });
  const guard = new Guard({ rules: STARTER_RULES, cwd, agent: "probe" });

  for (let i = 1; i <= FREE_ALLOWANCE + 5; i++) {
    const p = verdictOf(
      await pipeline.submit({ agent: "probe", action: "http.get", resource: `https://example.com/${i}` }),
    );
    const { decision: g } = await guard.authorize({ tool: "fetch_url", args: { url: `https://example.com/${i}` } });
    assert.notEqual(p.rule, "quota-exhausted", "an embedding caller metering nothing is supported");
    assert.notEqual(g.rule, "quota-exhausted", "the shared conformance fixture depends on this");
  }
  rmSync(cwd, { recursive: true, force: true });
});

test("a refused call is not counted against the allowance", async () => {
  const cwd = workspace();
  const meter = new Meter({ cwd });
  const pipeline = new Pipeline({ rules: STARTER_RULES, cwd, agent: "probe", licence: LICENCE, meter });

  for (let i = 1; i <= FREE_ALLOWANCE + 20; i++) {
    await pipeline.submit({ agent: "probe", action: "http.get", resource: `https://example.com/${i}` });
  }

  assert.equal(
    meter.used(),
    FREE_ALLOWANCE,
    "counting refusals would mean a user who hit the limit could never get back under it",
  );
  rmSync(cwd, { recursive: true, force: true });
});

test("the CLI hands the enforcement paths a licence, a meter and an agent registry", () => {
  // A source-level assertion, deliberately. The defect this guards against is
  // a dropped constructor argument, which every behavioural test misses
  // because it builds its own Pipeline correctly.
  const cli = readFileSync(join(HERE, "..", "bin", "cirvix.mjs"), "utf8");

  for (const needed of ["licence:", "meter:", "agents:"]) {
    const count = cli.split(needed).length - 1;
    assert.ok(
      count >= 2,
      `bin/cirvix.mjs must pass ${needed} to both the runtime Pipeline and the gateway Gateway (found ${count})`,
    );
  }

  assert.match(cli, /readLicence\(/, "the licence has to be read from disk, not assumed");
  assert.match(cli, /new Meter\(/, "the runtime needs its own meter");
  assert.match(cli, /new AgentRegistry\(/, "the concurrent-agent limit needs a registry to count against");
});

test("Gateway forwards the commercial arguments to its Guard", () => {
  // Gateway builds the Guard internally, so a caller supplying a meter has no
  // way to tell from the outside whether it was passed on.
  const gateway = readFileSync(join(HERE, "..", "src", "core", "gateway.mjs"), "utf8");
  const guardCall = gateway.slice(gateway.indexOf("new Guard({"));

  for (const field of ["licence", "meter", "agents"]) {
    assert.ok(
      new RegExp(`\\b${field}\\b`).test(guardCall.slice(0, 400)),
      `Gateway must forward ${field} to its Guard, or the MCP path is unmetered`,
    );
  }
});

/* ---------------------------------------------------------- upgrade prompts */

test("the quota notice fires once, on the transition into the limit", () => {
  const cwd = workspace();
  const meter = new Meter({ cwd });
  const out = [];
  const notice = commercialNotices({ licence: LICENCE, meter, write: (s) => out.push(s) });

  // Ten refused calls after the limit; the reader gets one paragraph, not ten.
  for (let i = 0; i < 10; i++) notice({ rule: "quota-exhausted" });

  assert.equal(out.length, 1, "a process calling past its quota must not repeat the notice");
  assert.match(out[0], /daily limit reached/i);
  assert.match(out[0], /100/, "the notice has to name the real number they hit");
  assert.match(out[0], /cirvix upgrade/, "a prompt with no next step is a complaint");
  rmSync(cwd, { recursive: true, force: true });
});

test("the notice reads the rule under either name the two cores use", () => {
  const cwd = workspace();
  const out = [];
  // A Pipeline audit event renames `rule` to `policy` on the way out.
  const notice = commercialNotices({
    licence: LICENCE,
    meter: new Meter({ cwd }),
    write: (s) => out.push(s),
  });
  notice({ policy: "quota-exhausted" });
  assert.equal(out.length, 1, "reading only `rule` would silently miss every Pipeline decision");
  rmSync(cwd, { recursive: true, force: true });
});

test("the soft nudge appears once per day, past the threshold and not before", () => {
  const cwd = workspace();
  const meter = new Meter({ cwd });
  const out = [];
  const notice = commercialNotices({ licence: LICENCE, meter, write: (s) => out.push(s) });

  for (let i = 0; i < Math.floor(FREE_ALLOWANCE * NUDGE_AT) - 1; i++) meter.count(1);
  notice({ rule: "permit" });
  assert.equal(out.length, 0, "nothing to say below the threshold");

  meter.count(5);
  notice({ rule: "permit" });
  assert.equal(out.length, 1, "one nudge once the threshold is crossed");
  assert.match(out[0], /Free stays free forever/, "the line that keeps it from reading as a threat");

  for (let i = 0; i < 10; i++) notice({ rule: "permit" });
  assert.equal(out.length, 1, "a nudge that reappears is nagging, and annoys the likeliest converter");
  rmSync(cwd, { recursive: true, force: true });
});

test("without a licence and meter the notice hook is inert", () => {
  const out = [];
  const notice = commercialNotices({ licence: null, meter: null, write: (s) => out.push(s) });
  notice({ rule: "quota-exhausted" });
  assert.equal(out.length, 0, "an embedding caller must not get marketing copy on stderr");
});

test("the CLI actually shows the prompts, and only on stderr", () => {
  // prompts.mjs was written, tested, and imported by nothing — every line of
  // the conversion argument existed and none of it was ever displayed. This
  // asserts the wiring, which no unit test of the copy can.
  const cli = readFileSync(join(HERE, "..", "bin", "cirvix.mjs"), "utf8");
  assert.match(cli, /commercialNotices/, "the CLI has to build the notice hook");
  assert.ok(
    (cli.split("commercialNotices(").length - 1) >= 2,
    "both the runtime and the gateway need one",
  );

  // The gateway's stdout carries MCP frames; a notice written there corrupts
  // the wire and the agent fails for reasons nobody will trace back to a
  // marketing line.
  const notices = readFileSync(join(HERE, "..", "src", "core", "notices.mjs"), "utf8");
  assert.ok(!/process\.stdout/.test(notices), "notices must never touch stdout");
  for (const call of cli.match(/commercialNotices\(\{[\s\S]{0,240}?\}\)/g) ?? []) {
    assert.match(call, /process\.stderr\.write/, "every notice sink must be stderr");
  }
});
