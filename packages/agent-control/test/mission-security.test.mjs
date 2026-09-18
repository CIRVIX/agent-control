import test from "node:test";
import assert from "node:assert/strict";
import { Pipeline } from "../src/core/pipeline.mjs";
import { Guard } from "../src/core/guard.mjs";
import { MissionRegistry, normalizeMission, assessAuthority } from "../src/core/authority.mjs";
import { compile } from "../src/core/policy-dsl.mjs";

const cwd = process.platform === "win32" ? "C:/workspace" : "/workspace";
const rules = compile("allow:\n  tool = filesystem.read\n", { cwd }).rules;
const raw = () => ({ tool: "read_file", arguments: { path: `${cwd}/notes.txt`, costUsd: 0, cost: 0 } });
function setup(constraints = { spend: { maxUsd: 1 } }, direct = false) {
  const missions = new MissionRegistry();
  const mission = missions.issue({ agent: "worker", capabilities: [{ actions: ["fs.read"] }], constraints });
  const options = { agent: "worker", cwd, rules, mission, ...(direct ? {} : { missions }) };
  return { missions, mission, options };
}
function make(kind, options) {
  const engine = kind === "Pipeline" ? new Pipeline(options) : new Guard(options);
  return { engine, submit: (request = raw(), ctx = {}) => kind === "Pipeline" ? engine.submit(request, ctx) : engine.authorize(request, ctx) };
}
function barrier() {
  let enter, release;
  const entered = new Promise((resolve) => { enter = resolve; });
  const pending = new Promise((resolve) => { release = resolve; });
  return { entered, release, audit: { async append(record) { if (record.verdict === "permit") { enter(); await pending; } } } };
}

for (const kind of ["Pipeline", "Guard"]) {
  test(`${kind}: only captured trusted cost is assessed and charged`, async () => {
    const { mission, options } = setup();
    const gate = barrier();
    const runner = make(kind, { ...options, audit: gate.audit });
    let reads = 0;
    const ctx = { get costUsd() { reads++; return 0.75; } };
    const request = raw();
    const pending = runner.submit(request, ctx);
    await gate.entered;
    request.arguments.costUsd = 10;
    gate.release();
    assert.equal((await pending).decision.verdict, "permit");
    assert.equal(reads, 1);
    assert.equal(mission.usage.spendUsd, 0.75);
    assert.equal((await runner.submit(raw(), { costUsd: 0.5 })).decision.verdict, "deny");
    assert.equal(mission.usage.spendUsd, 0.75);
  });

  test(`${kind}: request prices are ignored and invalid trusted prices fail closed`, async () => {
    const { mission, options } = setup();
    const runner = make(kind, options);
    const request = raw();
    request.arguments.costUsd = 99;
    assert.equal((await runner.submit(request)).decision.verdict, "permit");
    assert.equal(mission.usage.spendUsd, 0);
    for (const costUsd of [NaN, Infinity, -1, "0", null]) {
      assert.equal((await runner.submit(raw(), { costUsd })).decision.verdict, "deny");
    }
    assert.equal(mission.usage.calls.length, 1);
  });

  for (const direct of [false, true]) {
    test(`${kind}: overlapping shared ${direct ? "direct" : "registry"} mission submissions are bounded`, async () => {
      const { mission, options } = setup({ spend: { maxUsd: 1 }, rate: { max: 1 } }, direct);
      const gate = barrier();
      const first = make(kind, { ...options, audit: gate.audit });
      const second = make(kind === "Pipeline" ? "Guard" : "Pipeline", options);
      const pending = first.submit(raw(), { costUsd: 1 });
      await gate.entered;
      const overlaps = await Promise.all(Array.from({ length: 12 }, () => second.submit(raw(), { costUsd: 1 })));
      assert.ok(overlaps.every((r) => r.decision.rule === "authority-mission-busy"));
      assert.equal(mission.usage.spendUsd, 0);
      gate.release();
      assert.equal((await pending).decision.verdict, "permit");
      assert.equal((await second.submit(raw(), { costUsd: 1 })).decision.verdict, "deny");
      assert.equal(mission.usage.spendUsd, 1);
      assert.equal(mission.usage.calls.length, 1);
    });
  }
}


for (const kind of ["Pipeline", "Guard"]) {
  for (const failure of ["audit", "callback", "broker", "hold"]) {
    test(`${kind}: ${failure} failure releases allowance for retry`, async () => {
      const { mission, options } = setup({ spend: { maxUsd: 1 }, rate: { max: 1 } });
      const callback = () => { throw new Error("test callback unavailable"); };
      const extra = failure === "audit" ? { audit: { async append() { throw new Error("test audit unavailable"); } } }
        : failure === "callback" ? { onEvent: callback, onDecision: callback }
        : failure === "broker" ? { secrets: { async substitute() { throw new Error("test broker unavailable"); } } }
        : { rules: compile("require_approval:\n  tool = filesystem.read\n", { cwd }).rules };
      const runner = make(kind, { ...options, ...extra });
      const result = await runner.submit(raw(), { costUsd: 1 }).catch(() => null);
      assert.ok(!result || result.decision.verdict !== "permit");
      assert.equal(mission.usage.spendUsd, 0);
      assert.equal(mission.usage.calls.length, 0);
      assert.equal((await make(kind, options).submit(raw(), { costUsd: 1 })).decision.verdict, "permit");
      assert.equal(mission.usage.spendUsd, 1);
    });
  }
  test(`${kind}: rate alone limits zero-cost calls and independent missions proceed`, async () => {
    const { mission, options } = setup({ rate: { max: 1 } });
    const gate = barrier();
    const first = make(kind, { ...options, audit: gate.audit });
    const pending = first.submit();
    await gate.entered;
    assert.equal((await make(kind, setup().options).submit()).decision.verdict, "permit");
    gate.release();
    assert.equal((await pending).decision.verdict, "permit");
    assert.equal((await first.submit()).decision.verdict, "deny");
    assert.equal(mission.usage.calls.length, 1);
  });
}

test("rate history stays bounded without discarding live allowance", async () => {
  const { mission, options } = setup({ rate: { max: 5000, windowMs: 60_000 } });
  mission.usage.calls = Array(4096).fill(Date.now());
  assert.equal((await make("Pipeline", options).submit()).decision.verdict, "deny");
  assert.equal(mission.usage.calls.length, 4096);
  mission.usage.calls.fill(Date.now() - 60_001);
  assert.equal((await make("Guard", options).submit()).decision.verdict, "permit");
  assert.equal(mission.usage.calls.length, 1);
});

test("capability rate windows retain longer history and malformed windows fail closed", () => {
  const now = Date.now();
  const mission = normalizeMission({
    agent: "worker", capabilities: [{ actions: ["fs.read"], conditions: { rate: { max: 1, windowMs: 120_000 } } }],
    constraints: { rate: { max: 100, windowMs: 1000 } }, usage: { calls: [now - 60_000] },
  });
  assert.equal(assessAuthority({ agent: "worker", action: "fs.read" }, mission, { now }).authorized, false);
  for (const windowMs of [0, -1, NaN, Infinity]) {
    mission.constraints.rate.windowMs = windowMs;
    assert.equal(assessAuthority({ agent: "worker", action: "fs.read" }, mission, { now }).authorized, false);
  }
});

test("mission bounds cannot be shadowed and registry record cannot race authorization", async () => {
  const { missions, mission, options } = setup();
  const gate = barrier();
  const runner = make("Pipeline", { ...options, mode: "audit", audit: gate.audit });
  const pending = runner.submit(raw(), { costUsd: 1 });
  await gate.entered;
  assert.throws(() => missions.record(mission.id, { costUsd: 1 }), /in progress/);
  gate.release();
  await pending;
  const refused = await runner.submit(raw(), { costUsd: 1 });
  assert.equal(refused.decision.verdict, "deny");
  assert.equal(refused.decision.enforced, true);
  assert.equal(mission.usage.spendUsd, 1);
});
