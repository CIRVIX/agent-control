/**
 * Quota and entitlement enforcement.
 *
 * TWO PROPERTIES MATTER MORE THAN THE ARITHMETIC.
 *
 * 1. AN EXHAUSTED QUOTA DENIES. It never passes a call through unchecked. A
 *    security control that stops enforcing when a counter runs out is not a
 *    degraded product, it is an absent one — and the absence is invisible
 *    exactly when it matters. Several tests below exist only to make that
 *    impossible to regress.
 *
 * 2. THE NUMBERS MATCH THE PRICING PAGE. Two copies of a limit eventually
 *    disagree, and the direction they disagree in is always the embarrassing
 *    one: a customer who paid for 12,000 and receives 1,500. The figures are
 *    pinned here so a change on one side without the other fails a test rather
 *    than a customer.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_TIER,
  GATE,
  TIERS,
  TIER_ORDER,
  can,
  checkAgents,
  checkQuota,
  dailyAllowance,
  dayKey,
  nextTier,
  tierAtLeast,
  tierFor,
} from "../src/core/entitlements.mjs";
import { AgentRegistry, Meter, readLicence, writeLicence } from "../src/core/meter.mjs";
import { Pipeline } from "../src/core/pipeline.mjs";
import { PRICING, checkoutUrl, priceLine } from "../src/commands/upgrade.mjs";

const scratch = () => mkdtempSync(join(tmpdir(), "cirvix-ent-"));

/* -------------------------------------------------------------------------- */
/*  The published numbers                                                      */
/* -------------------------------------------------------------------------- */

describe("the tier table matches what is sold", () => {
  /** Straight from the pricing page. If this table changes, so must that one. */
  const PUBLISHED = [
    ["free", 100, 1, 12, false],
    ["starter", 1_500, 2, 24 * 7, true],
    ["pro", 12_000, 8, 24 * 90, true],
    ["team", 40_000, null, 24 * 365, true],
  ];

  for (const [id, perDay, agents, retention, persistent] of PUBLISHED) {
    test(`${id}: ${perDay.toLocaleString("en-US")} decisions/day`, () => {
      assert.equal(TIERS[id].decisionsPerDay, perDay);
    });
    test(`${id}: concurrent agents`, () => {
      assert.equal(TIERS[id].agents, agents);
    });
    test(`${id}: audit retention`, () => {
      assert.equal(TIERS[id].auditRetentionHours, retention);
    });
    test(`${id}: secret persistence`, () => {
      assert.equal(TIERS[id].persistentSecrets, persistent);
    });
  }

  test("prices match the pricing page", () => {
    assert.deepEqual(PRICING.starter, { monthly: 29, annual: 290 });
    assert.deepEqual(PRICING.pro, { monthly: 79, annual: 790 });
    assert.equal(PRICING.team.monthly, 149);
    assert.equal(PRICING.team.annual, 1490);
    assert.equal(PRICING.team.perSeat, true);
    assert.equal(PRICING.team.minSeats, 3);
    assert.equal(PRICING.free.monthly, 0);
    assert.equal(PRICING.enterprise.custom, true);
  });

  test("every paid tier is ten months for twelve", () => {
    // The "2 months free" claim on the page is arithmetic, so it can be checked.
    for (const id of ["starter", "pro", "team"]) {
      assert.equal(PRICING[id].annual, PRICING[id].monthly * 10, `${id} annual`);
    }
  });

  test("enterprise is uncapped, not zero", () => {
    // A null allowance read as 0 would make the most expensive contract the
    // most restricted plan in the product.
    assert.equal(TIERS.enterprise.decisionsPerDay, null);
    assert.equal(dailyAllowance({ tier: "enterprise" }), null);
    assert.equal(checkQuota({ tier: "enterprise" }, 10_000_000).ok, true);
  });
});

/* -------------------------------------------------------------------------- */
/*  Allowance arithmetic                                                       */
/* -------------------------------------------------------------------------- */

describe("daily allowance", () => {
  test("flat tiers ignore seats", () => {
    assert.equal(dailyAllowance({ tier: "pro", seats: 50 }), 12_000);
  });

  test("team multiplies by seats", () => {
    assert.equal(dailyAllowance({ tier: "team", seats: 3 }), 120_000);
    assert.equal(dailyAllowance({ tier: "team", seats: 10 }), 400_000);
  });

  test("team below its seat minimum is raised, not punished", () => {
    // A licence recording fewer seats than the tier allows is a data problem.
    // Answering it by cutting the customer's allowance is the wrong way round.
    assert.equal(dailyAllowance({ tier: "team", seats: 1 }), 120_000);
    assert.equal(dailyAllowance({ tier: "team", seats: 0 }), 120_000);
  });

  test("an unknown tier is Free, never the most generous", () => {
    assert.equal(tierFor("platinum").id, "free");
    assert.equal(tierFor(undefined).id, "free");
    assert.equal(tierFor(null).id, "free");
    assert.equal(dailyAllowance({ tier: "nonsense" }), 100);
  });

  test("tier ordering", () => {
    assert.deepEqual(TIER_ORDER, ["free", "starter", "pro", "team", "enterprise"]);
    assert.equal(tierAtLeast("pro", "starter"), true);
    assert.equal(tierAtLeast("starter", "pro"), false);
    assert.equal(tierAtLeast("pro", "pro"), true);
    assert.equal(nextTier("free"), "starter");
    assert.equal(nextTier("enterprise"), "enterprise", "nothing above the top");
  });
});

/* -------------------------------------------------------------------------- */
/*  The gate                                                                   */
/* -------------------------------------------------------------------------- */

describe("the quota gate", () => {
  test("permits up to the limit and refuses at it", () => {
    const licence = { tier: "free" };
    assert.equal(checkQuota(licence, 0).ok, true);
    assert.equal(checkQuota(licence, 99).ok, true, "the 100th call is allowed");
    assert.equal(checkQuota(licence, 100).ok, false, "the 101st is not");
  });

  test("the refusal says what and how much", () => {
    const r = checkQuota({ tier: "free" }, 100);
    assert.equal(r.gate, GATE.QUOTA_EXHAUSTED);
    assert.equal(r.allowance, 100);
    assert.equal(r.remaining, 0);
    assert.match(r.reason, /100/);
    assert.match(r.reason, /00:00 UTC/, "the reset time is the actionable part");
    assert.match(r.remediation, /cirvix upgrade starter/);
  });

  test("remaining counts down", () => {
    assert.equal(checkQuota({ tier: "starter" }, 500).remaining, 1_000);
  });

  test("concurrent agents", () => {
    assert.equal(checkAgents({ tier: "free" }, 0).ok, true);
    assert.equal(checkAgents({ tier: "free" }, 1).ok, false);
    assert.equal(checkAgents({ tier: "starter" }, 1).ok, true);
    assert.equal(checkAgents({ tier: "starter" }, 2).ok, false);
    assert.equal(checkAgents({ tier: "team" }, 9_999).ok, true, "unlimited");
  });

  test("feature gates fail closed on an unknown capability", () => {
    // A capability added to the product but not to the table must be
    // unavailable rather than accidentally universal.
    assert.equal(can({ tier: "enterprise" }, "teleportation"), false);
    assert.equal(can({ tier: "free" }, "persistentSecrets"), false);
    assert.equal(can({ tier: "starter" }, "persistentSecrets"), true);
    assert.equal(can({ tier: "starter" }, "approvals"), false);
    assert.equal(can({ tier: "pro" }, "approvals"), true);
    assert.equal(can({ tier: "pro" }, "attestation"), true);
    assert.equal(can(null, "approvals"), false, "no licence is Free");
  });
});

/* -------------------------------------------------------------------------- */
/*  The meter                                                                  */
/* -------------------------------------------------------------------------- */

describe("the meter", () => {
  test("counts, and survives a restart within the same day", () => {
    const cwd = scratch();
    const a = new Meter({ cwd });
    a.count(); a.count(); a.count();
    a.flush();

    const b = new Meter({ cwd });
    assert.equal(b.used(), 3, "the count is read back from disk");
  });

  test("a stored count from a previous day does not carry over", () => {
    const cwd = scratch();
    const a = new Meter({ cwd });
    a.set("2020-01-01", 9_999);
    a.flush();

    const b = new Meter({ cwd });
    assert.equal(b.used(), 0, "yesterday's usage is not today's");
  });

  test("the day rolls over inside a long-lived process", () => {
    const cwd = scratch();
    let now = new Date("2026-08-20T23:59:00Z");
    const m = new Meter({ cwd, now: () => now });
    m.count(); m.count();
    assert.equal(m.used(), 2);

    now = new Date("2026-08-21T00:00:01Z");
    assert.equal(m.used(), 0, "a process running past midnight resets");
  });

  test("a corrupt meter file does not take the runtime down", () => {
    const cwd = scratch();
    const m0 = new Meter({ cwd });
    m0.count();
    m0.flush();
    // Losing a count is recoverable; refusing to start is not.
    writeFileSync(join(cwd, ".cirvix", "meter.json"), "{ not json", "utf8");
    const m = new Meter({ cwd });
    assert.equal(m.used(), 0);
    assert.doesNotThrow(() => m.count());
  });

  test("dayKey is a UTC calendar day", () => {
    assert.equal(dayKey(new Date("2026-08-20T23:59:59Z")), "2026-08-20");
    assert.equal(dayKey(new Date("2026-08-21T00:00:00Z")), "2026-08-21");
  });
});

/* -------------------------------------------------------------------------- */
/*  The licence file                                                           */
/* -------------------------------------------------------------------------- */

describe("the licence", () => {
  test("absent means Free", () => {
    const l = readLicence(scratch());
    assert.equal(l.tier, DEFAULT_TIER);
    assert.equal(l.tier, "free");
  });

  test("a corrupt licence falls back to Free, not to the last paid tier", () => {
    // The failure mode of a damaged file must not be a free upgrade.
    const cwd = scratch();
    writeLicence({ tier: "team", seats: 5 }, cwd);
    writeFileSync(join(cwd, ".cirvix", "licence.json"), "<<<corrupt>>>", "utf8");
    assert.equal(readLicence(cwd).tier, "free");
  });

  test("an invented tier in the file resolves to Free", () => {
    const cwd = scratch();
    mkdirSync(join(cwd, ".cirvix"), { recursive: true });
    writeFileSync(join(cwd, ".cirvix", "licence.json"), JSON.stringify({ tier: "unlimited-god-mode" }), "utf8");
    assert.equal(readLicence(cwd).tier, "free");
  });

  test("round-trips a real licence", () => {
    const cwd = scratch();
    writeLicence({ tier: "pro", seats: 1, customerId: "ctm_1" }, cwd);
    const l = readLicence(cwd);
    assert.equal(l.tier, "pro");
    assert.equal(l.customerId, "ctm_1");
  });

  test("team defaults to its seat minimum", () => {
    const cwd = scratch();
    writeLicence({ tier: "team" }, cwd);
    assert.equal(readLicence(cwd).seats, 3);
  });
});

/* -------------------------------------------------------------------------- */
/*  End to end, through the real pipeline                                      */
/* -------------------------------------------------------------------------- */

describe("enforcement through the pipeline", () => {
  const RULES = [
    { name: "allow-reads", effect: "permit", actions: ["fs.read"], resources: ["**"] },
  ];

  const call = (n) => ({
    tool: "fs.read",
    arguments: { path: `/workspace/file-${n}.ts` },
  });

  function build(cwd, licence, opts = {}) {
    return new Pipeline({
      rules: RULES,
      cwd,
      licence,
      meter: opts.meter ?? new Meter({ cwd }),
      agents: opts.agents,
      log: () => {},
    });
  }

  test("a permitted call is permitted while under quota", async () => {
    const cwd = scratch();
    const p = build(cwd, { tier: "free" });
    const { decision } = await p.submit(call(1));
    assert.equal(decision.verdict, "permit");
  });

  test("the call at the limit is DENIED, not passed through", async () => {
    // The property this whole file exists for.
    const cwd = scratch();
    const meter = new Meter({ cwd });
    meter.set(dayKey(), 100);
    const p = build(cwd, { tier: "free" }, { meter });

    const { decision } = await p.submit(call(2));
    assert.equal(decision.verdict, "deny", "an exhausted quota must never allow");
    assert.equal(decision.rule, "quota-exhausted");
    assert.equal(decision.gate, GATE.QUOTA_EXHAUSTED);
  });

  test("the refusal explains itself and offers a way out", async () => {
    const cwd = scratch();
    const meter = new Meter({ cwd });
    meter.set(dayKey(), 100);
    const { decision } = await build(cwd, { tier: "free" }, { meter }).submit(call(3));
    assert.match(decision.reason, /100/);
    assert.match(decision.remediation, /upgrade/i);
    assert.equal(decision.quota.tier, "free");
    assert.equal(decision.quota.allowance, 100);
  });

  test("a gated call is not counted, so the limit is escapable", async () => {
    // Counting refusals would mean a user who hit the limit could never get
    // back under it, and the reset would never help.
    const cwd = scratch();
    const meter = new Meter({ cwd });
    meter.set(dayKey(), 100);
    const p = build(cwd, { tier: "free" }, { meter });
    await p.submit(call(4));
    await p.submit(call(5));
    assert.equal(meter.used(), 100, "still exactly at the limit, not above it");
  });

  test("a higher tier is not blocked at the lower tier's limit", async () => {
    const cwd = scratch();
    const meter = new Meter({ cwd });
    meter.set(dayKey(), 100);
    const { decision } = await build(cwd, { tier: "starter" }, { meter }).submit(call(6));
    assert.equal(decision.verdict, "permit");
  });

  test("the counter advances with real traffic", async () => {
    const cwd = scratch();
    const meter = new Meter({ cwd });
    const p = build(cwd, { tier: "free" }, { meter });
    for (let i = 0; i < 5; i++) await p.submit(call(i));
    assert.equal(meter.used(), 5);
  });

  test("a policy denial still counts — the decision was made", async () => {
    const cwd = scratch();
    const meter = new Meter({ cwd });
    const p = new Pipeline({
      rules: [{ name: "deny-all", effect: "forbid", actions: ["fs.read"], resources: ["**"] }],
      cwd, licence: { tier: "free" }, meter, log: () => {},
    });
    const { decision } = await p.submit(call(7));
    assert.equal(decision.verdict, "deny");
    assert.equal(meter.used(), 1, "evaluating a call is what is being sold, not permitting it");
  });

  test("with no meter, nothing is metered", async () => {
    // Every existing caller, the conformance fixture and the embedded SDK all
    // construct a Pipeline without these options. They must be unaffected.
    const cwd = scratch();
    const p = new Pipeline({ rules: RULES, cwd, log: () => {} });
    for (let i = 0; i < 500; i++) {
      const { decision } = await p.submit(call(i));
      assert.equal(decision.verdict, "permit");
    }
  });

  test("a second agent is refused on Free", async () => {
    const cwd = scratch();
    const agents = new AgentRegistry();
    const p = build(cwd, { tier: "free" }, { agents });

    const first = await p.submit(call(8), { agent: "agent-one" });
    assert.equal(first.decision.verdict, "permit");

    const second = await p.submit(call(9), { agent: "agent-two" });
    assert.equal(second.decision.verdict, "deny");
    assert.equal(second.decision.gate, GATE.AGENT_LIMIT);
  });

  test("the same agent calling twice is not a second agent", async () => {
    const cwd = scratch();
    const agents = new AgentRegistry();
    const p = build(cwd, { tier: "free" }, { agents });
    await p.submit(call(10), { agent: "solo" });
    const again = await p.submit(call(11), { agent: "solo" });
    assert.equal(again.decision.verdict, "permit", "one agent is not two");
  });

  test("Starter allows two agents and refuses the third", async () => {
    const cwd = scratch();
    const agents = new AgentRegistry();
    const p = build(cwd, { tier: "starter" }, { agents });
    for (const name of ["a", "b"]) {
      const r = await p.submit(call(12), { agent: name });
      assert.equal(r.decision.verdict, "permit", `${name} should be allowed`);
    }
    const third = await p.submit(call(13), { agent: "c" });
    assert.equal(third.decision.verdict, "deny");
  });

  test("a gated decision is still written to the audit chain", async () => {
    // A refusal nobody recorded is a refusal nobody can account for.
    const cwd = scratch();
    const meter = new Meter({ cwd });
    meter.set(dayKey(), 100);
    const appended = [];
    const p = new Pipeline({
      rules: RULES, cwd, licence: { tier: "free" }, meter, log: () => {},
      audit: { append: async (e) => appended.push(e) },
    });
    await p.submit(call(14));
    assert.equal(appended.length, 1);
    assert.equal(appended[0].verdict, "deny");
  });
});

/* -------------------------------------------------------------------------- */
/*  The upgrade command                                                        */
/* -------------------------------------------------------------------------- */

describe("cirvix upgrade", () => {
  const run = async (argv, cwd) => {
    let out = "";
    const { upgrade } = await import("../src/commands/upgrade.mjs");
    const result = await upgrade(argv, { cwd, write: (s) => { out += s; } });
    return { out, result };
  };

  test("reports the current plan and today's usage", async () => {
    const cwd = scratch();
    const m = new Meter({ cwd });
    m.count(7);
    m.flush();
    const { out } = await run([], cwd);
    assert.match(out, /Current plan\s+Free/);
    assert.match(out, /7 of 100 decisions/);
  });

  test("suggests the next tier by default", async () => {
    const { out } = await run([], scratch());
    assert.match(out, /Free → Starter/);
    assert.match(out, /\$29\/mo/);
  });

  test("only lists differences that are real", async () => {
    const { out } = await run([], scratch());
    assert.match(out, /1,500 decisions\/day/);
    assert.match(out, /Secret handles survive a restart/);
    // Starter does not add approvals; claiming it would be a false promise.
    assert.doesNotMatch(out, /approvals/i);
  });

  test("prices Team for the seats actually asked for", async () => {
    const { out } = await run(["team", "--seats", "5"], scratch());
    assert.match(out, /\$149\/seat\/mo/);
    assert.match(out, /\$745\/mo for 5 seats/);
  });

  test("enterprise carries no invented number", async () => {
    const { out } = await run(["enterprise"], scratch());
    assert.match(out, /Custom/);
    assert.doesNotMatch(out, /\$\d/, "no price is published for Enterprise");
  });

  test("the top tier has nothing to sell", async () => {
    const cwd = scratch();
    writeLicence({ tier: "enterprise" }, cwd);
    const { out } = await run([], cwd);
    assert.match(out, /highest tier/);
  });

  test("it says the free runtime stays free", async () => {
    const { out } = await run([], scratch());
    assert.match(out, /local runtime stays free/i);
  });

  test("the checkout link carries the plan", () => {
    assert.match(checkoutUrl("pro"), /plan=pro/);
    assert.match(checkoutUrl("team", { seats: 4 }), /seats=4/);
    assert.equal(checkoutUrl("free"), "https://www.cirvix.com/pricing.html");
  });

  test("it never writes a paid licence", async () => {
    // A command that can grant itself Pro is not an entitlement system.
    const cwd = scratch();
    await run(["pro"], cwd);
    assert.equal(readLicence(cwd).tier, "free");
    assert.equal(existsSync(join(cwd, ".cirvix", "licence.json")), false);
  });

  test("price lines are honest about the cycle", () => {
    assert.match(priceLine("starter"), /\$29\/mo · \$290\/yr/);
    assert.match(priceLine("team", 3), /\$447\/mo for 3 seats/);
  });
});
