/**
 * The upgrade prompts.
 *
 * These are the only marketing surface inside the runtime, and they appear in
 * somebody's terminal while they were doing something else. So the tests hold
 * them to the rules the module states rather than to exact strings: name the
 * real number, offer a real command, never overclaim, never nag.
 *
 * The numbers are asserted against the entitlement table rather than written
 * out, so a prompt cannot quote a figure the product does not enforce — the
 * failure mode being a customer who upgrades for an allowance they then do not
 * receive.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { TIERS, dailyAllowance } from "../src/core/entitlements.mjs";
import {
  quotaReached,
  agentLimitReached,
  ephemeralSecret,
  softNudge,
  NUDGE_AT,
} from "../src/core/prompts.mjs";
import { Meter } from "../src/core/meter.mjs";

const scratch = () => mkdtempSync(join(tmpdir(), "cirvix-prompt-"));
const ALL = ["free", "starter", "pro", "team"];

describe("what every prompt must do", () => {
  const samples = ALL.flatMap((tier) => [
    quotaReached({ tier }),
    agentLimitReached({ tier }),
    ephemeralSecret({ tier }),
    softNudge({ tier }, Math.floor(dailyAllowance({ tier, seats: 3 }) * 0.8)),
  ]).filter(Boolean);

  test("there is something to say on every capped tier", () => {
    assert.ok(samples.length >= 8, "the prompts went quiet — check the tier table");
  });

  test("each one is prefixed, so it is identifiable in a busy terminal", () => {
    for (const s of samples) assert.match(s, /^\[cirvix\] /, s);
  });

  test("each one ends with something the reader can actually run", () => {
    for (const s of samples) {
      assert.match(s.trim().split("\n").pop(), /^→ (cirvix (upgrade|status)|Contact)/, s);
    }
  });

  test("none of them sells with urgency or superlatives", () => {
    // The specific words that turn a limit notice into an advertisement.
    const banned =
      /\b(act now|hurry|limited time|don't miss|missing out|unlock your|supercharge|amazing|best[- ]in[- ]class|only \$)/i;
    for (const s of samples) assert.doesNotMatch(s, banned, s);
  });

  test("none of them claims Free is ending", () => {
    for (const s of samples) assert.doesNotMatch(s, /free (tier )?(ends|expires|is ending)/i, s);
  });
});

describe("the numbers come from the table, never from the copy", () => {
  test("the quota prompt quotes the allowance actually enforced", () => {
    for (const tier of ALL) {
      const allowance = dailyAllowance({ tier });
      const out = quotaReached({ tier });
      assert.match(out, new RegExp(allowance.toLocaleString("en-US").replace(/,/g, ",")), tier);
    }
  });

  test("the quota prompt quotes the NEXT tier's real allowance", () => {
    const out = quotaReached({ tier: "free" });
    assert.match(out, new RegExp(TIERS.starter.decisionsPerDay.toLocaleString("en-US")));
    assert.match(out, /cirvix upgrade starter/);
  });

  test("the agent prompt quotes the real agent counts", () => {
    const out = agentLimitReached({ tier: "free" });
    assert.ok(out.includes(`${TIERS.free.agents} concurrent agent`), out);
    assert.ok(out.includes(`unlocks ${TIERS.starter.agents}`), out);
  });

  test("the secret prompt quotes the real TTL and only fires where handles are ephemeral", () => {
    assert.match(ephemeralSecret({ tier: "free" }), new RegExp(`${TIERS.free.secretTtlHours}h`));
    for (const tier of ["starter", "pro", "team"]) {
      assert.equal(ephemeralSecret({ tier }), null, `${tier} has a persistent vault`);
    }
  });

  test("an uncapped tier has no limit to announce", () => {
    assert.equal(quotaReached({ tier: "enterprise" }), null);
    assert.equal(agentLimitReached({ tier: "enterprise" }), null);
    assert.equal(softNudge({ tier: "enterprise" }, 10_000_000), null);
  });

  test("Team's prompt is per seat, because its allowance is", () => {
    const out = quotaReached({ tier: "pro" });
    assert.match(out, /\/ seat/, "the jump to Team has to say the number is per seat");
  });
});

describe("the soft nudge stays soft", () => {
  test("it says nothing before the threshold and something after", () => {
    const allowance = dailyAllowance({ tier: "free" });
    const under = Math.floor(allowance * NUDGE_AT) - 1;
    assert.equal(softNudge({ tier: "free" }, under), null);
    assert.ok(softNudge({ tier: "free" }, under + 1));
  });

  test("past the limit it defers to the refusal rather than doubling up", () => {
    const allowance = dailyAllowance({ tier: "free" });
    assert.equal(softNudge({ tier: "free" }, allowance), null);
    assert.equal(softNudge({ tier: "free" }, allowance + 50), null);
  });

  test("it reassures rather than threatens on Free", () => {
    const out = softNudge({ tier: "free" }, Math.floor(dailyAllowance({ tier: "free" }) * 0.75));
    assert.match(out, /Free stays free forever/);
  });

  test("the meter allows exactly one nudge a day", () => {
    const cwd = scratch();
    const meter = new Meter({ cwd });
    assert.equal(meter.shouldNudge(), true, "the first ask of the day");
    assert.equal(meter.shouldNudge(), false, "and never again today");
    assert.equal(meter.shouldNudge(), false);
  });

  test("a new day earns a new nudge", () => {
    const cwd = scratch();
    let day = new Date("2026-08-20T10:00:00Z");
    const meter = new Meter({ cwd, now: () => day });
    assert.equal(meter.shouldNudge(), true);
    assert.equal(meter.shouldNudge(), false);

    day = new Date("2026-08-21T10:00:00Z");
    assert.equal(meter.shouldNudge(), true, "the counter reset, so the nudge does too");
  });

  test("the flag survives a restart within the same day", () => {
    const cwd = scratch();
    const day = new Date("2026-08-20T10:00:00Z");
    const first = new Meter({ cwd, now: () => day });
    assert.equal(first.shouldNudge(), true);
    first.flush();

    // A new process, same day, same state directory.
    const second = new Meter({ cwd, now: () => day });
    assert.equal(second.shouldNudge(), false, "restarting must not buy another nudge");
  });
});
