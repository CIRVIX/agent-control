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
  domainSignal,
  EGRESS_DENY_RULES,
  NUDGE_AT,
} from "../src/core/prompts.mjs";
import { Meter } from "../src/core/meter.mjs";
import { commercialNotices } from "../src/core/notices.mjs";

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

describe("the domain-signal prompt", () => {
  test("it speaks on the egress-class denials and stays quiet otherwise", () => {
    for (const rule of EGRESS_DENY_RULES) {
      const text = domainSignal({ tier: "free" }, { rule, destination: "api.example.com" });
      assert.ok(text, `${rule} is exactly the moment this prompt exists for`);
    }
    assert.equal(
      domainSignal({ tier: "free" }, { rule: "deny-workspace-escape" }),
      null,
      "a workspace write denial is housekeeping, not a Team signal",
    );
    assert.equal(domainSignal({ tier: "free" }), null, "no rule, nothing to say");
  });

  test("it names the rule it saw, never a secret value", () => {
    const text = domainSignal(
      { tier: "free" },
      { rule: "deny-external-egress-after-secret", destination: "collector.stripe.example" },
    );
    assert.match(text, /deny-external-egress-after-secret/);
    assert.match(text, /collector\.stripe\.example/, "the destination is the story, so it is named");
    // The prompt is built from the rule name and the canonical destination —
    // both of which are already in the audit chain. It has no channel to a
    // secret value; this asserts the shape rather than trusting the call site.
    assert.doesNotMatch(text, /(sk|pk|api[_-]?key|token)[_-]?[:=]/i);
  });

  test("it ends with somewhere real to go, and that place is the share flow", () => {
    const text = domainSignal(
      { tier: "starter" },
      { rule: "deny-unlisted-egress", destination: "webhook.acme.dev" },
    );
    assert.match(text, /share\.html$/, "the offer must land on the page that can receive it");
    assert.match(text, /^→ /m, "a prompt with no next step is a complaint");
  });

  test("the numbers it quotes come from the entitlement table", () => {
    const text = domainSignal({ tier: "free" }, { rule: "deny-dotenv-production" });
    assert.match(
      text,
      new RegExp(`\\b${TIERS.team.seatsIncluded}\\b`),
      "Team's seat minimum, not a rounded one",
    );
    assert.match(text, /Team/, "the upgrade path is Team, because the signal is org-shaped");
  });

  test("an uncapped-agent tier does not pretend to watch one agent", () => {
    const text = domainSignal({ tier: "team" }, { rule: "deny-credential-files" });
    assert.ok(!text.includes("watches"), "Team has no agent ceiling, so there is none to name");
  });

  test("notices.mjs fires it once per process, on denials only", () => {
    const out = [];
    const notice = commercialNotices({
      licence: { tier: "free" },
      meter: new Meter({ cwd: scratch() }),
      write: (s) => out.push(s),
    });

    // A permitted egress-class decision must not trigger it — the verdict
    // gate matters as much as the rule gate.
    notice({ rule: "deny-credential-files", verdict: "permit" });
    assert.equal(out.length, 0, "a permit is not a signal");

    notice({ policy: "deny-credential-files", verdict: "deny", destination: "~/.ssh" });
    assert.equal(out.length, 1, "first denial speaks");
    assert.match(out[0], /share\.html/);

    for (let i = 0; i < 5; i++) {
      notice({ policy: "deny-dotenv-production", verdict: "deny", destination: ".env.production" });
    }
    assert.equal(out.length, 1, "a prompt that repeats every denial is nagging");
  });
});
