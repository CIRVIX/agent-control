/**
 * The terminal-facing copy for every commercial limit.
 *
 * WHY THE WORDING LIVES IN ONE FILE.
 *
 * Every one of these lines appears in the middle of somebody's terminal while
 * they were trying to do something else. Scattered through the call sites they
 * drift into marketing language one edit at a time, and marketing language in
 * that position reads as an interruption rather than an offer. Here they can be
 * read together, and the tests below can hold them to a shape: state the limit,
 * state the number, give the command, stop.
 *
 * The rules these follow, which are worth stating because they are easy to
 * erode:
 *
 *   · No superlatives, no urgency, no "you're missing out". The reader is
 *     mid-task and did not ask for an advertisement.
 *   · Always name the real number they hit and the real number they would get.
 *     A prompt that says "upgrade for more" is asking them to go and look it up.
 *   · Always end with a command they can run. A prompt with no next step is a
 *     complaint.
 *   · Never claim Free is ending. It is not, and saying so to hurry someone is
 *     the kind of lie that gets screenshotted.
 *
 * These are strings. Nothing here decides anything — `entitlements.mjs` owns
 * every limit, and these functions only read what it already decided.
 */

import { TIERS, nextTier, dailyAllowance, tierFor } from "./entitlements.mjs";

const n = (v) => Number(v).toLocaleString("en-US");

/** `cirvix upgrade <tier>`, or the enterprise equivalent. */
function upgradeLine(tierId) {
  const next = nextTier(tierId);
  if (!next) return "→ Contact your account owner.";
  return `→ cirvix upgrade ${next}`;
}

/**
 * The daily allowance is spent.
 *
 * Names the tier's own number rather than a generic "limit reached", because
 * the number is the thing that makes the next line persuasive.
 */
export function quotaReached(licence = {}) {
  const tier = tierFor(licence.tier);
  const allowance = dailyAllowance(licence);
  if (allowance === null) return null; // uncapped; there is nothing to say

  const next = nextTier(tier.id);
  const lines = [`[cirvix] ${tier.name} daily limit reached (${n(allowance)} decisions).`];

  if (next) {
    const perSeat = TIERS[next].perSeat ? " / seat" : "";
    lines.push(
      `Upgrade to ${TIERS[next].name} → ${n(TIERS[next].decisionsPerDay)}${perSeat} decisions/day` +
        (TIERS[next].persistentSecrets && !tier.persistentSecrets
          ? " + persistent secret handles."
          : "."),
    );
  }
  lines.push("The counter resets at 00:00 UTC.");
  lines.push(upgradeLine(tier.id));
  return lines.join("\n");
}

/** A second (or nth) agent was started on a tier that does not allow it. */
export function agentLimitReached(licence = {}) {
  const tier = tierFor(licence.tier);
  if (tier.agents === null) return null;

  const next = nextTier(tier.id);
  const lines = [
    `[cirvix] ${tier.name} allows ${tier.agents} concurrent agent${tier.agents === 1 ? "" : "s"}.`,
  ];
  if (next) {
    const after = TIERS[next];
    lines.push(
      `${after.name} unlocks ${after.agents === null ? "unlimited agents" : `${n(after.agents)}`}.`,
    );
  }
  lines.push(upgradeLine(tier.id));
  return lines.join("\n");
}

/**
 * A secret handle that will not survive a restart.
 *
 * The strongest conversion lever in the table, and the one most likely to be
 * over-written. It states what will happen and when, and does not editorialise
 * about it — someone who cares about secrets already understands why this
 * matters, and someone who does not is not going to be argued into caring.
 */
export function ephemeralSecret(licence = {}, handle = "sec_handle_…") {
  const tier = tierFor(licence.tier);
  if (tier.persistentSecrets) return null;

  const next = nextTier(tier.id);
  const ttl = tier.secretTtlHours;
  return [
    `[cirvix] Secret handle ${handle} is ephemeral on ${tier.name}` +
      (ttl ? ` (clears on restart or after ${ttl}h).` : " (clears on restart)."),
    next ? `${TIERS[next].name} adds a persistent vault.` : "",
    upgradeLine(tier.id),
  ]
    .filter(Boolean)
    .join("\n");
}

/** The fraction of the allowance that triggers the one soft nudge. */
export const NUDGE_AT = 0.7;

/**
 * The single mid-day nudge, or null.
 *
 * ONCE PER DAY, AND ONLY ON A CAPPED TIER. The caller is responsible for
 * remembering that it has been shown — `Meter.shouldNudge()` does that — because
 * a nudge that reappears every few decisions is not a nudge, it is nagging, and
 * the person it annoys most is the heavy user who was the likeliest to convert.
 *
 * It also says Free stays free. That is true, and saying it is what keeps the
 * line from reading as a threat.
 */
export function softNudge(licence = {}, used = 0) {
  const tier = tierFor(licence.tier);
  const allowance = dailyAllowance(licence);
  if (allowance === null) return null;
  if (used < Math.floor(allowance * NUDGE_AT)) return null;
  if (used >= allowance) return null; // past the limit, `quotaReached` speaks instead

  const next = nextTier(tier.id);
  if (!next) return null;

  return [
    `[cirvix] ${n(used)}/${n(allowance)} ${tier.name.toLowerCase()} decisions today.`,
    `Heavy users move to ${TIERS[next].name} for headroom` +
      (TIERS[next].persistentSecrets && !tier.persistentSecrets
        ? " + persistent secrets."
        : "."),
    tier.id === "free" ? "Free stays free forever." : "",
    "→ cirvix status",
  ]
    .filter(Boolean)
    .join("\n");
}
