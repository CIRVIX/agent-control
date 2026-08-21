/**
 * What each tier is entitled to — the single source of truth in the runtime.
 *
 * THE NUMBERS HERE MUST MATCH THE PRICING PAGE. Two copies of a limit
 * eventually disagree, and the direction they disagree in is always the one
 * that embarrasses you: a customer who paid for 15,000 and gets 2,000. The
 * pricing page renders from `assets/pricing.js`; this table is the runtime's
 * mirror of it, and `entitlements.test.mjs` pins every figure so a change on
 * one side without the other fails a test rather than a customer.
 *
 * WHAT HAPPENS WHEN THE QUOTA RUNS OUT
 *
 * The call is DENIED. It is not allowed through unchecked.
 *
 * That is worth stating loudly because the alternative is genuinely tempting —
 * "don't break the customer's production over billing" — and it is the wrong
 * answer for this product specifically. A security control that stops
 * enforcing when a counter runs out is not a degraded product, it is an
 * absent one: the agent keeps running, the tool calls keep landing, and
 * nothing is checking them. The failure would be invisible precisely when it
 * mattered. Everywhere else in this codebase an indeterminate or exhausted
 * state resolves to a refusal, and a commercial limit is not the place to
 * invent an exception.
 *
 * So over-quota is a deny with its own reason code, which is loud, recoverable
 * (upgrade, or wait for the reset), and never silently permissive.
 *
 * WHAT THIS CANNOT DO, stated plainly
 *
 * The counter lives on the user's machine, in a file, inside a package they
 * have on disk. Anyone who wants to edit it can. This is honour-system
 * metering and calling it anything else would be dishonest.
 *
 * It is still worth having: the overwhelming majority of users never touch it,
 * the prompt at the limit is the conversion moment the pricing depends on, and
 * the features that genuinely cannot be faked locally — shared policy, team
 * approvals, org vault, hosted audit — are gated on the server side where
 * bypassing them is not a matter of editing a JSON file.
 */

/** Ordered least → most capable. Used for `atLeast` comparisons. */
export const TIER_ORDER = ["free", "starter", "pro", "team", "enterprise"];

/**
 * `decisionsPerDay` is per SEAT for tiers where `perSeat` is true, and
 * absolute otherwise. `null` means uncapped.
 *
 * `agents` is the number of concurrent agent processes; `null` is unlimited.
 *
 * WHICH OF THESE FIELDS ACTUALLY ENFORCE SOMETHING
 *
 * Not all of them do, and the ones that do not were sold on the pricing page
 * as though they did. A number in this table is a promise; nothing here makes
 * it true by itself. Keep this list honest when adding a field.
 *
 *   ENFORCED locally, by entitlement-gate.mjs:
 *     decisionsPerDay, agents
 *
 *   ENFORCED, but by architecture rather than by this table:
 *     persistentSecrets — the local Vault holds material in process memory for
 *     the life of a run, so a free handle cannot survive a restart whatever
 *     this field says. Persistence is a control-plane feature: SecretsClient,
 *     not Vault.
 *
 *   DESCRIPTIVE ONLY — read by upgrade.mjs and prompts.mjs to say what a tier
 *   would give you, and by nothing that enforces:
 *     auditRetentionHours — nothing prunes the local chain, on any tier. It is
 *       hash-linked, and truncating it costs verifiability back to genesis, so
 *       this is a deliberate hold rather than an oversight. The pricing page
 *       now reads "life of deployment" on every tier, which is what the code
 *       does; the paid ladder is hosted retention and export.
 *     secretTtlHours — Vault.issue() accepts a ttlSeconds and no caller passes
 *       one derived from the tier.
 *     policyPacks — not counted anywhere.
 *     sharedPolicy, approvals, attestation, shareableReplay — control-plane
 *       features, enforced server-side where editing a local JSON file cannot
 *       reach them.
 *
 * `persistentSecrets: false` means handles do not survive a restart — the
 * single strongest conversion lever for anyone who actually uses secrets, and
 * the one free-tier limit that is felt within a day rather than a week.
 */
export const TIERS = {
  free: {
    id: "free",
    name: "Free",
    decisionsPerDay: 100,
    perSeat: false,
    agents: 1,
    seatsIncluded: 1,
    auditRetentionHours: 12,
    persistentSecrets: false,
    secretTtlHours: 2,
    approvals: false,
    attestation: false,
    shareableReplay: false,
    policyPacks: 2,
    sharedPolicy: false,
  },
  starter: {
    id: "starter",
    name: "Starter",
    decisionsPerDay: 1_500,
    perSeat: false,
    agents: 2,
    seatsIncluded: 1,
    auditRetentionHours: 24 * 7,
    persistentSecrets: true,
    secretTtlHours: null,
    approvals: false,
    attestation: false,
    shareableReplay: "local",
    policyPacks: 6,
    sharedPolicy: false,
  },
  pro: {
    id: "pro",
    name: "Pro",
    decisionsPerDay: 12_000,
    perSeat: false,
    agents: 8,
    seatsIncluded: 1,
    auditRetentionHours: 24 * 90,
    persistentSecrets: true,
    secretTtlHours: null,
    approvals: true,
    attestation: true,
    shareableReplay: "full",
    policyPacks: null,
    sharedPolicy: "basic",
  },
  team: {
    id: "team",
    name: "Team",
    decisionsPerDay: 40_000,
    perSeat: true,
    agents: null,
    seatsIncluded: 3,
    auditRetentionHours: 24 * 365,
    persistentSecrets: true,
    secretTtlHours: null,
    approvals: true,
    attestation: true,
    shareableReplay: "team",
    policyPacks: null,
    sharedPolicy: "full",
  },
  enterprise: {
    id: "enterprise",
    name: "Enterprise",
    // Not sold from a rate card. `null` is "uncapped", never "zero" — the gate
    // below has to treat it as unlimited or an Enterprise contract would be
    // the most restricted tier in the table.
    decisionsPerDay: null,
    perSeat: false,
    agents: null,
    seatsIncluded: null,
    auditRetentionHours: null,
    persistentSecrets: true,
    secretTtlHours: null,
    approvals: true,
    attestation: true,
    shareableReplay: "team",
    policyPacks: null,
    sharedPolicy: "full",
  },
};

/** The tier an unlicensed install runs on. Free, always — never a paid default. */
export const DEFAULT_TIER = "free";

export function tierFor(id) {
  return TIERS[String(id ?? "").toLowerCase()] ?? TIERS[DEFAULT_TIER];
}

/** True when `id` is at least as capable as `required`. */
export function tierAtLeast(id, required) {
  const a = TIER_ORDER.indexOf(tierFor(id).id);
  const b = TIER_ORDER.indexOf(tierFor(required).id);
  return a >= 0 && b >= 0 && a >= b;
}

/**
 * The daily decision allowance for a licence, seats included.
 *
 * Seats below the tier's minimum are raised to it rather than rejected: a
 * Team licence recording two seats is a data problem, and answering it by
 * cutting the customer's allowance is the wrong way round.
 */
export function dailyAllowance(licence = {}) {
  const tier = tierFor(licence.tier);
  if (tier.decisionsPerDay === null) return null; // uncapped
  if (!tier.perSeat) return tier.decisionsPerDay;
  const seats = Math.max(Number(licence.seats) || 0, tier.seatsIncluded ?? 1);
  return tier.decisionsPerDay * seats;
}

/** Reasons a call can be refused for commercial rather than policy grounds. */
export const GATE = {
  QUOTA_EXHAUSTED: "quota_exhausted",
  AGENT_LIMIT: "agent_limit",
};

/**
 * Whether one more decision may be recorded.
 *
 * `used` is today's count. Returns the shape the pipeline needs to build a
 * refusal without re-deriving anything.
 */
export function checkQuota(licence, used) {
  const tier = tierFor(licence.tier);
  const allowance = dailyAllowance(licence);
  if (allowance === null) {
    return { ok: true, allowance: null, used, remaining: null, tier: tier.id };
  }
  const remaining = Math.max(0, allowance - used);
  if (used >= allowance) {
    return {
      ok: false,
      gate: GATE.QUOTA_EXHAUSTED,
      allowance,
      used,
      remaining: 0,
      tier: tier.id,
      reason:
        `Daily limit reached: ${allowance.toLocaleString("en-US")} decisions on ${tier.name}. ` +
        `The counter resets at 00:00 UTC.`,
      remediation:
        tier.id === "enterprise"
          ? "Contact your account owner."
          : `Run \`cirvix upgrade ${nextTier(tier.id)}\` for a higher daily allowance.`,
    };
  }
  return { ok: true, allowance, used, remaining, tier: tier.id };
}

/** Whether another concurrent agent may start. */
export function checkAgents(licence, activeAgents) {
  const tier = tierFor(licence.tier);
  if (tier.agents === null) return { ok: true, limit: null, active: activeAgents };
  if (activeAgents >= tier.agents) {
    return {
      ok: false,
      gate: GATE.AGENT_LIMIT,
      limit: tier.agents,
      active: activeAgents,
      tier: tier.id,
      reason: `${tier.name} allows ${tier.agents} concurrent agent${tier.agents === 1 ? "" : "s"}.`,
      remediation: `Run \`cirvix upgrade ${nextTier(tier.id)}\` for more.`,
    };
  }
  return { ok: true, limit: tier.agents, active: activeAgents };
}

/** The tier a user would move to next. Enterprise has nowhere above it. */
export function nextTier(id) {
  const i = TIER_ORDER.indexOf(tierFor(id).id);
  return i >= 0 && i < TIER_ORDER.length - 1 ? TIER_ORDER[i + 1] : TIER_ORDER[TIER_ORDER.length - 1];
}

/**
 * Whether a named capability is available on this licence.
 *
 * Feature keys mirror the pricing matrix. An unknown key returns false, so a
 * capability added to the product but not to this table is unavailable rather
 * than accidentally universal — the same fail-closed rule the permission
 * layer uses.
 */
export function can(licence, feature) {
  const tier = tierFor(licence?.tier);
  switch (feature) {
    case "persistentSecrets": return tier.persistentSecrets === true;
    case "approvals": return tier.approvals === true;
    case "attestation": return tier.attestation === true;
    case "sharedPolicy": return tier.sharedPolicy !== false;
    case "shareableReplay": return tier.shareableReplay !== false;
    default: return false;
  }
}

/** UTC calendar day key, `YYYY-MM-DD`. The reset boundary the copy promises. */
export function dayKey(at = new Date()) {
  const d = at instanceof Date ? at : new Date(at);
  return d.toISOString().slice(0, 10);
}
