/**
 * `cirvix upgrade [tier]` — show where the limits are, and how to lift them.
 *
 *   cirvix upgrade            what you are on, what you have used, what is next
 *   cirvix upgrade pro        the checkout link for a specific tier
 *   cirvix upgrade --seats 5  Team, priced for a real number of seats
 *
 * WHAT THIS DELIBERATELY DOES NOT DO
 *
 * It does not take a payment, and it does not write a paid licence. It prints
 * a URL. The licence file is written by the checkout callback, because a
 * command that could grant itself Pro is not an entitlement system — and the
 * one thing worse than honour-system metering is metering with a documented
 * bypass in its own CLI.
 *
 * The tone is deliberately flat. Every prompt this product prints appears in
 * the middle of somebody's terminal session while they were trying to do
 * something else, and marketing language in that position reads as an
 * interruption rather than an offer. State the limit, state the number, give
 * the command, stop.
 */

import { TIERS, TIER_ORDER, dailyAllowance, nextTier, tierFor } from "../core/entitlements.mjs";
import { Meter, readLicence } from "../core/meter.mjs";

/** Published prices. Mirrors the pricing page; pinned by the test suite. */
export const PRICING = {
  free: { monthly: 0, annual: 0 },
  starter: { monthly: 29, annual: 290 },
  pro: { monthly: 79, annual: 790 },
  team: { monthly: 149, annual: 1490, perSeat: true, minSeats: 3 },
  enterprise: { monthly: null, annual: null, custom: true },
};

const CHECKOUT_BASE = "https://www.cirvix.com/pricing.html";

export function checkoutUrl(tier, { seats } = {}) {
  const t = tierFor(tier);
  if (t.id === "free") return CHECKOUT_BASE;
  const params = new URLSearchParams({ plan: t.id });
  if (seats && PRICING[t.id]?.perSeat) params.set("seats", String(seats));
  return `${CHECKOUT_BASE}?${params.toString()}`;
}

const money = (n) => `$${n.toLocaleString("en-US")}`;

/** One line describing what a tier costs. */
export function priceLine(tierId, seats) {
  const p = PRICING[tierId];
  if (!p) return "";
  if (p.custom) return "Custom — scoped to your deployment";
  if (p.monthly === 0) return "Free, forever";
  if (p.perSeat) {
    const n = Math.max(Number(seats) || 0, p.minSeats);
    return `${money(p.monthly)}/seat/mo · ${money(p.monthly * n)}/mo for ${n} seats · ${money(p.annual)}/seat/yr`;
  }
  return `${money(p.monthly)}/mo · ${money(p.annual)}/yr (2 months free)`;
}

/** What a tier lifts, relative to the one below it. Only real differences. */
function liftsOver(fromId, toId) {
  const from = tierFor(fromId);
  const to = tierFor(toId);
  const out = [];

  const fromAllow = dailyAllowance({ tier: from.id, seats: from.seatsIncluded });
  const toAllow = dailyAllowance({ tier: to.id, seats: to.seatsIncluded });
  if (toAllow === null) out.push("Uncapped decisions");
  else if (fromAllow !== null && toAllow > fromAllow) {
    out.push(
      `${toAllow.toLocaleString("en-US")} decisions/day` +
        (to.perSeat ? ` (${to.decisionsPerDay.toLocaleString("en-US")} per seat)` : "") +
        ` — up from ${fromAllow.toLocaleString("en-US")}`,
    );
  }

  if (to.agents === null && from.agents !== null) out.push("Unlimited concurrent agents");
  else if (to.agents !== null && from.agents !== null && to.agents > from.agents) {
    out.push(`${to.agents} concurrent agents — up from ${from.agents}`);
  }

  if (to.persistentSecrets && !from.persistentSecrets) {
    out.push("Secret handles survive a restart");
  }
  if (to.approvals && !from.approvals) out.push("Human-in-the-loop approvals");
  if (to.attestation && !from.attestation) out.push("Attestation headers");
  if (to.sharedPolicy !== false && from.sharedPolicy === false) out.push("Shared policy + RBAC");

  if (to.auditRetentionHours === null) out.push("Unlimited audit retention");
  else if (from.auditRetentionHours !== null && to.auditRetentionHours > from.auditRetentionHours) {
    const days = Math.round(to.auditRetentionHours / 24);
    out.push(`${days === 1 ? "24 hours" : `${days} days`} of audit history`);
  }
  return out;
}

/**
 * @param {string[]} argv  tokens after `upgrade`
 */
export async function upgrade(argv = [], { cwd = process.cwd(), write = (s) => process.stdout.write(s) } = {}) {
  const seatsFlag = argv.indexOf("--seats");
  const seats = seatsFlag > -1 ? Number(argv[seatsFlag + 1]) || undefined : undefined;
  const requested = argv.find((a) => !a.startsWith("--") && TIER_ORDER.includes(a.toLowerCase()));

  const licence = readLicence(cwd);
  const current = tierFor(licence.tier);
  const meter = new Meter({ cwd });
  const used = meter.used();
  const allowance = dailyAllowance(licence);

  const lines = [];
  lines.push("");
  lines.push(`  Current plan   ${current.name}`);
  lines.push(
    `  Today          ${used.toLocaleString("en-US")}` +
      (allowance === null ? " decisions (uncapped)" : ` of ${allowance.toLocaleString("en-US")} decisions`),
  );
  if (allowance !== null) {
    const pct = allowance > 0 ? Math.round((used / allowance) * 100) : 0;
    lines.push(`  Resets         00:00 UTC${pct >= 80 ? `  ·  ${pct}% used` : ""}`);
  }
  lines.push("");

  const target = requested ?? nextTier(current.id);

  if (target === current.id) {
    lines.push(`  ${current.name} is the highest tier. Nothing to upgrade to.`);
    lines.push("");
    write(lines.join("\n") + "\n");
    return { tier: current.id, used, allowance, url: null };
  }

  const to = tierFor(target);
  lines.push(`  ${current.name} → ${to.name}`);
  lines.push(`  ${priceLine(to.id, seats)}`);
  lines.push("");
  for (const lift of liftsOver(current.id, to.id)) lines.push(`    · ${lift}`);
  lines.push("");

  const url = checkoutUrl(to.id, { seats });
  lines.push(`  ${url}`);
  lines.push("");
  // Said once, plainly, because it is true and because a free tier that keeps
  // implying it is about to end is not a free tier.
  lines.push("  The local runtime stays free. This lifts the limits on it.");
  lines.push("");

  write(lines.join("\n") + "\n");
  return { tier: current.id, target: to.id, used, allowance, url };
}

/** The one-off notice printed when a limit is actually hit. */
export function limitNotice(gateResult, { tier, seats } = {}) {
  const to = nextTier(tier ?? "free");
  return [
    `[cirvix] ${gateResult.reason}`,
    `          ${priceLine(to, seats)} — cirvix upgrade ${to}`,
  ].join("\n");
}

export { TIERS };
