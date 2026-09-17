/**
 * Referrals.
 *
 * Separate from invitations on purpose. An invitation says "join MY
 * organisation" and grants membership; a referral says "try this product" and
 * grants nothing. Building them as one thing is how a referral link quietly
 * becomes an access-control decision.
 *
 * DELIBERATELY BORING
 * -------------------
 * A code, a signup attributed to it, a qualification event, one reward. No
 * tiers, no multi-level anything, no balances that can be spent. Every rewards
 * economy starts simple and the complicated ones are complicated because
 * somebody gamed the simple one; there is no reason to arrive there early.
 *
 * ABUSE IS THE DESIGN CONSTRAINT
 * ------------------------------
 * The three attacks that matter on a referral system, and what stops each:
 *
 *   · self-referral — refused at attribution; the referrer cannot be the
 *     referred, checked on user AND on org, because one person owning two
 *     orgs is the cheap version of the same attack
 *   · replay — one referred party is attributed once, ever, even if the link
 *     is clicked a hundred times
 *   · reward-before-value — a signup earns nothing. Only a QUALIFYING event
 *     does, and qualification is defined by the product, not by the referrer
 *
 * None of that needs a fraud engine. It needs the rules to be in one place
 * with tests on them, which is what this file is.
 */

import { createHash, randomBytes } from "node:crypto";

export const REFERRAL_VERSION = 1;

/** What a referred org must do before anything is earned. */
export const QUALIFY = Object.freeze({
  VERIFIED: "email_verified",
  FIRST_DECISION: "first_decision_recorded",
  SUBSCRIBED: "subscription_started",
});

/** The one reward. Usage, not money — it cannot be cashed out or transferred. */
export const REWARD = Object.freeze({
  kind: "decision_allowance",
  amount: 5_000,
  note: "5,000 additional recorded decisions, one time, per qualified referral.",
});

/**
 * A referral code for an org.
 *
 * Derived, not random, so the same org always presents the same code and a
 * lost code is recoverable without a database lookup. Salted with the issuing
 * secret so codes cannot be enumerated from org ids, which are not secret.
 */
export function codeFor(orgId, { secret = "cirvix", length = 8 } = {}) {
  if (!orgId) throw new Error("A referral code needs an org.");
  const h = createHash("sha256").update(`${secret}:${orgId}`).digest("base64url");
  return h.replace(/[^a-zA-Z0-9]/g, "").slice(0, length).toUpperCase();
}

export function linkFor(orgId, { base = "https://www.cirvix.com", secret } = {}) {
  return `${base}/?ref=${codeFor(orgId, secret ? { secret } : {})}`;
}

/**
 * The ledger.
 *
 * In-memory here; the control plane persists the same shape. Kept as a class
 * so the rules live with the data rather than being re-implemented by whoever
 * writes the SQL.
 */
export class ReferralLedger {
  #byReferred = new Map();  // referred org -> attribution
  #records = [];
  #events = [];

  constructor({ secret = "cirvix", onEvent = () => {} } = {}) {
    this.secret = secret;
    this.onEvent = onEvent;
  }

  /**
   * Attributes a new org to a referrer.
   *
   * Returns a reason on refusal rather than throwing: a bad referral code is
   * an ordinary thing for a signup to carry, and a signup must never fail
   * because the marketing attribution did not work out.
   */
  attribute({ code, referredOrg, referredUser = null, referrerOrg = null, referrerUser = null, at = new Date().toISOString() }) {
    if (!referredOrg) return { ok: false, reason: "no_referred_org" };
    if (!code) return { ok: false, reason: "no_code" };

    if (this.#byReferred.has(referredOrg)) {
      return { ok: false, reason: "already_attributed", existing: this.#byReferred.get(referredOrg).referrerOrg };
    }
    /*
     * A code must resolve to a referrer, and the check is unconditional.
     *
     * It was guarded by `if (referrerOrg && …)`, so a caller that could not
     * resolve the code simply omitted the referrer and every check below was
     * skipped — an arbitrary string was attributed to nobody and counted as a
     * referral. Attribution without a verifiable referrer is not attribution,
     * so it is refused here rather than recorded as a fact.
     */
    if (!referrerOrg) return { ok: false, reason: "unresolved_code" };
    if (codeFor(referrerOrg, { secret: this.secret }) !== String(code).toUpperCase()) {
      return { ok: false, reason: "code_mismatch" };
    }
    /* Self-referral, on both axes. One person holding two orgs is the cheap
       version of the same attack, so the user check is not optional. */
    if (referrerOrg && referrerOrg === referredOrg) return { ok: false, reason: "self_referral" };
    if (referrerUser && referredUser && referrerUser === referredUser) return { ok: false, reason: "self_referral" };

    const rec = {
      v: REFERRAL_VERSION, code: String(code).toUpperCase(), referrerOrg, referrerUser,
      referredOrg, referredUser, attributedAt: at, qualifiedAt: null, qualifyingEvent: null,
      rewarded: false, reward: null,
    };
    this.#byReferred.set(referredOrg, rec);
    this.#records.push(rec);
    this.#emit("referral.attributed", rec, at);
    return { ok: true, record: rec };
  }

  /**
   * Marks a referred org as qualified, which is what earns the reward.
   *
   * A signup earns nothing. That is the whole anti-abuse position: creating
   * accounts is free, and anything rewarded on account creation will be.
   */
  qualify({ referredOrg, event, at = new Date().toISOString() }) {
    const rec = this.#byReferred.get(referredOrg);
    if (!rec) return { ok: false, reason: "not_attributed" };
    if (!Object.values(QUALIFY).includes(event)) return { ok: false, reason: "unknown_qualifying_event" };
    if (rec.qualifiedAt) return { ok: false, reason: "already_qualified" };

    rec.qualifiedAt = at;
    rec.qualifyingEvent = event;
    rec.rewarded = true;
    rec.reward = { ...REWARD };
    this.#emit("referral.qualified", rec, at);
    return { ok: true, record: rec, reward: rec.reward };
  }

  /** What one org has earned, and from whom. Never exposes the referred org's users. */
  forReferrer(orgId) {
    const mine = this.#records.filter((r) => r.referrerOrg === orgId);
    return {
      code: codeFor(orgId, { secret: this.secret }),
      link: linkFor(orgId, { secret: this.secret }),
      invited: mine.length,
      qualified: mine.filter((r) => r.qualifiedAt).length,
      rewardTotal: mine.filter((r) => r.rewarded).length * REWARD.amount,
      rewardKind: REWARD.kind,
      referrals: mine.map((r) => ({
        referredOrg: r.referredOrg,
        attributedAt: r.attributedAt,
        qualifiedAt: r.qualifiedAt,
        qualifyingEvent: r.qualifyingEvent,
        rewarded: r.rewarded,
      })),
    };
  }

  /** Every referral event, for the audit trail. */
  events() {
    return [...this.#events];
  }

  #emit(kind, rec, at) {
    const ev = {
      kind, at,
      referrerOrg: rec.referrerOrg, referredOrg: rec.referredOrg,
      qualifyingEvent: rec.qualifyingEvent ?? null,
      reward: rec.rewarded ? REWARD.kind : null,
    };
    this.#events.push(ev);
    this.onEvent(ev);
  }
}

/** A fresh secret for deriving codes. */
export function newReferralSecret() {
  return randomBytes(32).toString("hex");
}
