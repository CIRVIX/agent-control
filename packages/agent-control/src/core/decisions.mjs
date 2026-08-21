/**
 * The decision vocabulary.
 *
 * Five outcomes, one place. The policy engine, the gateway, the UDS runtime,
 * the SDK, the audit record, and the console all name the same thing the same
 * way, because a control plane where "hold" and "require_approval" are the same
 * state under two names is a control plane whose logs cannot be joined.
 *
 *   ALLOW             forward the call unchanged
 *   DENY              refuse it, legibly, with a remediation the agent can act on
 *   REQUIRE_APPROVAL  suspend it for a named human; it may still happen
 *   SANITIZE          forward it, but not as written — see below
 *   AUDIT_ONLY        record what would have happened; do not enforce
 *
 * TWO OF THESE ARE NEW AND BOTH ARE EASY TO GET WRONG.
 *
 * SANITIZE is a permit with a transform attached, not a softer allow. It exists
 * because the interesting cases are not "block this call" — they are "make this
 * call safe": strip the credential the model pasted into an argument, drop the
 * `IGNORE PREVIOUS INSTRUCTIONS` block out of a fetched web page before it
 * reaches the context window. It therefore OUTRANKS a plain permit. If one rule
 * says a payload must be cleaned and another says the call is fine, the call is
 * fine *and the payload still gets cleaned*. Letting `permit` win there would
 * mean any allow rule silently disables every sanitizer, which is the same
 * class of bug as a permit overriding a forbid.
 *
 * AUDIT_ONLY is the one with a genuine security trap in it, so it is
 * deliberately NOT a competing effect in the precedence chain.
 *
 * The naive design makes `audit_only` a rule effect that wins like any other.
 * That hands anyone who can add a rule a bypass for every prohibition in the
 * file: mark the tool `audit_only` and the forbid protecting it stops
 * enforcing. So here:
 *
 *   - A rule with effect `audit_only` OBSERVES. It records that it matched and
 *     contributes no authorization at all. It can never turn a deny into an
 *     allow, because it never produces an allow.
 *   - The AUDIT_ONLY *outcome* comes from engine mode, not from a rule. Running
 *     in `audit` mode computes the real verdict, records it, and suppresses
 *     enforcement — the honest shadow deployment. It is a whole-engine setting,
 *     visible in `cirvix status`, and every record written in that mode carries
 *     `enforced: false` so nobody later mistakes a shadow run for a protected
 *     one.
 */

import { RISK, riskAtLeast } from "./risk.mjs";

/** The five outcomes. */
export const DECISION = {
  ALLOW: "allow",
  DENY: "deny",
  REQUIRE_APPROVAL: "require_approval",
  SANITIZE: "sanitize",
  AUDIT_ONLY: "audit_only",
};

/**
 * Rule effects, which are not the same set as outcomes.
 *
 * `forbid`/`permit`/`hold` are the existing on-disk vocabulary and are kept
 * verbatim — policy files in the wild use them and renaming them would be a
 * silent breaking change to every deployed rule set.
 */
export const EFFECT = {
  PERMIT: "permit",
  FORBID: "forbid",
  HOLD: "hold",
  SANITIZE: "sanitize",
  AUDIT_ONLY: "audit_only",
};

/**
 * Legacy verdicts. The engine still returns these; `toDecision` widens them.
 * Kept as a separate name rather than aliased so it is obvious at a call site
 * which vocabulary is in play.
 */
export const VERDICT = { PERMIT: "permit", DENY: "deny", HOLD: "hold" };

const VERDICT_TO_DECISION = {
  permit: DECISION.ALLOW,
  deny: DECISION.DENY,
  hold: DECISION.REQUIRE_APPROVAL,
  sanitize: DECISION.SANITIZE,
  audit_only: DECISION.AUDIT_ONLY,
};

const DECISION_TO_VERDICT = {
  [DECISION.ALLOW]: VERDICT.PERMIT,
  [DECISION.SANITIZE]: VERDICT.PERMIT,
  [DECISION.AUDIT_ONLY]: VERDICT.PERMIT,
  [DECISION.DENY]: VERDICT.DENY,
  [DECISION.REQUIRE_APPROVAL]: VERDICT.HOLD,
};

export function toDecision(verdict) {
  return VERDICT_TO_DECISION[String(verdict ?? "").toLowerCase()] ?? DECISION.DENY;
}

/**
 * Narrows a decision to the three-state verdict the transports understand.
 *
 * SANITIZE and AUDIT_ONLY both narrow to `permit`, because both forward the
 * call — the difference lives in the flags that ride alongside, not in whether
 * the call proceeds. A transport that only knows permit/deny/hold therefore
 * behaves correctly by default instead of failing open on a value it has never
 * seen.
 */
export function toVerdict(decision) {
  return DECISION_TO_VERDICT[String(decision ?? "").toLowerCase()] ?? VERDICT.DENY;
}

/** True when the call proceeds to the upstream in some form. */
export function isForwarded(decision) {
  return (
    decision === DECISION.ALLOW ||
    decision === DECISION.SANITIZE ||
    decision === DECISION.AUDIT_ONLY
  );
}

/** True when a human can still turn this into a forwarded call. */
export function isAppealable(decision) {
  return decision === DECISION.REQUIRE_APPROVAL;
}

/* -------------------------------------------------------------------------- */
/*  Precedence                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Most authoritative first.
 *
 * `audit_only` is absent on purpose — see the header. It is an observation, and
 * observations do not compete with decisions.
 */
export const EFFECT_PRECEDENCE = [
  EFFECT.FORBID,
  EFFECT.HOLD,
  EFFECT.SANITIZE,
  EFFECT.PERMIT,
];

export function effectRank(effect) {
  const i = EFFECT_PRECEDENCE.indexOf(String(effect ?? "").toLowerCase());
  // Unknown effects rank last and are treated as contributing nothing, which
  // keeps a policy file from a newer version from loosening an older engine.
  return i === -1 ? EFFECT_PRECEDENCE.length : i;
}

/** True when `a` beats `b`. Equal effects tie and first-match wins. */
export function outranks(a, b) {
  return effectRank(a) < effectRank(b);
}

/* -------------------------------------------------------------------------- */
/*  Engine mode                                                                */
/* -------------------------------------------------------------------------- */

export const MODE = {
  /** Decisions are enforced. The default, and the only mode that protects anything. */
  ENFORCE: "enforce",
  /** Decisions are computed and recorded; nothing is blocked. */
  AUDIT: "audit",
};

/**
 * Applies engine mode to a decision.
 *
 * In `audit` mode the computed decision is preserved as `wouldHave` and the
 * effective decision becomes AUDIT_ONLY, with `enforced: false`. Nothing is
 * discarded: the point of a shadow deployment is to answer "what would this
 * rule set have broken", and that question needs the original answer intact.
 *
 * @returns {object} the decision, possibly downgraded, always carrying `enforced`
 */
export function applyMode(decision, mode = MODE.ENFORCE) {
  const computed = decision.decision ?? toDecision(decision.verdict);

  if (mode !== MODE.AUDIT) {
    return { ...decision, decision: computed, enforced: true, mode: MODE.ENFORCE };
  }

  return {
    ...decision,
    decision: DECISION.AUDIT_ONLY,
    // The transports read `verdict`; in audit mode every call must proceed.
    verdict: VERDICT.PERMIT,
    enforced: false,
    mode: MODE.AUDIT,
    wouldHave: {
      decision: computed,
      verdict: decision.verdict,
      rule: decision.rule ?? null,
      reason: decision.reason ?? null,
    },
    reason:
      computed === DECISION.ALLOW
        ? decision.reason
        : `Audit mode: this call was allowed to proceed. Enforcing, it would have been ${String(computed).toUpperCase()} by ${decision.rule ?? "default-deny"}.`,
  };
}

/* -------------------------------------------------------------------------- */
/*  Risk posture                                                               */
/* -------------------------------------------------------------------------- */

/**
 * Raises a decision to meet a risk floor.
 *
 * The risk engine's posture is a FLOOR, never a ceiling: it can escalate an
 * allow to an approval, and it can never de-escalate a deny to an allow. That
 * asymmetry is what lets the risk table be tuned without anyone auditing it as
 * a second, shadow policy — the worst it can do is ask for more scrutiny than
 * necessary.
 *
 * A rule that explicitly names the call wins over the floor, because the
 * operator who wrote it knew something a generic table cannot. `escalate` is
 * therefore applied only when the decision came from default-deny or from a
 * rule that opted in with `respectRiskFloor`.
 */
export function escalateForRisk(decision, risk, { floor = RISK.HIGH } = {}) {
  if (!risk || decision.decision === DECISION.DENY) return decision;
  if (decision.explicit && !decision.respectRiskFloor) return decision;

  if (risk.level === RISK.CRITICAL) {
    return {
      ...decision,
      decision: DECISION.DENY,
      verdict: VERDICT.DENY,
      riskEscalated: true,
      reason: `Risk is CRITICAL and no rule explicitly permits it. ${risk.reason}`,
      remediation:
        "If this call is intended, add an explicit permit rule naming it — a CRITICAL call should never be allowed by a wildcard.",
    };
  }

  if (riskAtLeast(risk.level, floor) && decision.decision === DECISION.ALLOW) {
    return {
      ...decision,
      decision: DECISION.REQUIRE_APPROVAL,
      verdict: VERDICT.HOLD,
      riskEscalated: true,
      reason: `Risk is ${String(risk.level).toUpperCase()}, which requires approval under the current posture. ${risk.reason}`,
    };
  }

  return decision;
}

/** Terminal-friendly label. One spelling, everywhere. */
export function decisionLabel(decision) {
  return String(decision ?? "unknown").toUpperCase().replace(/_/g, " ");
}
