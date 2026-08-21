/**
 * The commercial gate, in one place.
 *
 * WHY THIS FILE EXISTS
 *
 * It used to live inline in `Pipeline.submit()` and nowhere else. `Guard` —
 * the shared decision core behind both `guard.wrap()` and the MCP gateway —
 * had no entitlement gate at all, so a Free-tier user going through either of
 * those paths was never metered. `Pipeline` had the gate but the CLI never
 * passed it a licence or a meter, so it never fired there either.
 *
 * The net effect was that the published Free limits were not enforced on any
 * path, and the upgrade prompt that the pricing depends on could not fire. The
 * cause was the same one this codebase has hit before: two decision cores, one
 * of which quietly grew a rule the other did not have.
 *
 * So the rule lives here, both cores call it, and neither can answer the
 * question differently.
 *
 * IT IS AN OVERRIDE, NOT AN EARLY RETURN
 *
 * The call is still parsed, classified and evaluated against policy first, and
 * the refusal is layered on top of that decision. That costs microseconds and
 * buys a record showing what policy WOULD have said, which is what an operator
 * wants when they discover they ran out mid-session.
 *
 * AN EXHAUSTED QUOTA DENIES
 *
 * It does not pass the call through unchecked. A security control that stops
 * enforcing when a counter runs out is not a degraded product, it is an absent
 * one, and the absence would be invisible exactly when it mattered.
 *
 * A GATED CALL IS NOT COUNTED
 *
 * Counting refusals would mean a user who hit the limit could never get back
 * under it.
 */

import { GATE, checkAgents, checkQuota } from "./entitlements.mjs";
import { DECISION } from "./decisions.mjs";

/**
 * Applies the quota and concurrent-agent gates to an already-made decision.
 *
 * All three of `licence`, `meter` and `agents` are optional. Supplying none of
 * them — which is what the conformance fixture, the test suite and any
 * embedding library caller do — returns the decision untouched, so this cannot
 * change policy semantics.
 *
 * @param {object}  decision  the decision policy produced
 * @param {object}  ctx
 * @param {object|null} ctx.licence
 * @param {object|null} ctx.meter    Meter — consulted, then incremented on a pass
 * @param {object|null} ctx.agents   AgentRegistry — concurrent agent tracking
 * @param {string}  ctx.agent        the agent making this call
 * @returns {object} the decision, overridden if a commercial limit was hit
 */
export function applyEntitlements(decision, { licence, meter, agents, agent }) {
  if (licence && meter) {
    const quota = checkQuota(licence, meter.used());
    if (quota.ok) {
      // Counted only once a real policy decision has been produced: that is
      // the thing being sold.
      meter.count(1);
    } else {
      return {
        ...decision,
        verdict: "deny",
        decision: DECISION.DENY,
        rule: "quota-exhausted",
        reason: quota.reason,
        remediation: quota.remediation,
        gate: GATE.QUOTA_EXHAUSTED,
        quota: { used: quota.used, allowance: quota.allowance, tier: quota.tier },
      };
    }
  }

  // Only an agent this session has not already seen can be a new one, or a
  // permitted agent's second call would read as a second agent and every tier
  // would be a one-call tier.
  if (licence && agents && !agents.has(agent)) {
    const seats = checkAgents(licence, agents.size());
    if (seats.ok) {
      agents.register(agent);
    } else {
      return {
        ...decision,
        verdict: "deny",
        decision: DECISION.DENY,
        rule: "agent-limit",
        reason: seats.reason,
        remediation: seats.remediation,
        gate: GATE.AGENT_LIMIT,
      };
    }
  }

  return decision;
}
