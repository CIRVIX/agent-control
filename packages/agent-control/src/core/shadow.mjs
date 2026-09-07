/**
 * Shadow Mode Evaluator.
 *
 * Non-blocking policy evaluation allowing real agent actions to proceed
 * while recording counterfactual decisions ("Would Allow", "Would Block",
 * "Would Require Approval", "Would Quarantine") for safe policy rollout.
 */

import { DECISION } from "./decisions.mjs";

export class ShadowEngine {
  constructor({ logSink = () => {} } = {}) {
    this.logSink = logSink;
    this.metrics = {
      total: 0,
      wouldAllow: 0,
      wouldBlock: 0,
      wouldRequireApproval: 0,
      wouldQuarantine: 0,
      policiesTriggered: new Map(),
    };
    this.shadowLog = [];
  }

  /**
   * Evaluates what Cirvix WOULD have decided without blocking execution.
   *
   * @param {Object} callParams - Request details
   * @param {Function} policyEvaluator - Underlying evaluator function returning decision
   * @returns {Object} Hypothetical decision record
   */
  evaluateShadow(callParams, policyEvaluator) {
    const ts = new Date().toISOString();
    let hypotheticalDecision = DECISION.ALLOW;
    let ruleMatched = null;
    let riskLevel = "LOW";
    let reason = "Hypothetical shadow evaluation";

    try {
      const evaluation = policyEvaluator(callParams);
      hypotheticalDecision = evaluation.verdict ?? evaluation.decision ?? DECISION.ALLOW;
      ruleMatched = evaluation.rule ?? null;
      riskLevel = evaluation.risk ?? "LOW";
      reason = evaluation.reason ?? reason;
    } catch (err) {
      hypotheticalDecision = DECISION.DENY;
      reason = `Shadow evaluation error: ${err.message}`;
    }

    this.metrics.total += 1;
    if (hypotheticalDecision === DECISION.ALLOW) {
      this.metrics.wouldAllow += 1;
    } else if (hypotheticalDecision === DECISION.DENY) {
      this.metrics.wouldBlock += 1;
    } else if (hypotheticalDecision === DECISION.REQUIRE_APPROVAL) {
      this.metrics.wouldRequireApproval += 1;
    } else if (hypotheticalDecision === DECISION.QUARANTINE) {
      this.metrics.wouldQuarantine += 1;
    }

    if (ruleMatched) {
      const count = this.metrics.policiesTriggered.get(ruleMatched) ?? 0;
      this.metrics.policiesTriggered.set(ruleMatched, count + 1);
    }

    const record = {
      ts,
      call: callParams,
      hypotheticalDecision,
      ruleMatched,
      riskLevel,
      reason,
    };

    this.shadowLog.push(record);
    if (this.shadowLog.length > 500) {
      this.shadowLog.shift();
    }

    this.logSink(record);
    return record;
  }

  getSummary() {
    return {
      totalEvaluated: this.metrics.total,
      wouldAllow: this.metrics.wouldAllow,
      wouldBlock: this.metrics.wouldBlock,
      wouldRequireApproval: this.metrics.wouldRequireApproval,
      wouldQuarantine: this.metrics.wouldQuarantine,
      triggeredPolicies: Object.fromEntries(this.metrics.policiesTriggered),
      logSnippet: this.shadowLog.slice(-10),
    };
  }
}
