/**
 * Agent Behavioral Baseline & Anomaly Detection.
 *
 * Tracks normal tools, endpoints, action frequencies, and resource patterns
 * per agent, and detects significant statistical deviations.
 *
 * Example:
 *   FinanceBot normally uses: Stripe, Salesforce, PostgreSQL, Slack
 *   New behavior: AWS IAM, unknown MCP, external crypto API
 *   Verdict: BEHAVIORAL DEVIATION (Score: 97/100)
 */

export class BehavioralBaseline {
  constructor({
    agentId,
    normalTools = [],
    normalDomains = [],
    normalActions = [],
    anomalyThreshold = 75,
    minObservationsToEnforce = 10,
  } = {}) {
    this.agentId = agentId;
    this.normalTools = new Set(normalTools);
    this.normalDomains = new Set(normalDomains);
    this.normalActions = new Set(normalActions);
    this.anomalyThreshold = anomalyThreshold;
    this.minObservationsToEnforce = minObservationsToEnforce;
    this.observationCount = 0;
  }

  /**
   * Learns from an observed action.
   */
  learn({ tool = null, domain = null, action = null }) {
    this.observationCount += 1;
    if (tool) this.normalTools.add(tool);
    if (domain) this.normalDomains.add(domain);
    if (action) this.normalActions.add(action);
  }

  /**
   * Evaluates how severely an incoming action deviates from the baseline.
   *
   * @param {Object} call
   * @param {string} call.tool
   * @param {string} call.action
   * @param {string} call.resource
   * @returns {{ anomalyScore: number, isDeviation: boolean, reasons: string[] }}
   */
  scoreDeviation({ tool = null, action = null, resource = null }) {
    if (this.observationCount < this.minObservationsToEnforce && this.normalTools.size === 0) {
      return {
        anomalyScore: 0,
        isDeviation: false,
        reasons: ["Insufficient baseline history to calculate deviation"],
      };
    }

    let score = 0;
    const reasons = [];

    // Check unknown tool
    if (tool && !this.normalTools.has(tool)) {
      score += 45;
      reasons.push(`Unknown tool '${tool}' never observed in baseline for agent ${this.agentId}`);
    }

    // Check unknown action
    if (action && this.normalActions.size > 0 && !this.normalActions.has(action)) {
      score += 25;
      reasons.push(`Unusual action '${action}' outside baseline profile`);
    }

    // Check unknown external domain/destination in resource
    if (resource && (resource.startsWith("http://") || resource.startsWith("https://"))) {
      try {
        const url = new URL(resource);
        const host = url.hostname.toLowerCase();
        if (this.normalDomains.size > 0 && !this.normalDomains.has(host)) {
          score += 40;
          reasons.push(`Unseen network destination '${host}' outside baseline domains`);
        }
      } catch {
        // Not a standard URL
      }
    }

    const anomalyScore = Math.min(100, score);
    const isDeviation = anomalyScore >= this.anomalyThreshold;

    return {
      anomalyScore,
      isDeviation,
      reasons,
    };
  }
}
