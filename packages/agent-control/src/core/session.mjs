/**
 * Stateful Session Security & Action Chain Reasoning.
 *
 * Prevents multi-step attacks where each individual call may appear innocuous
 * in isolation, but the sequence forms an exfiltration or reconnaissance attack.
 *
 * Example:
 *   READ customer.csv (allowed)
 *          ↓
 *   compress / encode data (allowed)
 *          ↓
 *   POST external endpoint (BLOCKED: Data Exfiltration Chain)
 */

import { RISK } from "./risk.mjs";

export const CHAIN_TYPES = {
  EXFILTRATION: "DATA_EXFILTRATION",
  RECONNAISSANCE: "RECONNAISSANCE",
  PRIVILEGE_ESCALATION: "PRIVILEGE_ESCALATION",
};

/**
 * Tracks session state, action history, taint propagation, and risk accumulation.
 */
export class SessionTracker {
  constructor(sessionId, { agentId = null, maxHistory = 100 } = {}) {
    this.sessionId = sessionId;
    this.agentId = agentId;
    this.history = [];
    this.maxHistory = maxHistory;
    this.cumulativeRisk = 0;
    this.taint = {
      readSensitiveData: false,
      readSecrets: false,
      encodedData: false,
      accessedInternalNetwork: false,
    };
    this.status = "active"; // 'active' | 'quarantined' | 'terminated'
    this.quarantineReason = null;
    this.detectedChains = [];
  }

  /**
   * Records a step in the session and analyzes emerging action chains.
   *
   * @param {Object} step
   * @param {string} step.action - e.g. "fs:read", "net:post", "exec:run"
   * @param {string} step.resource - Target path or URL
   * @param {string} step.tool - Tool name
   * @param {string} step.decision - ALLOW, DENY, etc.
   * @param {string} step.risk - LOW, MEDIUM, HIGH, CRITICAL
   * @returns {{ suspicious: boolean, chainDetected?: string, reason?: string, risk: number }}
   */
  recordStep({ action, resource = "", tool = "", decision = "ALLOW", risk = RISK.LOW }) {
    const ts = new Date().toISOString();
    const entry = { action, resource, tool, decision, risk, ts };

    this.history.push(entry);
    if (this.history.length > this.maxHistory) {
      this.history.shift();
    }

    // Accumulate risk based on severity
    const rLower = String(risk ?? "low").toLowerCase();
    const riskPoints = {
      low: 1,
      medium: 5,
      high: 15,
      critical: 40,
    }[rLower] ?? 1;

    this.cumulativeRisk = Math.min(100, this.cumulativeRisk + riskPoints);

    // Update taint flags
    const resLower = String(resource).toLowerCase();
    const actLower = String(action).toLowerCase();

    if (
      actLower.includes("read") &&
      (resLower.includes("customer") ||
        resLower.includes(".env") ||
        resLower.includes("secret") ||
        resLower.includes("token") ||
        resLower.includes("credential") ||
        resLower.includes("users") ||
        resLower.includes("passwd"))
    ) {
      this.taint.readSensitiveData = true;
    }

    if (actLower.includes("secret") || resLower.includes("secret") || resLower.includes("key")) {
      this.taint.readSecrets = true;
    }

    if (
      actLower.includes("compress") ||
      actLower.includes("encode") ||
      resLower.includes(".tar") ||
      resLower.includes(".zip") ||
      resLower.includes("base64")
    ) {
      this.taint.encodedData = true;
    }

    if (actLower.includes("net") || resLower.startsWith("http://") || resLower.startsWith("https://")) {
      if (resLower.includes("169.254.") || resLower.includes("10.") || resLower.includes("192.168.")) {
        this.taint.accessedInternalNetwork = true;
      }
    }

    // Check for exfiltration chain:
    // Session previously read sensitive data/secrets -> now attempting external egress
    const isEgress = actLower.includes("net") || actLower.includes("egress") || actLower.includes("post") || actLower.includes("curl");
    const isExternalDest = resLower.startsWith("http://") || resLower.startsWith("https://");

    if ((this.taint.readSensitiveData || this.taint.readSecrets) && isEgress && isExternalDest) {
      const chain = {
        type: CHAIN_TYPES.EXFILTRATION,
        detectedAt: ts,
        reason: `Exfiltration sequence detected: Agent read sensitive resources earlier in session and is now egressing to '${resource}'`,
      };
      this.detectedChains.push(chain);
      return {
        suspicious: true,
        chainDetected: CHAIN_TYPES.EXFILTRATION,
        reason: chain.reason,
        risk: this.cumulativeRisk,
      };
    }

    // Check for reconnaissance chain:
    // Rapid multiple reads of environment/user tables followed by command execution
    if (this.history.length >= 3) {
      const last3 = this.history.slice(-3);
      const isReconSequence =
        last3[0].action.includes("read") &&
        last3[1].action.includes("read") &&
        last3[2].action.includes("exec");

      if (isReconSequence && (this.taint.readSecrets || this.taint.readSensitiveData)) {
        const chain = {
          type: CHAIN_TYPES.RECONNAISSANCE,
          detectedAt: ts,
          reason: "Reconnaissance sequence: Probing sensitive files followed by shell command execution",
        };
        this.detectedChains.push(chain);
        return {
          suspicious: true,
          chainDetected: CHAIN_TYPES.RECONNAISSANCE,
          reason: chain.reason,
          risk: this.cumulativeRisk,
        };
      }
    }

    return {
      suspicious: false,
      risk: this.cumulativeRisk,
    };
  }

  quarantine(reason) {
    this.status = "quarantined";
    this.quarantineReason = reason;
  }

  terminate(reason) {
    this.status = "terminated";
    this.quarantineReason = reason;
  }
}
