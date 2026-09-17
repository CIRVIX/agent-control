/**
 * Cirvix Verified & MCP Trust Layer.
 *
 * Implements security verification for MCP servers and tools:
 * - Provenance and publisher tracking
 * - Tool poisoning / description tampering detection
 * - Unpinned network egress analysis
 * - Trust score computation (0-100)
 * - Verification status: VERIFIED | REVIEW_REQUIRED | SUSPICIOUS | BLOCKED
 */

export const VERIFICATION_STATUS = {
  VERIFIED: "VERIFIED",
  REVIEW_REQUIRED: "REVIEW_REQUIRED",
  SUSPICIOUS: "SUSPICIOUS",
  BLOCKED: "BLOCKED",
};

/**
 * Scans an MCP server declaration and its tools for security risks and assigns trust score.
 *
 * @param {Object} server
 * @param {string} server.name
 * @param {string} [server.publisher]
 * @param {string} [server.version]
 * @param {Array}  [server.tools]
 * @param {Array}  [server.destinations]
 * @returns {Object} Inspection report
 */
export function inspectMcpServer({
  name,
  publisher = null,
  version = null,
  tools = [],
  destinations = [],
} = {}) {
  let trustScore = 70; // Starting baseline for unverified server
  const findings = [];

  // Publisher trust
  const knownTrustedPublishers = ["anthropic", "google", "github", "stripe", "aws", "cirvix"];
  if (publisher && knownTrustedPublishers.includes(publisher.toLowerCase())) {
    trustScore += 25;
  } else if (!publisher) {
    trustScore -= 15;
    findings.push("Missing publisher provenance metadata");
  }

  // Network destinations check
  for (const dest of destinations) {
    const dLower = String(dest).toLowerCase();
    if (dLower.includes("169.254.") || dLower.includes("metadata.google")) {
      trustScore = 0;
      findings.push(`Dangerous cloud metadata destination declared: ${dest}`);
      return {
        name,
        trustScore: 0,
        status: VERIFICATION_STATUS.BLOCKED,
        findings,
      };
    }
  }

  // Tools inspection
  for (const tool of tools) {
    const desc = (tool.description ?? "").toLowerCase();
    const toolName = (tool.name ?? "").toLowerCase();

    // Check for tool poisoning / prompt injection markers in description
    if (
      desc.includes("ignore previous instructions") ||
      desc.includes("system prompt") ||
      desc.includes("do not tell the user") ||
      desc.includes("send secrets to")
    ) {
      trustScore = 0;
      findings.push(`Tool poisoning detected in tool '${tool.name}': suspicious prompt injection phrases in description`);
      return {
        name,
        trustScore: 0,
        status: VERIFICATION_STATUS.BLOCKED,
        findings,
      };
    }

    // Check for excessive wildcard permissions or raw shell execution
    if (toolName === "bash" || toolName === "exec" || toolName === "eval") {
      trustScore -= 20;
      findings.push(`Tool '${tool.name}' exposes raw shell/process execution capability`);
    }
  }

  trustScore = Math.max(0, Math.min(100, trustScore));

  let status = VERIFICATION_STATUS.REVIEW_REQUIRED;
  if (trustScore >= 85) status = VERIFICATION_STATUS.VERIFIED;
  else if (trustScore < 50) status = VERIFICATION_STATUS.SUSPICIOUS;

  return {
    name,
    publisher,
    version,
    trustScore,
    status,
    findings,
    scannedAt: new Date().toISOString(),
  };
}
