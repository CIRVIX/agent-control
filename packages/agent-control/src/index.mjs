/** Public entry point for @cirvix/agent-control. */

/* Policy engine ----------------------------------------------------------- */
export {
  evaluate,
  matchGlob,
  parseRules,
  validateRules,
  canonicalizeResource,
  STARTER_RULES,
  EFFECT,
  VERDICT,
  DECISION,
} from "./core/policy.mjs";

/* Decision vocabulary ----------------------------------------------------- */
export {
  MODE,
  applyMode,
  decisionLabel,
  escalateForRisk,
  isAppealable,
  isForwarded,
  toDecision,
  toVerdict,
} from "./core/decisions.mjs";

/* Policy DSL -------------------------------------------------------------- */
export {
  compile as compilePolicy,
  parse as parsePolicySource,
  toSource as policyToSource,
  PolicySyntaxError,
} from "./core/policy-dsl.mjs";

/* Risk -------------------------------------------------------------------- */
export {
  RISK,
  RISK_ORDER,
  RISK_RULES,
  DEFAULT_POSTURE,
  classify,
  isKnownSafeCommand,
  maxRisk,
  riskAtLeast,
  riskLabel,
  riskRank,
} from "./core/risk.mjs";

/* Normalization ----------------------------------------------------------- */
export {
  SOURCE,
  TAXONOMY,
  canonicalAction,
  classifyTool,
  extractCommand,
  extractDestination,
  extractResource,
  normalize,
  policyContext,
  policyRequest,
  publicToolName,
  requestId,
} from "./core/normalize.mjs";

/* The runtime ------------------------------------------------------------- */
export { Pipeline } from "./core/pipeline.mjs";
export { UdsClient, UdsServer, defaultEndpoint, readToken, tokenPath, writeToken } from "./core/uds.mjs";

/* Transports -------------------------------------------------------------- */
export { Gateway, fingerprintTool } from "./core/gateway.mjs";
export { HttpGatewayServer, HttpUpstream, assertAllowedEndpoint } from "./core/http-transport.mjs";
export { Daemon } from "./core/daemon.mjs";

/* SDK --------------------------------------------------------------------- */
export {
  CirvixDenied,
  CirvixHeld,
  Guard,
  actionForTool,
  destinationFor,
  guard,
  resourceForCall,
  wrap,
} from "./core/guard.mjs";

/* Secrets ----------------------------------------------------------------- */
export { SecretsClient, HANDLE_PREFIX, findHandles, isHandle } from "./core/secrets.mjs";
export { Vault } from "./core/vault.mjs";
export {
  DETECTORS,
  SEVERITY,
  entropy,
  fingerprint as secretFingerprint,
  hasSecrets,
  mask,
  redact as redactSecrets,
  scan as scanSecrets,
  summarize as summarizeSecrets,
} from "./core/secret-detect.mjs";

/* Sanitization ------------------------------------------------------------ */
export {
  INJECTION_RULES,
  hasInjection,
  scan as scanInjection,
  stripInjection,
} from "./core/sanitize.mjs";

/* History ----------------------------------------------------------------- */
export { AuditChain, canonicalJson, hashRecord } from "./core/audit.mjs";
export {
  byRun,
  decideNow,
  find as findDecision,
  query as queryDecisions,
  read as readJournal,
  renderLine,
  renderTree,
  replay,
  replayOne,
  summarize as summarizeDecisions,
} from "./core/journal.mjs";

/* Delegation -------------------------------------------------------------- */
export {
  DELEGATION_ERROR,
  DelegationBroker,
  intersectScopes,
  isNarrowing,
  normalizeScope,
  scopePermits,
} from "./core/delegation.mjs";

/* Approvals --------------------------------------------------------------- */
export { ApprovalStore, STATE as APPROVAL_STATE, approvalFingerprint } from "./core/approvals.mjs";

/* Commands ---------------------------------------------------------------- */
export { scan } from "./commands/scan.mjs";
export { init, STARTER_POLICY } from "./commands/init.mjs";
export { status } from "./commands/status.mjs";
export { demo } from "./commands/demo.mjs";
export { check as policyCheck, explain as policyExplain, list as policyList, loadPolicyFile, test as policyTest } from "./commands/policy.mjs";
