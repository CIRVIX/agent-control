/** Public entry point for @cirvix_ai/agent-control. */

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

/* THE CANONICAL AUTHORIZATION CORE (P0-D) -------------------------------- */
/* The one implementation of the stage order and of what each stage means.
   `Guard` and `Pipeline` are transport adapters over it; an embedder that
   wants the decisions without either adapter — or that wants to assert the
   posture its boundary actually enforces — uses these. */
export {
  AUTHORITY_POSTURE,
  CANONICAL_STAGES,
  CANONICAL_VERB,
  DECISION_PRECEDENCE,
  SANDBOXED_PRINCIPAL as CANONICAL_SANDBOXED_PRINCIPAL,
  SECURITY_PROFILE,
  STAGE_CONTRACT,
  STAGE_STATUS,
  SURFACE,
  VERB_PRODUCER,
  authorize,
  defaultValidateRequest,
  describeCanonicalPosture,
  policyStamp,
  resolveSecurityProfile,
  stagePlan,
} from "./core/authorize.mjs";

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

/* Human / organization principals ---------------------------------------- */
export {
  PrincipalStore,
  PRINCIPAL_VERSION,
  PRINCIPAL_KIND,
  PRINCIPAL_STATUS,
  PRINCIPAL_STATUSES,
  PRINCIPAL_ROLE,
  PRINCIPAL_ROLES,
  PRINCIPAL_AUTH_METHOD,
  PRINCIPAL_ERROR,
  ISSUER_ROLES,
  RELEASE_ROLES,
  authenticatePrincipal,
  challengeBody,
  issueChallenge,
  principalRecordPath,
  principalStatusAt,
  principalsDir,
  releaseAuthorities,
} from "./core/principal.mjs";

/* Ed25519 delegation (the production authority path) ---------------------- */
export {
  Ed25519DelegationIssuer,
  Ed25519DelegationVerifier,
  DelegationStore,
  DELEGATION_TOKEN_VERSION,
  DELEGATION_KIND,
  buildCrossInstanceEnvelope,
  buildGrantPayload,
  signGrant,
  verifyEnvelopeToken,
  verifyGrantToken,
} from "./core/delegation-ed25519.mjs";

/* Durable missions and capabilities --------------------------------------- */
export {
  MissionStore,
  AUTHORITY_RECORD_KIND,
  AUTHORITY_RECORD_VERSION,
  AUTHORITY_RECORD_ERROR,
} from "./core/authority-store.mjs";

/* Approvals --------------------------------------------------------------- */
export { ApprovalStore, STATE as APPROVAL_STATE, approvalFingerprint } from "./core/approvals.mjs";

/* Commands ---------------------------------------------------------------- */
export { scan } from "./commands/scan.mjs";
export { init, STARTER_POLICY } from "./commands/init.mjs";
export { status } from "./commands/status.mjs";
export { demo } from "./commands/demo.mjs";
export { consoleCmd as console } from "./commands/console.mjs";
export { onboard } from "./commands/onboard.mjs";

/* Product UI (engine stays presentation-free; these render events) -------- */
export {
  THEME_NAMES,
  THEME_NAMES as THEMES,
  ROLES,
  badgeForDecision,
  colors,
  roleForDecision,
  roleForRisk,
  setTheme,
  style,
  themeName,
} from "./core/theme.mjs";
export {
  EVENT,
  EventBus,
  attachPipeline,
  createEvent,
  initialState,
  latencyStats,
  reduce,
} from "./core/events.mjs";
export {
  blockedCard,
  cirvixRow,
  explainDecision,
  frame,
  header,
  heldCard,
  policyCard,
  rule,
  spinnerFrame,
  toolCard,
  userRow,
} from "./tui/cards.mjs";
export { statusBar } from "./tui/status.mjs";
export { activitySummary, collapsedFeed, activityRow } from "./tui/activity.mjs";
export { COMMANDS, filterCommands, paletteBox } from "./tui/palette.mjs";
export { ConsoleApp, parseRequest } from "./tui/app.mjs";
export { check as policyCheck, explain as policyExplain, list as policyList, loadPolicyFile, test as policyTest } from "./commands/policy.mjs";

/* Adapters & Platform ---------------------------------------------------- */
export * as adapters from "./adapters/index.mjs";
export * as windows from "./core/windows.mjs";
export { ConfigBackupManager, SafeConfigPatcher, parseConfigJson, stripJsonComments } from "./core/config-store.mjs";

/* Platform Transformation Primitives ------------------------------------- */
export { evaluateIntent, classifyIntent, INTENT_CATEGORIES } from "./core/intent.mjs";
export { SessionTracker, CHAIN_TYPES } from "./core/session.mjs";
export { BehavioralBaseline } from "./core/baseline.mjs";
export {
  CallerVerifier,
  NonceCache,
  createCallerVerifier,
  createIdentityCredential,
  enrollAgent,
  requestDigest,
  signIdentityCredential,
  signRequest,
  verifyIdentityCredential,
} from "./core/identity.mjs";
export { AGENT_STATUS, AgentStore, agentsDir, agentRecordPath } from "./core/identity-store.mjs";
export { IDENTITY_MODE, IDENTITY_MODES, normalizeIdentityMode, resolveIdentityMode } from "./core/identity-modes.mjs";
export {
  ensureRoleKey,
  loadRoleKey,
  loadRolePublicKey,
  publicRoleKey,
  registerRolePublicKey,
  roleKeyPath,
  rolePublicKeyPath,
  KEY_ROLE,
  KEY_ROLES,
} from "./core/keys.mjs";
export { KillSwitchEngine, globalKillSwitch, KILL_SCOPES } from "./core/kill-switch.mjs";
export {
  RevocationStore,
  RevocationEngine,
  REVOCATION_ACTION,
  REVOCATION_SCOPE,
  REVOCATION_SCOPES,
  REVOCATION_PRECEDENCE,
  REVOCATION_UNAVAILABLE,
  buildRevocationEvent,
  signRevocationEvent,
  verifyRevocationEvent,
  revocationEventHash,
  foldRevocations,
  evaluateRevocations,
  scopeSubjects,
  cascadeRevocation,
  enforceRevocation,
  enforceRevocationAsync,
  revocationContextFor,
} from "./core/revocation.mjs";
export { AgentSandbox, SANDBOX_ADAPTERS } from "./core/sandbox.mjs";
export { ShadowEngine } from "./core/shadow.mjs";
export { runRedTeamSuite, BUILTIN_ATTACK_PLUGINS, ATTACK_VECTORS } from "./core/redteam/index.mjs";
export { inspectMcpServer, VERIFICATION_STATUS } from "./core/verified.mjs";
export {
  generateAgentKeypair,
  issueCryptographicPassport,
  verifyPassportSignature,
  rotatePassportKeys,
} from "./core/passport.mjs";
export {
  issueActionReceipt,
  verifyActionReceipt,
} from "./core/proof.mjs";
