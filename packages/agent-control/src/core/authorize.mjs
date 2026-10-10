/**
 * THE CANONICAL AUTHORIZATION CORE (P0-D).
 *
 * Before this file there were two engines — `Guard.authorize` (behind the MCP
 * gateway and `guard.wrap`) and `Pipeline.submit` (behind the local socket) —
 * and each implemented its own subset of the security stages. That was not a
 * missing feature; it was a silent bypass with the shape of a feature gap:
 *
 *   - Guard ran identity, delegation and authority, and NOT intent, session
 *     tracking, the behavioural baseline, engine mode or tool drift.
 *   - Pipeline ran intent, session tracking, baseline and mode, and had NO
 *     identity stage at all: the socket verified the caller and then threw the
 *     result away, so the engine that actually decided did not know who it had
 *     just authenticated.
 *
 * So "which security properties are in force" depended on which door the call
 * came through. This file removes that question. It is the ONLY implementation
 * of the stage order and of what each stage means. `Guard` and `Pipeline` are
 * transport adapters: they parse a transport request, establish or forward the
 * transport's authentication, call `authorize()`, and map the canonical outcome
 * back onto their own record/response shape.
 *
 * WHAT THE CORE OWNS
 *
 *   1. the ORDER of the stages (one order, asserted by the parity oracle);
 *   2. the SEMANTICS of each stage (what may refuse, what may only narrow);
 *   3. the PRECEDENCE between outcomes (a mandatory refusal is terminal);
 *   4. the FAILURE behaviour of each stage (what happens when it throws);
 *   5. the EVIDENCE every decision carries, including which stages were
 *      INERT on this boundary because nothing was wired into them.
 *
 * WHAT THE CORE DOES NOT OWN
 *
 *   - transport authentication itself. A socket token, a stdio peer, an HTTP
 *     bearer token: those are established upstream, and the transport hands the
 *     result in as trusted input (`securityContext.identityVerification`), or
 *     the core verifies a credential itself when the boundary supplied a
 *     verifier (`deps.identity`). Either way the RESULT is trusted input; a
 *     name that arrived in a request payload never is.
 *   - the record shape. Each transport renders its own record from
 *     `outcome.evidence`; the append and the fail-closed-on-unrecordable rule
 *     live here, once.
 *
 * TRUSTED CONTEXT IS BUILT BEFORE ANY IDENTITY-DEPENDENT STAGE (INV-018)
 *
 * Caller-controlled `agent`, `tenant`, `principal` and `role` fields never
 * become trusted context. The acting principal is, in order: a verified
 * identity; the authenticated host context; the operator-configured default.
 * A caller's claim is kept as untrusted metadata and is recorded, never
 * evaluated.
 */

import { canonicalizeResource, evaluate } from "./policy.mjs";
import {
  DECISION,
  MODE,
  applyMode,
  escalateForRisk,
  isForwarded,
  toDecision,
} from "./decisions.mjs";
import { classify, deriveConsequence } from "./risk.mjs";
import {
  classifyEgress,
  classifyTool,
  extractCommand,
  extractDestination,
  extractResource,
  isInsideWorkspace,
  policyRequest,
  requestId as makeRequestId,
} from "./normalize.mjs";
import { scan as scanSecrets, redact as redactSecrets } from "./secret-detect.mjs";
import { applyDelegation } from "./delegation.mjs";
import {
  acquireMission,
  applyAuthority,
  assessAuthority,
  captureMissionCost,
  missionAllowanceRefusal,
  recordMissionUsage,
} from "./authority.mjs";
import { applyEntitlements } from "./entitlement-gate.mjs";
import { SessionTaint, applyTrifecta, assessTrifecta } from "./trifecta.mjs";
import { approvalFingerprint } from "./approvals.mjs";
import { enforceKillSwitch } from "./kill-switch.mjs";
import { enforceRevocationAsync, revocationContextFor } from "./revocation.mjs";
import { evaluateIntent } from "./intent.mjs";
import { keyIdFor } from "./proof.mjs";
import { IDENTITY_MODE, normalizeIdentityMode } from "./identity-modes.mjs";
import { canonicalJson } from "./audit.mjs";
import { createHash } from "node:crypto";

/* ========================================================================== */
/*  Vocabulary                                                                 */
/* ========================================================================== */

/** The transport a request arrived on. Used for evidence, never for semantics. */
export const SURFACE = Object.freeze({
  MCP_GATEWAY: "mcp-gateway",
  UDS: "uds",
  SDK: "sdk",
  CLI: "cli",
  DIRECT: "direct",
});

/**
 * Whether this boundary refuses a governed call that presents no signed
 * authority, or decides it by policy alone.
 *
 * OPTIONAL is the historic library contract and stays available — but it is a
 * CHOICE a caller makes, reported by `doctor` and by every decision, rather
 * than the accident of not having typed a flag. See `resolveSecurityProfile`.
 */
export const AUTHORITY_POSTURE = Object.freeze({
  REQUIRED: "required",
  OPTIONAL: "optional",
});

/**
 * The effective security profile of a boundary.
 *
 * Same four values as `identity-modes.mjs`, reinterpreted as a whole-boundary
 * posture so a single object can be reported, asserted and printed:
 *
 *   PRODUCTION    hardened: identity is mandatory, authority is required
 *                 according to `authorityPosture`, unverified callers refused.
 *   BOOTSTRAP     an operator-selected enrolment window; closes itself once a
 *                 verifier exists. Never the default.
 *   DEV_INSECURE  explicit developer profile: identity enforcement off. Loudly
 *                 marked on every decision and refused unless asked for.
 *   COMPAT        the in-process SDK/library contract: no transport boundary,
 *                 so there is nothing to authenticate. Policy-only, reported
 *                 as `compatibility: true` everywhere.
 */
export const SECURITY_PROFILE = Object.freeze({
  PRODUCTION: "production",
  BOOTSTRAP: "bootstrap",
  DEV_INSECURE: "dev-insecure",
  COMPAT: "compat",
});

/**
 * What a stage is doing on a given boundary.
 *
 * INERT is the honest one, and the reason this vocabulary exists: a stage the
 * core runs but for which this boundary has wired no dependency is not
 * "enforced", it is INERT — and the operator has to be able to see that without
 * reading the source. `stagePlan()` produces this, `doctor` prints it, and the
 * parity oracle asserts that no surface claims MANDATORY for a stage it does
 * not actually run.
 */
export const STAGE_STATUS = Object.freeze({
  MANDATORY: "mandatory",
  OPTIONAL: "optional",
  INERT: "inert",
  PROFILE_DISABLED: "profile-disabled",
  NOT_APPLICABLE: "not-applicable",
});

/**
 * The canonical outcome vocabulary.
 *
 * The three states the transports understand (`permit`/`deny`/`hold`) are a
 * projection of these, not the vocabulary itself. Every verb here has a
 * declared producer in `VERB_PRODUCER`; a verb with no producer is NOT
 * reachable, and saying so is the point — a vocabulary that lists ten outcomes
 * and implements three, without marking which, is how a console ends up
 * claiming controls the runtime does not have.
 */
export const CANONICAL_VERB = Object.freeze({
  ALLOW: "allow",
  DENY: "deny",
  HOLD: "hold",
  REQUIRE_APPROVAL: "require_approval",
  SANITIZE: "sanitize",
  MASK: "mask",
  REDACT: "redact",
  REAUTHENTICATE: "reauthenticate",
  STEP_UP: "step_up",
  ISSUE_CAPABILITY: "issue_capability",
});

/**
 * Which stage may emit which verb. `null` means: defined, no producer yet —
 * documented as unreachable rather than quietly unimplemented.
 */
export const VERB_PRODUCER = Object.freeze({
  [CANONICAL_VERB.ALLOW]: "policy + every narrowing stage passing",
  [CANONICAL_VERB.DENY]: "identity, policy, delegation, authority, revocation, kill switch, intent, session, drift, validation, credential, audit",
  [CANONICAL_VERB.HOLD]: "policy hold, risk floor, baseline deviation, approval required",
  [CANONICAL_VERB.REQUIRE_APPROVAL]: "risk floor, policy hold, baseline deviation",
  [CANONICAL_VERB.SANITIZE]: "policy, secret redaction",
  [CANONICAL_VERB.MASK]: "credential stage (result path)",
  [CANONICAL_VERB.REDACT]: "sanitize stage",
  [CANONICAL_VERB.REAUTHENTICATE]: null,
  [CANONICAL_VERB.STEP_UP]: null,
  [CANONICAL_VERB.ISSUE_CAPABILITY]: null,
});

/**
 * THE STAGE ORDER. One order. Every surface.
 *
 * Read alongside `STAGE_CONTRACT` below. The ordering constraints that are not
 * arbitrary:
 *
 *   - identity first, because every later stage is evaluated against a
 *     principal and a principal that came from the request payload is not one;
 *   - normalization before risk/policy, because a rule may test `risk >= HIGH`
 *     and that value has to exist before the rule is evaluated;
 *   - revocation and the kill switch BEFORE approvals, because a hold that can
 *     be released by an approval must not be released for an agent that was
 *     revoked while the approval was pending;
 *   - credential substitution after the decision, because it is a consequence
 *     of a permit and a broker refusal must be able to turn the permit into a
 *     refusal rather than emit a second decision;
 *   - evidence last, and its failure is terminal.
 */
export const CANONICAL_STAGES = Object.freeze([
  "request",
  "identity",
  "normalize",
  "secrets",
  "risk",
  "policy",
  "delegation",
  "authority",
  "capability",
  "revocation",
  "kill",
  "trifecta",
  "policy-version",
  "mode",
  "entitlements",
  "intent",
  "session",
  "baseline",
  "drift",
  "validation",
  "approval",
  "credential",
  "sanitize",
  "final-tighten",
  "evidence",
]);

/**
 * THE STAGE CONTRACTS (§6).
 *
 * INPUT → OUTPUT → FAILURE → TRUST ASSUMPTION, per stage. This is data rather
 * than prose so the parity oracle can assert that every stage has a contract,
 * that a stage marked `narrowing: true` can never widen a decision, and that
 * the failure policy is fail-closed for everything that can refuse.
 */
export const STAGE_CONTRACT = Object.freeze({
  request: {
    input: "transport payload",
    output: "a well-formed request or `malformed`",
    failure: "deny (invalid-request)",
    trust: "untrusted — parsed, never trusted",
    narrows: false,
  },
  identity: {
    input: "transport authentication result, or credential material",
    output: "a trusted principal, or `identity-unverified`",
    failure: "deny (identity-unverified / identity-unavailable)",
    trust: "the RESULT is trusted; the claim never is",
    narrows: false,
  },
  normalize: {
    input: "request + trusted principal",
    output: "normalized call + trusted policy context",
    failure: "deny (invalid-request)",
    trust: "derived from the request, matched against canonical rules",
    narrows: false,
  },
  secrets: {
    input: "call arguments",
    output: "findings count + masked findings",
    failure: "deny (secret-scan-unavailable)",
    trust: "detector output; findings never carry values",
    narrows: false,
  },
  risk: {
    input: "normalized call",
    output: "risk level + signals",
    failure: "deny (risk-unavailable)",
    trust: "derived; a floor only, never a ceiling",
    narrows: false,
  },
  policy: {
    input: "trusted principal + action + resource + context",
    output: "candidate decision",
    failure: "deny (policy-unavailable)",
    trust: "deterministic over the loaded rule set",
    narrows: false,
  },
  delegation: {
    input: "presented chain + call circumstances",
    output: "effective narrowed authority, or `delegation-unverifiable`",
    failure: "deny (delegation-unverifiable)",
    trust: "cryptographic; may only remove authority",
    narrows: true,
  },
  authority: {
    input: "mission/capability + call",
    output: "authorized / not, with the constraint that refused it",
    failure: "deny (authority-unavailable)",
    trust: "signed or host-configured mission; subtractive",
    narrows: true,
  },
  capability: {
    input: "active mission's capabilities + call",
    output: "capability verdict + revocation-relevant ids",
    failure: "deny (capability-unavailable)",
    trust: "same as authority",
    narrows: true,
  },
  revocation: {
    input: "identity, tenant, runtime, capability, session, approval ids",
    output: "active, or revoked/stale/unavailable",
    failure: "deny or hold per the boundary's staleness profile — never allow",
    trust: "durable, signed, hash-chained, monotonic",
    narrows: true,
  },
  kill: {
    input: "agent, tool, session, environment, server",
    output: "active, or killed",
    failure: "deny (kill-switch-unavailable)",
    trust: "process-local operator intent",
    narrows: true,
  },
  trifecta: {
    input: "call + session sequence state",
    output: "complete / satisfied / imminent",
    failure: "deny (session-state-unavailable)",
    trust: "derived from this session's own observations",
    narrows: true,
  },
  "policy-version": {
    input: "enforced rule fingerprint + published stamp",
    output: "current, or `stale-policy`",
    failure: "deny or hold per `onStalePolicy`",
    trust: "the fingerprint is computed here; the stamp is operator input",
    narrows: true,
  },
  mode: {
    input: "decision + engine mode",
    output: "enforced decision, or a recorded would-have",
    failure: "deny (mode-unavailable)",
    trust: "operator-set",
    narrows: false,
  },
  entitlements: {
    input: "decision + licence/meter/agent registry",
    output: "decision, possibly tightened by quota",
    failure: "deny (entitlement-unavailable)",
    trust: "commercial state; may only tighten",
    narrows: true,
  },
  intent: {
    input: "declared intent (structured or text) + call",
    output: "aligned / misaligned",
    failure: "deny (intent-firewall-unavailable)",
    trust: "the caller declares it; it can only refuse, never permit",
    narrows: true,
  },
  session: {
    input: "this call + the session's step history",
    output: "chain risk, or a suspicious chain",
    failure: "hold or deny per `onStageFailure`",
    trust: "in-process sequence state",
    narrows: true,
  },
  baseline: {
    input: "this call + the behavioural baseline",
    output: "anomaly score, possibly an escalated floor",
    failure: "hold or deny per `onStageFailure`",
    trust: "in-process history; a floor only",
    narrows: true,
  },
  drift: {
    input: "the tool/server identity + its pinned definition",
    output: "in-pin, drifted, or unknown",
    failure: "hold or deny per `onStageFailure`",
    trust: "pin registry written by the operator",
    narrows: true,
  },
  validation: {
    input: "the request shape",
    output: "well-formed, or `invalid-request`",
    failure: "deny (invalid-request)",
    trust: "structural, mandatory in every mode",
    narrows: true,
  },
  approval: {
    input: "a held decision + the approval store",
    output: "released, still held, or denied; absent/expired/revoked/consumed",
    failure: "deny (approval-unavailable)",
    trust: "the approver is authenticated by the store, not by the request",
    narrows: false,
  },
  credential: {
    input: "the decision + the credential broker",
    output: "scoped material or a credential requirement",
    failure: "deny (secret-broker / credential-unavailable)",
    trust: "the broker's answer must be positively affirmed",
    narrows: true,
  },
  sanitize: {
    input: "outgoing arguments + sanitize targets",
    output: "redacted arguments",
    failure: "deny (sanitize-unavailable)",
    trust: "derived",
    narrows: true,
  },
  "final-tighten": {
    input: "the decision + kill/revocation re-check",
    output: "the most restrictive applicable outcome",
    failure: "deny",
    trust: "re-read; a revocation written mid-decision must land",
    narrows: true,
  },
  evidence: {
    input: "the whole run",
    output: "record/event, decision id, audit append",
    failure: "deny (audit-unavailable) when the record cannot be written",
    trust: "append-only chain",
    narrows: true,
  },
});

/* ========================================================================== */
/*  Profiles                                                                   */
/* ========================================================================== */

/**
 * Turns the flags a boundary was started with into ONE explicit profile.
 *
 * The reason this is a function rather than a default: the previous posture was
 * "authority required if the operator typed `--require-authority`", which means
 * a hardened deployment and a mitigated bypass were one omission apart, and
 * nothing in the runtime could tell them apart afterwards. Now every boundary
 * resolves a profile, records it, and a shipped surface cannot resolve to the
 * permissive one without saying so.
 */
export function resolveSecurityProfile({
  identityMode = IDENTITY_MODE.COMPAT,
  authorityPosture = AUTHORITY_POSTURE.OPTIONAL,
  compatibility = false,
} = {}) {
  const mode = normalizeIdentityMode(identityMode).mode;
  let profile;
  if (compatibility) profile = SECURITY_PROFILE.COMPAT;
  else if (mode === IDENTITY_MODE.PRODUCTION) profile = SECURITY_PROFILE.PRODUCTION;
  else if (mode === IDENTITY_MODE.BOOTSTRAP) profile = SECURITY_PROFILE.BOOTSTRAP;
  else if (mode === IDENTITY_MODE.DEV_INSECURE) profile = SECURITY_PROFILE.DEV_INSECURE;
  else profile = SECURITY_PROFILE.COMPAT;

  return Object.freeze({
    profile,
    identityMode: mode,
    authorityPosture: authorityPosture === AUTHORITY_POSTURE.REQUIRED
      ? AUTHORITY_POSTURE.REQUIRED
      : AUTHORITY_POSTURE.OPTIONAL,
    /* A hardened profile is one where an unverified caller cannot be decided by
       policy alone AND (either) authority is required or a verifier exists. */
    hardened: profile === SECURITY_PROFILE.PRODUCTION,
    compatibility: profile === SECURITY_PROFILE.COMPAT || profile === SECURITY_PROFILE.DEV_INSECURE,
  });
}

/**
 * Stages only one KIND of surface can evaluate at all.
 *
 * Two surfaces can disagree about a stage for two very different reasons: one
 * of them forgot to wire a control, or the control has nothing to inspect on
 * that surface. Only the second is acceptable, and the difference is invisible
 * in the status strings alone — both read as INERT. Declared HERE, once, so the
 * report that compares surfaces does not have to guess from a stage name.
 */
export const SURFACE_BOUND_STAGES = Object.freeze({
  /* Tool drift compares the tool definition an upstream server published
     against the pin an operator approved. Only the MCP gateway owns those
     definitions; a socket caller presents a tool name and no definition, so
     there is nothing on that surface to differ. */
  drift: Object.freeze([SURFACE.MCP_GATEWAY]),
});

/**
 * A dependency that is simply absent, reported as such.
 *
 * `stagePlan` answers "what is actually in force on this boundary", which is
 * the question `doctor` and the parity oracle both need, and which the two
 * engines previously could answer differently for the same call.
 */
export function stagePlan({ profile, posture = AUTHORITY_POSTURE.OPTIONAL, surface = SURFACE.DIRECT, deps = {} } = {}) {
  const hardened = profile === SECURITY_PROFILE.PRODUCTION;
  const plan = {};

  const set = (stage, status) => {
    plan[stage] = status;
  };

  set("request", STAGE_STATUS.MANDATORY);
  set("identity", STAGE_STATUS.MANDATORY);
  set("normalize", STAGE_STATUS.MANDATORY);
  set("secrets", STAGE_STATUS.MANDATORY);
  set("risk", STAGE_STATUS.MANDATORY);
  set("policy", STAGE_STATUS.MANDATORY);
  set("delegation", posture === AUTHORITY_POSTURE.REQUIRED || has(deps.delegation)
    ? STAGE_STATUS.MANDATORY
    : STAGE_STATUS.OPTIONAL);
  set("authority", has(deps.missions) || has(deps.mission) ? STAGE_STATUS.MANDATORY : STAGE_STATUS.INERT);
  set("capability", has(deps.missions) || has(deps.mission) ? STAGE_STATUS.MANDATORY : STAGE_STATUS.INERT);
  set("revocation", has(deps.revocation) ? STAGE_STATUS.MANDATORY : STAGE_STATUS.INERT);
  set("kill", has(deps.killSwitch) ? STAGE_STATUS.MANDATORY : STAGE_STATUS.INERT);
  set("trifecta", STAGE_STATUS.MANDATORY);
  set("policy-version", has(deps.publishedPolicy) ? STAGE_STATUS.MANDATORY : STAGE_STATUS.INERT);
  set("mode", STAGE_STATUS.MANDATORY);
  set("entitlements", has(deps.licence) || has(deps.meter) || has(deps.agents)
    ? STAGE_STATUS.MANDATORY
    : STAGE_STATUS.INERT);
  set("intent", has(deps.intent) ? STAGE_STATUS.MANDATORY : STAGE_STATUS.INERT);
  set("session", has(deps.sessionTracker) ? STAGE_STATUS.MANDATORY : STAGE_STATUS.INERT);
  set("baseline", has(deps.baseline) ? STAGE_STATUS.MANDATORY : STAGE_STATUS.INERT);
  set("drift", has(deps.drift) ? STAGE_STATUS.MANDATORY : STAGE_STATUS.INERT);
  set("validation", STAGE_STATUS.MANDATORY);
  set("approval", has(deps.approvals) ? STAGE_STATUS.MANDATORY : STAGE_STATUS.NOT_APPLICABLE);
  set("credential", has(deps.secrets) ? STAGE_STATUS.MANDATORY : STAGE_STATUS.NOT_APPLICABLE);
  set("sanitize", STAGE_STATUS.MANDATORY);
  set("final-tighten", STAGE_STATUS.MANDATORY);
  set("evidence", has(deps.audit) ? STAGE_STATUS.MANDATORY : STAGE_STATUS.OPTIONAL);

  if (hardened && !has(deps.identity) && !has(deps.identityVerification)) {
    plan.identity = STAGE_STATUS.MANDATORY;
    plan.identity_note = "no verifier configured: every caller is refused";
  }
  if (profile === SECURITY_PROFILE.DEV_INSECURE) {
    plan.identity = STAGE_STATUS.PROFILE_DISABLED;
    plan.identity_note = "developer profile: identity enforcement is OFF by explicit flag";
  }
  return { surface, profile, posture, stages: plan };
}

/** The operator-facing posture: what is actually trusted by this runtime. */
export function describeCanonicalPosture({ surface, deps = {}, profile, posture, stamps = {} } = {}) {
  const plan = stagePlan({ profile, posture, surface, deps });
  return {
    surface,
    profile,
    authorityPosture: posture,
    hardened: profile === SECURITY_PROFILE.PRODUCTION,
    compatibility: profile === SECURITY_PROFILE.COMPAT || profile === SECURITY_PROFILE.DEV_INSECURE,
    authorityRequired: posture === AUTHORITY_POSTURE.REQUIRED,
    stages: plan.stages,
    trustAnchors: {
      identity: has(deps.identity) ? "verifier configured" : "none",
      delegation: has(deps.delegation) ? "verifier configured" : "none",
      authority: has(deps.missions) || has(deps.mission) ? "mission registry" : "none",
      revocation: has(deps.revocation) ? "durable revocation fabric" : "none",
      receipt: "canonical core (P0-E signs)",
      policy: stamps.policyHash ?? null,
      principalIssuer: has(deps.missions) ? "mission issuer" : "none",
    },
    policyStamp: stamps,
  };
}

function has(value) {
  return value !== null && value !== undefined;
}

/* ========================================================================== */
/*  Policy stamp                                                               */
/* ========================================================================== */

/**
 * A deterministic fingerprint of the rule set actually being enforced.
 *
 * This is the producer `policyVersion`/`policyHash` needed and never had: a
 * runtime can only claim to enforce a published policy if it can name it, and
 * the name has to be a function of the rules themselves rather than a number
 * somebody typed. `published` is the operator's stamp (from the control plane
 * or the state directory); when it is present and disagrees with `hash`, the
 * runtime is enforcing a stale policy and says so.
 */
export function policyStamp(rules, { version = null, published = null } = {}) {
  const hash = "sha256:" + createHash("sha256").update(canonicalJson(rules ?? [])).digest("hex");
  const publishedHash = published?.hash ?? published?.policyHash ?? null;
  return {
    policyVersion: version ?? published?.version ?? published?.policyVersion ?? null,
    policyHash: hash,
    publishedHash,
    stale: Boolean(publishedHash) && publishedHash !== hash,
  };
}

/* ========================================================================== */
/*  The run                                                                    */
/* ========================================================================== */

/** Strictness order, harshest first. DEV_INSECURE is enforcement OFF. */
const IDENTITY_STRICTNESS = [
  IDENTITY_MODE.PRODUCTION,
  IDENTITY_MODE.BOOTSTRAP,
  IDENTITY_MODE.COMPAT,
  IDENTITY_MODE.DEV_INSECURE,
];

/**
 * The mode in force when BOTH the transport and the engine state one.
 *
 * `null`/`undefined` means "this layer made no statement" — which is NOT the
 * same as `compat`, and conflating them is how a library default silently
 * overrides a boundary's explicit configuration. So: an absent statement is
 * ignored, one statement is taken as written, and two statements resolve to
 * the stricter — a mode can be strengthened by being stated twice, never
 * weakened. When neither layer states one, COMPAT is the answer (no transport
 * boundary exists to authenticate against).
 */
export function stricterIdentityMode(a, b) {
  const stated = (value) => (value === null || value === undefined ? null : normalizeIdentityMode(value).mode);
  const left = stated(a);
  const right = stated(b);
  if (left === null) return right ?? IDENTITY_MODE.COMPAT;
  if (right === null) return left;
  const rank = (mode) => {
    const at = IDENTITY_STRICTNESS.indexOf(mode);
    return at === -1 ? IDENTITY_STRICTNESS.indexOf(IDENTITY_MODE.COMPAT) : at;
  };
  return IDENTITY_STRICTNESS[Math.min(rank(left), rank(right))];
}

/** A principal value that provably matches nothing. See guard.mjs history. */
export const SANDBOXED_PRINCIPAL = "__cirvix_unverified__";

/** Most restrictive first. Used by `finalize` — see §7 of the P0-D brief. */
export const DECISION_PRECEDENCE = Object.freeze([
  DECISION.DENY,
  DECISION.REQUIRE_APPROVAL,
  DECISION.SANITIZE,
  DECISION.AUDIT_ONLY,
  DECISION.ALLOW,
]);

/** Which rule attributed each mandatory refusal, for the evidence trail. */
const MANDATORY_STAGES = new Set(["identity", "revocation", "kill", "credential", "validation", "policy-version", "intent", "drift"]);

/**
 * Runs ONE request through the canonical stage sequence.
 *
 * Everything the caller can influence arrives as `request`; everything the
 * caller cannot is in `securityContext` (trusted) or `deps` (the boundary's
 * wiring). Nothing in this class consults a transport.
 */
class AuthorizationRun {
  constructor(request, securityContext, deps) {
    this.request = request && typeof request === "object" && !Array.isArray(request) ? request : {};
    this.ctx = securityContext && typeof securityContext === "object" ? securityContext : {};
    this.deps = deps ?? {};
    this.now = typeof this.deps.clock === "function" ? this.deps.clock : () => Date.now();

    this.startedAt = process.hrtime.bigint();
    this.trace = {};
    this.stageMs = {};
    this.stageStatus = {};
    this.mandatory = [];
    this.stageFailures = [];

    this.identity = null;
    this.principal = null;
    this.claim = null;
    this.call = null;
    this.context = null;
    this.risk = null;
    this.delegation = null;
    this.authority = null;
    this.mission = null;
    this.capabilities = [];
    this.intent = null;
    this.session = null;
    this.baseline = null;
    this.drift = null;
    this.revocation = null;
    this.approval = null;
    this.credential = null;
    this.obligations = [];
    this.outgoing = null;
    this.decision = null;
    this.planned = null;
    this.latencyMs = 0;
    this.decisionId = null;
    this.requestId = typeof this.request.request_id === "string" && this.request.request_id
      ? this.request.request_id
      : makeRequestId();
    this.missionLease = null;
    this.trifectaCall = null;
    this.stats = { calls: 1, permitted: 0, denied: 0, held: 0, secrets: 0 };
  }

  /* ---------------------------------------------------------------- helpers */

  get surface() {
    return this.ctx.surface ?? SURFACE.DIRECT;
  }

  get profile() {
    return this.ctx.profile ?? resolveSecurityProfile({
      identityMode: this.deps.identityMode ?? IDENTITY_MODE.COMPAT,
      authorityPosture: this.ctx.authorityPosture ?? (this.deps.requireDelegation ? AUTHORITY_POSTURE.REQUIRED : AUTHORITY_POSTURE.OPTIONAL),
      compatibility: this.deps.compatibility === true,
    }).profile;
  }

  /** Times a stage and records its status. Never swallows a throw silently. */
  async stage(name, fn) {
    const t0 = process.hrtime.bigint();
    try {
      const result = await fn();
      this.stageMs[name] = Number(process.hrtime.bigint() - t0) / 1e6;
      this.stageStatus[name] = "ran";
      return result;
    } catch (err) {
      this.stageMs[name] = Number(process.hrtime.bigint() - t0) / 1e6;
      const failure = this.#failureFor(name, err);
      this.stageStatus[name] = `failed:${failure.policy}`;
      this.stageFailures.push({ stage: name, policy: failure.policy, error: String(err?.message ?? err) });
      if (failure.decision) this.#refuse(failure.decision, { stage: name, mandatory: failure.mandatory });
      return undefined;
    }
  }

  #failureFor(name, err) {
    const contract = STAGE_CONTRACT[name];
    const configured = this.deps.onStageFailure?.[name];
    const policy = configured ?? (MANDATORY_STAGES.has(name) ? "deny" : "hold");
    const message = String(err?.message ?? err);
    const fields = {
      rule: `${name}-unavailable`,
      reason: `${contract?.failure ?? "This stage failed"} (${message}).`,
      remediation: "Check the runtime configuration for this stage, then retry.",
    };
    if (policy === "skip") return { policy: "skip", mandatory: false, decision: null };
    return {
      policy,
      mandatory: policy === "deny",
      decision: policy === "deny"
        ? { decision: DECISION.DENY, verdict: "deny", enforced: true, ...fields }
        : { decision: DECISION.REQUIRE_APPROVAL, verdict: "hold", enforced: true, ...fields },
    };
  }

  /**
   * Records a refusal and applies it to the decision.
   *
   * A mandatory refusal is TERMINAL: `finalize()` will not let a later stage
   * turn it back into an ALLOW. That is the invariant three separate bypass
   * fixes in the old engines were groping for, stated once.
   */
  #refuse(partial, { stage, mandatory = false } = {}) {
    const next = {
      decision: partial.decision ?? DECISION.DENY,
      verdict: partial.verdict ?? (partial.decision === DECISION.REQUIRE_APPROVAL ? "hold" : "deny"),
      ...partial,
    };
    if (!this.decision) this.decision = {};
    Object.assign(this.decision, next, { stage });
    if (mandatory) this.mandatory.push({ stage, rule: next.rule ?? null, reason: next.reason ?? null });
    return this.decision;
  }

  /* ------------------------------------------------------------------- run */

  async execute() {
    /* 1. request shape — parsed before it is trusted. */
    await this.stage("request", () => this.#requestStage());

    /* 2. IDENTITY, before anything identity-dependent depends on it. */
    await this.stage("identity", () => this.#identityStage());
    if (this.#identityRefused()) return await this.#finish({ refusedIdentity: true });

    /* 3. normalization + trusted context. */
    await this.stage("normalize", () => this.#normalizeStage());
    if (!this.decision) this.decision = {};
    if (!this.mandatory.length && this.#refusalFrom(this.decision) === "invalid-request") {
      /* shape refusal from the normalize stage */
    }

    await this.stage("secrets", () => this.#secretsStage());
    await this.stage("risk", () => this.#riskStage());
    await this.stage("policy", () => this.#policyStage());

    await this.stage("delegation", () => this.#delegationStage());
    await this.stage("authority", () => this.#authorityStage());
    await this.stage("capability", () => this.#capabilityStage());

    /* Revocation and the kill switch run BEFORE approvals can release
       anything: an approval pending when the agent was revoked must not
       become an execution. */
    await this.stage("revocation", () => this.#revocationStage({ early: true }));
    await this.stage("kill", () => this.#killStage());

    await this.stage("trifecta", () => this.#trifectaStage());
    await this.stage("policy-version", () => this.#policyVersionStage());
    await this.stage("mode", () => this.#modeStage());
    await this.stage("entitlements", () => this.#entitlementStage());
    await this.stage("intent", () => this.#intentStage());
    await this.stage("session", () => this.#sessionStage());
    await this.stage("baseline", () => this.#baselineStage());
    await this.stage("drift", () => this.#driftStage());
    await this.stage("validation", () => this.#validationStage());

    try {
      await this.stage("approval", () => this.#approvalStage());
      await this.stage("credential", () => this.#credentialStage());
      await this.stage("sanitize", () => this.#sanitizeStage());
      await this.stage("final-tighten", () => this.#finalTightenStage());
      await this.stage("evidence", () => this.#evidenceStage());
    } finally {
      if (this.missionLease) this.missionLease.release();
    }

    return this.#finish();
  }

  /* --------------------------------------------------------------- stages */

  #requestStage() {
    const validate = this.deps.validateRequest ?? defaultValidateRequest;
    const verdict = validate(this.request, this.ctx);
    if (verdict) {
      this.malformed = verdict;
    }
    const { tool } = classifyTool(this.request.tool, this.request.server ?? null);
    this.tool = this.request.tool ?? null;
    this.classifiedTool = tool;
  }

  async #identityStage() {
    const deps = this.deps;
    /* THE STRICTER OF THE TWO MODES WINS.
     *
     * The boundary that owns the transport (the socket server) and the engine
     * that decides (the pipeline) each state a mode. Taking the first one
     * configured would let a permissive engine default silently override a
     * hardened transport — which is the exact shape of the bug this file
     * exists to remove. Taking the stricter of the two means a mode can only
     * ever be strengthened by being stated twice, never weakened. */
    const mode = stricterIdentityMode(deps.identityMode, this.ctx.identityMode);

    /* A transport that already authenticated the caller hands the RESULT in.
       That is the socket's contract: it owns the peer, so it owns the
       verification, and the core must not re-derive it. */
    let verification = this.ctx.identityVerification ?? null;
    let verifiedBy = verification ? "transport" : null;

    /* Otherwise, verify here — with the verifier this boundary configured. */
    if (!verification && deps.identity) {
      verifiedBy = "core";
      verification = await deps.identity.verify({
        meta: this.ctx.callerMeta ?? null,
        method: this.ctx.method ?? null,
        params: this.ctx.params ?? {},
      });
    }

    const claimed = typeof this.request.agent === "string" && this.request.agent ? this.request.agent : null;
    const hostAgent = typeof this.ctx.principal === "string" && this.ctx.principal
      ? this.ctx.principal
      : (typeof this.ctx.agent === "string" && this.ctx.agent ? this.ctx.agent : (deps.agent ?? "local"));

    const verified = verification?.verified === true;
    const agentId = verified ? (verification.agentId ?? hostAgent) : null;

    this.identity = {
      verified,
      agentId,
      issuer: verification?.issuer ?? null,
      keyId: verification?.keyId ?? null,
      binding: verification?.binding ?? null,
      reason: verified ? null : (verification?.reason ?? "no identity verifier is configured"),
      mode,
      verifiedBy,
      tenant: verification?.tenant ?? this.ctx.tenant ?? null,
      runtime: verification?.runtime ?? this.ctx.runtime ?? null,
      audience: verification?.audience ?? this.ctx.audience ?? null,
      credentialKeyId: verification?.identity?.publicKey ? keyIdFor(verification.identity.publicKey) : null,
    };

    /* The acting principal, in precedence order: proven identity, then the
       authenticated host context, then the operator default. The request's own
       `agent` is deliberately not on the list. */
    this.principal = verified ? agentId : hostAgent;
    this.claim = claimed && claimed !== this.principal ? claimed : null;

    if (verified) return;

    if (mode === IDENTITY_MODE.DEV_INSECURE) {
      this.stageStatus.identity = "profile-disabled";
      return;
    }

    if (!deps.identity && !this.ctx.identityVerification) {
      if (mode === IDENTITY_MODE.PRODUCTION) {
        return this.#identityRefusal("no identity verifier is configured on this boundary", { mandatory: true });
      }
      /* COMPAT / BOOTSTRAP with no verifier: accepted, loudly marked. */
      this.stageStatus.identity = "accepted-unverified";
      return;
    }

    /* A verifier refused the proof. The claim is never credited: policy is
       re-evaluated under a principal that matches nothing, purely so the
       record can show what WOULD have been decided. */
    this.planned = this.#plannedPolicy();
    return this.#identityRefusal(this.identity.reason ?? "the caller's proof was refused", { mandatory: true });
  }

  #identityRefusal(reason, { mandatory }) {
    this.identityRefused = true;
    this.decisionId = this.#newDecisionId();
    this.decision = {
      decision: DECISION.DENY,
      verdict: "deny",
      rule: "identity-unverified",
      decisionId: this.decisionId,
      decision_id: this.decisionId,
      reason: "The caller identity could not be verified: " + reason + ".",
      remediation:
        "Enrol this agent and sign requests with its identity key, or configure the boundary for an explicit bootstrap window.",
      enforced: true,
      risk: "critical",
      riskSignals: ["identity-unverified"],
      identity: this.identity,
      ...(this.planned ? { planned: plannedRule(this.planned) } : {}),
    };
    if (mandatory) this.mandatory.push({ stage: "identity", rule: "identity-unverified", reason: this.decision.reason, verdict: "deny" });
  }

  #identityRefused() {
    return this.identityRefused === true;
  }

  #normalizeStage() {
    const cwd = this.deps.cwd ?? process.cwd();
    const environment = this.ctx.environment ?? this.deps.environment ?? "local";
    const tool = this.request.tool;
    const args = this.request.arguments ?? this.request.args ?? {};
    const { action } = classifyTool(tool, this.request.server ?? null);
    const rawResource = extractResource(args);
    const resource = rawResource ? canonicalizeResource(rawResource, cwd) : "";
    const destination = extractDestination(args, rawResource);

    this.call = {
      request_id: this.requestId,
      run_id: this.deps.runId ?? null,
      agent: this.principal,
      source: this.ctx.source ?? null,
      timestamp: this.ctx.timestamp ?? new Date(this.now()).toISOString(),
      tool: this.classifiedTool,
      raw_tool: String(tool ?? ""),
      action,
      server: this.request.server ?? null,
      arguments: args,
      resource,
      raw_resource: rawResource,
      destination,
      command: extractCommand(args),
      sql: typeof args?.sql === "string" ? args.sql : typeof args?.query === "string" ? args.query : null,
      environment,
      insideWorkspace: isInsideWorkspace(cwd, resource),
      egress: classifyEgress(destination ?? rawResource),
      touchedSecret: Boolean(this.deps.taint?.touchedSecret),
      secretsDetected: 0,
    };
  }

  #secretsStage() {
    const findings = scanSecrets(this.call.arguments);
    this.call.secretsDetected = findings.length;
    this.findings = findings;
    this.stats.secrets += findings.length;
  }

  #riskStage() {
    const risk = classify(this.call);
    this.risk = risk;
    this.call.risk = risk.level;
    this.call.risk_signals = risk.signals.map((s) => s.id);
    this.call.risk_reason = risk.reason;
    /* Consequence is derived HERE, in the canonical core, next to risk — not
       left to the transport's own normalize(). The core builds this.call by
       hand (it must not depend on the transport envelope), so without this the
       consequence conditions in policy and the maxConsequence constraints on
       missions and delegations would be silently inert on every wired
       boundary while still working for a caller that normalized the call
       itself. A control that fires on one code path and not another is the
       exact failure the canonical core exists to prevent. */
    this.call.consequence = deriveConsequence(this.call);
    this.context = policyRequest(this.call).context;
    /* The record's copy of the context deliberately omits `arguments`: the
       payload is already carried by the transport's own fields, and a second
       copy in every journal entry is both redundant and a second place to
       leak it. Policy still evaluates against the argument-aware context. */
    const { arguments: _args, ...reportContext } = this.context;
    this.reportContext = reportContext;
    /* The policy request carries the trusted principal, never the claim. */
    this.policyRequest = policyRequest(this.call);
    if (this.planned) {
      this.planned.risk = risk.level;
      this.planned.context = this.context;
    }
  }

  #policyStage() {
    const deps = this.deps;
    const rules = deps.rules ?? [];
    const cwd = deps.cwd ?? process.cwd();
    let decision = evaluate(
      { agent: this.principal, action: this.call.action, resource: this.call.resource, context: { ...this.context, arguments: this.call.arguments } },
      rules,
      { cwd },
    );
    decision.decision = decision.decision ?? toDecision(decision.verdict);
    decision.risk = this.risk.level;
    decision.riskSignals = this.risk.signals.map((s) => s.id);
    /* The consequence rides the DECISION as well as the call. A rule like
       `consequence >= data_export` fired because of this value, and the
       record/evidence must be able to say what was enforced, not merely that
       something was — an audit trail that cannot name the consequence makes
       the control unauditable. */
    decision.consequence = this.call.consequence ?? null;
    decision = escalateForRisk(decision, this.risk, { floor: deps.riskFloor ?? "high" });
    this.decision = { ...this.decision, ...decision };
    /* A malformed request is refused later, by the mandatory validation stage —
       recorded here so both surfaces agree on the rule that will name it. */
    if (this.malformed) {
      this.decision.malformedRule = this.malformed.rule;
    }
  }

  async #delegationStage() {
    const presented = this.request.delegation ?? null;
    const broker = this.deps.delegation ?? null;
    const required = this.deps.requireDelegation === true;
    if (!presented && !broker && !required) {
      this.stageStatus.delegation = "not-applicable";
      return;
    }
    const context = await applyDelegation(this.decision, {
      broker,
      presented,
      required,
      agent: this.principal,
      action: this.call.action,
      resource: this.decision.resource ?? this.call.resource,
      call: {
        tool: this.call.tool,
        action: this.call.action,
        resource: this.decision.resource ?? this.call.resource,
        server: this.call.server,
        environment: this.call.environment,
        destination: this.call.destination,
        consequence: this.call.consequence ?? null,
      },
    });
    if (context) {
      this.delegation = context;
      this.call.delegation = context;
    }
    /* Delegation verification can refuse; that refusal is mandatory. */
    if (this.#refusalFrom(this.decision)?.startsWith?.("delegation-")) {
      this.mandatory.push({ stage: "delegation", rule: this.decision.rule ?? null, reason: this.decision.reason ?? null });
    }
  }

  async #authorityStage() {
    const deps = this.deps;
    const costUsd = captureMissionCost(this.ctx);
    this.costUsd = costUsd;
    let mission = this.request.mission ?? this.ctx.mission ?? deps.mission ?? (deps.missions ? deps.missions.forAgent(this.principal) : null);
    if (typeof mission === "string") {
      mission = deps.missions?.get(mission) ?? null;
      if (!mission) {
        this.#refuse(
          { decision: DECISION.DENY, verdict: "deny", rule: "authority-mission-unavailable", reason: "The requested mission could not be resolved.", enforced: true },
          { stage: "authority", mandatory: true },
        );
      }
    }
    if (mission?.id && deps.missions?.get(mission.id)) mission = deps.missions.get(mission.id);
    this.mission = mission ?? null;
    this.missionLease = acquireMission(this.mission);

    if (!this.mission) {
      this.stageStatus.authority = "inert";
      return;
    }

    if (this.decision.rule === "authority-mission-unavailable") {
      this.stageStatus.authority = "refused";
      return;
    }
    const allowanceRefusal = missionAllowanceRefusal(this.mission, costUsd, this.missionLease);
    const assessment = assessAuthority(
      {
        agent: this.principal,
        action: this.call.action,
        resource: this.decision.resource ?? this.call.resource,
        tool: this.call.tool,
        server: this.call.server,
        destination: this.call.destination,
        environment: this.call.environment,
        consequence: this.call.consequence ?? null,
        costUsd,
        delegating: Boolean(this.delegation),
      },
      this.mission,
      { now: this.now() },
    );
    this.authority = assessment;
    this.authorityContext = applyAuthority(this.decision, assessment);
    if (allowanceRefusal) {
      this.#refuse({ ...allowanceRefusal, decision: DECISION.DENY, verdict: "deny", enforced: true }, { stage: "authority", mandatory: true });
    }
    if (deps.missions && assessment.applicable && !assessment.authorized) {
      this.mandatory.push({ stage: "authority", rule: this.decision.rule ?? null, reason: this.decision.reason ?? null });
      deps.missions.recordEscape({
        missionId: this.mission?.id ?? null,
        agent: this.principal,
        kind: assessment.escape?.kind ?? null,
        stage: assessment.stage,
        code: assessment.code,
        action: this.call.action,
        resource: this.decision.resource ?? this.call.resource,
        tool: this.call.tool,
        reason: assessment.reason,
        blocked: this.decision.verdict === "deny" || this.decision.verdict === "hold",
      });
    }
  }

  #capabilityStage() {
    const caps = Array.isArray(this.mission?.capabilities) ? this.mission.capabilities : [];
    this.capabilities = caps.map((c) => c?.name).filter(Boolean);
    if (!this.mission) {
      this.stageStatus.capability = "inert";
      return;
    }
    const assessment = this.authority;
    if (assessment?.capability && !assessment.capability.ok) {
      /* assessAuthority already refused, but the capability verdict is what the
         evidence must name, and revocation matches on the capability id. */
      this.stageStatus.capability = "refused";
    }
  }

  #revocationContext(extra = {}) {
    return revocationContextFor({
      agentId: this.principal,
      tenant: this.identity?.tenant ?? this.ctx.tenant ?? null,
      runtime: this.identity?.runtime ?? this.ctx.runtime ?? null,
      environment: this.call.environment,
      tool: this.call.tool,
      rawTool: this.call.raw_tool,
      resource: this.decision.resource ?? this.call.resource,
      session: this.deps.runId ?? null,
      approvalId: this.decision.approvalId ?? this.pendingApprovalId ?? null,
      missionId: this.mission?.id ?? null,
      capabilities: this.capabilities,
      delegationIds: this.delegation?.chain ?? [],
      principals: this.delegation?.principals ?? [],
      credential: this.identity?.credentialKeyId ?? null,
      keyId: this.identity?.credentialKeyId ?? this.identity?.keyId ?? null,
      identityKeyId: this.identity?.credentialKeyId ?? null,
      ...extra,
    });
  }

  async #revocationStage() {
    if (!this.deps.revocation) {
      this.stageStatus.revocation = "inert";
      return;
    }
    /* An approval on the table for THIS call, resolved before the approval
       branch consumes it: revoking a pending approval must not be a no-op. */
    if (!this.pendingApprovalId) this.pendingApprovalId = this.#pendingApprovalId();
    this.decision = await enforceRevocationAsync(this.decision, this.deps.revocation, this.#revocationContext());
    this.revocation = this.decision.revocation ?? null;
    if (this.revocation?.revoked) this.#markMandatory("revocation");
  }

  #pendingApprovalId() {
    if (!this.deps.approvals) return null;
    if (this.decision?.verdict !== "hold" && this.decision?.decision !== DECISION.REQUIRE_APPROVAL) return null;
    try {
      const grant = this.deps.approvals.findGrant(this.#approvalFingerprint());
      return typeof grant?.id === "string" ? grant.id : null;
    } catch {
      return null;
    }
  }

  #killStage() {
    if (!this.deps.killSwitch) {
      this.stageStatus.kill = "inert";
      return;
    }
    this.killContext = {
      agentId: this.principal,
      tool: this.call.tool,
      rawTool: this.call.raw_tool,
      session: this.deps.runId ?? null,
      environment: this.call.environment,
      mcp: this.call.server,
    };
    this.decision = enforceKillSwitch(this.decision, this.deps.killSwitch, this.killContext);
    if (this.decision.rule === "emergency-kill-switch") this.#markMandatory("kill");
  }

  #trifectaStage() {
    this.trifectaCall = {
      action: this.call.action,
      resource: this.decision.resource ?? this.call.resource,
      tool: this.call.tool,
      server: this.call.server,
      destination: this.call.destination,
      environment: this.call.environment,
      egress: classifyEgress(this.call.destination ?? this.call.resource),
      timestamp: this.call.timestamp,
      sql: this.call.sql,
      secretsDetected: this.call.secretsDetected,
    };
    const taint = this.deps.taint ?? new SessionTaint();
    const trifecta = assessTrifecta(this.trifectaCall, taint, { response: this.deps.trifectaResponse });
    this.decision = applyTrifecta(this.decision, trifecta);
    this.trifecta = trifecta;
    this.decision.trifecta = { complete: trifecta.complete, satisfied: trifecta.satisfied, imminent: trifecta.imminent };
  }

  #policyVersionStage() {
    const stamp = policyStamp(this.deps.rules ?? [], {
      version: this.deps.policyVersion ?? null,
      published: this.deps.publishedPolicy ?? null,
    });
    this.policy = stamp;
    if (!this.deps.publishedPolicy) {
      this.stageStatus["policy-version"] = "inert";
      return;
    }
    if (stamp.stale) {
      const policy = this.deps.onStalePolicy === "hold" ? "hold" : "deny";
      this.#refuse(
        {
          decision: policy === "hold" ? DECISION.REQUIRE_APPROVAL : DECISION.DENY,
          verdict: policy === "hold" ? "hold" : "deny",
          rule: "stale-policy",
          reason: `This runtime is enforcing policy ${stamp.policyHash} but ${stamp.publishedHash} is published. A boundary may not claim a policy it is not enforcing.`,
          remediation: "Reload the published policy, or re-publish the rule set this runtime is actually running.",
          enforced: true,
        },
        { stage: "policy-version", mandatory: policy === "deny" },
      );
    }
  }

  #modeStage() {
    const mode = this.deps.mode ?? MODE.ENFORCE;
    this.decision = applyMode(this.decision, mode);
    this.mode = mode;

    /*  MISSION ALLOWANCE AND CONTENTION ARE HARD BOUNDS, NOT SHADOWS.
     *
     *  Audit mode answers "what would this rule set have broken" by recording
     *  the computed decision and letting the call through. But a mission's
     *  spend and rate limits are not a rule set — they are the budget its
     *  holder was granted, and a boundary that lets an agent exceed them while
     *  "observing" has not shadowed anything, it has spent somebody else's
     *  allowance. So the authority refusal is re-applied after the mode
     *  downgrade, with `enforced: true`, exactly as the socket engine did. */
    if (this.mission && this.authority?.applicable && !this.authority.authorized) {
      this.#refuse(
        {
          decision: DECISION.DENY,
          verdict: "deny",
          enforced: true,
          rule: this.decision.wouldHave?.rule ?? this.decision.rule ?? "authority",
          reason: this.decision.wouldHave?.reason ?? this.decision.reason,
        },
        { stage: "authority", mandatory: true },
      );
    }
    if (this.allowanceRefusal) {
      this.#refuse(
        { ...this.allowanceRefusal, decision: DECISION.DENY, verdict: "deny", enforced: true },
        { stage: "authority", mandatory: true },
      );
    }
  }

  #entitlementStage() {
    const deps = this.deps;
    if (!deps.licence && !deps.meter && !deps.agents) {
      this.stageStatus.entitlements = "inert";
      return;
    }
    Object.assign(
      this.decision,
      applyEntitlements(this.decision, {
        licence: deps.licence,
        meter: deps.meter,
        agents: deps.agents,
        agent: this.principal,
      }),
    );
  }

  #intentStage() {
    const declared = this.request.intent ?? this.ctx.intent ?? this.deps.intent ?? null;
    if (!declared) {
      this.stageStatus.intent = "inert";
      return;
    }
    if (this.decision.decision === DECISION.DENY || this.decision.decision === DECISION.AUDIT_ONLY) {
      this.stageStatus.intent = "skipped-already-refused";
      this.intent = { evaluated: false, reason: "the call was already refused" };
      return;
    }
    const evaluation = evaluateIntent({
      intent: declared,
      action: this.call.action,
      resource: this.call.resource,
      tool: this.call.tool,
      context: this.ctx,
    });
    this.intent = evaluation;
    this.call.intentEvaluation = evaluation;
    if (!evaluation.aligned) {
      this.#refuse(
        {
          decision: DECISION.DENY,
          verdict: "deny",
          rule: "intent-firewall-boundary",
          reason: evaluation.reason,
          risk: "high",
          enforced: true,
        },
        { stage: "intent", mandatory: true },
      );
    }
  }

  #sessionStage() {
    if (!this.deps.sessionTracker) {
      this.stageStatus.session = "inert";
      return;
    }
    const tracker = this.deps.sessionTracker;
    const chainCheck = tracker.recordStep({
      action: this.call.action,
      resource: this.call.resource,
      tool: this.call.tool,
      decision: this.decision.decision,
      risk: this.call.risk,
    });
    this.session = { ...chainCheck, status: tracker.status ?? null };
    this.call.sessionRisk = chainCheck.risk;
    const auditOnly = this.decision.decision === DECISION.AUDIT_ONLY;
    if (chainCheck.suspicious && this.decision.decision !== DECISION.DENY && (!auditOnly || (tracker.status ?? "active") !== "active")) {
      this.#refuse(
        {
          decision: DECISION.DENY,
          verdict: "deny",
          rule: "stateful-exfiltration-chain",
          reason: chainCheck.reason,
          risk: "critical",
          enforced: true,
        },
        { stage: "session", mandatory: true },
      );
    }
  }

  #baselineStage() {
    if (!this.deps.baseline) {
      this.stageStatus.baseline = "inert";
      return;
    }
    const deviation = this.deps.baseline.scoreDeviation({
      tool: this.call.tool,
      action: this.call.action,
      resource: this.call.resource,
    });
    this.baseline = deviation;
    this.call.anomalyScore = deviation.anomalyScore;
    if (deviation.isDeviation && this.decision.decision === DECISION.ALLOW) {
      this.decision = escalateForRisk(
        this.decision,
        { level: "HIGH", signals: ["behavioral_anomaly"], reason: deviation.reasons?.[0] ?? "behavioural deviation" },
        { floor: this.deps.riskFloor ?? "high" },
      );
      this.baselineEscalated = true;
    }
  }

  #driftStage() {
    const drift = this.deps.drift;
    if (!drift) {
      this.stageStatus.drift = "inert";
      return;
    }
    const verdict = typeof drift === "function"
      ? drift({ tool: this.call.raw_tool, server: this.call.server, action: this.call.action })
      : drift.check?.({ tool: this.call.raw_tool, server: this.call.server, action: this.call.action }) ?? { status: "unknown" };
    this.drift = verdict ?? { status: "unknown" };
    if (this.drift.status === "drifted" || this.drift.status === "unpinned") {
      const policy = this.deps.onDrift === "hold" ? "hold" : "deny";
      this.#refuse(
        {
          decision: policy === "hold" ? DECISION.REQUIRE_APPROVAL : DECISION.DENY,
          verdict: policy === "hold" ? "hold" : "deny",
          rule: "tool-definition-drift",
          reason: this.drift.reason ?? "The tool definition does not match the approved pin.",
          remediation: "Review and re-approve the tool definition, then retry.",
          enforced: true,
        },
        { stage: "drift", mandatory: policy === "deny" },
      );
    }
  }

  #validationStage() {
    if (!this.malformed) return;
    const { rule, reason } = this.malformed;
    this.#refuse(
      { decision: DECISION.DENY, verdict: "deny", rule, reason, enforced: true },
      { stage: "validation", mandatory: true },
    );
  }

  #approvalFingerprint() {
    return approvalFingerprint({
      agent: this.principal,
      server: this.call.server,
      environment: this.call.environment,
      action: this.call.action,
      resource: this.decision.resource ?? this.call.resource,
      command: this.call.command,
      delegation: this.delegation?.principals ?? null,
      arguments: this.call.arguments,
    });
  }

  async #approvalStage() {
    const deps = this.deps;
    const held = this.decision.verdict === "hold" || this.decision.decision === DECISION.REQUIRE_APPROVAL;
    if (!held) return;
    if (!deps.approvals) {
      this.approval = { state: "absent", approvalId: this.decision.approvalId ?? this.#newApprovalId() };
      this.decision.approvalId = this.approval.approvalId;
      return;
    }

    const fingerprint = this.#approvalFingerprint();
    try {
      const grant = deps.approvals.findGrant(fingerprint);
      if (grant) {
        await deps.approvals.consume(grant.id, this.decisionId ?? this.requestId);
        this.decision.decision = DECISION.ALLOW;
        this.decision.verdict = "permit";
        this.decision.approvalId = grant.id;
        this.decision.approvedBy = grant.decidedBy;
        this.decision.reason = `Approved by ${grant.decidedBy}. ${this.decision.reason ?? ""}`.trim();
        this.approval = { state: "valid", approvalId: grant.id, approvedBy: grant.decidedBy };
        return;
      }
      const approval = await deps.approvals.request({
        request_id: this.requestId,
        agent: this.principal,
        /* The CLASSIFIED tool name, which is what the rest of the system reads
           (`shell_exec` and `shell.exec` are one tool, and the approval queue
           is joined on the canonical spelling). The raw spelling stays in the
           decision record, where "what the agent actually called" belongs. */
        tool: this.call.tool,
        resource: this.decision.resource ?? this.call.resource,
        risk: this.call.risk,
        rule: this.decision.rule,
        reason: this.decision.reason,
        approvers: this.decision.approvers ?? [],
        fingerprint,
      });
      this.decision.approvalId = approval.id;
      this.approval = { state: approval.state ?? "pending", approvalId: approval.id };
      if (approval.state === "denied") {
        this.decision.decision = DECISION.DENY;
        this.decision.verdict = "deny";
        this.decision.reason = `Denied by ${approval.decidedBy}. ${this.decision.reason ?? ""}`.trim();
        this.approval.state = "denied";
      }
    } catch (err) {
      this.#refuse(
        {
          decision: DECISION.DENY,
          verdict: "deny",
          rule: "approval-unavailable",
          reason: `This call needs human approval and the approval store is unavailable (${err.message}). Refused rather than held, because a hold nobody can see is not a hold.`,
          remediation: "Check the approval log is writable, then retry.",
          enforced: true,
        },
        { stage: "approval", mandatory: true },
      );
    }
  }

  #newApprovalId() {
    return `apr_${String(this.decisionId ?? this.requestId).replace(/^dec_/, "").replace(/^req_/, "")}`;
  }

  /**
   * CREDENTIAL STAGE (§17).
   *
   * Two things live here, and they must not be confused:
   *
   *   - STATIC SECRET SUBSTITUTION: a handle in the arguments is replaced by
   *     the material the vault holds. Compatibility mechanism.
   *   - SHORT-LIVED SCOPED CREDENTIAL VENDING: the core states a REQUIREMENT
   *     (`outcome.credentialRequirement`) and a broker that can mint scoped,
   *     expiring material satisfies it. No broker in this codebase does that
   *     yet (AR-4), so the requirement is produced and reported, never faked.
   *
   * The core never couples itself to AWS/Stripe: it says what is required.
   */
  async #credentialStage() {
    const deps = this.deps;
    this.outgoing = this.call.arguments;
    this.credentialRequirement = null;

    if (!deps.secrets) {
      if (this.findings?.length) {
        this.credentialRequirement = {
          kind: "static-secret-substitution",
          required: false,
          reason: "secret-shaped material is present in the arguments but no credential broker is configured",
        };
      }
      this.stageStatus.credential = "not-applicable";
      return;
    }

    if (!isForwarded(this.decision.decision)) return;

    let substitution;
    try {
      substitution = await deps.secrets.substitute(this.call.arguments, {
        destination: this.call.destination,
        subject: this.principal,
      });
    } catch (err) {
      substitution = {
        ok: false,
        reason: `The secret broker is unavailable (${err.message}), so this call was refused rather than sent with unresolved arguments.`,
      };
    }

    const substituted =
      substitution !== null &&
      typeof substitution === "object" &&
      substitution.ok === true &&
      substitution.value !== undefined;

    if (substituted) {
      this.outgoing = substitution.value;
      this.brokered = Array.isArray(substitution.substituted) ? substitution.substituted : [];
      this.credential = { state: "substituted", kind: "static-secret-substitution", handles: this.brokered };
      return;
    }

    if (substitution === null || typeof substitution !== "object" || substitution.ok !== false) {
      this.#refuse(
        {
          decision: DECISION.DENY,
          verdict: "deny",
          rule: "secret-broker",
          reason:
            "The secret broker returned a response this engine cannot interpret, so the call was refused rather than forwarded with unverified arguments.",
          remediation: "Check the broker version matches the runtime.",
          enforced: true,
        },
        { stage: "credential", mandatory: true },
      );
      return;
    }

    this.credential = { state: substitution.outcome === "revoked" ? "revoked" : "refused", reason: substitution.reason };
    this.#refuse(
      {
        decision: DECISION.DENY,
        verdict: "deny",
        rule: substitution.outcome === "revoked" ? "credential-revoked" : "secret-broker",
        reason: substitution.reason,
        remediation:
          substitution.outcome === "revoked"
            ? "Re-issue or restore the credential handle in the vault."
            : "Request a handle scoped to this destination, or add the destination to the secret's allowlist.",
        enforced: true,
      },
      { stage: "credential", mandatory: true },
    );
  }

  #sanitizeStage() {
    if (this.decision.decision !== DECISION.SANITIZE) return;
    const targets = new Set(this.decision.sanitize?.flatMap((s) => s.targets) ?? ["arguments", "result"]);
    if (!targets.has("arguments")) return;
    const cleaned = redactSecrets(this.outgoing ?? this.call.arguments);
    if (cleaned.findings?.length) {
      this.outgoing = cleaned.value;
      this.decision.sanitized = {
        arguments: cleaned.findings.map((f) => ({ path: f.path, detector: f.detector, fingerprint: f.fingerprint })),
      };
    }
  }

  async #finalTightenStage() {
    /* Revocation and the kill switch are re-read: state can have moved between
       the first check and here (another process killing mid-decision), and the
       record must carry the version that actually decided. */
    if (this.deps.killSwitch && this.killContext) {
      this.decision = enforceKillSwitch(this.decision, this.deps.killSwitch, this.killContext);
    }
    if (this.deps.revocation) {
      this.decision = await enforceRevocationAsync(this.decision, this.deps.revocation, this.#revocationContext());
      this.revocation = this.decision.revocation ?? this.revocation;
      if (this.revocation?.revoked) this.#markMandatory("revocation");
      this.call.revocation = this.revocation;
    }
    this.#finalize();
    if (!isForwarded(this.decision.decision)) this.outgoing = this.call.arguments;
  }

  /**
   * PRECEDENCE (§7).
   *
   * The most restrictive applicable outcome wins, and a mandatory refusal is
   * terminal. `applyMode` may have downgraded a decision to AUDIT_ONLY by an
   * explicit operator choice; that is reported (`enforced: false`) rather than
   * hidden, and the mandatory refusals still ride the evidence.
   */
  #finalize() {
    if (!this.mandatory.length) return;
    /* Audit mode is an explicit operator choice: it records what would have
       happened and lets the call through (`enforced: false`). The mandatory
       refusals still ride the evidence, and `wouldHave` carries the outcome a
       hardened boundary would have produced. Hiding this is the failure mode;
       the marker is what makes it a shadow run rather than a bypass. */
    if (this.decision.enforced === false) return;

    const deny = this.mandatory.find((m) => m.verdict !== "hold");
    const hold = this.mandatory.find((m) => m.verdict === "hold");
    const winner = deny ?? hold;
    if (!winner) return;

    const mostRestrictive = deny ? DECISION.DENY : DECISION.REQUIRE_APPROVAL;
    const rank = (d) => DECISION_PRECEDENCE.indexOf(d);
    /* Most restrictive applicable result wins, and a mandatory refusal can
       never be turned back into ALLOW by a later stage. */
    if (this.decision.decision !== mostRestrictive && rank(mostRestrictive) <= rank(this.decision.decision)) {
      this.decision.decision = mostRestrictive;
      this.decision.verdict = deny ? "deny" : "hold";
      this.decision.rule = winner.rule ?? this.decision.rule;
      this.decision.reason = winner.reason ?? this.decision.reason;
    }
  }

  #markMandatory(stage) {
    if (!this.mandatory.some((m) => m.stage === stage)) {
      this.mandatory.push({
        stage,
        rule: this.decision.rule ?? null,
        reason: this.decision.reason ?? null,
        verdict: this.decision.verdict ?? "deny",
      });
    }
  }

  #refusalFrom(decision) {
    if (!decision) return null;
    if (decision.decision === DECISION.DENY || decision.decision === DECISION.REQUIRE_APPROVAL) return decision.rule ?? "deny";
    return null;
  }

  /** Policy re-evaluated under a principal that matches nothing, for the record only. */
  #plannedPolicy() {
    const cwd = this.deps.cwd ?? process.cwd();
    const args = this.request.arguments ?? this.request.args ?? {};
    const { action } = classifyTool(this.request.tool, this.request.server ?? null);
    const rawResource = extractResource(args);
    const resource = rawResource ? canonicalizeResource(rawResource, cwd) : "";
    const destination = extractDestination(args, rawResource);
    const scanned = scanSecrets(args);
    const classified = classify({
      action,
      tool: this.request.tool,
      resource,
      command: extractCommand(args),
      destination,
      environment: this.ctx.environment ?? this.deps.environment ?? "local",
      insideWorkspace: isInsideWorkspace(cwd, resource),
      touchedSecret: Boolean(this.deps.taint?.touchedSecret),
      secretsDetected: scanned.length,
    });
    const context = {
      environment: this.ctx.environment ?? this.deps.environment ?? "local",
      path: { insideWorkspace: isInsideWorkspace(cwd, resource) },
      egress: {
        external: classifyEgress(destination ?? resource) === "external",
        internal: classifyEgress(destination ?? resource) === "internal",
        allowlisted: false,
        destination,
      },
      session: { touchedSecret: Boolean(this.deps.taint?.touchedSecret) },
      mcp: { server: this.request.server ?? null, tool: this.request.tool ?? null },
      risk: classified.level,
      tool: action,
      command: extractCommand(args),
      secrets: { detected: scanned.length },
    };
    const planned = evaluate(
      { agent: SANDBOXED_PRINCIPAL, action, resource, context: { ...context, arguments: args } },
      this.deps.rules ?? [],
      { cwd },
    );
    planned.decision = planned.decision ?? toDecision(planned.verdict);
    planned.risk = classified.level;
    return planned;
  }

  /**
   * The decision id.
   *
   * A transport may name decisions its own way (`deps.newDecisionId`) because
   * the id is what `cirvix why`, `replay` and the console join on, and each
   * surface derives it from what it has: the MCP boundary from its own
   * sequence, the socket from the request id the client supplied. What the
   * core owns is that the decision, the record and the receipt all carry the
   * SAME one.
   */
  #newDecisionId() {
    if (typeof this.deps.newDecisionId === "function") {
      const supplied = this.deps.newDecisionId(this.requestId);
      if (typeof supplied === "string" && supplied) return supplied;
    }
    const n = typeof this.deps.nextDecisionSeq === "function" ? this.deps.nextDecisionSeq() : 0;
    return `dec_${Date.now().toString(36)}${(n ?? 0).toString(36)}`;
  }

  /**
   * EVIDENCE (§20 of P0-D, and the P0-E seam).
   *
   * Builds the authoritative record of WHAT WAS DECIDED and hands it to the
   * transport's own renderer, then performs the ONE append. A record that
   * cannot be written turns a forwarded decision into a refusal — once, here,
   * instead of once per engine.
   */
  async #evidenceStage() {
    this.#finalize();
    const latencyMs = Number(process.hrtime.bigint() - this.startedAt) / 1e6;
    this.latencyMs = latencyMs;
    if (!this.decision) this.decision = { decision: DECISION.DENY, verdict: "deny", rule: "no-decision", reason: "No stage produced a decision.", enforced: true };
    this.decisionId = this.decision.decisionId ?? this.#newDecisionId();
    this.decision.decisionId = this.decisionId;
    this.decision.decision_id = this.decisionId;
    this.decision.requestId = this.requestId;
    this.decision.timestamp = new Date(this.now()).toISOString();
    this.decision.runId = this.deps.runId ?? null;
    this.decision.agentId = this.principal;
    this.decision.tenant = this.identity?.tenant ?? null;
    this.decision.runtime = this.identity?.runtime ?? null;
    this.decision.audience = this.identity?.audience ?? null;
    this.decision.action = this.call.action;
    this.decision.resource = this.decision.resource ?? this.call.resource;
    this.decision.policyVersion = this.policy?.policyVersion ?? null;
    this.decision.policyHash = this.policy?.policyHash ?? null;
    this.decision.profile = this.profile;
    this.decision.surface = this.surface;

    /* The session's own observation of this call (leg A). One place, so the
       gateway and the socket taint identically — a brokered substitution
       deliberately does not taint, because the agent never held the material. */
    if (this.deps.taint && this.trifectaCall) {
      this.deps.taint.observeCall(this.trifectaCall, isForwarded(this.decision.decision));
    }

    this.evidence = this.#buildEvidence();
    this.decision.authority = this.evidence.authority ?? undefined;

    const record = typeof this.deps.buildRecord === "function"
      ? this.deps.buildRecord(this)
      : this.evidence;

    const forwarded = isForwarded(this.decision.decision);
    if (this.deps.audit) {
      try {
        await this.deps.audit.append(record);
      } catch (err) {
        record.audit_write_failed = true;
        this.auditFailed = String(err?.message ?? err);
        if (forwarded) {
          Object.assign(this.decision, {
            decision: DECISION.DENY,
            verdict: "deny",
            rule: "audit-unavailable",
            reason: `The decision could not be recorded (${this.auditFailed}), so the call was refused. A call with no audit record is a call nobody can account for.`,
            remediation: "Check the audit log path is writable, then retry.",
            enforced: true,
          });
          Object.assign(record, {
            decision: DECISION.DENY,
            verdict: "deny",
            rule: "audit-unavailable",
            policy: "audit-unavailable",
            reason: this.decision.reason,
          });
          this.outgoing = this.call.arguments;
          this.mandatory.push({ stage: "evidence", rule: "audit-unavailable", reason: this.decision.reason });
        }
      }
    }

    this.record = record;
    /* The transport's own sink (its record/event emitter) runs BEFORE the
       mission is charged, and deliberately so: a sink that throws must leave
       the allowance unspent, or the agent pays for a call whose decision never
       reached anybody and cannot retry it. */
    if (typeof this.deps.publish === "function") this.deps.publish(this);
    if (this.decision.verdict === "deny") this.stats.denied += 1;
    else if (this.decision.verdict === "hold") this.stats.held += 1;
    else this.stats.permitted += 1;
    if (this.mission && isForwarded(this.decision.decision)) recordMissionUsage(this.mission, { costUsd: this.costUsd ?? 0 });
  }

  #buildEvidence() {
    const stages = {};
    for (const name of CANONICAL_STAGES) {
      stages[name] = {
        status: this.stageStatus[name] ?? "ran",
        ms: Number((this.stageMs[name] ?? 0).toFixed(4)),
      };
    }
    return {
      surface: this.surface,
      profile: this.profile,
      authorityPosture: this.deps.requireDelegation ? AUTHORITY_POSTURE.REQUIRED : AUTHORITY_POSTURE.OPTIONAL,
      decisionId: this.decisionId,
      requestId: this.requestId,
      traceId: this.requestId,
      timestamp: this.decision.timestamp,
      agentId: this.principal,
      principalId: this.principal,
      claim: this.claim,
      tenant: this.identity?.tenant ?? null,
      runtime: this.identity?.runtime ?? null,
      audience: this.identity?.audience ?? null,
      identity: this.identity,
      action: this.call.action,
      resource: this.decision.resource ?? this.call.resource,
      risk: this.risk?.level ?? null,
      riskSignals: this.risk?.signals?.map((s) => s.id) ?? [],
      consequence: this.call.consequence ?? null,
      policy: this.policy ?? null,
      delegation: this.delegation ?? null,
      authority: this.authorityContext ?? null,
      mission: this.mission ? { id: this.mission.id, status: this.mission.status ?? null } : null,
      capabilities: this.capabilities,
      intent: this.intent ?? null,
      session: this.session ?? null,
      baseline: this.baseline ?? null,
      drift: this.drift ?? null,
      revocation: this.revocation ?? null,
      approval: this.approval ?? null,
      credentialRequirement: this.credentialRequirement ?? null,
      credential: this.credential ?? null,
      obligations: this.obligations,
      mandatoryRefusals: this.mandatory,
      stageFailures: this.stageFailures,
      stages,
      enforced: this.decision.enforced !== false,
      mode: this.decision.mode ?? this.mode ?? MODE.ENFORCE,
      latencyMs: Number(this.latencyMs.toFixed(3)),
      secretsDetected: (this.findings ?? []).map((f) => ({
        path: f.path,
        detector: f.detector,
        severity: f.severity,
        masked: f.masked,
        fingerprint: f.fingerprint,
      })),
      secretsBrokered: this.brokered ?? [],
      trifecta: this.trifecta
        ? { complete: this.trifecta.complete, satisfied: this.trifecta.satisfied, imminent: this.trifecta.imminent }
        : null,
      escape: this.decision.escape ?? null,
      considered: this.decision.considered ?? null,
      auditWriteFailed: this.auditFailed ?? null,
    };
  }

  /**
   * The identity-refusal exit.
   *
   * An unverified caller gets its decision, its record, its audit entry and its
   * counters from ONE place — here — so there is nowhere else that has to
   * remember to attribute a refusal correctly, and the transport's own record
   * shape is produced by the same builder the successful path uses.
   */
  async #finish({ refusedIdentity = false } = {}) {
    if (!refusedIdentity) return this.#outcome();
    this.latencyMs = Number(process.hrtime.bigint() - this.startedAt) / 1e6;
    this.risk = this.risk ?? { level: "critical", signals: [{ id: "identity-unverified" }], reason: "the caller identity was not verified" };
    /* No call was ever normalized. The placeholder exists so the transport's
       record builder can render the refusal from the same fields it always
       reads, instead of a second, refusal-only shape. */
    this.call = this.call ?? {
      request_id: this.requestId,
      run_id: this.deps.runId ?? null,
      agent: this.principal,
      source: this.ctx.source ?? null,
      timestamp: new Date(this.now()).toISOString(),
      tool: null,
      raw_tool: null,
      action: null,
      server: null,
      arguments: {},
      resource: null,
      destination: null,
      command: null,
      environment: this.ctx.environment ?? this.deps.environment ?? "local",
      insideWorkspace: true,
      egress: "none",
      touchedSecret: Boolean(this.deps.taint?.touchedSecret),
      secretsDetected: 0,
    };
    this.evidence = this.#buildEvidence();
    const record = typeof this.deps.buildRecord === "function"
      ? this.deps.buildRecord(this, { identityRefusal: true })
      : this.evidence;
    this.record = record;
    this.stats.denied += 1;
    if (this.deps.audit) {
      try {
        await this.deps.audit.append(record);
      } catch {
        /* Already a refusal: an unwritable journal cannot make it worse. */
        record.audit_write_failed = true;
      }
    }
    if (typeof this.deps.publish === "function") this.deps.publish(this);
    return this.#outcome();
  }

  #outcome() {
    return {
      decision: this.decision,
      verb: this.decision.decision,
      decisionId: this.decisionId,
      requestId: this.requestId,
      traceId: this.requestId,
      identity: this.identity,
      principal: this.principal,
      claim: this.claim,
      call: this.call,
      context: this.context,
      evidence: this.evidence,
      record: this.record,
      /* NOT `??`: a broker that legitimately returns `null` is a broker
         response the transport must be handed as-is, so the caller can refuse
         it. Coalescing it here silently restored the unsubstituted arguments —
         which is the exact fail-open this stage exists to prevent. */
      args: this.outgoing === undefined ? this.call?.arguments ?? {} : this.outgoing,
      counters: this.stats,
      latencyMs: this.latencyMs,
      mandatoryRefusals: this.mandatory,
      stageFailures: this.stageFailures,
      profile: this.profile,
    };
  }
}

/* ========================================================================== */
/*  Canonical request validation                                               */
/* ========================================================================== */

/**
 * The DEFAULT request contract. A transport may tighten it (the socket also
 * requires a string request id) but may not loosen it: a tool call needs a
 * non-empty tool name and object arguments, in every mode, on every surface.
 */
export function defaultValidateRequest(request, _ctx = {}) {
  const tool = request?.tool ?? request?.name;
  const args = request?.arguments ?? request?.args;
  if (typeof tool !== "string" || !tool.trim()) {
    return {
      rule: "invalid-request",
      reason: "A tool call needs a non-empty string tool name and object arguments.",
    };
  }
  if (args != null && (typeof args !== "object" || Array.isArray(args))) {
    return {
      rule: "invalid-request",
      reason: "A tool call needs a non-empty string tool name and object arguments.",
    };
  }
  return null;
}

function plannedRule(decision) {
  /* The record shows the rule policy WOULD have applied, without ever
     crediting the unverified caller with a decision. */
  if (!decision) return null;
  const verdict = decision.verdict ?? (decision.decision === DECISION.ALLOW ? "permit" : decision.decision === DECISION.REQUIRE_APPROVAL ? "hold" : "deny");
  return { verdict, rule: decision.rule ?? null };
}

/**
 * The canonical entry point.
 *
 * @param {object} request            transport-shaped, UNTRUSTED
 * @param {object} securityContext    trusted input from the transport
 * @param {object} deps               the boundary's wiring
 * @returns {Promise<object>} the canonical outcome
 */
export async function authorize(request, securityContext = {}, deps = {}) {
  return await new AuthorizationRun(request, securityContext, deps).execute();
}

/* -------------------------------------------------------------------------- */

