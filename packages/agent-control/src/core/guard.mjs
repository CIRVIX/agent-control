/**
 * The decision core, and the in-process SDK built on it.
 *
 * IDENTITY ORDERING (INV-009). `authorize()` ESTABLISHES WHO IS CALLING before
 * it decides anything. The order inside this file is the trust model:
 *
 *   transport authentication (socket token / stdio peer, upstream of here)
 *   -> cryptographic verification (credential + request signatures)
 *   -> enrolment / status / revocation / replay / clock-skew checks
 *   -> a trusted principal replaces every claimed name
 *   -> request normalization
 *   -> the authorization pipeline
 *
 * An unverified caller is denied by a SHORT-CIRCUIT before policy, delegation,
 * authority, trifecta, entitlements or approvals run on its behalf. No
 * identity-dependent stage ever evaluates a claim, and no later stage can
 * convert a planned identity denial into ALLOW. The record carries the planned
 * rule alongside the enforced one, so the audit trail shows what would have
 * been decided without crediting the unverified caller with a decision.
 *
 * The MCP gateway and `guard.wrap()` are two transports for one question: may
 * this agent make this tool call. They MUST NOT be two implementations of the
 * answer. A guard that permits what the gateway denies is worse than having no
 * SDK at all — it is a governance product with a documented bypass — so the
 * decision path lives here once and both call it.
 *
 * WHAT `wrap` IS FOR
 *
 * The gateway governs everything an agent does, including tools added after
 * you deployed it, because it sits on the wire. It also requires the agent to
 * speak MCP. `wrap` is for the case where it does not: a LangChain executor, a
 * CrewAI crew, a hand-rolled loop over some functions. You give up the
 * "governs tools you did not know about" property — you are wrapping a list —
 * and you keep every other one: same engine, same rules, same decision record,
 * same secret brokering, same audit chain.
 *
 * That trade is stated in the docs rather than glossed, because an operator
 * who believes `wrap` is equivalent to the gateway will not understand why a
 * tool the agent reached directly was never evaluated.
 */

import { canonicalizeResource } from "./policy.mjs";
import { DECISION, MODE } from "./decisions.mjs";
import { classifyTool, classifyEgress, isInsideWorkspace, extractResource, extractDestination, publicToolName } from "./normalize.mjs";
import { redact as redactSecrets } from "./secret-detect.mjs";
import { stripInjection } from "./sanitize.mjs";
import { captureMissionCost } from "./authority.mjs";
import { SessionTaint } from "./trifecta.mjs";
import { IDENTITY_MODE, normalizeIdentityMode } from "./identity-modes.mjs";
/* THE CANONICAL AUTHORIZATION CORE. Every stage semantics lives there; this
   file is the MCP/SDK transport adapter over it. See core/authorize.mjs. */
import {
  AUTHORITY_POSTURE,
  CANONICAL_STAGES,
  SECURITY_PROFILE,
  STAGE_STATUS,
  SURFACE,
  authorize as authorizeCanonical,
  describeCanonicalPosture,
  policyStamp,
  resolveSecurityProfile,
  stagePlan,
} from "./authorize.mjs";

/**
 * A refusal the agent can read and plan around.
 *
 * Thrown rather than returned because a wrapped tool has to interrupt the
 * call, and carrying structure rather than a string is what lets an agent
 * re-plan instead of retrying the same thing: `remediation` frequently names
 * the legitimate path ("request it as a handle").
 */
export class CirvixDenied extends Error {
  constructor({ policy, decisionId, reason, remediation, appealable = false, resource, action }) {
    super(reason ?? `Denied by ${policy ?? "policy"}.`);
    this.name = "CirvixDenied";
    /** The rule that decided it. */
    this.policy = policy ?? null;
    /** Hand to `cirvix why` for the full record. */
    this.decisionId = decisionId ?? null;
    this.reason = reason ?? null;
    this.remediation = remediation ?? null;
    /** Whether re-requesting with an approval could succeed. */
    this.appealable = appealable;
    this.resource = resource ?? null;
    this.action = action ?? null;
  }
}

/**
 * A call suspended for a person.
 *
 * A distinct type from a denial, because they call for different behaviour: a
 * denial means re-plan, a hold means this exact call may still happen once
 * somebody says yes. Collapsing them teaches agents to treat both as failure.
 */
export class CirvixHeld extends CirvixDenied {
  constructor(fields) {
    super({ ...fields, appealable: true });
    this.name = "CirvixHeld";
    this.approvers = fields.approvers ?? [];
    this.approvalId = fields.approvalId ?? null;
  }
}

/**
 * Maps a tool name to the action vocabulary policy is written against.
 *
 * DELEGATES TO `classifyTool`. THERE IS ONE CLASSIFIER.
 *
 * This used to be a second, independent set of patterns, and the two disagreed.
 * `fetch_url` was `http.request` to the pipeline and `fs.read` here — so the
 * gateway evaluated a network fetch against the filesystem rules, and a policy
 * that read correctly governed a different thing depending on which door the
 * call came through. `fetch_file` had the mirror-image bug in the other
 * direction.
 *
 * That is the same class of defect as two policy engines, one level further
 * up: what a tool *is* has to be decided once, or every rule below it is
 * conditional on the transport. The consistency oracle found it.
 *
 * The MCP resource operations keep their explicit mapping, because they are
 * protocol methods rather than tool names and `classifyTool` has no reason to
 * know about them.
 */
export function actionForTool(server, tool) {
  const t = String(tool).toLowerCase();

  /*
   * A resource URI is overwhelmingly a file, and a subscription is a standing
   * read of one. Mapped explicitly because `resources.subscribe` matches no
   * pattern and would fall through to `mcp.<server>.resources.subscribe` —
   * default-denied, so every legitimate subscription breaks, and governed by no
   * filesystem rule, so the rules protecting `~/.aws/**` would not apply if
   * someone later added a permit for it.
   */
  if (t === "resources.read" || t === "resources.subscribe") return "fs.read";
  if (t === "resources.list" || t === "resources.templates.list") return "fs.list";

  return classifyTool(tool, server).action;
}

/**
 * Extracts the resource a call targets. Best-effort by design: an unrecognised
 * shape yields the empty string, so the call is still evaluated rather than
 * skipped.
 */
export function resourceForCall(args) {
  return extractResource(args);
}

/**
 * The endpoint a call will reach, or null. Only an absolute http(s) URL counts.
 *
 * Canonical, not raw. A destination rule is a string match, so the raw form let
 * `http://2852039166/` — decimal for 169.254.169.254 — walk past a rule naming
 * the dotted address. Same normalization as `normalize.extractDestination`,
 * because the gateway reaches policy through this function and the socket
 * reaches it through that one; two spellings of the destination is two policies.
 */
export function destinationFor(resource, args) {
  return extractDestination(args, resource) ?? null;
}

/* -------------------------------------------------------------------------- */

/**
 * One decision, made the same way wherever it is made from.
 *
 * Holds the session-scoped state a verdict can depend on — most importantly
 * `touchedSecret`, which is what makes "read a credential, then post it
 * somewhere" fail even when both calls are individually allowed.
 */
export class Guard {
  constructor({
    /* The enforcement surface this adapter speaks for (P0-D). It rides every
       canonical decision as evidence; it never selects a stage. */
    surface = "mcp-gateway",
    rules,
    agent = "local",
    environment = "local",
    cwd = process.cwd(),
    audit = null,
    secrets = null,
    onDecision = () => {},
    log = () => {},
    runId = null,
    riskFloor = "high",
    delegation = null,
    /* Mission-scoped authority. Absent by default, and absent means INERT —
       not "deny everything". Authority is subtractive: it can take away what
       policy allows and can never add to it, so a Guard built without a
       mission behaves exactly as before. See core/authority.mjs. */
    missions = null,
    mission = null,
    /* AUTHORITY-REQUIRED posture. When true, a governed call that presents no
       signed delegation is REFUSED rather than decided by policy alone. Default
       false keeps the historic contract for library callers; the CLI turns it
       on with `--require-authority`. Presenting authority this boundary cannot
       verify is a refusal in either posture. */
    requireDelegation = false,
    /* Commercial enforcement. All three default to absent, so a Guard built
       without them behaves exactly as before — which is what keeps the SDK's
       library callers and the shared conformance fixture working unchanged.
       The CLI supplies them. */
    licence = null,
    meter = null,
    agents = null,
    approvals = null,
    killSwitch = null,
    /* The durable revocation fabric (core/revocation.mjs). Absent means this
       boundary has no revocation source and revocation never refuses — the
       same "absent is inert" contract every other optional layer keeps. It is
       evaluated BESIDE the kill switch, not instead of it: the kill switch is
       a process-local Map, this survives restarts and reaches other
       processes, and a boundary armed with either must honour it. */
    revocation = null,
    /* Authenticated identity. Absent means the boundary runs unverified, which
       the record states rather than implying. Supplied by the CLI/gateway once
       the host is enrolled. See core/identity.mjs. */
    identity = null,
    /* How the boundary behaves when identity cannot be established. From
       IDENTITY_MODE. NEVER inferred from enrolment state: a fresh production
       install must not become an unauthenticated authorization endpoint just
       because nobody has enrolled yet. Library callers default to COMPAT (the
       historic behaviour); shipped boundaries default to PRODUCTION.
       `null` means NO STATEMENT: the core then takes the transport's mode, or
       COMPAT if neither layer states one. A library default that silently
       overrode a boundary's explicit mode is the same class of bug as a
       default that silently weakened it. */
    identityMode = null,
    /* P0-D — the stages that used to exist on ONE engine only, or in tests
       only. They are accepted here now so that the gateway runs the same
       canonical sequence as the socket. Absent is INERT, and `doctor` reports
       it as inert; what it must never be is silently skipped. */
    mode = MODE.ENFORCE,
    sessionTracker = null,
    baseline = null,
    intent = null,
    drift = null,
    /* Policy identity: the fingerprint of the rules in force is computed by
       the core; `publishedPolicy` is the operator's stamp. Present and
       different means this runtime is enforcing a stale policy and says so.
       Absent means there is nothing published to compare against — reported
       as inert rather than as agreement. */
    publishedPolicy = null,
    policyVersion = null,
    onStalePolicy = "deny",
    /* What a tool-definition drift event does to a call. `deny` by default:
       drift is an approved-definition mismatch, not a hint. */
    onDrift = "deny",
    /* The in-process library contract: there is no transport boundary for the
       caller to be authenticated by, so identity is not refused. A SHIPPED
       surface (the MCP gateway, the runtime) must not set this. */
    compatibility = true,
  } = {}) {
    this.rules = rules ?? [];
    this.agent = agent;
    this.environment = environment;
    this.cwd = cwd;
    this.audit = audit;
    this.secrets = secrets;
    this.approvals = approvals;
    this.killSwitch = killSwitch;
    this.revocation = revocation;
    this.identity = identity;
    /** DelegationBroker, when agent-to-agent delegation is in use. */
    this.delegation = delegation;
    this.requireDelegation = Boolean(requireDelegation);
    /** MissionRegistry, and/or a single mission this Guard always acts under. */
    this.missions = missions;
    this.mission = mission;
    this.licence = licence;
    this.meter = meter;
    this.agents = agents;
    this.onDecision = onDecision;
    this.log = log;
    this.runId = runId;
    /** Risk level at or above which an unnamed call is escalated to approval. */
    this.riskFloor = riskFloor;
    /** Sequence taint tracking for Lethal Trifecta. */
    this.taint = new SessionTaint();
    this.stats = { calls: 0, permitted: 0, denied: 0, held: 0, leaks: 0, latencyTotal: 0 };
    this.nextId = 1;
    // Normalized through the setter: an unknown mode throws here, at
    // construction, rather than being discovered by the first refused caller.
    this.identityMode = identityMode;
    this.surface = surface;
    this.mode = mode;
    this.sessionTracker = sessionTracker;
    this.baseline = baseline;
    this.intent = intent;
    this.drift = drift;
    this.publishedPolicy = publishedPolicy;
    this.policyVersion = policyVersion;
    this.onStalePolicy = onStalePolicy;
    this.onDrift = onDrift;
    this.compatibility = compatibility;
  }

  #identityMode = null;

  /** The identity mode in force, normalized to a known mode value. */
  get identityMode() {
    return this.#identityMode ?? normalizeIdentityMode(IDENTITY_MODE.COMPAT).mode;
  }

  set identityMode(value) {
    this.#identityMode = value === null || value === undefined ? null : normalizeIdentityMode(value).mode;
  }

  /** What this boundary STATED, or undefined when it stated nothing. */
  get explicitIdentityMode() {
    return this.#identityMode ?? undefined;
  }

  get touchedSecret() {
    return this.taint.touchedSecret;
  }

  set touchedSecret(value) {
    this.taint.touchedSecret = value;
  }

  /**
   * Decides one call, and brokers any secret handles it carries.
   *
   * Returns the decision plus the arguments to forward — which are not
   * necessarily the arguments passed in, because handles are substituted here
   * and nowhere else.
   *
   * @returns {Promise<{decision:object, record:object, args:any}>}
   */  /**
   * Decides one call, and brokers any secret handles it carries (P0-D).
   *
   * THIS METHOD IS A TRANSPORT ADAPTER. It parses the MCP/SDK request, hands
   * the trusted parts to the canonical authorization core, and renders the
   * canonical outcome as this surface's record. It owns NO stage semantics:
   * identity, normalization, risk, policy, delegation, authority, capability,
   * revocation, the kill switch, the trifecta, intent, session state, the
   * behavioural baseline, tool drift, validation, approval, credential,
   * sanitization and evidence all live in `core/authorize.mjs`, once.
   *
   * What that buys, stated as the property it is: the gateway and the local
   * socket cannot answer the same authorization question differently, and
   * neither can silently skip a stage the other runs. The two engines used to
   * differ by identity, intent, session tracking, baseline, mode and drift —
   * every one of which was a control one surface advertised and did not have.
   *
   * `ctx` is supplied by the trusted embedder, never copied from tool
   * arguments.
   *
   * @returns {Promise<{decision:object, record:object, args:any}>}
   */
  async authorize(input, ctx = {}) {
    const request = input && typeof input === "object" && !Array.isArray(input) ? input : {};
    const trusted = ctx && typeof ctx === "object" ? ctx : {};

    const outcome = await authorizeCanonical(
      {
        tool: request.tool,
        server: request.server ?? null,
        arguments: request.args ?? request.arguments ?? {},
        /* The caller's own declared name: UNTRUSTED, and never a principal. It
           rides to the core as a claim so the core can record it — and so the
           core, not this adapter, decides what a claim is worth. */
        agent: typeof request.agent === "string" && request.agent ? request.agent : null,
        delegation: request.delegation ?? null,
        mission: request.mission ?? null,
        intent: request.intent ?? null,
        request_id: typeof request.request_id === "string" && request.request_id ? request.request_id : null,
      },
      {
        surface: this.surface,
        /* The authenticated host context: the same channel `Pipeline` uses,
           never copied from the payload. */
        principal: typeof trusted.agent === "string" && trusted.agent ? trusted.agent : this.agent,
        callerMeta: trusted.callerMeta ?? null,
        method: trusted.method ?? null,
        params: trusted.params ?? {},
        /* A transport that authenticated the caller already (or one that was
           handed the result by its own transport) passes the RESULT here. */
        identityVerification: trusted.identityVerification ?? null,
        environment: this.environment,
        runId: this.runId,
        source: trusted.source ?? null,
        timestamp: trusted.timestamp,
        tenant: trusted.tenant ?? null,
        runtime: trusted.runtime ?? null,
        audience: trusted.audience ?? null,
        costUsd: captureMissionCost(trusted),
        profile: this.#profile(),
      },
      this.#dependencies(),
    );

    return { decision: outcome.decision, record: outcome.record, args: outcome.args };
  }

  /** The wiring this boundary hands the canonical core. One place, visible. */
  #dependencies() {
    return {
      rules: this.rules,
      cwd: this.cwd,
      environment: this.environment,
      riskFloor: this.riskFloor,
      mode: this.mode,
      identity: this.identity,
      /* Only what this boundary STATED — never its reading default. */
      identityMode: this.explicitIdentityMode,
      delegation: this.delegation,
      requireDelegation: this.requireDelegation,
      missions: this.missions,
      mission: this.mission,
      approvals: this.approvals,
      killSwitch: this.killSwitch,
      revocation: this.revocation,
      licence: this.licence,
      meter: this.meter,
      agents: this.agents,
      secrets: this.secrets,
      sessionTracker: this.sessionTracker,
      baseline: this.baseline,
      intent: this.intent,
      drift: this.drift,
      audit: this.audit,
      taint: this.taint,
      runId: this.runId,
      agent: this.agent,
      publishedPolicy: this.publishedPolicy,
      policyVersion: this.policyVersion,
      onStalePolicy: this.onStalePolicy,
      onDrift: this.onDrift,
      trifectaResponse: this.trifectaResponse,
      compatibility: this.compatibility,
      nextDecisionSeq: () => this.nextId++,
      buildRecord: (run, opts) => this.#record(run, opts),
      publish: (run) => {
        this.onDecision({ kind: "decision", ...run.record });
        this.#absorb(run);
      },
    };
  }

  #profile() {
    /* A boundary that STATED an identity mode is not a compatibility boundary,
       whatever the library default says — otherwise an explicitly hardened
       runtime would be reported (and treated) as a policy-only one. */
    return resolveSecurityProfile({
      identityMode: this.identityMode,
      authorityPosture: this.requireDelegation ? AUTHORITY_POSTURE.REQUIRED : AUTHORITY_POSTURE.OPTIONAL,
      compatibility: this.explicitIdentityMode ? false : this.compatibility,
    }).profile;
  }

  /** The canonical posture this boundary actually enforces (P0-D §23). */
  securityPosture() {
    return describeCanonicalPosture({
      surface: this.surface,
      profile: this.#profile(),
      posture: this.requireDelegation ? AUTHORITY_POSTURE.REQUIRED : AUTHORITY_POSTURE.OPTIONAL,
      deps: this.#dependencies(),
      stamps: policyStamp(this.rules ?? [], { version: this.policyVersion, published: this.publishedPolicy }),
    });
  }

  /**
   * The canonical outcome, rendered as THIS surface's record.
   *
   * The record shape is the transport's business — `cirvix logs`, `replay` and
   * the console read these field names, and the socket's event shape differs
   * on purpose. The DECISION is the core's business. This function is the
   * seam: it copies canonical evidence into transport vocabulary and adds no
   * semantics of its own.
   */
  #record(run, opts = {}) {
    const decision = run.decision ?? {};
    const identity = run.identity ?? { verified: false, reason: "unknown" };
    const decisionId = run.decisionId;
    return {
      decision_id: decisionId,
      // Both spellings, deliberately. `cirvix logs`, `replay`, and the control
      // plane read `request_id`; the older records and the SDK read
      // `decision_id`. Emitting one and not the other split the history in two.
      request_id: decisionId.replace(/^dec_/, "req_"),
      runId: this.runId,
      run_id: this.runId,
      agent: run.principal,
      server: run.call?.server ?? null,
      tool: run.call?.raw_tool ?? null,
      action: run.call?.action ?? null,
      resource: decision.resource ?? null,
      verdict: decision.verdict,
      decision: decision.decision,
      rule: decision.rule,
      // `policy` is what the journal renders and what the console joins on.
      policy: decision.rule,
      reason: decision.reason,
      risk: decision.risk ?? run.risk?.level ?? null,
      risk_signals: decision.riskSignals ?? run.risk?.signals?.map((s) => s.id) ?? [],
      // What happened in the world, as derived by the canonical core. A
      // `consequence` rule that fired must name the value it fired on; a
      // journal that records only `risk` cannot explain the refusal.
      consequence: decision.consequence ?? run.call?.consequence ?? null,
      latencyMs: Number(run.latencyMs.toFixed(3)),
      latency_ms: Number(run.latencyMs.toFixed(3)),
      context: run.reportContext ?? run.context,
      considered: decision.considered?.slice(0, 200),
      ...(decision.riskEscalated || run.baselineEscalated ? { risk_escalated: true } : {}),
      ...(decision.approvalId ? { approval_id: decision.approvalId } : {}),
      ...(decision.approvedBy ? { approved_by: decision.approvedBy } : {}),
      // Who authorized this must be answerable after the fact, on every surface
      // — not only the one that happened to record it.
      ...(run.delegation ? { delegation: run.delegation } : {}),
      // Revocation is part of the record for the same reason delegation is:
      // "who refused this, and what did they revoke" must be answerable after
      // the fact, from the journal somebody else wrote.
      ...(decision.revocation ? { revocation: decision.revocation } : {}),
      // Authority is part of the record for the same reason delegation is:
      // "who authorized this" must be answerable after the fact.
      ...(run.authorityContext ? { authority: run.authorityContext } : {}),
      ...(decision.escape ? { escape: decision.escape } : {}),
      ...(run.brokered?.length ? { secrets: run.brokered, secrets_brokered: run.brokered } : {}),
      ...(decision.trifecta ? { trifecta: decision.trifecta } : {}),
      // On every record, whatever the mode: an operator must be able to tell
      // a proven principal from a mode that accepted a name.
      identity: {
        verified: identity.verified === true,
        agentId: identity.agentId ?? null,
        issuer: identity.issuer ?? null,
        keyId: identity.keyId ?? null,
        binding: identity.binding ?? null,
        reason: identity.verified ? null : identity.reason,
        mode: identity.mode ?? this.identityMode,
      },
      // Findings never carry the value — see secret-detect.mjs.
      ...(run.findings?.length
        ? {
            secrets_detected: run.findings.map((f) => ({
              path: f.path,
              detector: f.detector,
              severity: f.severity,
              masked: f.masked,
              fingerprint: f.fingerprint,
            })),
          }
        : {}),
      /* Mode and untrusted claim ride EVERY record, so an operator reading the
         journal can always tell a proven principal from a mode that accepted a
         name — a permit must never be mistakable for an authenticated one. */
      identity_mode: identity.mode ?? this.identityMode,
      ...(run.claim ? { claimed_agent: run.claim } : {}),
      ...(opts.identityRefusal && decision.planned ? { planned: decision.planned } : {}),
    };
  }

  /** Counters and session taint, taken from the canonical outcome. */
  #absorb(outcome) {
    this.stats.calls += 1;
    this.stats.latencyTotal += outcome.latencyMs;
    if (outcome.decision.verdict === "deny") this.stats.denied += 1;
    else if (outcome.decision.verdict === "hold") this.stats.held += 1;
    else this.stats.permitted += 1;
  }



  /** Scans a result for material this session resolved, and puts handles back. */
  scrub(payload, decision = {}) {
    const swept = this.secrets ? this.secrets.redact(payload) : null;
    const detected = redactSecrets(swept ? swept.payload : payload);
    const result = {
      payload: detected.value,
      findings: [...(swept?.findings ?? []), ...(swept?.detected ?? []), ...detected.findings],
    };
    if (decision.decision === DECISION.SANITIZE &&
        (decision.sanitize ?? []).some((s) => s.targets.includes("result"))) {
      const stripped = stripInjection(result.payload);
      result.payload = stripped.value;
      result.findings.push(...stripped.findings);
    }
    if (result.findings.length) {
      this.stats.leaks += result.findings.length;
      this.log(`leak caught on the return path: ${result.findings.map((f) => f.name).join(", ")}`);
      this.onDecision({
        kind: "leak",
        agent: this.agent,
        secrets: result.findings.map((f) => f.name),
      });
    }
    return result;
  }

  /** Turns a non-permit verdict into the error a caller should see. */
  toError(decision) {
    const fields = {
      policy: decision.rule,
      decisionId: decision.decisionId,
      reason: decision.reason,
      remediation: decision.remediation,
      resource: decision.resource,
      action: decision.action,
    };
    return decision.verdict === "hold"
      ? new CirvixHeld({ ...fields, approvers: decision.approvers, approvalId: decision.approvalId })
      : new CirvixDenied(fields);
  }

  insideWorkspace(resource) {
    return isInsideWorkspace(this.cwd, canonicalizeResource(resource, this.cwd));
  }

  isExternal(resource) {
    return classifyEgress(resource) === "external";
  }
}

/* -------------------------------------------------------------------------- */
/*  Identity, and the sandboxed principal                                      */
/* -------------------------------------------------------------------------- */

/*
 * A principal value that provably matches nothing. Policy matching is exact or
 * glob over caller-supplied strings; a name is attacker-controlled input, so a
 * legitimate principal can never collide with this one, and any rule that ever
 * DID match it would be a misconfiguration that shows up here rather than
 * being silently attributed to a real agent.
 *
 * Defined by the canonical core (core/authorize.mjs) and re-exported here,
 * because the identity-refusal path — including the sandboxed policy re-eval
 * that fills the record's `planned` field — now lives there, once, instead of
 * in each engine.
 */
export { SANDBOXED_PRINCIPAL } from "./authorize.mjs";

export {
  IDENTITY_MODE,
  IDENTITY_MODES,
  normalizeIdentityMode,
  resolveIdentityMode,
} from "./identity-modes.mjs";

/* -------------------------------------------------------------------------- */
/*  wrap                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Governs a collection of tools in place.
 *
 * Accepts the three shapes tool collections actually come in and returns the
 * same shape back, so this is a one-line change at the executor boundary
 * rather than a rewrite of how tools are registered:
 *
 *   - a plain object of `name → function`
 *   - an array of tool objects carrying a callable (`func`, `invoke`, `call`,
 *     `execute`, or `handler`) — LangChain, CrewAI, and AutoGen all land here
 *   - a single function, named by `options.name`
 *
 * The returned tools are the originals with the callable replaced. Everything
 * else on them — descriptions, schemas, framework metadata — is preserved by
 * reference, because a framework that reads `tool.schema` after wrapping must
 * still find it.
 */
export function wrap(tools, options = {}) {
  const guard = options.guard ?? new Guard(options);

  if (typeof tools === "function") {
    return wrapCallable(tools, options.name ?? tools.name ?? "tool", guard);
  }

  if (Array.isArray(tools)) {
    return Array.from(tools, (tool) => {
      if (typeof tool === "function") return wrapCallable(tool, tool.name ?? "tool", guard);
      return wrapToolObject(tool, null, guard);
    });
  }

  if (isPlainObject(tools)) {
    return Object.fromEntries(
      Reflect.ownKeys(tools).map((name) => {
        const descriptor = Object.getOwnPropertyDescriptor(tools, name);
        if (typeof name !== "string" || !Object.hasOwn(descriptor, "value")) {
          throw new TypeError("Tool collections require string names and data properties.");
        }
        const value = descriptor.value;
        return [name, typeof value === "function" ? wrapCallable(value, name, guard) : wrapToolObject(value, name, guard)];
      }),
    );
  }

  throw new TypeError("guard.wrap expects a function, an array of tools, or an object of tools.");
}

const CALLABLE_KEYS = ["func", "invoke", "call", "execute", "handler", "_call", "run"];

function wrapToolObject(tool, collectionName, guard) {
  if (!tool || typeof tool !== "object" || Array.isArray(tool)) {
    throw new TypeError("Each tool must be a function or an object with supported callable entrypoints.");
  }
  const descriptors = new Map();
  for (let current = tool; current && current !== Object.prototype; current = Object.getPrototypeOf(current)) {
    for (const key of Reflect.ownKeys(current)) {
      if (key === "constructor" && current !== tool) continue;
      if (!descriptors.has(key)) descriptors.set(key, Object.getOwnPropertyDescriptor(current, key));
    }
  }
  const callables = [];
  for (const [key, descriptor] of descriptors) {
    if (!Object.hasOwn(descriptor, "value")) throw new TypeError("Tool accessors require an explicit adapter.");
    if (typeof descriptor.value === "function") {
      if (!CALLABLE_KEYS.includes(key)) throw new TypeError("Unsupported callable entrypoint; provide an explicit adapter.");
      callables.push([key, descriptor.value]);
    } else if (CALLABLE_KEYS.includes(key)) {
      throw new TypeError("Callable entrypoints must be functions.");
    }
  }
  if (!callables.length) throw new TypeError("Tool object has no supported callable entrypoint.");
  const name = collectionName ?? descriptors.get("name")?.value ?? descriptors.get("title")?.value;
  if (typeof name !== "string" || !name.trim()) throw new TypeError("Tool objects require a nonempty name.");
  const copy = Object.create(null);
  for (const [key, descriptor] of descriptors) {
    if (!CALLABLE_KEYS.includes(key)) Object.defineProperty(copy, key, descriptor);
  }
  for (const [key, fn] of callables) {
    Object.defineProperty(copy, key, {
      value: wrapCallable(fn.bind(tool), name, guard),
      enumerable: descriptors.get(key).enumerable,
      configurable: true,
      writable: true,
    });
  }
  return copy;
}

function wrapCallable(fn, name, guard) {
  if (typeof name !== "string" || !name.trim()) throw new TypeError("Tools require a nonempty name.");
  const governed = async (...callArgs) => {
    if (callArgs.length > 1 || (callArgs.length === 1 && !isPlainObject(callArgs[0]))) {
      throw new TypeError("Governed tools accept zero arguments or one plain argument object.");
    }
    const args = callArgs.length ? callArgs[0] : {};

    const { decision, args: outgoing } = await guard.authorize({ tool: name, args });
    if (decision.verdict !== "permit") throw guard.toError(decision);
    if (!isPlainObject(outgoing)) throw new TypeError("Authorization must return a plain argument object.");

    const result = await fn(...(callArgs.length || Reflect.ownKeys(outgoing).length ? [outgoing] : []));
    return guard.scrub(result, decision).payload;
  };

  // Frameworks introspect `fn.name` to build their tool registry, and an
  // anonymous arrow would silently rename every governed tool.
  Object.defineProperty(governed, "name", { value: name, configurable: true });
  return governed;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** The documented entry point: `guard.wrap(tools, { … })`. */
export const guard = { wrap, Guard };
