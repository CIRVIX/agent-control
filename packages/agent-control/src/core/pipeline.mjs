/**
 * The request pipeline — one tool call, start to finish.
 *
 *   AI AGENT
 *      │
 *      ▼
 *   CIRVIX CLI
 *      │
 *      ▼
 *   UDS / Local proxy
 *      │
 *      ├── Parse
 *      ├── Normalize
 *      ├── Secret detection
 *      ├── Risk classification
 *      ├── Policy evaluation
 *      ├── Approval check
 *      ├── Sanitization
 *      └── Audit event
 *      │
 *      ▼
 *   TOOL / MCP SERVER
 *
 * ON THE ORDER OF THOSE STAGES
 *
 * Secret detection and risk classification run BEFORE policy, not after. This
 * is not a preference — it is the only order in which the feature works.
 *
 * A rule may say `risk >= HIGH` or `secrets.detected > 0`. For the engine to
 * evaluate that condition, the values must already exist. Running policy first
 * and classifying afterwards would leave every risk-based rule matching against
 * `undefined`, which the comparators treat as a non-match — so the rules would
 * load, validate, appear in `cirvix policy list`, and silently never fire. That
 * is the worst failure mode available to a security product: a control that
 * reports itself as present and is not.
 *
 * Approval and sanitization run after policy because both are consequences of
 * a decision rather than inputs to one.
 *
 * EVERY STAGE IS TIMED, AND THE TOTAL IS THE HONEST NUMBER
 *
 * `latency_ms` covers parse through audit — everything Cirvix adds. It excludes
 * the upstream tool round trip, which is orders of magnitude larger and would
 * flatter the figure into meaninglessness. `stages` carries the per-stage
 * breakdown so a slow deployment can be diagnosed rather than guessed at.
 */

import { DECISION, MODE, isForwarded } from "./decisions.mjs";
import { requestId } from "./normalize.mjs";
import { policyStamp } from "./authorize.mjs";
import { captureMissionCost } from "./authority.mjs";
import { redact as redactSecrets } from "./secret-detect.mjs";
import { stripInjection } from "./sanitize.mjs";
import { SessionTaint } from "./trifecta.mjs";
import { SessionTracker } from "./session.mjs";
import { BehavioralBaseline } from "./baseline.mjs";
import { IDENTITY_MODE, normalizeIdentityMode } from "./identity-modes.mjs";
/* THE CANONICAL AUTHORIZATION CORE. Every stage semantics lives there; this
   file is the local-socket transport adapter over it. See core/authorize.mjs. */
import {
  AUTHORITY_POSTURE,
  CANONICAL_STAGES,
  SECURITY_PROFILE,
  STAGE_STATUS,
  SURFACE,
  authorize as authorizeCanonical,
  describeCanonicalPosture,
  resolveSecurityProfile,
  stagePlan,
} from "./authorize.mjs";

/** Wall-clock for one stage, in fractional milliseconds. */
function timer() {
  const t0 = process.hrtime.bigint();
  return () => Number(process.hrtime.bigint() - t0) / 1e6;
}

/* -------------------------------------------------------------------------- */

export class Pipeline {
  /**
   * @param {object} opts
   * @param {Array}  opts.rules                    the policy rule set
   * @param {string} [opts.agent]
   * @param {string} [opts.environment]
   * @param {string} [opts.cwd]
   * @param {string} [opts.mode]                   MODE.ENFORCE | MODE.AUDIT
   * @param {object} [opts.audit]                  AuditChain
   * @param {object} [opts.secrets]                Vault or SecretsClient
   * @param {object} [opts.approvals]              ApprovalStore
   * @param {string} [opts.riskFloor]              risk level that forces approval
   * @param {(e:object)=>void} [opts.onEvent]
   * @param {(m:string)=>void} [opts.log]
   */
  constructor({
    rules = [],
    agent = "local",
    environment = "local",
    cwd = process.cwd(),
    mode = MODE.ENFORCE,
    audit = null,
    secrets = null,
    approvals = null,
    delegation = null,
    /* Authority-required posture: see Guard. A Pipeline told to require signed
       authority refuses a governed call that arrives without one instead of
       falling back to policy alone. */
    requireDelegation = false,
    missions = null,
    mission = null,
    /* Commercial enforcement. All three default to absent, so a Pipeline
       built without them behaves exactly as before — which is what keeps the
       existing suite, the shared conformance fixture and every embedding
       caller working unchanged. The CLI and the daemon supply them; a library
       user metering nothing is a supported configuration. */
    licence = null,
    meter = null,
    agents = null,
    riskFloor = "high",
    runId = null,
    killSwitch = null,
    /* The durable revocation fabric (core/revocation.mjs). Absent is inert;
       present, it is evaluated on the SAME decision path as the kill switch,
       before every audit append. See guard.mjs for why both exist. */
    revocation = null,
    sessionTracker = null,
    baseline = null,
    intent = null,
    /* The enforcement surface this adapter speaks for (P0-D). Evidence only;
       it never selects a stage. */
    surface = "uds",
    /* Boundary identity verifier (core/identity.mjs). Null means this engine
       has no verifier of its own and relies on the transport above having
       authenticated the caller and handed the RESULT in. Either way the core
       owns what an unverified caller gets; the engine no longer guesses. */
    identity = null,
    /* `null` means NO STATEMENT — see Guard. The core then takes the
       transport's mode, or COMPAT when neither layer states one. */
    identityMode = null,
    /* Tool-definition drift, the policy stamp, and the stages the socket
       engine already ran — accepted here so both surfaces can be wired
       identically. Absent is INERT and reported as inert. */
    drift = null,
    publishedPolicy = null,
    policyVersion = null,
    onStalePolicy = "deny",
    onDrift = "deny",
    /* The in-process/library contract: no transport boundary exists, so an
       unverified caller is not refused. A SHIPPED surface must not set this. */
    compatibility = true,
    onEvent = () => {},
    log = () => {},
  } = {}) {
    this.rules = rules;
    this.agent = agent;
    this.environment = environment;
    this.cwd = cwd;
    this.mode = mode;
    this.audit = audit;
    this.secrets = secrets;
    this.approvals = approvals;
    /** DelegationBroker, when agent-to-agent delegation is in use. */
    this.delegation = delegation;
    this.requireDelegation = Boolean(requireDelegation);
    this.missions = missions;
    this.mission = mission;
    this.licence = licence;
    this.meter = meter;
    this.agents = agents;
    this.riskFloor = riskFloor;
    this.runId = runId;
    this.killSwitch = killSwitch;
    this.revocation = revocation;
    this.sessionTracker = sessionTracker;
    this.baseline = baseline;
    this.intent = intent;
    this.surface = surface;
    this.identity = identity;
    this.identityMode = identityMode ? normalizeIdentityMode(identityMode).mode : null;
    this.drift = drift;
    this.publishedPolicy = publishedPolicy;
    this.policyVersion = policyVersion;
    this.onStalePolicy = onStalePolicy;
    this.onDrift = onDrift;
    this.compatibility = compatibility;
    this.onEvent = onEvent;
    this.log = log;

    /**
     * Sequence state for this session.
     *
     * Was a bare `touchedSecret` boolean. It is now the full three-leg record
     * the Lethal Trifecta needs, with `touchedSecret` kept as an accessor so
     * the gateway and every existing caller are unaffected.
     */
    this.taint = new SessionTaint();

    this.stats = {
      calls: 0,
      allowed: 0,
      denied: 0,
      approvals: 0,
      sanitized: 0,
      auditOnly: 0,
      leaks: 0,
      secretsDetected: 0,
      latencyTotal: 0,
      latencies: [],
    };
  }

  /**
   * Kept so the gateway, the guard and any embedder that set or read this
   * boolean keep working unchanged. Leg A of the trifecta and the old
   * "this session touched a secret" flag are the same fact.
   */
  get touchedSecret() {
    return this.taint.touchedSecret;
  }

  set touchedSecret(value) {
    this.taint.touchedSecret = value;
  }

  /**
   * Runs one call through every stage (P0-D).
   *
   * THIS METHOD IS A TRANSPORT ADAPTER. It parses whatever arrived on the
   * socket, hands the trusted parts to the canonical authorization core
   * (`core/authorize.mjs`), and renders the canonical outcome as this surface's
   * event. It owns NO stage semantics.
   *
   * That is a change with a security consequence, not a tidy-up. This engine
   * used to run the Lethal Trifecta, session chains, the behavioural baseline,
   * the intent firewall and engine mode, and it had NO identity stage at all:
   * the socket verified the caller upstream and then handed this engine a bare
   * agent name, so the engine that decided did not know who had been
   * authenticated. Meanwhile the MCP gateway ran identity, delegation and
   * authority and none of the stateful stages. The two engines were answering
   * different questions with the same vocabulary.
   *
   * Now both call the same stages in the same order. The transport-specific
   * differences that remain are TRUSTED INPUT differences — what the socket
   * authenticated versus what the gateway was handed — and nothing else.
   *
   * Never throws for a policy outcome — a denial is a return value, because the
   * transports need to render it as data the agent can read rather than as an
   * exception that aborts the run.
   *
   * @returns {Promise<{event:object, call:object, decision:object, arguments:any}>}
   */
  async submit(raw, ctx = {}) {
    const input = raw;
    const trusted = ctx && typeof ctx === "object" ? ctx : {};
    raw = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
    const name = raw.method === "tools/call" ? raw.params?.name : raw.tool ?? raw.name;
    const args = raw.method === "tools/call" ? raw.params?.arguments : raw.arguments ?? raw.args ?? raw.params;

    /* This surface's request contract, tighter than the canonical minimum: a
       request id, when present, has to be a usable string. `validateRequest`
       is what the core calls; the shape is declared here because it is a
       transport fact, and enforced there because enforcement is not. */
    const malformed = !input || typeof name !== "string" || !name.trim() ||
      (raw.request_id != null && (typeof raw.request_id !== "string" || !raw.request_id)) ||
      (args != null && (typeof args !== "object" || Array.isArray(args)));
    const id = typeof raw.request_id === "string" && raw.request_id ? raw.request_id : requestId();
    const parsed = malformed ? { tool: "", server: null, arguments: {} } : this.#parse(raw);

    const outcome = await authorizeCanonical(
      {
        tool: parsed.tool,
        server: parsed.server,
        arguments: parsed.arguments,
        /* A socket caller is authenticated by the TRANSPORT above (the token
           plus, when enrolled, a signed credential). `trusted.agent` is that
           authenticated identity, never a field from the payload. */
        agent: typeof trusted.agent === "string" && trusted.agent ? trusted.agent : null,
        delegation: trusted.delegation ?? null,
        mission: trusted.mission ?? null,
        intent: trusted.intent ?? null,
        request_id: id,
      },
      {
        surface: this.surface,
        principal: typeof trusted.agent === "string" && trusted.agent ? trusted.agent : this.agent,
        identityVerification: trusted.identityVerification ?? null,
        identityMode: trusted.identityMode ?? null,
        callerMeta: trusted.callerMeta ?? null,
        method: trusted.method ?? null,
        params: trusted.params ?? {},
        environment: trusted.environment ?? this.environment,
        runId: this.runId,
        source: trusted.source ?? raw.source ?? null,
        timestamp: trusted.timestamp,
        tenant: trusted.tenant ?? null,
        runtime: trusted.runtime ?? null,
        audience: trusted.audience ?? null,
        costUsd: captureMissionCost(trusted),
        profile: this.#profile(),
      },
      this.#dependencies(malformed),
    );

    /* Counters, the event, and the last-call pointer were all emitted by the
       core's publish hook, in this surface's historic order, BEFORE the mission
       was charged — so a throwing subscriber cannot leave the agent paying for
       a decision nobody saw. */
    return { event: outcome.record, call: outcome.call ?? null, decision: outcome.decision, arguments: outcome.args };
  }

  /** The wiring this boundary hands the canonical core. One place, visible. */
  #dependencies(malformed = false) {
    return {
      rules: this.rules,
      cwd: this.cwd,
      environment: this.environment,
      riskFloor: this.riskFloor,
      mode: this.mode,
      identity: this.identity,
      /* Only what this boundary STATED — never its reading default. */
      identityMode: this.identityMode ?? undefined,
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
      /* The socket names a decision after the request it answers, which is
         what makes `cirvix why <request-id>` land. This is NOT a counter:
         `#count` owns `stats.calls`, and incrementing it here as well
         double-counted every call (600 for 300 submissions). */
      newDecisionId: (id) => `dec_${String(id).startsWith("req_") ? String(id).slice(4) : id}`,
      validateRequest: () => (malformed
        ? { rule: "invalid-request", reason: "A tool call needs a string tool name, object arguments and a string request id." }
        : null),
      buildRecord: (run) => this.#event(run),
      /* The sink, in the order this surface has always used it: counters, then
         the event, then the last-call pointer the return path needs. It runs
         before the mission is charged, so a throwing subscriber leaves the
         allowance unspent. */
      publish: (run) => {
        this.stats.secretsDetected += run.evidence?.secretsDetected?.length ?? 0;
        if (run.decision.sanitized) this.stats.sanitized += 1;
        this.#count(run.decision, run.latencyMs);
        this.onEvent({ kind: "decision", ...run.record });
        this.lastCall = run.call ?? null;
      },
    };
  }

  #profile() {
    /* A boundary that STATED an identity mode is not a compatibility boundary,
       whatever the library default says. */
    return resolveSecurityProfile({
      identityMode: this.identityMode ?? IDENTITY_MODE.COMPAT,
      authorityPosture: this.requireDelegation ? AUTHORITY_POSTURE.REQUIRED : AUTHORITY_POSTURE.OPTIONAL,
      compatibility: this.identityMode ? false : this.compatibility,
    }).profile;
  }

  /** The canonical posture this boundary actually enforces (P0-D §23). */
  securityPosture() {
    return describeCanonicalPosture({
      surface: this.surface,
      profile: this.#profile(),
      posture: this.requireDelegation ? AUTHORITY_POSTURE.REQUIRED : AUTHORITY_POSTURE.OPTIONAL,
      deps: this.#dependencies(false),
      stamps: policyStamp(this.rules ?? [], { version: this.policyVersion, published: this.publishedPolicy }),
    });
  }

  /**
   * The canonical outcome, rendered as THIS surface's event.
   *
   * The event shape is the transport's contract — `cirvix logs`, `replay`, the
   * console and the control plane read these names. The DECISION is the core's.
   * This function copies canonical evidence into transport vocabulary and adds
   * no semantics of its own.
   */
  #event(run) {
    const decision = run.decision ?? {};
    return {
      request_id: run.requestId,
      decision_id: run.decisionId,
      run_id: this.runId,
      agent: run.principal,
      source: run.call?.source ?? null,
      server: run.call?.server ?? null,
      tool: run.call?.tool ?? null,
      action: run.call?.action ?? null,
      resource: decision.resource ?? run.call?.resource ?? null,
      destination: run.call?.destination ?? null,
      command: run.call?.command ? run.call.command.slice(0, 500) : null,
      risk: decision.risk ?? run.risk?.level ?? null,
      risk_signals: decision.riskSignals ?? run.risk?.signals?.map((s) => s.id) ?? [],
      // The derived consequence, so a socket consumer can answer "what was
      // this call about to do" from the event alone.
      consequence: decision.consequence ?? run.call?.consequence ?? null,
      decision: decision.decision,
      verdict: decision.verdict,
      policy: decision.rule,
      reason: decision.reason,
      enforced: decision.enforced !== false,
      mode: decision.mode ?? this.mode,
      timestamp: run.call?.timestamp ?? null,
      latency_ms: Number(run.latencyMs.toFixed(3)),
      stages: this.#stageTimings(run),
      // Who the caller PROVED it was, on the record. The socket's event did not
      // carry this before, which is how a verified identity became an
      // unverified name one process later.
      identity: run.identity ?? null,
      // The untrusted half of the same question, under the name the MCP record
      // already uses. Without it the socket could say "the principal is X" and
      // not "the caller said Y", so an operator could not tell a verified
      // caller from one that merely asked to be believed (INV-018).
      ...(run.claim ? { claimed_agent: run.claim } : {}),
      profile: run.profile ?? null,
      ...(decision.wouldHave ? { would_have: decision.wouldHave } : {}),
      ...(decision.riskEscalated || run.baselineEscalated ? { risk_escalated: true } : {}),
      ...(run.delegation ? { delegation: run.delegation } : {}),
      // Revocation rides the record: "why was this refused" must name the
      // event and the issuer, and that event was written by another process.
      ...(decision.revocation ? { revocation: decision.revocation } : {}),
      ...(decision.approvalId ? { approval_id: decision.approvalId } : {}),
      ...(decision.approvedBy ? { approved_by: decision.approvedBy } : {}),
      ...(run.authorityContext ? { authority: run.authorityContext } : {}),
      ...(decision.escape ? { escape: decision.escape } : {}),
      ...(run.brokered?.length ? { secrets_brokered: run.brokered } : {}),
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
      ...(decision.sanitized ? { sanitized: decision.sanitized } : {}),
      ...(decision.observed ? { observed_by: decision.observed.map((o) => o.rule) } : {}),
      ...(decision.auditWriteFailed ? { audit_write_failed: true } : {}),
      considered: decision.considered?.slice(0, 200),
      ...(run.trifecta?.complete
        ? { trifecta: { complete: true, legs: run.trifecta.legs, response: run.trifecta.decision } }
        : run.trifecta?.satisfied?.length
          ? { trifecta: { complete: false, satisfied: run.trifecta.satisfied, imminent: run.trifecta.imminent } }
          : {}),
    };
  }

  /** The canonical stage ledger, under the names this surface has always used. */
  #stageTimings(run) {
    const ms = (name) => Number((run.stageMs?.[name] ?? 0).toFixed(3));
    return {
      parse: ms("request"),
      normalize: ms("normalize"),
      secrets: ms("secrets"),
      risk: ms("risk"),
      policy: ms("policy"),
      approval: ms("approval"),
      substitute: ms("credential"),
      audit: ms("evidence"),
      stages: Object.fromEntries(Object.entries(run.stageMs ?? {}).map(([k, v]) => [k, Number(v.toFixed(3))])),
    };
  }


  /**
   * The return path. Scrubs a tool result before it reaches the model.
   *
   * Two distinct jobs that are easy to conflate:
   *
   *   1. Credential material — a key the upstream echoed back. Swapped for its
   *      handle if the vault knows it, masked if it does not.
   *   2. Injected instructions — text in a fetched page or a tool result that
   *      is addressed to the model rather than to the user. Stripped only when
   *      the decision asked for sanitization, because rewriting every result by
   *      default would corrupt legitimate content that merely discusses
   *      prompts.
   */
  scrubResult(payload, decision = {}, call = null) {
    let out = payload;
    const findings = [];

    if (this.secrets) {
      const result = this.secrets.redact(out);
      out = result.payload;
      for (const f of result.findings ?? []) findings.push({ ...f, kind: "credential" });
      for (const d of result.detected ?? []) {
        findings.push({ kind: "credential", detector: d.detector, path: d.path, masked: d.masked });
      }
    } else {
      const result = redactSecrets(out);
      out = result.value;
      for (const f of result.findings) {
        findings.push({ kind: "credential", detector: f.detector, path: f.path, masked: f.masked });
      }
    }

    const wantsResultSanitize =
      decision.decision === DECISION.SANITIZE &&
      (decision.sanitize ?? []).some((s) => s.targets.includes("result"));

    if (wantsResultSanitize) {
      const stripped = stripInjection(out);
      out = stripped.value;
      for (const f of stripped.findings) findings.push({ ...f, kind: "injection" });
    }

    /* Leg B. The injection findings were already computed here and then
       discarded; remembering them is what makes the trifecta detectable. */
    this.taint.observeResult(call ?? decision.call ?? this.lastCall ?? {}, findings);

    if (findings.length) {
      this.stats.leaks += findings.filter((f) => f.kind === "credential").length;
      this.onEvent({
        kind: "scrub",
        agent: this.agent,
        findings: findings.map((f) => ({ kind: f.kind, detector: f.detector ?? f.rule, path: f.path })),
      });
    }

    return { payload: out, findings };
  }

  /* ------------------------------------------------------------------------ */

  /**
   * Stage 1: turn whatever arrived into `{ tool, server, arguments }`.
   *
   * Accepts a JSON-RPC `tools/call` message, an already-flat call, or the
   * namespaced `server__tool` form the gateway uses. A shape it cannot read
   * becomes a call with an empty tool name, which default-deny then refuses —
   * rather than throwing, which would turn a malformed frame from a hostile
   * upstream into a crash.
   */
  #parse(raw) {
    if (raw?.method === "tools/call") {
      const full = raw.params?.name ?? "";
      const sep = full.indexOf("__");
      return {
        server: sep === -1 ? null : full.slice(0, sep),
        tool: sep === -1 ? full : full.slice(sep + 2),
        arguments: raw.params?.arguments ?? {},
      };
    }
    const full = String(raw?.tool ?? raw?.name ?? "");
    const sep = raw?.server ? -1 : full.indexOf("__");
    return {
      server: raw?.server ?? (sep === -1 ? null : full.slice(0, sep)),
      tool: sep === -1 ? full : full.slice(sep + 2),
      arguments: raw?.arguments ?? raw?.args ?? raw?.params ?? {},
    };
  }

  #count(decision, latency) {
    this.stats.calls++;
    this.stats.latencyTotal += latency;
    // Bounded so a long-running gateway does not grow without limit; the tail
    // is what percentiles are computed from and 10k samples is plenty for P99.
    this.stats.latencies.push(latency);
    if (this.stats.latencies.length > 10_000) this.stats.latencies.shift();

    switch (decision.decision) {
      case DECISION.ALLOW:
        this.stats.allowed++;
        break;
      case DECISION.DENY:
        this.stats.denied++;
        break;
      case DECISION.REQUIRE_APPROVAL:
        this.stats.approvals++;
        break;
      case DECISION.SANITIZE:
        this.stats.allowed++;
        break;
      case DECISION.AUDIT_ONLY:
        this.stats.auditOnly++;
        break;
      default:
        break;
    }
  }

  /** Latency percentiles over the retained window. */
  percentiles() {
    const s = [...this.stats.latencies].sort((a, b) => a - b);
    if (!s.length) return { p50: 0, p95: 0, p99: 0, max: 0, samples: 0 };
    const at = (q) => s[Math.min(s.length - 1, Math.floor(q * s.length))];
    return {
      p50: Number(at(0.5).toFixed(3)),
      p95: Number(at(0.95).toFixed(3)),
      p99: Number(at(0.99).toFixed(3)),
      max: Number(s[s.length - 1].toFixed(3)),
      samples: s.length,
    };
  }
}
