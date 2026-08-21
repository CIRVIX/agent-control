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

import { evaluate } from "./policy.mjs";
import {
  DECISION,
  MODE,
  applyMode,
  escalateForRisk,
  isForwarded,
  toDecision,
} from "./decisions.mjs";
import { classify } from "./risk.mjs";
import { applyEntitlements } from "./entitlement-gate.mjs";
import { normalize, policyRequest, requestId } from "./normalize.mjs";
import { approvalFingerprint } from "./approvals.mjs";
import { applyDelegation } from "./delegation.mjs";
import { redact as redactSecrets, scan as scanSecrets } from "./secret-detect.mjs";
import { stripInjection } from "./sanitize.mjs";

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
    this.licence = licence;
    this.meter = meter;
    this.agents = agents;
    this.riskFloor = riskFloor;
    this.runId = runId;
    this.onEvent = onEvent;
    this.log = log;

    /** Set once this session reads secret-shaped material. */
    this.touchedSecret = false;

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
   * Runs one call through every stage.
   *
   * Never throws for a policy outcome — a denial is a return value, because the
   * transports need to render it as data the agent can read rather than as an
   * exception that aborts the run.
   *
   * @returns {Promise<{event:object, call:object, decision:object, arguments:any}>}
   */
  async submit(raw, ctx = {}) {
    const total = timer();
    const stages = {};
    const id = raw.request_id ?? requestId();

    /* ------------------------------------------------------------ 1. parse */
    let t = timer();
    const parsed = this.#parse(raw);
    stages.parse = t();

    /* -------------------------------------------------------- 2. normalize */
    t = timer();
    const call = normalize(
      { ...parsed, request_id: id },
      {
        agent: ctx.agent ?? this.agent,
        source: ctx.source ?? raw.source,
        cwd: this.cwd,
        environment: ctx.environment ?? this.environment,
        touchedSecret: this.touchedSecret,
        runId: this.runId,
        timestamp: ctx.timestamp,
      },
    );
    stages.normalize = t();

    /* -------------------------------------------- 3. secret detection (in) */
    t = timer();
    const argumentFindings = scanSecrets(call.arguments);
    call.secretsDetected = argumentFindings.length;
    this.stats.secretsDetected += argumentFindings.length;
    stages.secrets = t();

    /* ------------------------------------------------ 4. risk (re-classify) */
    // Re-run now that `secretsDetected` is known: the `secret-material-in-
    // arguments` rule cannot fire during normalization because the scan had
    // not happened yet.
    t = timer();
    const risk = classify(call);
    call.risk = risk.level;
    call.risk_signals = risk.signals.map((s) => s.id);
    call.risk_reason = risk.reason;
    stages.risk = t();

    /* ------------------------------------------------------------ 5. policy */
    t = timer();
    let decision = evaluate(policyRequest(call), this.rules, { cwd: this.cwd });
    decision.decision = decision.decision ?? toDecision(decision.verdict);
    decision = escalateForRisk(decision, risk, { floor: this.riskFloor });

    /*
     * Delegation narrows. It never grants.
     *
     * Applied AFTER policy and only ever as an intersection, so there is no
     * path by which presenting a token turns a denied call into a permitted
     * one. If delegation were evaluated as an alternative source of authority,
     * a leaked grant would be leaked authority — and the confused-deputy
     * problem it exists to solve would be reintroduced by its own solution.
     *
     * A call arriving WITHOUT a delegation is unaffected: an agent acting on
     * its own behalf is governed by policy alone.
     */
    if (ctx.delegation && this.delegation) {
      const context = applyDelegation(decision, {
        broker: this.delegation,
        presented: ctx.delegation,
        agent: call.agent,
        action: call.action,
        resource: call.resource,
      });
      if (context) call.delegation = context;
    }

    decision = applyMode(decision, this.mode);
    decision.decision_id = `dec_${id.slice(4)}`;

    /* ------------------------------------------------- entitlement gate ----
     * Quota and concurrent-agent limits, applied as an OVERRIDE of the
     * decision rather than as an early return.
     *
     * The rule itself lives in entitlement-gate.mjs because `Guard` — the core
     * behind guard.wrap() and the MCP gateway — has to apply exactly the same
     * one. It used to live here and only here, which meant every path except
     * this one was unmetered. See that file for the full reasoning. */
    decision = applyEntitlements(decision, {
      licence: this.licence,
      meter: this.meter,
      agents: this.agents,
      agent: call.agent,
    });

    stages.policy = t();

    /* ---------------------------------------------------------- 6. approval */
    t = timer();
    if (decision.decision === DECISION.REQUIRE_APPROVAL && this.approvals) {
      /*
       * The release path.
       *
       * A grant is looked up FIRST, by a fingerprint of this exact call. This
       * is what turns "a person said yes" into "the call runs" — without it
       * every submission created a fresh pending request and an approved
       * approval released nothing, so a hold could never become an execution.
       *
       * Bound to the call rather than the tool, so approving a write to
       * `audit_log` cannot be spent on `salaries`, and single-use, so one yes
       * does not authorize an unbounded number of identical calls.
       */
      const fingerprint = approvalFingerprint(call);

      try {
        const grant = this.approvals.findGrant(fingerprint);

        if (grant) {
          await this.approvals.consume(grant.id, id);
          decision.decision = DECISION.ALLOW;
          decision.verdict = "permit";
          decision.approvalId = grant.id;
          decision.approvedBy = grant.decidedBy;
          decision.reason = `Approved by ${grant.decidedBy}. ${decision.reason}`;
        } else {
          const approval = await this.approvals.request({
            request_id: id,
            agent: call.agent,
            tool: call.tool,
            resource: call.resource,
            risk: call.risk,
            rule: decision.rule,
            reason: decision.reason,
            approvers: decision.approvers ?? [],
            fingerprint,
          });
          decision.approvalId = approval.id;
          if (approval.state === "denied") {
            decision.decision = DECISION.DENY;
            decision.verdict = "deny";
            decision.reason = `Denied by ${approval.decidedBy}. ${decision.reason}`;
          }
        }
      } catch (err) {
        // The approval store is unreachable or unwritable. A held call whose
        // approval cannot be recorded must not proceed, and must not silently
        // become a pending request nobody will ever see.
        decision.decision = DECISION.DENY;
        decision.verdict = "deny";
        decision.rule = "approval-unavailable";
        decision.reason = `This call needs human approval and the approval store is unavailable (${err.message}). Refused rather than held, because a hold nobody can see is not a hold.`;
        decision.remediation = "Check the approval log is writable, then retry.";
      }
    } else if (decision.decision === DECISION.REQUIRE_APPROVAL) {
      decision.approvalId = `apr_${id.slice(4)}`;
    }
    stages.approval = t();

    /* ------------------------------------------- 7. substitution + sanitize */
    t = timer();
    let outgoing = call.arguments;
    let brokered = [];

    if (isForwarded(decision.decision) && this.secrets) {
      /*
       * A broker that throws is a broker that cannot be trusted, so the call
       * does not go out.
       *
       * The failure mode this closes: the vault is unreachable, `substitute`
       * rejects, the exception escapes `submit`, and the transport above sees
       * an unhandled rejection rather than a decision. The agent then hangs
       * with no answer — fail-closed by accident, illegible by design. Worse,
       * a caller that wraps `submit` in a try/catch and continues would forward
       * arguments that were never brokered.
       */
      let substitution;
      try {
        substitution = await this.secrets.substitute(call.arguments, {
          destination: call.destination,
          // Who is spending the handle. A handle is deliberately not secret —
          // it appears in arguments, logs, and results another agent can read —
          // so possession must not be authority. See `Vault#authorize`.
          subject: call.agent,
        });
      } catch (err) {
        substitution = {
          ok: false,
          reason: `The secret broker is unavailable (${err.message}), so this call was refused rather than sent with unresolved arguments.`,
        };
      }

      /*
       * Success must be positively affirmed, in the expected shape.
       *
       * `substitution.ok` alone was a truthiness check, so a broker returning
       * `{ ok: "yes" }` took the success branch and forwarded
       * `substitution.value` — which was `undefined`. The arguments an agent
       * sent were replaced with nothing and the call went out anyway. `null`
       * was worse: reading `.ok` threw, and the exception escaped into the
       * transport.
       *
       * A component that cannot answer in its own contract has not answered.
       */
      const substituted =
        substitution !== null &&
        typeof substitution === "object" &&
        substitution.ok === true &&
        substitution.value !== undefined;

      if (substituted) {
        outgoing = substitution.value;
        brokered = Array.isArray(substitution.substituted) ? substitution.substituted : [];
      } else if (substitution === null || typeof substitution !== "object" || substitution.ok !== false) {
        decision.decision = DECISION.DENY;
        decision.verdict = "deny";
        decision.rule = "secret-broker";
        decision.reason =
          "The secret broker returned a response this engine cannot interpret, so the call was refused rather than forwarded with unverified arguments.";
        decision.remediation = "Check the broker version matches the runtime.";
      } else {
        // A broker refusal converts the permit into a deny carrying its own
        // rule, so one call still produces exactly one decision.
        decision.decision = DECISION.DENY;
        decision.verdict = "deny";
        decision.rule = "secret-broker";
        decision.reason = substitution.reason;
        decision.remediation =
          "Request a handle scoped to this destination, or add the destination to the secret's allowlist.";
      }
    }

    if (decision.decision === DECISION.SANITIZE) {
      const targets = new Set(decision.sanitize?.flatMap((s) => s.targets) ?? ["arguments", "result"]);
      if (targets.has("arguments")) {
        const cleaned = redactSecrets(outgoing);
        if (cleaned.findings.length) {
          outgoing = cleaned.value;
          this.stats.sanitized++;
          decision.sanitized = {
            arguments: cleaned.findings.map((f) => ({
              path: f.path,
              detector: f.detector,
              fingerprint: f.fingerprint,
            })),
          };
        }
      }
    }
    stages.substitute = t();

    /* ------------------------------------------------------------- 8. audit */
    t = timer();
    const latency = total();

    const event = {
      request_id: id,
      decision_id: decision.decision_id,
      run_id: this.runId,
      agent: call.agent,
      source: call.source,
      server: call.server,
      tool: call.tool,
      action: call.action,
      resource: call.resource,
      destination: call.destination,
      command: call.command ? call.command.slice(0, 500) : null,
      risk: call.risk,
      risk_signals: call.risk_signals,
      decision: decision.decision,
      verdict: decision.verdict,
      policy: decision.rule,
      reason: decision.reason,
      enforced: decision.enforced !== false,
      mode: decision.mode ?? this.mode,
      timestamp: call.timestamp,
      latency_ms: Number(latency.toFixed(3)),
      stages: Object.fromEntries(Object.entries(stages).map(([k, v]) => [k, Number(v.toFixed(3))])),
      ...(decision.wouldHave ? { would_have: decision.wouldHave } : {}),
      ...(decision.riskEscalated ? { risk_escalated: true } : {}),
      ...(call.delegation ? { delegation: call.delegation } : {}),
      ...(decision.approvalId ? { approval_id: decision.approvalId } : {}),
      ...(brokered.length ? { secrets_brokered: brokered } : {}),
      // Findings never carry the value — see secret-detect.mjs.
      ...(argumentFindings.length
        ? {
            secrets_detected: argumentFindings.map((f) => ({
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
      considered: decision.considered?.slice(0, 200),
    };

    /*
     * AN UNRECORDABLE DECISION IS A REFUSED DECISION.
     *
     * If the audit chain cannot be written — disk full, permission denied,
     * directory gone — then a call that proceeds is a call with no history, and
     * the whole tamper-evidence property becomes "true of the records that
     * happened to be writable". So a failed append turns a forwarded decision
     * into a denial.
     *
     * A decision that was ALREADY a denial is left alone: refusing it a second
     * time changes nothing, and reporting the storage failure as though it were
     * the reason would misattribute the refusal in the one record an operator
     * later reads.
     */
    if (this.audit) {
      try {
        await this.audit.append(event);
      } catch (err) {
        this.log(`audit append failed: ${err.message}`);
        if (isForwarded(decision.decision)) {
          decision.decision = DECISION.DENY;
          decision.verdict = "deny";
          decision.rule = "audit-unavailable";
          decision.reason = `The decision could not be recorded (${err.message}), so the call was refused. A call with no audit record is a call nobody can account for.`;
          decision.remediation = "Check the audit log path is writable, then retry.";

          event.decision = DECISION.DENY;
          event.verdict = "deny";
          event.policy = "audit-unavailable";
          event.reason = decision.reason;
          event.audit_write_failed = true;
          outgoing = call.arguments;
        } else {
          event.audit_write_failed = true;
        }
      }
    }
    stages.audit = t();
    event.stages.audit = Number(stages.audit.toFixed(3));

    this.#count(decision, latency);
    this.onEvent({ kind: "decision", ...event });

    // Any permitted read of secret-shaped material taints the session. A
    // brokered substitution deliberately does not: the agent never held the
    // material, which is the entire point of a handle.
    if (isForwarded(decision.decision) && /secret|credential|token|password|\.env/i.test(call.resource)) {
      this.touchedSecret = true;
    }

    return { event, call, decision, arguments: outgoing };
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
  scrubResult(payload, decision = {}) {
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
