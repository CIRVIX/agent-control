/**
 * The decision core, and the in-process SDK built on it.
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

import { canonicalizeResource, evaluate } from "./policy.mjs";
import { escalateForRisk, toDecision } from "./decisions.mjs";
import { classify } from "./risk.mjs";
import { classifyTool, extractCommand, publicToolName, extractResource, extractDestination, classifyEgress, isInsideWorkspace } from "./normalize.mjs";
import { scan as scanSecrets, redact as redactSecrets } from "./secret-detect.mjs";
import { stripInjection } from "./sanitize.mjs";
import { applyDelegation } from "./delegation.mjs";
import { assessAuthority, applyAuthority, acquireMission, captureMissionCost, missionAllowanceRefusal, recordMissionUsage } from "./authority.mjs";
import { applyEntitlements } from "./entitlement-gate.mjs";
import { SessionTaint, assessTrifecta, applyTrifecta } from "./trifecta.mjs";
import { approvalFingerprint } from "./approvals.mjs";
import { DECISION } from "./decisions.mjs";
import { enforceKillSwitch } from "./kill-switch.mjs";

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
    /* Commercial enforcement. All three default to absent, so a Guard built
       without them behaves exactly as before — which is what keeps the SDK's
       library callers and the shared conformance fixture working unchanged.
       The CLI supplies them. */
    licence = null,
    meter = null,
    agents = null,
    approvals = null,
    killSwitch = null,
  } = {}) {
    this.rules = rules ?? [];
    this.agent = agent;
    this.environment = environment;
    this.cwd = cwd;
    this.audit = audit;
    this.secrets = secrets;
    this.approvals = approvals;
    this.killSwitch = killSwitch;
    /** DelegationBroker, when agent-to-agent delegation is in use. */
    this.delegation = delegation;
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
   */
  // ctx is supplied by the trusted embedder, never copied from tool arguments.
  async authorize(input, ctx = {}) {
    const costUsd = captureMissionCost(ctx);
    const request = input && typeof input === "object" && !Array.isArray(input) ? input : {};
    let { tool, server = null, args, arguments: callArguments, delegation = null, agent = null, mission = null } = request;
    args = args ?? callArguments ?? {};
    const action = actionForTool(server, tool);
    const resource = resourceForCall(args);
    // A caller may act as a specific agent per call — a gateway serving several
    // agents must not evaluate all of them under one configured name.
    const caller = agent ?? this.agent;

    // Measured around the decision itself, not the tool round trip — the
    // latter is orders of magnitude larger and would flatter us dishonestly.
    const startedAt = process.hrtime.bigint();

    /*
     * RISK AND SECRET DETECTION RUN HERE, NOT ONLY IN THE PIPELINE.
     *
     * They used to run only in `Pipeline`, and the gateway does not go through
     * `Pipeline` — it goes through this method. The consequence was not a
     * missing feature, it was a silent one: a rule saying `risk >= HIGH` or
     * `command = "rm -rf"` loaded, validated, appeared in `cirvix policy list`,
     * fired correctly over the local socket, and never matched a single call
     * arriving over MCP. The two surfaces enforced different policies from the
     * same file.
     *
     * That is exactly the bypass this file's header warns about, so the fix is
     * the one the header demands: one context builder, used by both. The
     * end-to-end MCP test now asserts it.
     */
    const scanned = scanSecrets(args);
    const classified = classify({
      action,
      tool,
      resource: canonicalizeResource(resource, this.cwd),
      command: extractCommand(args),
      destination: destinationFor(resource, args),
      environment: this.environment,
      insideWorkspace: this.insideWorkspace(resource),
      touchedSecret: this.touchedSecret,
      secretsDetected: scanned.length,
    });

    const context = {
      environment: this.environment,
      path: { insideWorkspace: this.insideWorkspace(resource) },
      egress: {
        external: this.isExternal(destinationFor(resource, args) ?? resource),
        internal: classifyEgress(destinationFor(resource, args) ?? resource) === "internal",
        allowlisted: false,
        destination: destinationFor(resource, args),
      },
      session: { touchedSecret: this.touchedSecret },
      mcp: { server, tool },
      risk: classified.level,
      tool: publicToolName(action),
      command: extractCommand(args),
      secrets: { detected: scanned.length },
    };

    let decision = evaluate(
      { agent: caller, action, resource, context: { ...context, arguments: args } },
      this.rules,
      { cwd: this.cwd },
    );

    decision.decision = decision.decision ?? toDecision(decision.verdict);
    decision.risk = classified.level;
    decision.riskSignals = classified.signals.map((s) => s.id);

    // The risk floor is a floor: it can escalate an unnamed decision, and it
    // can never de-escalate one a rule made explicitly.
    const escalated = escalateForRisk(decision, classified, { floor: this.riskFloor });
    Object.assign(decision, escalated);

    /*
     * A CALL WITH NO TOOL NAME IS REFUSED HERE.
     *
     * `actionForTool(server, undefined)` yields the literal action `tool.`. A
     * policy containing a wildcard permit — `permit *`, which the docs show —
     * matches that string, so `guard.authorize({})` returned `permit` while
     * `Pipeline` refused the identical input as `invalid-request`. Both cores
     * are documented to answer the same question the same way; this was one of
     * them answering a different one.
     *
     * The MCP gateway already rejects a nameless `tools/call` at its parameter
     * check, so this is not a reachable bypass through that transport. It is
     * reachable by an embedder using the SDK directly, and "there is no tool
     * here" is not a call any policy can authorize.
     */
    const wellFormedTool = typeof tool === "string" && tool.trim().length > 0;
    const wellFormedArgs = args == null || (typeof args === "object" && !Array.isArray(args));
    if (!wellFormedTool || !wellFormedArgs) {
      Object.assign(decision, {
        decision: DECISION.DENY,
        verdict: "deny",
        rule: "invalid-request",
        reason: "A tool call needs a non-empty string tool name and object arguments.",
        enforced: true,
      });
    }

    /*
     * DELEGATION NARROWS HERE TOO, NOT ONLY IN THE PIPELINE.
     *
     * It used to narrow only in `Pipeline`, and the gateway does not go through
     * `Pipeline` — it goes through this method. Same shape as the risk-rule
     * bypass documented above, with a worse failure direction: delegation only
     * ever takes authority away, so a surface that ignores it does not lose a
     * feature, it grants everything policy allows. A worker delegated `fs.read`
     * could write the database simply by arriving over MCP instead of the
     * socket.
     *
     * `applyDelegation` is the single implementation both engines call, so
     * there is no second copy to drift.
     */
    const delegationContext = applyDelegation(decision, {
      broker: this.delegation,
      presented: delegation,
      agent: caller,
      action,
      resource: decision.resource ?? resource,
    });

    /*
     * AUTHORITY RUNS HERE, ON THE SAME PATH AS EVERYTHING ELSE.
     *
     * Mission, capability, constraint and expiry are evaluated for every call,
     * not only for the ones a caller remembers to check. Placing it beside
     * delegation is deliberate: both answer "does this principal actually hold
     * the authority it is exercising", both can only narrow, and both have to
     * be on the ONE path that `guard.wrap()`, the MCP gateway and the socket
     * all go through. The three bypasses documented above this line were all
     * the same mistake — a check that lived on one surface and not the others —
     * and an authority layer with that shape would be worse than none, because
     * the console would show a boundary the runtime was not enforcing.
     *
     * `assessAuthority` is pure. It reads the mission and reports; it does not
     * spend the budget. A shared mission lease protects its allowance through
     * asynchronous approval, broker and audit work. Only a successful
     * authorization is charged; external execution is outside this transaction.
     * Charging a refused call would let a blocked agent exhaust its own mission,
     * turning every constraint into a denial-of-service against the agent's work.
     */
    let activeMission =
      mission ?? this.mission ?? (this.missions ? this.missions.forAgent(caller) : null);
    if (typeof activeMission === "string") {
      activeMission = this.missions?.get(activeMission) ?? null;
      if (!activeMission) Object.assign(decision, { decision: DECISION.DENY, verdict: "deny", rule: "authority-mission-unavailable", reason: "The requested mission could not be resolved." });
    }

    if (activeMission?.id && this.missions?.get(activeMission.id)) activeMission = this.missions.get(activeMission.id);
    const missionLease = acquireMission(activeMission);
    try {
    const allowanceRefusal = missionAllowanceRefusal(activeMission, costUsd, missionLease);
    const authorityAssessment = assessAuthority(
      {
        agent: caller,
        action,
        resource: decision.resource ?? resource,
        tool,
        server,
        destination: destinationFor(decision.resource ?? resource, args),
        environment: this.environment,
        costUsd,
        delegating: Boolean(delegation),
      },
      activeMission,
    );

    const authorityContext = applyAuthority(decision, authorityAssessment);
    if (allowanceRefusal) Object.assign(decision, allowanceRefusal, { decision: DECISION.DENY, verdict: "deny" });

    /*
     * An attempt is recorded whether or not authority is what refused it.
     *
     * A call policy already denied is still an agent reaching outside its
     * boundary, and if only authority-attributed refusals were counted an
     * agent could probe the boundary for free by choosing actions policy
     * denies anyway. The benchmark scores attempts, not attributions.
     */
    if (this.missions && authorityAssessment.applicable && !authorityAssessment.authorized) {
      this.missions.recordEscape({
        missionId: activeMission?.id ?? null,
        agent: caller,
        kind: authorityAssessment.escape?.kind ?? null,
        stage: authorityAssessment.stage,
        code: authorityAssessment.code,
        action,
        resource: decision.resource ?? resource,
        tool,
        reason: authorityAssessment.reason,
        blocked: decision.verdict === "deny" || decision.verdict === "hold",
      });
    }

    /*
     * Sequence-aware enforcement (Lethal Trifecta) in Guard.
     * Prevents untrusted content + sensitive data read + outbound egress.
     */
    const trifectaCall = {
      action,
      resource: decision.resource ?? resource,
      tool,
      server,
      destination: destinationFor(decision.resource ?? resource, args),
      environment: this.environment,
      egress: classifyEgress(destinationFor(decision.resource ?? resource, args) ?? resource),
      timestamp: new Date().toISOString(),
      sql: typeof args?.sql === "string" ? args.sql : typeof args?.query === "string" ? args.query : null,
      secretsDetected: scanned.length,
    };
    const trifecta = assessTrifecta(trifectaCall, this.taint);
    decision = applyTrifecta(decision, trifecta);
    decision.trifecta = { complete: trifecta.complete, satisfied: trifecta.satisfied, imminent: trifecta.imminent };

    /*
     * THE COMMERCIAL GATE RUNS HERE TOO, NOT ONLY IN THE PIPELINE.
     *
     * Same shape as the two bypasses documented above, and the same cause: the
     * quota and concurrent-agent limits existed only in `Pipeline`, and
     * neither `guard.wrap()` nor the MCP gateway goes through `Pipeline`. A
     * Free-tier user on either path was never metered, the published limits
     * were not enforced, and the upgrade prompt the pricing depends on could
     * not fire.
     *
     * `applyEntitlements` is the single implementation both cores call. With
     * no licence and no meter it returns the decision untouched, so library
     * callers and the shared conformance fixture are unaffected.
     */
    Object.assign(
      decision,
      applyEntitlements(decision, {
        licence: this.licence,
        meter: this.meter,
        agents: this.agents,
        agent: caller,
      }),
    );

    const killContext = { agentId: caller, tool: publicToolName(action), rawTool: tool, session: this.runId, environment: this.environment, mcp: server };
    decision = enforceKillSwitch(decision, this.killSwitch, killContext);

    const latencyMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
    const decisionId = `dec_${Date.now().toString(36)}${(this.nextId++).toString(36)}`;
    decision.decisionId = decisionId;

    if ((decision.verdict === "hold" || decision.decision === DECISION.REQUIRE_APPROVAL) && this.approvals) {
      const callForFingerprint = {
        agent: caller,
        server,
        environment: this.environment,
        action,
        resource: decision.resource ?? resource,
        command: extractCommand(args),
        delegation: delegationContext?.principals ?? null,
        arguments: args,
      };
      const fingerprint = approvalFingerprint(callForFingerprint);

      try {
        const grant = this.approvals.findGrant(fingerprint);

        if (grant) {
          await this.approvals.consume(grant.id, decisionId);
          decision.decision = DECISION.ALLOW;
          decision.verdict = "permit";
          decision.approvalId = grant.id;
          decision.approvedBy = grant.decidedBy;
          decision.reason = `Approved by ${grant.decidedBy}. ${decision.reason ?? ""}`.trim();
        } else {
          const approval = await this.approvals.request({
            request_id: decisionId.replace(/^dec_/, "req_"),
            agent: caller,
            tool,
            resource: decision.resource ?? resource,
            risk: classified.level,
            rule: decision.rule,
            reason: decision.reason,
            approvers: decision.approvers ?? [],
            fingerprint,
          });
          decision.approvalId = approval.id;
          if (approval.state === "denied") {
            decision.decision = DECISION.DENY;
            decision.verdict = "deny";
            decision.reason = `Denied by ${approval.decidedBy}. ${decision.reason ?? ""}`.trim();
          }
        }
      } catch (err) {
        decision.decision = DECISION.DENY;
        decision.verdict = "deny";
        decision.rule = "approval-unavailable";
        decision.reason = `This call needs human approval and the approval store is unavailable (${err.message}). Refused rather than held.`;
        decision.remediation = "Check the approval log is writable, then retry.";
      }
    } else if (decision.verdict === "hold" || decision.decision === DECISION.REQUIRE_APPROVAL) {
      decision.approvalId = decision.approvalId ?? `apr_${decisionId.slice(4)}`;
    }

    this.stats.calls++;
    this.stats.latencyTotal += latencyMs;

    // Substitution sits between the decision and the record, so one call still
    // produces exactly one decision. A broker refusal turns the permit into a
    // deny carrying its own rule rather than emitting a second decision.
    let outgoing = args;
    let brokered = [];
    if (this.secrets && decision.verdict === "permit") {
      let substitution;
      try {
        substitution = await this.secrets.substitute(args, {
          destination: destinationFor(decision.resource, args),
          subject: caller,
        });
      } catch {
        substitution = { ok: false, reason: "The secret broker is unavailable." };
      }
      if (substitution?.ok === true && substitution.value !== undefined) {
        outgoing = substitution.value;
        brokered = Array.isArray(substitution.substituted) ? substitution.substituted : [];
      } else {
        substitution = substitution?.ok === false
          ? substitution
          : { ok: false, reason: "The secret broker returned an invalid response." };
        decision.verdict = "deny";
        decision.decision = DECISION.DENY;
        decision.rule = substitution.outcome === "revoked" ? "credential-revoked" : "secret-broker";
        decision.reason = substitution.reason;
        decision.remediation = substitution.outcome === "revoked"
          ? "This credential was revoked. Request a fresh credential handle."
          : "Request a handle scoped to this destination, or add the destination to the secret's allowlist.";
      }
    }

    if (decision.decision === DECISION.SANITIZE &&
        (decision.sanitize ?? []).some((s) => s.targets.includes("arguments"))) {
      outgoing = redactSecrets(outgoing).value;
    }

    decision = enforceKillSwitch(decision, this.killSwitch, killContext);
    if (decision.verdict !== "permit") outgoing = args;

    const record = {
      decision_id: decisionId,
      // Both spellings, deliberately. `cirvix logs`, `replay`, and the control
      // plane read `request_id`; the older records and the SDK read
      // `decision_id`. Emitting one and not the other split the history in two.
      request_id: decisionId.replace(/^dec_/, "req_"),
      runId: this.runId,
      run_id: this.runId,
      agent: caller,
      server,
      tool,
      action,
      resource: decision.resource,
      verdict: decision.verdict,
      decision: decision.decision,
      rule: decision.rule,
      // `policy` is what the journal renders and what the console joins on.
      policy: decision.rule,
      reason: decision.reason,
      risk: decision.risk,
      risk_signals: decision.riskSignals,
      latencyMs: Number(latencyMs.toFixed(3)),
      latency_ms: Number(latencyMs.toFixed(3)),
      context,
      considered: decision.considered?.slice(0, 200),
      ...(decision.riskEscalated ? { risk_escalated: true } : {}),
      ...(decision.approvalId ? { approval_id: decision.approvalId } : {}),
      ...(decision.approvedBy ? { approved_by: decision.approvedBy } : {}),
      // Who authorized this must be answerable after the fact, on every surface
      // — not only the one that happened to record it.
      ...(delegationContext ? { delegation: delegationContext } : {}),
      // Authority is part of the record for the same reason delegation is:
      // "who authorized this" must be answerable after the fact.
      ...(authorityContext ? { authority: authorityContext } : {}),
      ...(decision.escape ? { escape: decision.escape } : {}),
      ...(brokered.length ? { secrets: brokered, secrets_brokered: brokered } : {}),
      ...(decision.trifecta ? { trifecta: decision.trifecta } : {}),
      // Findings never carry the value — see secret-detect.mjs.
      ...(scanned.length
        ? {
            secrets_detected: scanned.map((f) => ({
              path: f.path,
              detector: f.detector,
              severity: f.severity,
              masked: f.masked,
              fingerprint: f.fingerprint,
            })),
          }
        : {}),
    };

    if (this.audit) {
      try {
        await this.audit.append(record);
      } catch {
        record.audit_write_failed = true;
        if (decision.verdict === "permit") {
          Object.assign(decision, {
            decision: DECISION.DENY,
            verdict: "deny",
            rule: "audit-unavailable",
            reason: "The decision could not be recorded, so the call was refused.",
            remediation: "Check the audit log path is writable, then retry.",
          });
          Object.assign(record, {
            decision: decision.decision,
            verdict: decision.verdict,
            rule: decision.rule,
            policy: decision.rule,
            reason: decision.reason,
          });
          outgoing = args;
        }
      }
    }
    this.onDecision({ kind: "decision", ...record });

    if (decision.verdict === "deny") this.stats.denied++;
    else if (decision.verdict === "hold") this.stats.held++;
    else {
      this.stats.permitted++;
      // The successful authorization is charged below, just before return.
      this.taint.observeCall(trifectaCall, true);
      // Any successful read of secret-shaped material taints the session. A
      // brokered substitution deliberately does not: the agent never held the
      // material, which is the entire point of a handle.
      if (/secret|credential|token|password|\.env/i.test(decision.resource)) {
        this.touchedSecret = true;
      }
    }

    if (activeMission && decision.verdict === "permit") recordMissionUsage(activeMission, { costUsd });
    return { decision, record, args: outgoing };
    } finally {
      missionLease.release();
    }
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
