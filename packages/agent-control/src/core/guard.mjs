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
import { canonicalUrl } from "./canonical.mjs";
import { escalateForRisk, toDecision } from "./decisions.mjs";
import { classify } from "./risk.mjs";
import { classifyTool, extractCommand, publicToolName } from "./normalize.mjs";
import { scan as scanSecrets } from "./secret-detect.mjs";
import { applyDelegation } from "./delegation.mjs";
import { applyEntitlements } from "./entitlement-gate.mjs";

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
  if (!args || typeof args !== "object") return "";
  for (const key of [
    "path",
    "file",
    "filename",
    "filepath",
    "uri",
    "url",
    "resource",
    "target",
    "query",
    "sql",
  ]) {
    const v = args[key];
    if (typeof v === "string" && v.length) return v;
  }
  const first = Object.values(args).find((v) => typeof v === "string" && v.length);
  return typeof first === "string" ? first : "";
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
  const candidates = [resource, args?.url, args?.uri, args?.endpoint, args?.href];
  for (const candidate of candidates) {
    if (typeof candidate === "string" && /^https?:\/\//i.test(candidate)) {
      return canonicalUrl(candidate) ?? candidate;
    }
  }
  return null;
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
    /* Commercial enforcement. All three default to absent, so a Guard built
       without them behaves exactly as before — which is what keeps the SDK's
       library callers and the shared conformance fixture working unchanged.
       The CLI supplies them. */
    licence = null,
    meter = null,
    agents = null,
  } = {}) {
    this.rules = rules ?? [];
    this.agent = agent;
    this.environment = environment;
    this.cwd = cwd;
    this.audit = audit;
    this.secrets = secrets;
    /** DelegationBroker, when agent-to-agent delegation is in use. */
    this.delegation = delegation;
    this.licence = licence;
    this.meter = meter;
    this.agents = agents;
    this.onDecision = onDecision;
    this.log = log;
    this.runId = runId;
    /** Risk level at or above which an unnamed call is escalated to approval. */
    this.riskFloor = riskFloor;
    /** Set once this session reads secret-shaped material. */
    this.touchedSecret = false;
    this.stats = { calls: 0, permitted: 0, denied: 0, held: 0, leaks: 0, latencyTotal: 0 };
    this.nextId = 1;
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
  async authorize({ tool, server = null, args = {}, delegation = null, agent = null }) {
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
        external: this.isExternal(resource),
        internal: false,
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

    const decision = evaluate(
      { agent: caller, action, resource, context },
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

    const latencyMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
    const decisionId = `dec_${Date.now().toString(36)}${(this.nextId++).toString(36)}`;
    decision.decisionId = decisionId;
    this.stats.calls++;
    this.stats.latencyTotal += latencyMs;

    // Substitution sits between the decision and the record, so one call still
    // produces exactly one decision. A broker refusal turns the permit into a
    // deny carrying its own rule rather than emitting a second decision.
    let outgoing = args;
    let brokered = [];
    if (this.secrets && decision.verdict === "permit") {
      const substitution = await this.secrets.substitute(args, {
        destination: destinationFor(decision.resource, args),
        // See the matching note in `Pipeline`: possession of a handle is not
        // authority to spend it.
        subject: caller,
      });
      if (substitution.ok) {
        outgoing = substitution.value;
        brokered = substitution.substituted;
      } else {
        decision.verdict = "deny";
        decision.rule = "secret-broker";
        decision.reason = substitution.reason;
        decision.remediation =
          "Request a handle scoped to this destination, or add the destination to the secret's allowlist.";
      }
    }

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
      // Who authorized this must be answerable after the fact, on every surface
      // — not only the one that happened to record it.
      ...(delegationContext ? { delegation: delegationContext } : {}),
      ...(brokered.length ? { secrets: brokered, secrets_brokered: brokered } : {}),
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

    if (this.audit) await this.audit.append(record);
    this.onDecision({ kind: "decision", ...record });

    if (decision.verdict === "deny") this.stats.denied++;
    else if (decision.verdict === "hold") this.stats.held++;
    else {
      this.stats.permitted++;
      // Any successful read of secret-shaped material taints the session. A
      // brokered substitution deliberately does not: the agent never held the
      // material, which is the entire point of a handle.
      if (/secret|credential|token|password|\.env/i.test(decision.resource)) {
        this.touchedSecret = true;
      }
    }

    return { decision, record, args: outgoing };
  }

  /** Scans a result for material this session resolved, and puts handles back. */
  scrub(payload) {
    if (!this.secrets) return { payload, findings: [] };
    const result = this.secrets.redact(payload);
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
    if (!resource) return true;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(resource)) return false;
    const norm = (s) => s.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
    const abs = /^([A-Za-z]:|\/)/.test(resource) ? resource : `${this.cwd}/${resource}`;
    const parts = [];
    for (const seg of norm(abs).split("/")) {
      if (seg === "..") parts.pop();
      else if (seg !== ".") parts.push(seg);
    }
    const flat = parts.join("/");
    const root = norm(this.cwd);
    return flat === root || flat.startsWith(root + "/");
  }

  isExternal(resource) {
    if (!/^https?:\/\//i.test(resource)) return false;
    try {
      const host = new URL(resource).hostname;
      return !/^(localhost|127\.|::1|0\.0\.0\.0|.*\.internal|.*\.local)$/i.test(host);
    } catch {
      return true;
    }
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
    return tools.map((tool) => {
      if (typeof tool === "function") return wrapCallable(tool, tool.name ?? "tool", guard);
      const key = CALLABLE_KEYS.find((k) => typeof tool?.[k] === "function");
      if (!key) return tool;
      const name = tool.name ?? tool.title ?? "tool";
      // A shallow copy with the callable replaced, rather than a mutation:
      // frameworks hold references to the tool objects they were given, and
      // mutating them governs the caller's array as a side effect of reading
      // ours.
      return Object.assign(Object.create(Object.getPrototypeOf(tool) ?? Object.prototype), tool, {
        [key]: wrapCallable(tool[key].bind(tool), name, guard),
      });
    });
  }

  if (tools && typeof tools === "object") {
    return Object.fromEntries(
      Object.entries(tools).map(([name, value]) => [
        name,
        typeof value === "function" ? wrapCallable(value, name, guard) : value,
      ]),
    );
  }

  throw new TypeError("guard.wrap expects a function, an array of tools, or an object of tools.");
}

const CALLABLE_KEYS = ["func", "invoke", "call", "execute", "handler", "_call", "run"];

function wrapCallable(fn, name, guard) {
  const governed = async (...callArgs) => {
    // Frameworks call tools with a single argument object, or positionally.
    // Only the first form carries anything a policy can read, and pretending
    // otherwise would evaluate a positional call against an empty resource and
    // report the result as if it meant something.
    const args = callArgs.length === 1 && isPlainObject(callArgs[0]) ? callArgs[0] : { input: callArgs[0] };

    const { decision, args: outgoing } = await guard.authorize({ tool: name, args });
    if (decision.verdict !== "permit") throw guard.toError(decision);

    const result = await fn(...(callArgs.length === 1 && isPlainObject(callArgs[0]) ? [outgoing] : callArgs));
    return guard.scrub(result).payload;
  };

  // Frameworks introspect `fn.name` to build their tool registry, and an
  // anonymous arrow would silently rename every governed tool.
  Object.defineProperty(governed, "name", { value: name, configurable: true });
  return governed;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

/** The documented entry point: `guard.wrap(tools, { … })`. */
export const guard = { wrap, Guard };
