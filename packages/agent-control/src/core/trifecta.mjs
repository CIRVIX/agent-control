/**
 * The Lethal Trifecta — sequence-aware enforcement.
 *
 * Three conditions are each individually reasonable and jointly catastrophic:
 *
 *   A. the agent has read sensitive material
 *   B. the agent has ingested content from outside the trust boundary
 *   C. the agent is now trying to act outbound
 *
 * Any one of those is ordinary work. A is `cat .env` during debugging. B is
 * fetching a web page. C is a POST. A rule engine that only ever sees one call
 * at a time cannot refuse any of them without refusing normal development, so
 * it lets all three through and the exfiltration happens in the gaps between
 * them.
 *
 * WHAT ALREADY EXISTED, AND WHY IT WAS NOT ENOUGH
 * ----------------------------------------------
 * risk.mjs carries `session-tainted-egress`: `touchedSecret && egress !== none`
 * → HIGH. That is A + C, and it is a genuinely useful rule. Two gaps:
 *
 *   · B was never tracked at all. The signal exists — sanitize.mjs already
 *     finds injected instructions in fetched results — but the finding was
 *     reported and then dropped on the floor rather than remembered.
 *   · It raises RISK, and risk alone does not refuse anything. It needs a
 *     separate policy rule to become a decision.
 *
 * So this module does not replace that rule; it completes it. A + C stays
 * HIGH. A + B + C becomes a decision in its own right, because the presence of
 * B is what turns "this agent is handling secrets near a network call" into
 * "something outside the trust boundary has had the opportunity to steer this
 * agent, and the agent is holding secrets, and it is now talking outward".
 *
 * WHY PROVENANCE, NOT BOOLEANS
 * ----------------------------
 * Each leg records when it was set and what set it. A refusal that says
 * "blocked: trifecta" is indistinguishable from a bug, and a developer who
 * cannot tell those apart turns the feature off. A refusal that says which
 * three calls combined, in order, with timestamps, is a finding the developer
 * can act on — and it is the artifact worth putting in a proof report.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO
 * ----------------------------------
 * It does not attempt data-flow analysis. Knowing that the specific bytes read
 * in call 1 reached the request body of call 3 would be stronger, and every
 * approximation of it that fits in a synchronous hot path is guesswork wearing
 * a proof's clothing. This tracks capability and opportunity, which is what
 * can be established with certainty, and says so in its explanation.
 */

import { RISK } from "./risk.mjs";
import { DECISION } from "./decisions.mjs";

/** The three legs, by the names used in explanations and audit records. */
export const LEG = Object.freeze({
  SENSITIVE: "sensitive_data",
  UNTRUSTED: "untrusted_content",
  OUTBOUND: "outbound_action",
});

const LEG_LABEL = Object.freeze({
  [LEG.SENSITIVE]: "private data",
  [LEG.UNTRUSTED]: "untrusted content",
  [LEG.OUTBOUND]: "an outbound action",
});

/**
 * How a completed trifecta is answered, per environment.
 *
 * Production denies. Everywhere else holds for a human instead, because the
 * combination is common and benign while a developer is exploring — reading a
 * config, opening docs, pushing a branch — and a tool that refuses that
 * outright gets uninstalled before it ever protects anything. The strictness
 * follows the blast radius rather than being one global setting somebody has
 * to remember to raise.
 */
const DEFAULT_RESPONSE = Object.freeze({
  production: DECISION.DENY,
  staging: DECISION.REQUIRE_APPROVAL,
  local: DECISION.REQUIRE_APPROVAL,
  unknown: DECISION.REQUIRE_APPROVAL,
});

/* -------------------------------------------------------------- leg C ---- */

/**
 * Is THIS call an outbound action?
 *
 * Leg C is a property of the call being judged, not of the session — which is
 * the whole reason the trifecta can be refused *before* it completes rather
 * than reported after. Legs A and B are history; C is the proposal.
 */
export function outboundLegOf(call = {}) {
  const egress = String(call.egress ?? "none");
  if (egress === "external") {
    return { at: call.timestamp, why: `Sends data to ${call.destination ?? "a destination outside your network"}.`, scope: "external" };
  }
  if (egress === "internal") {
    return { at: call.timestamp, why: `Sends data to ${call.destination ?? "another host on your network"}.`, scope: "internal" };
  }
  // A write is outbound in the sense that matters here: it leaves an effect
  // somewhere the agent does not own, whether or not a packet is involved.
  const action = String(call.action ?? "");
  if (/\.(write|create|update|delete|put|post|send|publish|deploy|push|upload)$/.test(action)) {
    return { at: call.timestamp, why: `Writes to ${call.resource ?? "an external system"}.`, scope: "write" };
  }
  if (call.sql && /^\s*(insert|update|delete|drop|alter|truncate)/i.test(call.sql)) {
    return { at: call.timestamp, why: "Mutates a database.", scope: "write" };
  }
  return null;
}

/* ------------------------------------------------------- session taint ---- */

const SENSITIVE_RESOURCE = /secret|credential|token|password|api[-_]?key|\.env|\.pem|\.p12|id_rsa|\.aws|\.ssh|\.kube/i;

/**
 * The per-session record of which legs have already been satisfied.
 *
 * Lives for the life of one agent session and holds no payload — only that a
 * leg was satisfied, when, and by which call. Storing the sensitive value
 * itself in order to reason about sensitive values would be its own incident.
 */
export class SessionTaint {
  constructor() {
    this.legs = { [LEG.SENSITIVE]: null, [LEG.UNTRUSTED]: null };
  }

  /** Back-compatible with the boolean the pipeline and guard already pass. */
  get touchedSecret() {
    return this.legs[LEG.SENSITIVE] !== null;
  }

  set touchedSecret(value) {
    if (value && !this.legs[LEG.SENSITIVE]) {
      this.legs[LEG.SENSITIVE] = { at: new Date().toISOString(), why: "Read secret-shaped material.", action: null, resource: null };
    } else if (!value) {
      this.legs[LEG.SENSITIVE] = null;
    }
  }

  get ingestedUntrusted() {
    return this.legs[LEG.UNTRUSTED] !== null;
  }

  /**
   * Leg A. A permitted read of secret-shaped material taints the session.
   *
   * A brokered substitution deliberately does not, which is the same rule the
   * pipeline already applied: with a handle the agent never held the material,
   * and that is the entire point of a handle.
   */
  observeCall(call = {}, forwarded = true) {
    if (!forwarded) return this;
    if (this.legs[LEG.SENSITIVE]) return this;
    const resource = String(call.resource ?? "");
    if (SENSITIVE_RESOURCE.test(resource) || Number(call.secretsDetected) > 0) {
      this.legs[LEG.SENSITIVE] = {
        at: call.timestamp ?? new Date().toISOString(),
        action: call.action ?? null,
        resource: resource || null,
        why: `Read secret-shaped material from ${resource || "a tool result"}.`,
      };
    }
    return this;
  }

  /**
   * Leg B. Content came back from outside the trust boundary.
   *
   * Two independent triggers, because they fail in different directions.
   * Injection findings are strong evidence and weak coverage — they only fire
   * when the text looked like instructions. Provenance is weak evidence and
   * strong coverage — anything fetched from outside is untrusted whether or
   * not it happened to contain an obvious payload. A page that carries a
   * cleverly-worded injection nobody's regex matched is exactly the case the
   * provenance trigger is for.
   */
  observeResult(call = {}, findings = []) {
    if (this.legs[LEG.UNTRUSTED]) return this;

    const injected = findings.filter((f) => f?.kind === "injection");
    if (injected.length) {
      this.legs[LEG.UNTRUSTED] = {
        at: call.timestamp ?? new Date().toISOString(),
        action: call.action ?? null,
        resource: call.resource ?? null,
        why: `A tool result contained ${injected.length} injected instruction${injected.length === 1 ? "" : "s"} addressed to the model.`,
        evidence: injected.map((f) => f.rule ?? f.detector).filter(Boolean).slice(0, 5),
      };
      return this;
    }

    if (call.egress === "external" || call.external === true) {
      this.legs[LEG.UNTRUSTED] = {
        at: call.timestamp ?? new Date().toISOString(),
        action: call.action ?? null,
        resource: call.resource ?? null,
        why: `Content was ingested from ${call.destination ?? call.resource ?? "outside the trust boundary"}.`,
      };
    }
    return this;
  }

  /** Structured state for the audit record. Never contains payload. */
  snapshot() {
    return {
      [LEG.SENSITIVE]: this.legs[LEG.SENSITIVE],
      [LEG.UNTRUSTED]: this.legs[LEG.UNTRUSTED],
    };
  }

  reset() {
    this.legs = { [LEG.SENSITIVE]: null, [LEG.UNTRUSTED]: null };
    return this;
  }
}

/* --------------------------------------------------------- assessment ---- */

/**
 * Would this call complete the trifecta?
 *
 * Returns an assessment whether or not it does — `complete: false` with the
 * legs that ARE satisfied is useful on its own, because it is what lets a
 * dashboard show an agent one step away from the cliff rather than only
 * telling anyone once it has gone over.
 */
export function assessTrifecta(call = {}, taint = new SessionTaint(), options = {}) {
  const outbound = outboundLegOf(call);
  const legs = {
    [LEG.SENSITIVE]: taint.legs?.[LEG.SENSITIVE] ?? null,
    [LEG.UNTRUSTED]: taint.legs?.[LEG.UNTRUSTED] ?? null,
    [LEG.OUTBOUND]: outbound,
  };

  const satisfied = Object.entries(legs).filter(([, v]) => v !== null).map(([k]) => k);
  const missing = Object.keys(legs).filter((k) => legs[k] === null);
  const complete = missing.length === 0;

  const environment = String(call.environment ?? "unknown");
  const configured = options.response ?? DEFAULT_RESPONSE[environment] ?? DEFAULT_RESPONSE.unknown;

  return {
    complete,
    legs,
    satisfied,
    missing,
    /* One short of the cliff. Worth surfacing before it matters. */
    imminent: !complete && missing.length === 1,
    risk: complete ? RISK.CRITICAL : satisfied.length >= 2 ? RISK.HIGH : RISK.LOW,
    decision: complete ? configured : null,
    environment,
    explain: explainTrifecta({ complete, legs, missing, environment, decision: complete ? configured : null }),
  };
}

/**
 * The sentence a developer reads at 2am.
 *
 * Ordered by when each leg was satisfied rather than by leg name, because the
 * order is the argument: this happened, then this happened, and now you are
 * asking for the third thing.
 */
export function explainTrifecta({ complete, legs, missing, environment, decision }) {
  const ordered = Object.entries(legs)
    .filter(([, v]) => v !== null)
    .sort((a, b) => String(a[1].at ?? "").localeCompare(String(b[1].at ?? "")));

  const steps = ordered.map(([leg, v], i) => `  ${i + 1}. ${LEG_LABEL[leg]} — ${v.why}${v.at ? `  (${v.at})` : ""}`);

  if (!complete) {
    const short = missing.map((m) => LEG_LABEL[m]).join(" and ");
    return [
      ordered.length
        ? `${ordered.length} of 3 trifecta conditions are satisfied in this session:`
        : "No trifecta conditions are satisfied in this session.",
      ...steps,
      ordered.length ? `\nStill missing: ${short}. This call is permitted on trifecta grounds.` : "",
    ].filter(Boolean).join("\n");
  }

  return [
    `This call would complete the Lethal Trifecta:`,
    ...steps,
    ``,
    `Private data, untrusted content and an outbound action have now all`,
    `occurred in one session. Anything that steered this agent through the`,
    `untrusted content can reach the outside through this call.`,
    ``,
    `Cirvix does not claim the sensitive bytes are in this request — proving`,
    `that would require data-flow analysis it does not do. It refuses on`,
    `capability and opportunity, which are established.`,
    ``,
    `Environment is ${environment}, so the configured response is ${decision}.`,
  ].join("\n");
}

/**
 * Fold the assessment into a decision.
 *
 * Only ever tightens. A call already denied stays denied with its original
 * reason, because the first refusal is the one the developer needs to fix and
 * overwriting it with a second one buries the cause.
 */
export function applyTrifecta(decision, assessment) {
  if (!assessment?.complete) return decision;
  if (decision.decision === DECISION.DENY) return decision;

  const next = { ...decision };
  next.decision = assessment.decision;
  next.verdict = assessment.decision === DECISION.DENY ? "deny" : "hold";
  next.rule = "lethal-trifecta";
  next.reason = "private data + untrusted content + outbound action in one session";
  next.trifecta = {
    complete: true,
    legs: assessment.legs,
    explain: assessment.explain,
  };
  next.risk = RISK.CRITICAL;
  return next;
}
