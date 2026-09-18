/**
 * Authority: Mission, Capability, Constraint, Expiry.
 *
 * THE ONE IDEA
 * ------------
 * An agent's objective does not grant it authority.
 *
 * Everything else in this file follows from that sentence. A mission says what
 * an agent is *for*; it says nothing about what the agent may *do*. Authority
 * is a separate, explicit, expiring grant, and it is checked against the call
 * actually being made rather than against the agent's stated intent.
 *
 * This matters because an agent's intent is the one input an attacker can
 * rewrite for free. Prompt injection does not steal a credential — it changes
 * what the agent believes it is trying to accomplish. A system that derives
 * permission from intent hands the attacker permission along with it. So the
 * mission is deliberately inert: it is a boundary and a clock, never a key.
 *
 * FOUR STAGES, IN THIS ORDER
 * --------------------------
 *   MISSION     Is there an active mission, and is it this agent's?
 *   CAPABILITY  Does a granted, live capability cover this exact action and
 *               resource? Expired and revoked capabilities are not in the set,
 *               so asking for one is reported as its own thing rather than as
 *               a generic miss.
 *   CONSTRAINT  Under the circumstances of THIS call — destination, data,
 *               tool, spend, rate, delegation, environment — is it allowed?
 *   EXPIRY      Is the mission's authorization window still open?
 *
 * Mission expiry is checked last on purpose. When a call is both outside the
 * granted set and under a stale mission, the escalation is the more
 * significant event and should be what the operator sees; an expired mission
 * with a legitimate capability reports EXPIRY, which is also what they want.
 *
 * NARROWING ONLY — THE PROPERTY THAT MAKES THIS SAFE
 * --------------------------------------------------
 * `applyAuthority` follows `applyDelegation` and `applyTrifecta` exactly: it
 * can turn a permit into a denial and never the reverse. Authority is ANDed
 * with policy, never substituted for it. A mission cannot grant what policy
 * forbids, which is what makes it safe to let a caller present one at all.
 *
 * An agent with NO mission is unchanged — the layer is inert, the way
 * delegation is inert without a grant. That is what keeps every existing
 * caller and the shared conformance fixture working. Missions are something
 * you opt into; they take authority away, they never add it.
 *
 * WHAT AN ESCAPE ATTEMPT IS
 * -------------------------
 * An escape attempt is an agent trying to obtain or exercise authority outside
 * its current boundary. Every refusal here is classified as one, because the
 * refusal is not the interesting artifact — the attempt is. A capability
 * escalation that is blocked ninety-nine times and succeeds once is a story
 * only visible if the ninety-nine were recorded.
 */
import { matchGlob } from "./policy.mjs";
import { canonicalAction, TAXONOMY } from "./normalize.mjs";
import { normalizeScope, scopePermits } from "./delegation.mjs";
import { DECISION, isForwarded } from "./decisions.mjs";

/* -------------------------------------------------------------------------- */
/*  Vocabulary                                                                 */
/* -------------------------------------------------------------------------- */

/** The four stages, in evaluation order. Exported so a UI cannot invent a fifth. */
export const STAGE = Object.freeze({
  MISSION: "mission",
  CAPABILITY: "capability",
  CONSTRAINT: "constraint",
  EXPIRY: "expiry",
});

export const MISSION_STATUS = Object.freeze({
  ACTIVE: "active",
  EXPIRED: "expired",
  REVOKED: "revoked",
  COMPLETED: "completed",
});

export const CAPABILITY_STATUS = Object.freeze({
  ACTIVE: "active",
  EXPIRED: "expired",
  REVOKED: "revoked",
});

/**
 * Why authority refused.
 *
 * Distinct codes rather than one `denied`, because the operator response
 * differs: an expired capability is reissued, an escalation is investigated,
 * and a constraint violation is usually the agent doing exactly what it was
 * told to do by something it read.
 */
export const AUTHORITY_ERROR = Object.freeze({
  MISSION_UNKNOWN: "mission_unknown",
  MISSION_NOT_ACTIVE: "mission_not_active",
  MISSION_WRONG_AGENT: "mission_wrong_agent",
  MISSION_EXPIRED: "mission_expired",
  CAPABILITY_NOT_GRANTED: "capability_not_granted",
  CAPABILITY_EXPIRED: "capability_expired",
  CAPABILITY_REVOKED: "capability_revoked",
  CONSTRAINT_VIOLATED: "constraint_violated",
});

/**
 * How an agent tried to leave its boundary.
 *
 * These are the categories the escape benchmark scores, so they are a closed
 * set and each one names a mechanism rather than a severity.
 */
export const ESCAPE = Object.freeze({
  CAPABILITY_ESCALATION: "capability_escalation",
  EXPIRED_AUTHORITY: "expired_authority",
  CONSTRAINT_VIOLATION: "constraint_violation",
  MISSION_VIOLATION: "mission_violation",
  DATA_EXFILTRATION: "data_exfiltration",
  CREDENTIAL_ABUSE: "credential_abuse",
  DELEGATION_ESCAPE: "delegation_escape",
  TOOL_CHAIN_ESCAPE: "tool_chain_escape",
  PROMPT_INJECTION: "prompt_injection",
});

/* -------------------------------------------------------------------------- */
/*  Capabilities                                                               */
/* -------------------------------------------------------------------------- */

let seq = 0;
const newId = (prefix) =>
  `${prefix}_${Date.now().toString(36)}${(seq++).toString(36)}${Math.random().toString(36).slice(2, 6)}`;

const ms = (v) => (v == null ? null : typeof v === "number" ? v : Date.parse(v));

/**
 * Normalizes a capability into the one shape everything downstream reads.
 *
 * A capability is deliberately the SAME shape as a delegation scope
 * (`{actions, resources}`), because it answers the same question — may this
 * (action, resource) pair go through — and two matchers for one question is
 * how the two answers eventually differ. `scopePermits` is reused verbatim
 * for the same reason.
 *
 * The shorthand `"tickets.read"` expands to `{actions:["tickets.read"],
 * resources:["*"]}`. That is a convenience for writing a mission by hand, and
 * it is the ONLY place a wildcard is inferred: an omitted axis on an explicit
 * capability object still means unconstrained, but an omitted axis is a
 * decision the author made, whereas a bare string has no axis to omit.
 */
export function normalizeCapability(input, { issuer = "cirvix", now = Date.now() } = {}) {
  const c = typeof input === "string" ? { actions: [input] } : { ...(input ?? {}) };

  /* Accept the singular spellings a human would write. */
  const actions = c.actions ?? (c.action == null ? undefined : [c.action]);
  const resources = c.resources ?? (c.resource == null ? undefined : [c.resource]);

  /*
   * IDEMPOTENT ON PURPOSE — RE-NORMALIZING MUST NOT WIDEN.
   *
   * An already-normalized capability carries its axes under `scope` and has no
   * top-level `actions`/`resources`. Without this branch those read as absent,
   * absent means "unconstrained on this axis", and normalizing a normalized
   * capability a second time silently turned a tightly scoped grant into
   * `{actions:["*"], resources:["*"]}` — everything policy allows.
   *
   * That is the same absent-vs-empty confusion `normalizeScope` documents, one
   * level up, and it is worth the four lines: any code path that normalizes
   * defensively (a registry re-issue, a lint pass, a round trip through JSON
   * and back) would otherwise be an escalation.
   */
  const scope =
    actions === undefined && resources === undefined && c.scope
      ? normalizeScope(c.scope)
      : normalizeScope({ actions, resources });

  return {
    id: c.id ?? newId("cap"),
    scope,
    /* Human-facing name. Never used for matching — matching is on scope. */
    name: c.name ?? scope.actions.join(","),
    conditions: c.conditions ?? null,
    issuer: c.issuer ?? issuer,
    issuedAt: ms(c.issuedAt) ?? now,
    expiresAt: ms(c.expiresAt) ?? null,
    status: c.status ?? CAPABILITY_STATUS.ACTIVE,
  };
}

/** A capability's status *at a moment*, which is not the same as its stored status. */
export function capabilityStatusAt(cap, now = Date.now()) {
  if (cap.status === CAPABILITY_STATUS.REVOKED) return CAPABILITY_STATUS.REVOKED;
  if (cap.expiresAt != null && now >= cap.expiresAt) return CAPABILITY_STATUS.EXPIRED;
  return CAPABILITY_STATUS.ACTIVE;
}

/* -------------------------------------------------------------------------- */
/*  Missions                                                                   */
/* -------------------------------------------------------------------------- */

export function normalizeMission(input, { now = Date.now() } = {}) {
  const m = { ...(input ?? {}) };
  const issuedAt = ms(m.issuedAt) ?? now;
  const expiresAt =
    ms(m.expiresAt) ?? (m.ttlMs != null ? issuedAt + Number(m.ttlMs) : null);

  return {
    id: m.id ?? newId("msn"),
    name: m.name ?? "Untitled mission",
    /* Prose. Recorded in evidence, shown in the console, and deliberately
       never consulted by any decision — see the header. */
    objective: m.objective ?? "",
    agent: m.agent ?? null,
    capabilities: (m.capabilities ?? []).map((c) =>
      normalizeCapability(c, { issuer: m.id ?? "mission", now }),
    ),
    constraints: m.constraints ?? {},
    issuedAt,
    expiresAt,
    status: m.status ?? MISSION_STATUS.ACTIVE,
    /* Mutable usage, for the spend and rate constraints. Kept on the mission
       because a budget is a property of the authorization, not of the agent:
       two missions for the same agent must not share one wallet. */
    usage: { spendUsd: Number(m.usage?.spendUsd ?? 0), calls: [...(m.usage?.calls ?? [])] },
  };
}

export function missionStatusAt(mission, now = Date.now()) {
  if (mission.status === MISSION_STATUS.REVOKED) return MISSION_STATUS.REVOKED;
  if (mission.status === MISSION_STATUS.COMPLETED) return MISSION_STATUS.COMPLETED;
  if (mission.expiresAt != null && now >= mission.expiresAt) return MISSION_STATUS.EXPIRED;
  return MISSION_STATUS.ACTIVE;
}

export function remainingMs(mission, now = Date.now()) {
  if (mission.expiresAt == null) return null;
  return Math.max(0, mission.expiresAt - now);
}

/* -------------------------------------------------------------------------- */
/*  Constraints                                                                */
/* -------------------------------------------------------------------------- */

const hostOf = (resource, destination) => {
  const candidate = destination ?? resource ?? "";
  if (!/^https?:\/\//i.test(candidate)) return null;
  try {
    return new URL(candidate).hostname.toLowerCase();
  } catch {
    /* An unparseable URL is not "no host" — treating it as absent would let a
       malformed destination skip the network constraint entirely. */
    return " unparseable";
  }
};

/** Data that must not leave, expressed the way a person would say it. */
const PII_HINT = /customer|subscriber|patient|user[s]?[._-]?(data|table|export|dump)|pii|personal|email[s]?[._-]?(list|export)|ssn|passport|address(es)?/i;
const SECRET_HINT = /secret|credential|token|password|api[_-]?key|private[_-]?key|\.env|\.pem|id_rsa|\.aws|\.ssh|keychain|vault/i;
const EXPORT_HINT = /export|dump|backup|extract|download[_-]?all|bulk|archive|snapshot/i;

/**
 * The constraint evaluators.
 *
 * Each returns `null` when satisfied, or a violation. They are separate
 * functions rather than one branchy check so that a mission can carry any
 * subset and an unrecognised key is inert instead of silently permissive —
 * `evaluateConstraints` reports unknown keys rather than skipping them.
 */
const CONSTRAINTS = {
  /**
   * Where the call may talk to.
   *
   * `deny` wins over `allow`, and the DEFAULT for a declared network
   * constraint is deny-unknown. A network constraint that allowed everything
   * it had not thought to name would be decoration: exfiltration goes to a
   * domain nobody listed, by definition.
   */
  network(rule, call) {
    const host = hostOf(call.resource, call.destination);
    if (!host) return null; // not an outbound call

    const deny = rule.deny ?? [];
    if (deny.some((p) => matchGlob(p, host))) {
      return {
        id: "network.denied",
        reason: `Outbound to ${host} is explicitly denied by this mission.`,
        escape: ESCAPE.DATA_EXFILTRATION,
      };
    }

    const allow = rule.allow ?? null;
    const unknownDenied = rule.denyUnknown !== false;
    if (allow && allow.some((p) => matchGlob(p, host))) return null;
    if (allow && unknownDenied) {
      return {
        id: "network.unknown_destination",
        reason:
          `${host} is not on this mission's allowed destination list ` +
          `(${allow.join(", ")}). Unknown external domains are denied.`,
        escape: ESCAPE.DATA_EXFILTRATION,
      };
    }
    return null;
  },

  /** What kind of data the call may touch or move. */
  data(rule, call) {
    const target = `${call.resource ?? ""} ${call.tool ?? ""} ${call.action ?? ""}`;
    const leaving = Boolean(hostOf(call.resource, call.destination)) || EXPORT_HINT.test(target);

    if (rule.secrets === "deny" && SECRET_HINT.test(target)) {
      return {
        id: "data.secrets",
        reason: "This mission may not read credential or secret material.",
        escape: ESCAPE.CREDENTIAL_ABUSE,
      };
    }
    if (rule.pii === "deny" && PII_HINT.test(target) && leaving) {
      return {
        id: "data.pii_export",
        reason: "Customer or personal data may not be exported or sent outbound under this mission.",
        escape: ESCAPE.DATA_EXFILTRATION,
      };
    }
    if (rule.export === "deny" && EXPORT_HINT.test(target)) {
      return {
        id: "data.export",
        reason: "Bulk export is not permitted under this mission.",
        escape: ESCAPE.DATA_EXFILTRATION,
      };
    }
    return null;
  },

  /** Tools the mission may not reach, whatever the capability set says. */
  tools(rule, call) {
    const action = canonicalAction(call.action ?? "");
    const tool = String(call.tool ?? "");
    const hit = (p) => matchGlob(p, action) || matchGlob(p, tool);

    if ((rule.deny ?? []).some(hit)) {
      return {
        id: "tools.denied",
        reason: `${action || tool} is on this mission's denied tool list.`,
        escape: ESCAPE.CONSTRAINT_VIOLATION,
      };
    }
    if (rule.allow && !rule.allow.some(hit)) {
      return {
        id: "tools.not_allowed",
        reason: `${action || tool} is not on this mission's allowed tool list.`,
        escape: ESCAPE.CONSTRAINT_VIOLATION,
      };
    }
    return null;
  },

  /** Money. Checked BEFORE the spend, against the cost the call would incur. */
  spend(rule, call, mission) {
    const max = Number(rule.maxUsd ?? rule.max ?? Infinity);
    const already = Number(mission?.usage?.spendUsd ?? 0);
    const incoming = Number(call.costUsd ?? 0);
    if (!Number.isFinite(incoming) || incoming < 0 || !Number.isFinite(already) || already < 0 || Number.isNaN(max) || max < 0) {
      return { id: "spend.invalid", reason: "Spend and budget must be non-negative valid amounts.", escape: ESCAPE.CONSTRAINT_VIOLATION };
    }
    if (!Number.isFinite(already + incoming) || already + incoming > max) {
      return {
        id: "spend.exceeded",
        reason:
          `This call would take the mission to $${(already + incoming).toFixed(2)}, ` +
          `over its $${max.toFixed(2)} budget.`,
        escape: ESCAPE.CONSTRAINT_VIOLATION,
      };
    }
    return null;
  },

  /** Tool calls per window. A runaway loop is a security event, not just a bill. */
  rate(rule, call, mission, now) {
    const max = Number(rule.maxPerMinute ?? rule.max ?? Infinity);
    const windowMs = Number(rule.windowMs ?? 60_000);
    if (Number.isNaN(max) || max < 0 || !Number.isFinite(windowMs) || windowMs <= 0) {
      return { id: "rate.invalid", reason: "Rate limits require a non-negative maximum and positive finite window.", escape: ESCAPE.CONSTRAINT_VIOLATION };
    }
    const recent = (mission?.usage?.calls ?? []).filter((t) => now - t < windowMs);
    if (recent.length + 1 > max || retainedCalls(mission, now).length >= MAX_MISSION_CALLS) {
      return {
        id: "rate.exceeded",
        reason: `${recent.length} calls in the last ${Math.round(windowMs / 1000)}s; this mission allows ${max}.`,
        escape: ESCAPE.CONSTRAINT_VIOLATION,
      };
    }
    return null;
  },

  /** Whether this mission's authority may be handed to another agent at all. */
  delegation(rule, call) {
    if (!call.delegating) return null;
    if (rule.allow === false || rule.privileged === "deny") {
      return {
        id: "delegation.denied",
        reason: "This mission's authority may not be delegated to another agent.",
        escape: ESCAPE.DELEGATION_ESCAPE,
      };
    }
    return null;
  },

  /** Where the call may run. */
  environment(rule, call) {
    const env = String(call.environment ?? "local");
    const allow = rule.allow ?? null;
    if ((rule.deny ?? []).includes(env)) {
      return {
        id: "environment.denied",
        reason: `This mission may not act in ${env}.`,
        escape: ESCAPE.CONSTRAINT_VIOLATION,
      };
    }
    if (allow && !allow.includes(env)) {
      return {
        id: "environment.not_allowed",
        reason: `This mission is scoped to ${allow.join(", ")}; the call is in ${env}.`,
        escape: ESCAPE.CONSTRAINT_VIOLATION,
      };
    }
    return null;
  },
};

/**
 * Runs every declared constraint.
 *
 * Returns the violations and the list of what was actually checked, because
 * "no violation" and "nothing was evaluated" look identical in a log and mean
 * opposite things. An unrecognised constraint key is surfaced as `unknown`
 * rather than ignored — a typo in a mission definition would otherwise read as
 * a satisfied constraint forever.
 */
export function evaluateConstraints(constraints, call, mission, now = Date.now()) {
  const checked = [];
  const unknown = [];
  const violations = [];

  for (const [key, rule] of Object.entries(constraints ?? {})) {
    if (rule == null || rule === false) continue;
    const evaluator = Object.hasOwn(CONSTRAINTS, key) ? CONSTRAINTS[key] : null;
    if (!evaluator) {
      unknown.push(key);
      continue;
    }
    checked.push(key);
    const violation = evaluator(rule, call, mission, now);
    if (violation) violations.push({ constraint: key, ...violation });
  }

  return { checked, unknown, violations, ok: violations.length === 0 };
}

/* -------------------------------------------------------------------------- */
/*  The assessment                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Evaluates one call against one mission.
 *
 * Pure: it reads the mission and reports. The orchestration paths hold a shared
 * mission lease and call `recordMissionUsage` only when authorization succeeds.
 * This assessment alone does not reserve allowance or authorize external work.
 *
 * @param {object} call    { agent, action, resource, tool, destination,
 *                           environment, costUsd, delegating }
 * @param {object} mission a normalized mission, or null
 * @returns assessment
 */
export function assessAuthority(call = {}, mission = null, { now = Date.now() } = {}) {
  const requested = {
    action: canonicalAction(call.action ?? ""),
    resource: call.resource ?? "",
  };

  /* No mission: the layer is inert. See the header — missions are opt-in and
     subtractive, so absence must not deny and must not grant. */
  if (!mission) {
    return {
      applicable: false,
      authorized: true,
      stage: null,
      code: null,
      reason: null,
      mission: null,
      capability: null,
      granted: [],
      requested,
      escape: null,
      constraints: { checked: [], unknown: [], violations: [], ok: true },
    };
  }

  const base = {
    applicable: true,
    requested,
    mission: {
      id: mission.id,
      name: mission.name,
      objective: mission.objective,
      agent: mission.agent,
      status: missionStatusAt(mission, now),
      expiresAt: mission.expiresAt,
      remainingMs: remainingMs(mission, now),
    },
    granted: mission.capabilities
      .filter((c) => capabilityStatusAt(c, now) === CAPABILITY_STATUS.ACTIVE)
      .map((c) => ({ id: c.id, name: c.name, scope: c.scope, expiresAt: c.expiresAt })),
    capability: null,
    constraints: { checked: [], unknown: [], violations: [], ok: true },
  };

  const deny = (stage, code, reason, escape, extra = {}) => ({
    ...base,
    ...extra,
    authorized: false,
    stage,
    code,
    reason,
    escape: escape ? { kind: escape, stage, code } : null,
  });

  /* ---- 1. MISSION ------------------------------------------------------ */

  const status = missionStatusAt(mission, now);
  if (status === MISSION_STATUS.REVOKED || status === MISSION_STATUS.COMPLETED) {
    return deny(
      STAGE.MISSION,
      AUTHORITY_ERROR.MISSION_NOT_ACTIVE,
      `Mission "${mission.name}" is ${status}. Authority ended with it.`,
      ESCAPE.MISSION_VIOLATION,
    );
  }
  if (mission.agent && mission.agent !== call.agent) {
    /* A mission belongs to one agent. Another agent presenting it is trying to
       borrow authority, which is the delegation attack in its simplest form. */
    return deny(
      STAGE.MISSION,
      AUTHORITY_ERROR.MISSION_WRONG_AGENT,
      `Mission "${mission.name}" authorizes ${mission.agent}, not ${call.agent}.`,
      ESCAPE.DELEGATION_ESCAPE,
    );
  }

  /* ---- 2. CAPABILITY --------------------------------------------------- */

  const covering = mission.capabilities.filter((c) => scopePermits(c.scope, requested));

  if (!covering.length) {
    return deny(
      STAGE.CAPABILITY,
      AUTHORITY_ERROR.CAPABILITY_NOT_GRANTED,
      `${requested.action} on ${requested.resource || "(no resource)"} is outside this mission's ` +
        `authorization set. Granted: ${base.granted.map((g) => g.name).join(", ") || "nothing"}.`,
      ESCAPE.CAPABILITY_ESCALATION,
    );
  }

  /* A capability exists but is not live. Reported distinctly from "never had
     it": reissuing is the fix for one and an investigation is the fix for the
     other, and an operator must not have to guess which they are looking at. */
  const live = covering.find((c) => capabilityStatusAt(c, now) === CAPABILITY_STATUS.ACTIVE);
  if (!live) {
    const stale = covering[0];
    const state = capabilityStatusAt(stale, now);
    return deny(
      STAGE.CAPABILITY,
      state === CAPABILITY_STATUS.REVOKED
        ? AUTHORITY_ERROR.CAPABILITY_REVOKED
        : AUTHORITY_ERROR.CAPABILITY_EXPIRED,
      state === CAPABILITY_STATUS.REVOKED
        ? `Capability ${stale.name} was revoked.`
        : `Capability ${stale.name} expired at ${new Date(stale.expiresAt).toISOString()}. ` +
          `Stale authorization is not authority.`,
      ESCAPE.EXPIRED_AUTHORITY,
      { capability: { id: stale.id, name: stale.name, status: state, expiresAt: stale.expiresAt } },
    );
  }

  base.capability = { id: live.id, name: live.name, scope: live.scope, expiresAt: live.expiresAt };

  /* ---- 3. CONSTRAINT --------------------------------------------------- */

  /* Per-capability conditions are ANDed with the mission's. A capability may
     tighten its own use; it may never loosen the mission's. */
  const missionConstraints = evaluateConstraints(mission.constraints, { ...call, ...requested }, mission, now);
  const capabilityConstraints = evaluateConstraints(live.conditions, { ...call, ...requested }, mission, now);
  const constraints = {
    checked: [...new Set([...missionConstraints.checked, ...capabilityConstraints.checked])],
    unknown: [...new Set([...missionConstraints.unknown, ...capabilityConstraints.unknown])],
    violations: [...missionConstraints.violations, ...capabilityConstraints.violations],
    ok: missionConstraints.ok && capabilityConstraints.ok,
  };
  base.constraints = constraints;

  if (!constraints.ok) {
    const first = constraints.violations[0];
    return deny(
      STAGE.CONSTRAINT,
      AUTHORITY_ERROR.CONSTRAINT_VIOLATED,
      first.reason,
      first.escape,
      { constraintViolated: first },
    );
  }

  /* ---- 4. EXPIRY ------------------------------------------------------- */

  if (status === MISSION_STATUS.EXPIRED) {
    return deny(
      STAGE.EXPIRY,
      AUTHORITY_ERROR.MISSION_EXPIRED,
      `Authorization expired at ${new Date(mission.expiresAt).toISOString()}. ` +
        `The capability is intact; the mission's window is not.`,
      ESCAPE.EXPIRED_AUTHORITY,
    );
  }

  return { ...base, authorized: true, stage: null, code: null, reason: null, escape: null };
}

/* -------------------------------------------------------------------------- */
/*  Applying it                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Narrows a policy decision by the authority assessment.
 *
 * Same contract as `applyDelegation`: mutates in place, can only make the
 * decision stricter, and leaves an already-denied call under its own rule
 * rather than re-attributing the refusal. An operator reading one record needs
 * the reason it was FIRST refused, not the last check that would also have
 * refused it.
 *
 * @returns the authority context for the audit record, or null when inert
 */
export function applyAuthority(decision, assessment) {
  if (!assessment || !assessment.applicable) return null;

  const context = {
    mission: assessment.mission,
    capability: assessment.capability,
    granted: assessment.granted?.map((g) => g.name) ?? [],
    requested: assessment.requested,
    stage: assessment.stage,
    code: assessment.code,
    constraints: {
      checked: assessment.constraints?.checked ?? [],
      violated: assessment.constraints?.violations?.map((v) => v.constraint) ?? [],
    },
    ...(assessment.escape ? { escape: assessment.escape } : {}),
  };

  if (!assessment.authorized && (isForwarded(decision.decision) || decision.decision === DECISION.REQUIRE_APPROVAL || decision.verdict === "hold")) {
    decision.decision = DECISION.DENY;
    decision.verdict = "deny";
    decision.rule = `authority-${assessment.code}`;
    decision.reason = assessment.reason;
    decision.remediation = REMEDIATION[assessment.code] ?? "Reissue authority scoped to this call.";
    decision.authorityStage = assessment.stage;
    decision.escape = assessment.escape;
  } else if (!assessment.authorized) {
    /* Policy already refused. The attempt is still an escape attempt and must
       still be recorded as one — otherwise an agent could probe the boundary
       for free simply by choosing calls policy denies anyway. */
    decision.escape = assessment.escape;
    decision.authorityStage = assessment.stage;
  }

  return context;
}

const REMEDIATION = Object.freeze({
  [AUTHORITY_ERROR.CAPABILITY_NOT_GRANTED]:
    "This is outside the mission's authorization set. Ask for a capability scoped to this action and resource — do not retry the call.",
  [AUTHORITY_ERROR.CAPABILITY_EXPIRED]:
    "Request a fresh capability. Expired authorization cannot be reused.",
  [AUTHORITY_ERROR.CAPABILITY_REVOKED]:
    "This capability was revoked. Escalate to a human rather than seeking another route.",
  [AUTHORITY_ERROR.CONSTRAINT_VIOLATED]:
    "The capability covers this action, but the circumstances do not. Change the circumstances, not the capability.",
  [AUTHORITY_ERROR.MISSION_EXPIRED]:
    "Start a new mission. Work does not continue on a closed authorization.",
  [AUTHORITY_ERROR.MISSION_NOT_ACTIVE]:
    "This mission has ended. A new one must be issued by a human.",
  [AUTHORITY_ERROR.MISSION_WRONG_AGENT]:
    "Missions are not transferable. The owning agent must make this call, or delegate explicitly.",
});

/* -------------------------------------------------------------------------- */
/*  Linting                                                                    */
/* -------------------------------------------------------------------------- */

/** Every action the classifier can actually produce from a tool name. */
const KNOWN_ACTIONS = new Set(TAXONOMY.map((t) => t.action));

/**
 * Finds capabilities that cannot ever match, and grants that are wider than
 * their author probably meant.
 *
 * A DEAD CAPABILITY IS THE DANGEROUS KIND OF MISTAKE.
 *
 * Writing `knowledge.search` when the runtime derives `fs.search` from
 * `search_knowledge` produces a capability that never matches anything. The
 * mission looks generous in the console and grants nothing in practice, so the
 * agent is blocked doing its own job — and the natural fix under deadline
 * pressure is to widen the mission until the work goes through, which is how a
 * scoped authorization quietly becomes `*`.
 *
 * This was not hypothetical. The first draft of the escape benchmark's own
 * missions had three of them, and the failing signal was three legitimate
 * control steps being refused rather than anything security-shaped.
 *
 * Warnings, never errors: an unrecognised tool legitimately becomes
 * `tool.<name>` or `mcp.<server>.<tool>`, so a custom action is a normal thing
 * to grant. What is reported is "no known tool produces this", which is the
 * useful half.
 */
export function lintMission(mission) {
  /* Always normalize — now safe, because normalizeCapability is idempotent. */
  const m = normalizeMission(mission ?? {});
  const findings = [];

  if (!m.capabilities.length) {
    findings.push({
      severity: "warn",
      code: "no_capabilities",
      message: `Mission "${m.name}" grants nothing. Every call under it will be refused at the capability stage.`,
    });
  }

  for (const cap of m.capabilities) {
    for (const action of cap.scope.actions) {
      if (action === "*" || action === "**" || /[*?]/.test(action)) continue;
      if (KNOWN_ACTIONS.has(action)) continue;
      if (/^(tool|mcp)\./.test(action)) continue;
      findings.push({
        severity: "warn",
        code: "unreachable_action",
        capability: cap.name,
        action,
        message:
          `No known tool classifies to "${action}", so capability "${cap.name}" can never match. ` +
          `Grant the action the runtime derives instead — check with \`classifyTool\`.`,
      });
    }

    /*
     * AN OUTBOUND CAPABILITY BOUNDED ONLY BY HOST IS BARELY BOUNDED.
     *
     * The escape benchmark found this one: a support mission granted
     * `http.request` on `*` and allowlisted `api.cirvix.com`, which reads as a
     * tight grant and is not. The host allowlist stops exfiltration to an
     * attacker's domain and does nothing about the admin endpoint on the
     * allowed domain — so an agent that finds a token in its own legitimate
     * work can spend it against the org's own API.
     *
     * The network constraint cannot fix this on its own: it is asked "may this
     * host be reached", which is the wrong granularity. The resource axis of
     * the capability is where a URL prefix belongs.
     */
    const outbound = cap.scope.actions.some((a) => /^(http\.request|net\.|network\.)/.test(a));
    if (outbound && cap.scope.resources.some((r) => r === "*" || r === "**")) {
      findings.push({
        severity: "warn",
        code: "unbounded_egress",
        capability: cap.name,
        message:
          `Capability "${cap.name}" allows outbound requests to any URL. A host allowlist still ` +
          `permits every endpoint on an allowed host, including administrative ones. Scope the ` +
          `resource axis to a URL prefix, e.g. "https://api.example.com/v1/tickets/**".`,
      });
    }

    const wideAction = cap.scope.actions.some((a) => a === "*" || a === "**");
    const wideResource = cap.scope.resources.some((r) => r === "*" || r === "**");
    if (wideAction && wideResource) {
      findings.push({
        severity: "warn",
        code: "unbounded_capability",
        capability: cap.name,
        message: `Capability "${cap.name}" is unbounded on both axes — it grants everything policy allows.`,
      });
    }

    if (cap.expiresAt != null && cap.expiresAt <= m.issuedAt) {
      findings.push({
        severity: "warn",
        code: "born_expired",
        capability: cap.name,
        message: `Capability "${cap.name}" expires at or before the mission was issued; it is dead on arrival.`,
      });
    }
  }

  for (const key of Object.keys(m.constraints ?? {})) {
    if (!CONSTRAINTS[key]) {
      findings.push({
        severity: "warn",
        code: "unknown_constraint",
        constraint: key,
        message:
          `"${key}" is not a constraint this runtime evaluates, so it restricts nothing. ` +
          `Known: ${Object.keys(CONSTRAINTS).join(", ")}.`,
      });
    }
  }

  return { ok: findings.length === 0, findings };
}

/* -------------------------------------------------------------------------- */
/*  Registry                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Holds missions and the escape attempts made against them.
 *
 * In-memory by design at this layer — the control plane persists; the runtime
 * carries only what the current process needs to decide. Keeping the store
 * behind a small interface is what lets both share this file.
 */
/* One non-queued authorization per shared mission object, across both Node
 * orchestration paths. Weak keys do not retain completed missions. There is no
 * timeout that could unlock an authorization still running inside a broker.
 * This is process-local, not a distributed or restart-persistent transaction.
 */
const missionLocks = new WeakSet();
const MAX_MISSION_CALLS = 4096;

export function acquireMission(mission) {
  if (!mission) return { acquired: true, release() {} };
  if (missionLocks.has(mission)) return { acquired: false, release() {} };
  missionLocks.add(mission);
  return { acquired: true, release() { missionLocks.delete(mission); } };
}

/** Capture once from host-owned context; never coerce request data into money.
 * Missing cost stays zero for compatibility. Embedders must provide a trusted
 * estimate for spend enforcement; this code cannot discover vendor pricing.
 */
export function captureMissionCost(ctx) {
  const cost = ctx.costUsd;
  return cost === undefined ? 0 : cost;
}

export function missionAllowanceRefusal(mission, costUsd, lease) {
  if (!mission) return null;
  if (!lease.acquired) return { rule: "authority-mission-busy", reason: "Another authorization is using this mission; retry after it finishes." };
  const spend = mission.usage?.spendUsd ?? 0;
  if (typeof costUsd !== "number" || !Number.isFinite(costUsd) || costUsd < 0 ||
      typeof spend !== "number" || !Number.isFinite(spend) || spend < 0 || !Number.isFinite(spend + costUsd)) {
    return { rule: "authority-spend-invalid", reason: "Trusted mission cost must be a finite non-negative number." };
  }
  if ([mission.constraints, ...(mission.capabilities ?? []).map((c) => c.conditions)].some((c) => c?.rate) &&
      retainedCalls(mission, Date.now()).length >= MAX_MISSION_CALLS) {
    return { rule: "authority-rate-capacity", reason: "Mission rate history is full; retry after its window expires." };
  }
  return null;
}

function retainedCalls(mission, now) {
  const rules = [mission.constraints, ...(mission.capabilities ?? []).map((c) => c.conditions)];
  const windows = rules.map((c) => c?.rate).filter(Boolean).map((r) => Number(r.windowMs ?? 60_000));
  // Retain the longest capability window, not just the window used by this call.
  const windowMs = windows.length ? Math.max(...windows) : 60_000;
  return (mission.usage?.calls ?? []).filter((t) => now - t < windowMs);
}

/** Authorization consumption, NOT a measurement of external tool execution.
 * Commit only immediately before returning a successful authorization. Audit,
 * broker, approval and callback failures release the lease without consuming.
 * An external execution failure does not refund an authorization already issued.
 * At most 4096 timestamps are retained; configured rate limits fail closed at
 * that ceiling until history expires, rather than forgetting live usage.
 */
export function recordMissionUsage(mission, { costUsd = 0, now = Date.now() } = {}) {
  const amount = costUsd;
  const spend = mission.usage?.spendUsd ?? 0;
  if (typeof amount !== "number" || !Number.isFinite(amount) || amount < 0 ||
      !Number.isFinite(spend) || spend < 0 || !Number.isFinite(spend + amount)) throw new Error("Invalid mission spend.");
  const calls = retainedCalls(mission, now);
  const hasRate = [mission.constraints, ...(mission.capabilities ?? []).map((c) => c.conditions)].some((c) => c?.rate);
  if (hasRate && calls.length >= MAX_MISSION_CALLS) throw new Error("Mission rate history is full.");
  calls.push(now);
  mission.usage = { spendUsd: spend + amount, calls: calls.slice(-MAX_MISSION_CALLS) };
  return mission.usage;
}

export class MissionRegistry {
  #missions = new Map();
  #byAgent = new Map();
  #escapes = [];

  /** @param {object} mission raw or normalized */
  issue(mission, { now = Date.now() } = {}) {
    const m = normalizeMission(mission, { now });
    this.#missions.set(m.id, m);
    if (m.agent) this.#byAgent.set(m.agent, m.id);
    return m;
  }

  get(id) {
    return this.#missions.get(id) ?? null;
  }

  /** The mission an agent is currently acting under, if any. */
  forAgent(agent) {
    const id = this.#byAgent.get(agent);
    return id ? this.#missions.get(id) ?? null : null;
  }

  list() {
    return [...this.#missions.values()];
  }

  revoke(id, { reason = null } = {}) {
    const m = this.#missions.get(id);
    if (!m) return null;
    m.status = MISSION_STATUS.REVOKED;
    m.revokedReason = reason;
    return m;
  }

  complete(id) {
    const m = this.#missions.get(id);
    if (!m) return null;
    m.status = MISSION_STATUS.COMPLETED;
    return m;
  }

  /** Revokes ONE capability without ending the mission. */
  revokeCapability(missionId, capabilityId) {
    const m = this.#missions.get(missionId);
    const c = m?.capabilities.find((x) => x.id === capabilityId);
    if (!c) return null;
    c.status = CAPABILITY_STATUS.REVOKED;
    return c;
  }

  /**
   * Legacy accounting entry point for trusted embedders. Not an authorization
   * gate: callers must assess and coordinate their own external work. It cannot
   * update an allowance currently leased by Pipeline or Guard.
   */
  record(missionId, { costUsd = 0, now = Date.now() } = {}) {
    const m = this.#missions.get(missionId);
    if (!m) return null;
    if (missionLocks.has(m)) throw new Error("Mission authorization is in progress.");
    return recordMissionUsage(m, { costUsd, now });
  }

  /** Every refusal is an attempt worth keeping. */
  recordEscape(entry) {
    const e = { at: Date.now(), ...entry };
    this.#escapes.push(e);
    if (this.#escapes.length > 10_000) this.#escapes = this.#escapes.slice(-5_000);
    return e;
  }

  escapes({ missionId = null, agent = null, limit = 100 } = {}) {
    return this.#escapes
      .filter((e) => (!missionId || e.missionId === missionId) && (!agent || e.agent === agent))
      .slice(-limit)
      .reverse();
  }

  /** Counts by escape kind, for the passport and the benchmark. */
  escapeSummary({ agent = null } = {}) {
    const out = { total: 0, blocked: 0, byKind: {} };
    for (const e of this.#escapes) {
      if (agent && e.agent !== agent) continue;
      out.total++;
      if (e.blocked) out.blocked++;
      out.byKind[e.kind] = (out.byKind[e.kind] ?? 0) + 1;
    }
    return out;
  }
}
