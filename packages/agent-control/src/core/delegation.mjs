/**
 * Agent-to-agent delegation.
 *
 *   Agent A ──▶ Agent B ──▶ tool
 *
 * One invariant, and everything in this file exists to enforce it:
 *
 *   AN AGENT CANNOT GAIN AUTHORITY MERELY BECAUSE ANOTHER AGENT HAS IT.
 *
 * The failure this prevents is the confused deputy, and in a multi-agent system
 * it is the default outcome rather than an edge case. A planner agent holds
 * database authority; a summariser agent does not. The planner asks the
 * summariser to "just run this one query". If the summariser's call is
 * evaluated against the *planner's* authority, the summariser now has database
 * access — permanently, invisibly, and by design rather than by bug.
 *
 * THE RULE: SCOPE ONLY NARROWS
 *
 * A delegation is a *subset* of what the issuer holds. Never a superset, never
 * a sideways set. The effective authority of a chain is the intersection of
 * every link in it, so going one hop deeper can only ever reduce what is
 * reachable. That makes the depth of a chain irrelevant to its danger, which is
 * the property that lets you allow delegation at all.
 *
 * DELEGATION IS A CONSTRAINT, NOT A GRANT
 *
 * The effective scope is ANDed with the policy, never ORed. A delegation can
 * only take authority away from what policy already permits. There is
 * deliberately no path by which presenting a token makes a denied call
 * permitted — if there were, the token would be a capability, and a capability
 * that leaks is authority that leaks.
 *
 * IDENTITY IS NOT A NAME
 *
 * A grant is bound to (issuer, subject) and signed. An agent claiming to be
 * `planner` proves nothing; a grant that verifies under the runtime's key and
 * names it as subject proves exactly one thing, which is what it says. Names
 * are attacker-controlled strings and are treated as such throughout.
 *
 * WHAT THIS DOES NOT DO
 *
 * The signing key is local to one runtime. Two Cirvix instances on two machines
 * cannot verify each other's grants without a shared key, and issuing one is
 * the control plane's job rather than this file's. Stated here rather than
 * implied, because "A2A works" would otherwise read as "across a fleet".
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import { matchGlob } from "./policy.mjs";
import { canonicalAction } from "./normalize.mjs";
import { DECISION, isForwarded } from "./decisions.mjs";

/**
 * How deep a delegation chain may go.
 *
 * Not a security boundary — scope narrowing already makes depth harmless — but
 * an unbounded chain is an unbounded verification loop over attacker-supplied
 * data, and a cycle check that walks forever is a denial of service.
 */
export const MAX_DEPTH = 8;

/** Default lifetime of a grant. Delegation is for a task, not for a quarter. */
const DEFAULT_TTL_MS = 15 * 60 * 1000;

export const DELEGATION_ERROR = {
  UNSIGNED: "unsigned",
  BAD_SIGNATURE: "bad_signature",
  EXPIRED: "expired",
  REVOKED: "revoked",
  TOO_DEEP: "too_deep",
  CYCLE: "cycle",
  SUBJECT_MISMATCH: "subject_mismatch",
  BROKEN_CHAIN: "broken_chain",
  WIDENED: "widened",
  UNKNOWN_TENANT: "unknown_tenant",
};

/* -------------------------------------------------------------------------- */
/*  Scope                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * A scope is `{ actions, resources }`, each a list of globs.
 *
 * `["*"]` means unrestricted *within whatever policy already allows* — it is
 * not a grant of anything, because scope is only ever a constraint.
 */
export function normalizeScope(scope) {
  /*
   * ABSENT AND EMPTY ARE DIFFERENT, AND CONFLATING THEM IS AN ESCALATION.
   *
   * `undefined` means "not constrained on this axis" and becomes `["*"]`.
   * `[]` means "constrained to nothing" and MUST stay empty.
   *
   * They were the same, and the consequence was severe: `intersectScopes`
   * returns `[]` when two scopes do not overlap, and normalizing that back to
   * `["*"]` turned the intersection of two disjoint authorities into universal
   * authority. Two agents with nothing in common, delegating through each
   * other, ended up able to do anything.
   */
  const list = (v) => {
    if (v === undefined || v === null) return ["*"];
    const arr = Array.isArray(v) ? v : [v];
    return arr.map(String);
  };
  return {
    actions: list(scope?.actions).map(canonicalAction),
    resources: list(scope?.resources),
  };
}

/**
 * True when `pattern` permits everything `candidate` does.
 *
 * Glob-vs-glob containment is the hard case, and getting it wrong in either
 * direction is a defect: too strict and a legitimate narrowing (`/src/**` to
 * `/src/lib/**`) is refused; too loose and a widening slips through.
 *
 * The rule used here is a SOUND APPROXIMATION by literal prefix — it may refuse
 * a narrowing it cannot prove, and it never accepts a widening:
 *
 *   · a bare `*` or `**` in a scope means "unrestricted on this axis", so it
 *     covers anything, and only another bare wildcard covers it
 *   · a concrete candidate is covered when the pattern matches it
 *   · two globs: the candidate's literal prefix must extend the pattern's, and
 *     a candidate that crosses separators needs a pattern that also does
 */
function patternCovers(pattern, candidate) {
  if (pattern === candidate) return true;

  const universal = (p) => p === "*" || p === "**";
  if (universal(pattern)) return true;
  if (universal(candidate)) return false;

  if (!/[*?]/.test(candidate)) return matchGlob(pattern, candidate);

  const literalPrefix = (p) => p.split(/[*?]/)[0];
  const patternPrefix = literalPrefix(pattern);
  const candidatePrefix = literalPrefix(candidate);

  if (!candidatePrefix.startsWith(patternPrefix)) return false;
  // A single `*` does not cross `/`; a `**` does. Narrowing to something that
  // crosses when the parent did not is widening.
  if (!pattern.includes("**") && candidate.includes("**")) return false;
  return true;
}

/**
 * True when `child` grants nothing `parent` does not already grant.
 *
 * This is the check that makes narrowing mean narrowing. A delegation that
 * fails it is rejected outright rather than silently clamped — clamping hides
 * the attempt, and an agent trying to widen its authority is exactly the event
 * an operator wants to see in the log.
 */
export function isNarrowing(parent, child) {
  const p = normalizeScope(parent);
  const c = normalizeScope(child);

  const covered = (parentList, childList) =>
    childList.every((item) => parentList.some((pattern) => patternCovers(pattern, item)));

  return covered(p.actions, c.actions) && covered(p.resources, c.resources);
}

/**
 * The intersection of two scopes — what both permit.
 *
 * Used to collapse a chain into one effective scope. Intersection rather than
 * "the last link wins", because the last link is the least trusted party in the
 * chain and letting it decide would invert the whole model.
 */
export function intersectScopes(a, b) {
  const x = normalizeScope(a);
  const y = normalizeScope(b);

  const narrow = (left, right) => {
    const out = [];
    for (const item of right) {
      // Keep the more specific of any pair that overlaps.
      if (left.some((pattern) => patternCovers(pattern, item))) out.push(item);
    }
    for (const item of left) {
      if (!out.includes(item) && right.some((pattern) => patternCovers(pattern, item))) out.push(item);
    }
    return out.length ? [...new Set(out)] : [];
  };

  return { actions: narrow(x.actions, y.actions), resources: narrow(x.resources, y.resources) };
}

/** True when a scope permits this action on this resource. */
export function scopePermits(scope, { action, resource }) {
  const s = normalizeScope(scope);
  if (s.actions.length === 0 || s.resources.length === 0) return false;
  const actionOk = s.actions.some((p) => matchGlob(p, action ?? ""));
  const resourceOk = s.resources.some((p) => matchGlob(p, resource ?? ""));
  return actionOk && resourceOk;
}

/* -------------------------------------------------------------------------- */
/*  Grants                                                                     */
/* -------------------------------------------------------------------------- */

/** Deterministic serialization, so a signature covers meaning rather than spacing. */
function canonicalGrant(grant) {
  const scope = normalizeScope(grant.scope);
  return JSON.stringify({
    id: grant.id,
    issuer: grant.issuer,
    subject: grant.subject,
    tenant: grant.tenant ?? null,
    parent: grant.parent ?? null,
    depth: grant.depth,
    scope: { actions: [...scope.actions].sort(), resources: [...scope.resources].sort() },
    issuedAt: grant.issuedAt,
    expiresAt: grant.expiresAt,
  });
}

function sign(grant, key) {
  return createHmac("sha256", key).update(canonicalGrant(grant)).digest("hex");
}

function signatureMatches(grant, key) {
  const expected = Buffer.from(sign(grant, key));
  const actual = Buffer.from(String(grant.signature ?? ""));
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}

/* -------------------------------------------------------------------------- */
/*  The broker                                                                 */
/* -------------------------------------------------------------------------- */

export class DelegationBroker {
  /** id → grant, for chain walking and revocation. */
  #grants = new Map();
  #revoked = new Set();
  /**
   * subject → tenant, learned from root grants.
   *
   * An agent's tenancy is a property of who it IS, which only an operator
   * establishes by creating its root. A grant states which tenant's authority
   * it carries; this map states which tenant the presenting agent belongs to.
   * The two must agree — see `#tenantMismatch`.
   */
  #tenancy = new Map();
  #key;
  #next = 1;

  /**
   * @param {object} [opts]
   * @param {Buffer|string} [opts.key]   signing key; generated if absent
   * @param {number} [opts.ttlMs]
   * @param {(e:object)=>void} [opts.onEvent]
   */
  constructor({ key, ttlMs = DEFAULT_TTL_MS, onEvent = () => {} } = {}) {
    // Generated per runtime when not supplied. A predictable key would let
    // anyone who can read this source forge a grant.
    this.#key = key ? Buffer.from(key) : randomBytes(32);
    this.ttlMs = ttlMs;
    this.onEvent = onEvent;
  }

  /**
   * Registers a root authority — what an agent holds on its own.
   *
   * Roots are how an agent has any scope at all. They are not delegations and
   * have no issuer; an operator creates them, and nothing an agent does can
   * mint one.
   */
  root(agent, scope, { tenant = null } = {}) {
    /*
     * An agent belongs to exactly one tenant.
     *
     * Re-rooting a known agent into a second tenant is not a configuration
     * nuance, it is the cross-tenant escalation written as setup: register
     * `globex-worker` in acme as well, and every acme grant it is handed now
     * resolves. There is no legitimate call that needs this, so it is refused
     * loudly at the point an operator makes the mistake rather than silently at
     * the point an attacker exploits it.
     */
    const known = this.#tenancy.get(String(agent));
    if (known !== undefined && known !== tenant) {
      throw new Error(
        `${agent} is already rooted in tenant ${known === null ? "(none)" : known} and cannot also be rooted in ` +
          `${tenant === null ? "(none)" : tenant}. An agent belongs to one tenant.`,
      );
    }
    this.#tenancy.set(String(agent), tenant);

    const grant = {
      id: `dlg_root_${this.#next++}`,
      issuer: null,
      subject: String(agent),
      tenant,
      parent: null,
      depth: 0,
      scope: normalizeScope(scope),
      issuedAt: Date.now(),
      expiresAt: null,
    };
    grant.signature = sign(grant, this.#key);
    this.#grants.set(grant.id, grant);
    return grant;
  }

  /**
   * Issues a delegation from `parentGrant`'s subject to `subject`.
   *
   * Refuses — rather than clamps — a scope the parent does not already hold.
   * See `isNarrowing`.
   *
   * @returns {{ok:true, grant:object}|{ok:false, error:string, reason:string}}
   */
  delegate(parentGrant, subject, scope, { ttlMs = this.ttlMs } = {}) {
    const parent = typeof parentGrant === "string" ? this.#grants.get(parentGrant) : parentGrant;

    if (!parent || !this.#grants.has(parent.id)) {
      return { ok: false, error: DELEGATION_ERROR.BROKEN_CHAIN, reason: "The parent grant is not known to this broker." };
    }
    if (this.#revoked.has(parent.id)) {
      return { ok: false, error: DELEGATION_ERROR.REVOKED, reason: `Grant ${parent.id} has been revoked.` };
    }
    if (parent.expiresAt && Date.now() > parent.expiresAt) {
      return { ok: false, error: DELEGATION_ERROR.EXPIRED, reason: `Grant ${parent.id} has expired.` };
    }
    if (parent.depth + 1 > MAX_DEPTH) {
      return { ok: false, error: DELEGATION_ERROR.TOO_DEEP, reason: `A delegation chain may be at most ${MAX_DEPTH} deep.` };
    }

    // A cycle would let authority laundered around a ring look like a fresh
    // chain, and it makes verification non-terminating.
    for (const link of this.#walk(parent)) {
      if (link.subject === String(subject)) {
        return {
          ok: false,
          error: DELEGATION_ERROR.CYCLE,
          reason: `${subject} already appears in this chain; delegating back to it would be circular.`,
        };
      }
    }

    /*
     * Checked here as well as at presentation, because an error an operator can
     * see at issue time is worth far more than the same error surfacing as a
     * mysterious denial in production. It is not sufficient on its own —
     * tenancy can be registered after a grant is minted — so `resolve` checks
     * it again where it can actually be enforced.
     */
    const crossTenant = this.#tenantMismatch(subject, parent.tenant ?? null);
    if (crossTenant) {
      this.onEvent({
        kind: "delegation_cross_tenant_refused",
        issuer: parent.subject,
        subject: String(subject),
        tenant: parent.tenant ?? null,
      });
      return { ok: false, error: DELEGATION_ERROR.UNKNOWN_TENANT, reason: crossTenant };
    }

    if (!isNarrowing(parent.scope, scope)) {
      this.onEvent({ kind: "delegation_widening_refused", issuer: parent.subject, subject: String(subject) });
      return {
        ok: false,
        error: DELEGATION_ERROR.WIDENED,
        reason: `A delegation cannot grant more than the issuer holds. ${parent.subject} cannot give ${subject} authority it does not have itself.`,
      };
    }

    const grant = {
      id: `dlg_${this.#next++}`,
      issuer: parent.subject,
      subject: String(subject),
      // Tenancy is inherited, never chosen. An agent cannot delegate itself
      // into another tenant.
      tenant: parent.tenant ?? null,
      parent: parent.id,
      depth: parent.depth + 1,
      scope: normalizeScope(scope),
      issuedAt: Date.now(),
      expiresAt: Date.now() + ttlMs,
    };
    grant.signature = sign(grant, this.#key);
    this.#grants.set(grant.id, grant);

    this.onEvent({ kind: "delegation_issued", id: grant.id, issuer: grant.issuer, subject: grant.subject });
    return { ok: true, grant };
  }

  /**
   * Why `subject` may not act under a grant carrying `tenant`, or null if it may.
   *
   * THE BOUNDARY A CUSTOMER WILL NEVER ACCEPT BEING SOFT.
   *
   * Tenancy was previously inherited and *recorded* — a cross-tenant delegation
   * resolved successfully and showed up honestly in the audit log. But a record
   * of a breach is not a control against one. `acme-planner` could hand
   * `globex-worker` a signed, correctly-narrowing grant, and globex's agent
   * would act inside acme's authority with nothing refusing it. The
   * `UNKNOWN_TENANT` error existed for exactly this and was never raised
   * anywhere in the codebase.
   *
   * THE RULE: a tenanted grant presented by an agent with a KNOWN, DIFFERENT
   * tenancy is refused.
   *
   * WHY "UNKNOWN" IS NOT ALSO REFUSED, WHICH IS THE INTERESTING HALF.
   *
   * The stricter rule — refuse anyone whose tenancy is not registered — looks
   * safer and is wrong. Delegating to an agent that has no root of its own is
   * the ORDINARY case: a planner spawns a helper for one task, and that helper
   * never gets an operator-created root. Refusing there would break normal
   * single-tenant use to defend a boundary nobody crossed.
   *
   * And it defends nothing. To present a grant you must be its signed subject,
   * so an attacker inventing an agent name cannot use a grant unless somebody
   * inside the tenant already minted one FOR that name — which is the tenant
   * deliberately vouching for it. Naming yourself `helper` gains nothing; the
   * grant either exists and names you, or it does not.
   *
   * What is genuinely dangerous is the opposite shape: an agent that DOES have
   * a tenancy, and it is a different one. `globex-worker` acting under acme's
   * authority is one customer's agent inside another customer's data, no matter
   * how correctly the chain narrows.
   *
   * A grant with no tenant at all is unaffected, because most installs never
   * set one and a tenant check must not become a tax on single-tenant use.
   */
  #tenantMismatch(subject, tenant) {
    if (tenant === null || tenant === undefined) return null;

    const known = this.#tenancy.get(String(subject));
    if (known === undefined) return null;
    if (known !== tenant) {
      return (
        `This delegation carries tenant ${tenant}, and ${subject} belongs to ` +
        `${known === null ? "no tenant" : known}. Authority does not cross a tenant boundary.`
      );
    }
    return null;
  }

  /** Every link from a grant up to its root, nearest first. */
  #walk(grant) {
    const chain = [];
    let current = grant;
    let hops = 0;
    while (current && hops++ <= MAX_DEPTH + 1) {
      chain.push(current);
      if (!current.parent) break;
      current = this.#grants.get(current.parent);
    }
    return chain;
  }

  /**
   * Resolves a presented grant into an effective scope, or refuses it.
   *
   * `presentedBy` is who is *making the call*. A grant naming somebody else as
   * subject proves nothing about the caller, and accepting it is precisely the
   * impersonation this exists to stop.
   *
   * @returns {{ok:true, scope:object, chain:string[], depth:number, tenant:string|null}
   *          |{ok:false, error:string, reason:string}}
   */
  resolve(presented, presentedBy, { now = Date.now() } = {}) {
    const grant = typeof presented === "string" ? this.#grants.get(presented) : presented;

    if (!grant) {
      return { ok: false, error: DELEGATION_ERROR.BROKEN_CHAIN, reason: "No such delegation." };
    }
    if (!grant.signature) {
      return { ok: false, error: DELEGATION_ERROR.UNSIGNED, reason: "The delegation carries no signature." };
    }
    if (!signatureMatches(grant, this.#key)) {
      // Covers both forgery and tampering: the signature is over the scope, the
      // subject, the depth, and the parent, so editing any of them invalidates
      // it.
      return { ok: false, error: DELEGATION_ERROR.BAD_SIGNATURE, reason: "The delegation's signature does not verify." };
    }
    if (String(presentedBy) !== grant.subject) {
      return {
        ok: false,
        error: DELEGATION_ERROR.SUBJECT_MISMATCH,
        reason: `This delegation was issued to ${grant.subject}, and was presented by ${presentedBy}.`,
      };
    }

    // The tenant boundary. See `#tenantMismatch`.
    const crossTenant = this.#tenantMismatch(presentedBy, grant.tenant ?? null);
    if (crossTenant) {
      return { ok: false, error: DELEGATION_ERROR.UNKNOWN_TENANT, reason: crossTenant };
    }

    // Walk to the root, verifying every link. A chain is only as valid as its
    // weakest hop, and checking the presented grant alone would let a revoked
    // parent keep authorizing through a still-valid child.
    const chain = this.#walk(grant);
    const rooted = chain[chain.length - 1];
    if (rooted.parent) {
      return { ok: false, error: DELEGATION_ERROR.BROKEN_CHAIN, reason: "The chain does not terminate in a root grant." };
    }

    let effective = null;
    for (const link of chain) {
      if (!this.#grants.has(link.id)) {
        return { ok: false, error: DELEGATION_ERROR.BROKEN_CHAIN, reason: `Link ${link.id} is missing.` };
      }
      if (!signatureMatches(link, this.#key)) {
        return { ok: false, error: DELEGATION_ERROR.BAD_SIGNATURE, reason: `Link ${link.id} does not verify.` };
      }
      if (this.#revoked.has(link.id)) {
        return { ok: false, error: DELEGATION_ERROR.REVOKED, reason: `Link ${link.id} has been revoked.` };
      }
      if (link.expiresAt && now > link.expiresAt) {
        return { ok: false, error: DELEGATION_ERROR.EXPIRED, reason: `Link ${link.id} expired.` };
      }
      effective = effective === null ? normalizeScope(link.scope) : intersectScopes(effective, link.scope);
    }

    return {
      ok: true,
      scope: effective,
      chain: chain.map((l) => l.id).reverse(),
      principals: chain.map((l) => l.subject).reverse(),
      depth: grant.depth,
      tenant: grant.tenant ?? null,
    };
  }

  /**
   * Revokes a grant and everything derived from it.
   *
   * Cascading, because revoking a link and leaving its children usable revokes
   * nothing — the authority simply flows around the hole.
   */
  revoke(id) {
    const revoked = [];
    const queue = [String(id)];
    while (queue.length) {
      const current = queue.shift();
      if (this.#revoked.has(current)) continue;
      this.#revoked.add(current);
      revoked.push(current);
      for (const grant of this.#grants.values()) {
        if (grant.parent === current) queue.push(grant.id);
      }
    }
    this.onEvent({ kind: "delegation_revoked", ids: revoked });
    return revoked;
  }

  isRevoked(id) {
    return this.#revoked.has(String(id));
  }

  get(id) {
    return this.#grants.get(String(id)) ?? null;
  }

  /** Which tenant an agent belongs to, or undefined if it has no root. */
  tenantOf(agent) {
    return this.#tenancy.get(String(agent));
  }

  /** Grants held, with no signatures — safe to print. */
  inventory() {
    return [...this.#grants.values()].map((g) => ({
      id: g.id,
      issuer: g.issuer,
      subject: g.subject,
      tenant: g.tenant,
      depth: g.depth,
      scope: g.scope,
      revoked: this.#revoked.has(g.id),
      expiresAt: g.expiresAt ? new Date(g.expiresAt).toISOString() : null,
    }));
  }
}

/* -------------------------------------------------------------------------- */
/*  The one place delegation is applied to a decision                          */
/* -------------------------------------------------------------------------- */

/**
 * Narrows an already-made decision by a presented delegation, in place.
 *
 * WHY THIS IS A FUNCTION AND NOT A BLOCK INSIDE THE PIPELINE
 *
 * It was a block inside the pipeline, and the consequence was the failure this
 * codebase has now hit twice: a control that is real on one code path and
 * absent on another.
 *
 * `Pipeline` serves the local socket. `Guard` serves MCP and the SDK. They are
 * deliberately separate objects, and delegation existed only in the first —
 * which meant a delegation could be presented over the socket and was silently
 * ignored everywhere else. Because delegation only ever NARROWS, ignoring it is
 * not a missing feature that fails safe. It is a widening: a worker delegated
 * `fs.read` got everything policy allowed the moment its call arrived over MCP
 * instead. Silence was the dangerous direction.
 *
 * So there is one implementation, both engines call it, and a test asserts the
 * two produce the same rule for the same call.
 *
 * @param {object} decision            mutated in place
 * @param {object} opts
 * @param {DelegationBroker} opts.broker
 * @param {object|string} opts.presented   the grant the caller presented
 * @param {string} opts.agent              who is making the call
 * @param {string} opts.action             canonical action
 * @param {string} opts.resource
 * @returns {{chain:string[], principals:string[], depth:number, tenant:string|null}|null}
 *          the delegation context for the audit record, or null if refused
 */
export function applyDelegation(decision, { broker, presented, agent, action, resource }) {
  if (!presented || !broker) return null;

  const resolved = broker.resolve(presented, agent);

  if (!resolved.ok) {
    decision.decision = DECISION.DENY;
    decision.verdict = "deny";
    decision.rule = `delegation-${resolved.error}`;
    decision.reason = resolved.reason;
    decision.remediation =
      "Ask the issuing agent for a delegation scoped to this call, presented by the agent making it.";
    return null;
  }

  const context = {
    chain: resolved.chain,
    principals: resolved.principals,
    depth: resolved.depth,
    tenant: resolved.tenant,
  };

  /*
   * Only a decision that would otherwise go out is narrowed.
   *
   * A call already denied stays denied under its own rule — re-refusing it as
   * "out of scope" would misattribute the refusal in the one record an operator
   * later reads. And a delegation can never turn a denial into a permit, which
   * is the property that makes it safe to accept a token at all.
   */
  if (isForwarded(decision.decision) && !scopePermits(resolved.scope, { action, resource })) {
    decision.decision = DECISION.DENY;
    decision.verdict = "deny";
    decision.rule = "delegation-out-of-scope";
    decision.reason =
      `Policy permits this call, but the delegation ${agent} is acting under does not cover it. ` +
      `Authority narrows at every hop: ${resolved.principals.join(" → ")}.`;
    decision.remediation = "The call is outside what was delegated. It is not a policy change you need.";
  }

  return context;
}
