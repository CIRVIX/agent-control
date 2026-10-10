/**
 * Ed25519 delegation — signed grants, durable records, cross-instance proofs.
 *
 * WHY A SECOND MODULE. delegation.mjs owns the SEMANTICS of delegation:
 * narrowing (isNarrowing), intersection (intersectScopes), scope evaluation,
 * depth limits, tenant boundaries. Its weakness is the TRUST ANCHOR: grants
 * are HMAC-signed with a key that lives inside one runtime process, so the
 * file itself says, in its own header, that two Cirvix instances cannot verify
 * each other's grants, and that every grant evaporates when the process dies.
 *
 * This module keeps the semantics and replaces the trust anchor:
 *
 *   - every grant is signed with an Ed25519 DELEGATION role key
 *     (core/keys.mjs, KEY_ROLE.DELEGATION) via proof.mjs envelopes — the same
 *     scheme, verifier and key-id discipline as identity credentials;
 *
 *   - grants are DURABLE: a `DelegationStore` keeps the signed tokens and a
 *     revocation journal on disk, so a grant survives the process that issued
 *     it and a revoked grant stays revoked across restarts (anti-rollback is
 *     the revocation journal's monotonic sequence);
 *
 *   - grants are CROSS-INSTANCE: a verifier holds only the ISSUER'S PUBLIC
 *     key. Instance B verifies a token minted by instance A with no shared
 *     secret anywhere;
 *
 *   - a MINIMUM SIGNED ENVELOPE (the wire form) carries the whole chain for
 *     presentation to a verifier that has never seen these grants, with a
 *     one-time nonce so a captured envelope cannot be replayed.
 *
 * WHAT DOES NOT CHANGE: the narrowing invariants. `resolveGrant` delegates the
 * semantic checks to the SAME functions the local broker uses — isNarrowing,
 * intersectScopes, scopePermits — so there are not two definitions of
 * "narrowing" in the product. The result object is shaped exactly like
 * `DelegationBroker.resolve`, which is what `applyDelegation` already
 * consumes: whatever enforcement flows through the one decision path keeps
 * flowing through it.
 *
 * THE HUMAN ANCHOR. A chain's root is an operator grant signed by the
 * host AUTHORITY key — the same key that signs identity credentials. The
 * `human` field on a root records WHO approved it; reconstruction of "who
 * authorized this" therefore terminates at a person, not at another agent.
 */

import { mkdir, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";

import { canonicalJson } from "./audit.mjs";
import { buildProofEnvelope, verifyProofEnvelope } from "./proof.mjs";
import { ensureRoleKey, loadRoleKey, KEY_ROLE } from "./keys.mjs";
import {
  MAX_DEPTH,
  DELEGATION_ERROR,
  isNarrowing,
  intersectScopes,
  normalizeScope,
  scopePermits,
} from "./delegation.mjs";
import { CONSTRAINT_KINDS, maxConsequenceKind } from "./authority.mjs";
import { consequenceAtLeast } from "./risk.mjs";
import { principalStatusAt } from "./principal.mjs";

export const DELEGATION_TOKEN_VERSION = 1;
export const DELEGATION_KIND = "cirvix-delegation";

/**
 * Validates a constraints object at ISSUE time and returns the form that gets
 * SIGNED: every key must be one this build can evaluate, and every
 * consequence ceiling must name a consequence this build derives. A grant
 * minted with an unknown constraint — or with a misspelled `maxConsequence`
 * value, which is the same failure one level down — would be a restriction
 * that does not exist, so it is refused where it is signed rather than
 * discovered by a verifier later.
 *
 * CANONICALIZING HERE IS WHAT MAKES NARROWING COMPARABLE. `data_write`, the
 * object form `{max: "data_write"}` and `DATA_WRITE` are one kind; comparing
 * the raw spellings would read two spellings of the same ceiling as a
 * widening (or, worse, a different spelling of a wider ceiling as equal).
 */
function assertConstraintShape(constraints) {
  if (typeof constraints !== "object" || constraints === null || Array.isArray(constraints)) {
    const err = new Error("Grant constraints must be an object keyed by constraint kind.");
    err.code = DELEGATION_ERROR.WIDENED;
    throw err;
  }
  const canonical = {};
  for (const [key, value] of Object.entries(constraints)) {
    if (!CONSTRAINT_KINDS.includes(key)) {
      const err = new Error(`Unknown constraint "${key}". Known: ${CONSTRAINT_KINDS.join(", ")}.`);
      err.code = "unknown_constraint";
      throw err;
    }
    if (key === "maxConsequence") {
      const kind = maxConsequenceKind(value);
      if (!kind) {
        const err = new Error(
          `maxConsequence "${typeof value === "string" ? value : value?.max}" is not a consequence this build derives; a boundary that cannot be evaluated is not a boundary.`,
        );
        err.code = "unknown_constraint";
        throw err;
      }
      canonical[key] = kind;
      continue;
    }
    canonical[key] = value;
  }
  return canonical;
}

/** Reads the payload half of a token without verifying it (callers verify first). */
function decodeGrantPayload(token) {
  try {
    return JSON.parse(Buffer.from(String(token).split(".")[0], "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

/**
 * Collapses the universal spellings ("*", "**") to one canonical form after
 * an intersection. `intersectScopes` can return ["**", "*"] when both sides
 * were universal — semantically identical, but noisy in records and tests.
 * Collapsing is safe: both spellings match everything in matchGlob and in
 * patternCovers, so the collapsed scope permits exactly the same calls.
 */
function canonicalScope(scope) {
  const collapse = (list) => {
    const universal = list.some((p) => p === "*" || p === "**");
    if (universal) return ["**"];
    return [...new Set(list)];
  };
  const s = normalizeScope(scope);
  return { actions: collapse(s.actions), resources: collapse(s.resources) };
}

/* ------------------------------------------------------------------ */
/*  Grant construction and verification                                */
/* ------------------------------------------------------------------ */

/** The canonical payload inside a signed delegation token. */
export function buildGrantPayload({
  id,
  issuer,
  subject,
  tenant = null,
  parent = null,
  depth,
  scope,
  issuedAt,
  expiresAt,
  human = null,
  purpose = null,
  nonce = null,
  policyVersion = null,
  constraints = null,
  /* WHO on the human side, as an ID that resolves to an authenticated
     principal record — never as a name that establishes identity. */
  issuerPrincipalId = null,
  issuerRole = null,
  /* WHERE it is valid. Four distinct bindings, none of them interchangeable:
     issuer (who signed), subject (who may present), audience (which runtime or
     agent it was issued FOR) and tenant (which organization's authority it
     carries). A matching tenant alone must never be sufficient. */
  audience = null,
  /* Consumption semantics, stated at issue time rather than assumed. */
  singleUse = false,
  maxUses = null,
}) {
  return {
    v: DELEGATION_TOKEN_VERSION,
    kind: DELEGATION_KIND,
    id,
    issuer,
    subject,
    tenant,
    parent,
    depth,
    scope: canonicalScope(scope),
    issuedAt,
    expiresAt,
    /* A per-grant nonce. It is not replay protection by itself — the chain's
       subject binding and the one-time envelope are — but it makes a grant
       individually identifiable, and a chain that carries the same nonce twice
       is provably not a chain this issuer minted. */
    nonce: nonce ?? randomBytes(16).toString("hex"),
    ...(human ? { human } : {}),
    ...(purpose ? { purpose } : {}),
    ...(policyVersion ? { policyVersion } : {}),
    ...(constraints ? { constraints } : {}),
    ...(issuerPrincipalId ? { issuerPrincipalId } : {}),
    ...(issuerRole ? { issuerRole } : {}),
    ...(audience ? { audience } : {}),
    ...(singleUse ? { singleUse: true } : {}),
    ...(maxUses != null ? { maxUses } : {}),
  };
}

/**
 * Signs one grant with the issuer's private key (Ed25519 PEM).
 *
 * The token is the two-segment base64url envelope from proof.mjs: the same
 * artifact identity credentials use, verifiable by the same machinery.
 */
export function signGrant({ grant, privateKey, keyId = null }) {
  const { token } = buildProofEnvelope({ payload: grant, privateKey, keyId });
  return token;
}

/**
 * Verifies one token against the ISSUER PUBLIC key alone — the property that
 * makes cross-instance verification possible.
 *
 * Signature first (a hostile artifact never steers the verifier), then the
 * semantic checks: kind, version, scope shape, expiry. Returns the same
 * `{ ok, ... }` discipline as verifyIdentityCredential.
 */
export function verifyGrantToken(publicKeyPem, token, { now = Date.now(), skewMs = 60_000, expectedPolicyVersion = null, expectedAudience = null } = {}) {
  const fail = (reason, failed = "grant") => ({ ok: false, failed, reason });
  const base = verifyProofEnvelope(publicKeyPem, token);
  if (!base.ok) return fail(base.reason ?? "the token does not verify", base.failed ?? "signature");

  const g = base.payload;
  for (const field of ["v", "kind", "id", "issuer", "subject", "depth", "scope", "issuedAt", "expiresAt", "nonce"]) {
    if (g[field] === undefined) return fail(`the grant is missing "${field}"`);
  }
  if (g.kind !== DELEGATION_KIND) return fail(`this is a "${g.kind}" artifact, not a delegation`);
  if (g.v !== DELEGATION_TOKEN_VERSION) return fail(`this grant is version ${g.v}; this verifier understands ${DELEGATION_TOKEN_VERSION}`);
  if (typeof g.subject !== "string" || !g.subject) return fail("the grant names no subject");
  if (typeof g.nonce !== "string" || !g.nonce) return fail("the grant carries no nonce");
  const scope = normalizeScope(g.scope);
  if (scope.actions.length === 0 || scope.resources.length === 0) return fail("the grant scope is empty on an axis");

  /* A CONSTRAINT THIS BUILD CANNOT EVALUATE IS A REFUSAL, not a comment. A
     grant carrying `constraints: { netwrok: ... }` would otherwise be a grant
     whose restriction silently does not exist. */
  if (g.constraints != null) {
    if (typeof g.constraints !== "object" || Array.isArray(g.constraints)) return fail("the grant constraints are not an object");
    for (const [key, value] of Object.entries(g.constraints)) {
      if (!CONSTRAINT_KINDS.includes(key)) return fail(`the grant carries an unknown constraint "${key}" (known: ${CONSTRAINT_KINDS.join(", ")})`);
      /* The same rule one level down: a KNOWN key whose value names no
         consequence derives is a restriction that does not exist. A grant can
         arrive from another process — the authority key outlives the runtime
         that minted it — so issuance-time validation is not enough on its own. */
      if (key === "maxConsequence" && maxConsequenceKind(value) === null) {
        return fail(`the grant's maxConsequence ("${typeof value === "string" ? value : value?.max}") is not a consequence this build derives`);
      }
    }
  }
  /* Policy version pinning: a verifier that knows which policy generation it is
     willing to enforce refuses a grant minted under another one. */
  if (expectedPolicyVersion != null && (g.policyVersion ?? null) !== expectedPolicyVersion) {
    return fail(`the grant was issued under policy ${g.policyVersion ?? "(none)"}; this boundary enforces ${expectedPolicyVersion}`);
  }
  /* AUDIENCE. A boundary that knows what it is (a runtime id, an agent id)
     refuses a grant issued for something else, and refuses an UNBOUND grant
     outright: authority that names no audience travels anywhere, which is the
     whole problem audience exists to solve. */
  if (expectedAudience != null) {
    const audience = g.audience ?? null;
    if (audience == null) {
      return fail("the grant names no audience, and this boundary requires one", DELEGATION_ERROR.AUDIENCE_MISMATCH);
    }
    if (audience !== expectedAudience) {
      return fail(`the grant was issued for audience "${audience}", and this boundary is "${expectedAudience}"`, DELEGATION_ERROR.AUDIENCE_MISMATCH);
    }
  }
  if (g.singleUse !== undefined && g.singleUse !== true) return fail("the grant's singleUse flag is not a boolean true");
  if (g.maxUses !== undefined && (!Number.isInteger(g.maxUses) || g.maxUses < 1)) return fail("the grant's maxUses is not a positive integer");

  if (g.expiresAt != null) {
    const exp = Date.parse(g.expiresAt);
    if (!Number.isFinite(exp)) return fail("the grant has an unreadable expiry");
    if (now > exp + skewMs) return fail(`the grant expired ${new Date(exp).toISOString()}`, DELEGATION_ERROR.EXPIRED);
  }
  return { ok: true, grant: g, scope };
}

/* ------------------------------------------------------------------ */
/*  The durable store                                                  */
/* ------------------------------------------------------------------ */

/**
 * Verifies the CROSS-INSTANCE ENVELOPE — a distinct kind from a grant, with
 * its own required fields. Same signature-first discipline: the envelope's
 * contents are only read after its signature checks out.
 */
export function verifyEnvelopeToken(publicKeyPem, token, { now = Date.now(), skewMs = 60_000 } = {}) {
  const fail = (reason, failed = "envelope") => ({ ok: false, failed, reason });
  const base = verifyProofEnvelope(publicKeyPem, token);
  if (!base.ok) return fail(base.reason ?? "the token does not verify", base.failed ?? "signature");

  const env = base.payload;
  if (env.kind !== "cirvix-delegation-envelope") return fail(`this is a "${env.kind}" artifact, not a delegation envelope`);
  for (const field of ["v", "id", "subject", "nonce", "chainTokens", "expiresAt"]) {
    if (env[field] === undefined) return fail(`the envelope is missing "${field}"`);
  }
  const exp = Date.parse(env.expiresAt);
  if (!Number.isFinite(exp)) return fail("the envelope has an unreadable expiry");
  if (now > exp + skewMs) return fail("the envelope has expired", DELEGATION_ERROR.EXPIRED);
  return { ok: true, envelope: env };
}

/**
 * Durable delegation state: signed tokens, the derivation index, and a
 * MONOTONIC revocation journal.
 *
 * Why the journal is append-only with a sequence: a persisted set of revoked
 * ids can be rolled back by restoring an old file, silently un-revoking
 * everything. An append-only journal with a sequence number can only be
 * rolled back as a whole, and a truncated one is detectable (a gap, or a
 * sequence below the verifier's high-water mark, is a rollback).
 */
export class DelegationStore {
  #dir;
  #seqHighWater = 0;
  #revoked = new Map(); // id -> { seq, reason, at }
  #tokens = new Map(); // id -> token
  #parents = new Map(); // child id -> parent id

  constructor(stateDir) {
    this.#dir = join(stateDir, "delegations");
  }

  get #tokensFile() {
    return join(this.#dir, "tokens.json");
  }
  get #revocationsFile() {
    return join(this.#dir, "revocations.jsonl");
  }
  get #usageFile() {
    return join(this.#dir, "usage.jsonl");
  }
  #usageFingerprint = null;

  async init() {
    await mkdir(this.#dir, { recursive: true });
    await this.#loadTokens();
    await this.#loadRevocations();
    /* ANTI-ROLLBACK. tokens.json carries the highest revocation sequence ever
       written; the journal carries the entries. If the journal's high-water
       is BELOW the manifest's, the journal was truncated or restored from an
       older snapshot — which is how a revoked grant gets un-revoked. The
       store refuses to confirm any revocation state after that, and the
       verifier fails closed. */
    this.rollbackDetected = this.#manifestSeq > this.#journalSeq;
    return this;
  }

  #manifestSeq = 0;
  #journalSeq = 0;
  rollbackDetected = false;

  async #loadTokens() {
    try {
      const raw = JSON.parse(await readFile(this.#tokensFile, "utf8"));
      for (const [id, token] of Object.entries(raw.tokens ?? {})) {
        this.#tokens.set(id, token);
        const g = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
        if (g.parent) this.#parents.set(g.id, g.parent);
      }
      if ((raw.revocationSeq ?? 0) > this.#seqHighWater) this.#seqHighWater = raw.revocationSeq;
      this.#manifestSeq = this.#seqHighWater;
    } catch {
      /* first run: no state yet */
    }
  }

  async #loadRevocations() {
    try {
      const text = await readFile(this.#revocationsFile, "utf8");
      for (const line of text.split("\n")) {
        if (!line.trim()) continue;
        const rec = JSON.parse(line);
        this.#revoked.set(rec.id, rec);
        if (Number.isFinite(rec.seq) && rec.seq > this.#seqHighWater) this.#seqHighWater = rec.seq;
        if (Number.isFinite(rec.seq) && rec.seq > this.#journalSeq) this.#journalSeq = rec.seq;
      }
    } catch {
      /* no revocations yet */
    }
  }

  /**
   * Re-reads the on-disk journals. Called at RESOLVE time by the verifier:
   * revocation is checked at use (INV-006), including revocations written by
   * another instance or process since this store was constructed. A rollback
   * of the journal shows up as a sequence at or below the high-water mark.
   */
  async refresh() {
    const before = this.#journalSeq;
    await this.#loadRevocations();
    if (before > this.#journalSeq) this.rollbackDetected = true;
    return this;
  }

  async saveToken(token) {
    const g = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
    this.#tokens.set(g.id, token);
    if (g.parent) this.#parents.set(g.id, g.parent);
    await this.#atomicWrite(this.#tokensFile, JSON.stringify({ revocationSeq: this.#seqHighWater, tokens: Object.fromEntries(this.#tokens) }, null, 2));
    return g;
  }

  /**
   * Revokes a grant and everything derived from it, appending to the journal
   * with a strictly increasing sequence.
   */
  async revoke(id, reason = "revoked") {
    const cascade = [];
    const queue = [String(id)];
    while (queue.length) {
      const current = queue.shift();
      if (this.#revoked.has(current)) continue;
      const seq = ++this.#seqHighWater;
      const rec = { id: current, seq, reason, at: new Date().toISOString() };
      this.#revoked.set(current, rec);
      cascade.push(current);
      await this.#appendRevocation(rec);
      for (const [child, parent] of this.#parents) {
        if (parent === current) queue.push(child);
      }
    }
    await this.#atomicWrite(this.#tokensFile, JSON.stringify({ revocationSeq: this.#seqHighWater, tokens: Object.fromEntries(this.#tokens) }, null, 2));
    return cascade;
  }

  isRevoked(id) {
    return this.#revoked.has(String(id));
  }

  token(id) {
    return this.#tokens.get(String(id)) ?? null;
  }

  /** Highest revocation sequence seen — a rollback lands below this. */
  get revocationSeq() {
    return this.#seqHighWater;
  }

  list() {
    return [...this.#tokens.keys()];
  }

  /**
   * Every stored grant DECODED, for callers that need subjects rather than
   * ids — the revocation fabric's cascade is the first one: revoking an agent
   * has to find the grants it was the subject of, and a list of opaque ids
   * cannot answer that.
   */
  listGrants() {
    const grants = [];
    for (const token of this.#tokens.values()) {
      const payload = decodeGrantPayload(token);
      if (payload) grants.push(payload);
    }
    return grants.sort((a, b) => String(a.id).localeCompare(String(b.id)));
  }

  /**
   * Consumes one use of a BOUNDED grant, atomically and durably.
   *
   * Why not in `resolveChain`: verification is a READ. Counting a use while
   * merely checking a chain would spend authority on calls that are then
   * refused by policy, by a mission constraint or by an approval that never
   * arrives — the same denial-of-service the mission budget deliberately
   * avoids. Consumption happens in `applyDelegation`, on a call that would
   * otherwise be forwarded.
   *
   * Atomicity: the count is read and appended under a lock file, so two
   * concurrent requests cannot both believe they took the last use. The
   * ledger is append-only, which also makes the count survive a restart and
   * makes every use attributable (who, what, when).
   */
  async consume(grantId, { maxUses = 1, agent = null, action = null, resource = null, nonce = null, now = Date.now() } = {}) {
    const id = String(grantId);
    const limit = Number.isInteger(maxUses) && maxUses > 0 ? maxUses : 1;
    await this.#loadUsage();
    return this.#withUsageLock(async () => {
      await this.#loadUsage({ force: true });
      const used = this.#usage.get(id) ?? 0;
      if (used + 1 > limit) {
        return { ok: false, code: DELEGATION_ERROR.CONSUMED, uses: used, limit };
      }
      const entry = { grantId: id, use: used + 1, limit, agent, action, resource, nonce, at: new Date(now).toISOString() };
      const { appendFile } = await import("node:fs/promises");
      await appendFile(this.#usageFile, JSON.stringify(entry) + "\n", "utf8");
      this.#usage.set(id, used + 1);
      return { ok: true, uses: used + 1, limit };
    });
  }

  /**
   * Uses consumed for a grant id, read from the DURABLE ledger.
   *
   * The in-memory map is a cache loaded at init and updated by `consume`, so a
   * process that did not do the consuming (the CLI listing grants, or a
   * boundary that started after the use) would report 0 — the count would look
   * like unconsumed authority in exactly the place an operator audits it. The
   * fingerprint check makes this one `stat` when nothing changed.
   */
  async refreshUsage() {
    await this.#loadUsage();
    return this;
  }

  /** Uses consumed for a grant id. Call `refreshUsage()` first for a fresh count. */
  uses(grantId) {
    return this.#usage.get(String(grantId)) ?? 0;
  }

  #usage = new Map();

  #withUsageLock(fn, { attempts = 50, waitMs = 4 } = {}) {
    return (async () => {
      const lockPath = join(this.#dir, "usage.lock");
      await mkdir(this.#dir, { recursive: true });
      let handle = null;
      for (let i = 0; i < attempts && !handle; i++) {
        try {
          handle = await open(lockPath, "wx");
        } catch (err) {
          if (err.code !== "EEXIST") throw err;
          await new Promise((r) => setTimeout(r, waitMs));
        }
      }
      if (!handle) {
        const err = new Error("The delegation usage ledger is locked by another writer.");
        err.code = "usage_locked";
        throw err;
      }
      try {
        return await fn();
      } finally {
        await handle.close().catch(() => {});
        await rm(lockPath, { force: true }).catch(() => {});
      }
    })();
  }

  async #loadUsage({ force = false } = {}) {
    let info = null;
    try {
      info = await stat(this.#usageFile);
    } catch {
      info = null;
    }
    const fingerprint = info ? `${info.size}:${info.mtimeMs}` : "absent";
    if (!force && fingerprint === this.#usageFingerprint) return;
    this.#usageFingerprint = fingerprint;
    try {
      const text = await readFile(this.#usageFile, "utf8");
      const counts = new Map();
      for (const line of text.split("\n")) {
        if (!line.trim()) continue;
        try {
          const entry = JSON.parse(line);
          if (typeof entry?.grantId === "string") counts.set(entry.grantId, Math.max(counts.get(entry.grantId) ?? 0, Number(entry.use) || 0));
        } catch {
          /* a corrupt line is not a use: the ledger only ever ADDS authority
             pressure, so skipping is safe in the deny direction and cannot
             reset a count downward */
        }
      }
      this.#usage = counts;
    } catch (err) {
      if (err.code !== "ENOENT") this.#usage = new Map();
    }
  }

  async #appendRevocation(rec) {
    const { appendFile } = await import("node:fs/promises");
    await appendFile(this.#revocationsFile, JSON.stringify(rec) + "\n", "utf8");
  }

  async #atomicWrite(file, data) {
    await mkdir(dirname(file), { recursive: true });
    const tmp = file + ".tmp-" + randomBytes(4).toString("hex");
    await writeFile(tmp, data, "utf8");
    await rename(tmp, file);
  }
}

/* ------------------------------------------------------------------ */
/*  The issuing authority                                              */
/* ------------------------------------------------------------------ */

/**
 * Issues and signs Ed25519 delegation grants, persisting every one.
 *
 * The ROOT of a chain is an operator act: it is signed by the host AUTHORITY
 * key and carries `human` — the person who approved it. Agent-issued
 * delegations are signed by the DELEGATION key and are always narrowings of
 * their parent; the narrowing check is the one from delegation.mjs.
 */
export class Ed25519DelegationIssuer {
  constructor({
    stateDir,
    store = null,
    defaultTtlMs = 15 * 60 * 1000,
    now = () => new Date(),
    policyVersion = null,
    /* A shipped issuer refuses to mint a root grant that names no authenticated
       principal: authority nobody can withdraw is authority nobody can audit.
       Library composition may leave it off; every CLI path turns it on. */
    requireIssuerPrincipal = false,
    /* The audience every root grant is issued for, when the operator does not
       name one. A boundary pinned to an audience refuses an unbound grant, so
       an issuer that defaults this produces artifacts that actually work. */
    defaultAudience = null,
  } = {}) {
    this.stateDir = stateDir;
    this.store = store ?? new DelegationStore(stateDir);
    this.defaultTtlMs = defaultTtlMs;
    this.now = now;
    /* Which policy generation these grants belong to, recorded on every grant
       so a boundary can pin the generation it is willing to enforce. */
    this.policyVersion = policyVersion;
    this.requireIssuerPrincipal = Boolean(requireIssuerPrincipal);
    this.defaultAudience = defaultAudience;
  }

  async init() {
    this.authority = await ensureRoleKey(this.stateDir, KEY_ROLE.AUTHORITY);
    this.delegation = await ensureRoleKey(this.stateDir, KEY_ROLE.DELEGATION);
    await this.store.init();
    this.seq = Math.floor(this.now().getTime() / 1000);
    return this;
  }

  /**
   * A grant id that is unique ACROSS PROCESSES.
   *
   * `droot_<epoch-seconds>` was the whole id, and two grants issued inside one
   * second by two `cirvix authority grant issue` invocations got the SAME id.
   * That is not a cosmetic collision:
   *
   *   - the token store is keyed by id, so the second grant silently REPLACED
   *     the first, and `authority grant show <id>` answered with a grant the
   *     caller never issued;
   *   - revoking one of them revoked the other, because revocation is keyed by
   *     the same id — an operator revoking a leaked grant would take down an
   *     unrelated live one.
   *
   * The time prefix stays because grant ids are read in `list` output and should
   * sort chronologically. The random suffix is what makes "revoke THAT grant"
   * name one grant.
   */
  #mintGrantId(prefix) {
    return `${prefix}_${(this.seq++).toString(36)}${randomBytes(6).toString("base64url")}`;
  }

  /**
   * A HUMAN grants an agent its base authority. Signed by the authority key;
   * reconstructable as "who authorized this" all the way down the chain.
   */
  async root({
    agent,
    scope,
    tenant = null,
    human = null,
    id = null,
    purpose = null,
    constraints = null,
    policyVersion = null,
    /* THE HUMAN SIDE, AS AN ID. `principalId` is what makes "who granted this"
       answerable; `human` is a display name for the operator's log and is
       explicitly NOT an identity. */
    principalId = null,
    principalRole = null,
    audience = null,
    singleUse = false,
    maxUses = null,
  }) {
    const issuedAt = this.now().toISOString();
    // Roots carry no expiry of their own: the human grant is anchored to the
    // agent's CREDENTIAL lifetime, which the identity boundary already checks.
    const payload = buildGrantPayload({
      id: id ?? this.#mintGrantId("droot"),
      issuer: "human",
      subject: agent,
      tenant,
      parent: null,
      depth: 0,
      scope,
      issuedAt,
      expiresAt: null,
      human: human ?? null,
      purpose,
      policyVersion: policyVersion ?? this.policyVersion,
      constraints: constraints ? assertConstraintShape(constraints) : null,
      issuerPrincipalId: principalId,
      issuerRole: principalRole,
      audience: audience ?? this.defaultAudience,
      singleUse,
      maxUses,
    });
    if (this.requireIssuerPrincipal && !principalId) {
      const err = new Error("This issuer requires an AUTHENTICATED PRINCIPAL to issue a root grant; a name is not an identity.");
      err.code = "principal_required";
      throw err;
    }
    const token = signGrant({ grant: payload, privateKey: this.authority.privateKey, keyId: this.authority.keyId });
    await this.store.saveToken(token);
    return { grant: payload, token };
  }

  /**
   * An agent delegates a NARROWING of what it holds. Signed by the delegation
   * key; verified downstream against the delegation public key alone.
   */
  async delegate({ parent, subject, scope, ttlMs = null, purpose = null, issuer = null, now = null, constraints = null, singleUse = false, maxUses = null }) {
    const parentGrant = typeof parent === "string" ? JSON.parse(Buffer.from(parent.split(".")[0], "base64url").toString("utf8")) : parent;

    // THE NARROWING INVARIANT — the same function the local broker uses. A
    // delegation that widens is refused, never clamped: the attempt itself is
    // the event an operator wants to see.
    const parentScope = parentGrant.scope;
    if (!parentScope || !isNarrowing(parentScope, scope)) {
      const err = new Error(
        `A delegation cannot grant more than the issuer holds. ${parentGrant.subject} cannot give ${subject} authority it does not have itself.`,
      );
      err.code = DELEGATION_ERROR.WIDENED;
      throw err;
    }

    if (this.store.isRevoked(parentGrant.id)) {
      const err = new Error(`Grant ${parentGrant.id} has been revoked.`);
      err.code = DELEGATION_ERROR.REVOKED;
      throw err;
    }

    /* A CHILD MAY NOT DROP ITS PARENT'S CONSTRAINTS. Scope narrowing is
       checked by isNarrowing; dropping a constraint is the same act on a
       different axis (the child would suddenly be allowed what the parent
       restricted), so it is refused the same way. Adding constraints is
       always allowed: that narrows. */
    const parentConstraints = parentGrant.constraints ? Object.keys(parentGrant.constraints) : [];
    const childConstraints = constraints ? assertConstraintShape(constraints) : null;
    for (const key of parentConstraints) {
      if (!childConstraints || !Object.hasOwn(childConstraints, key)) {
        const err = new Error(
          `A delegation cannot drop the "${key}" constraint its parent declared — dropping a restriction is widening.`,
        );
        err.code = DELEGATION_ERROR.WIDENED;
        throw err;
      }
      /* KEEPING THE KEY IS NOT ENOUGH FOR A CEILING. A child that carried
         `maxConsequence: "financial_transfer"` under a parent's `"data_write"`
         would keep the key and still widen the authority on the exact axis the
         constraint exists to bound — money moving where the issuer allowed only
         data writes. The parent must allow everything the child allows:
         consequenceAtLeast(parentMax, childMax). */
      if (key !== "maxConsequence") continue;
      const parentMax = maxConsequenceKind(parentGrant.constraints[key]);
      if (parentMax === null) {
        const err = new Error(
          `The parent grant's maxConsequence ("${typeof parentGrant.constraints[key] === "string" ? parentGrant.constraints[key] : parentGrant.constraints[key]?.max}") is not a consequence this build derives; a chain cannot be narrowed through an unreadable ceiling.`,
        );
        err.code = "unknown_constraint";
        throw err;
      }
      if (!consequenceAtLeast(parentMax, childConstraints[key])) {
        const err = new Error(
          `A delegation cannot widen "maxConsequence" from "${parentMax}" to "${childConstraints[key]}".`,
        );
        err.code = DELEGATION_ERROR.WIDENED;
        throw err;
      }
    }

    const depth = (parentGrant.depth ?? 0) + 1;
    if (depth > MAX_DEPTH) {
      const err = new Error(`A delegation chain may be at most ${MAX_DEPTH} deep.`);
      err.code = DELEGATION_ERROR.TOO_DEEP;
      throw err;
    }
    // A cycle would let authority launder around a ring; walk the parent ids
    // through the store to check every upstream subject.
    for (let link = parentGrant; link; ) {
      if (link.subject === subject) {
        const err = new Error(`${subject} already appears in this chain; delegating back to it would be circular.`);
        err.code = DELEGATION_ERROR.CYCLE;
        throw err;
      }
      if (!link.parent) break;
      const parentToken = this.store.token(link.parent);
      if (!parentToken) break;
      link = JSON.parse(Buffer.from(parentToken.split(".")[0], "base64url").toString("utf8"));
    }

    const at = now ?? this.now;
    const issuedAt = at().toISOString();
    const ttl = ttlMs ?? this.defaultTtlMs;
    /* A caller that asks for an ALREADY-EXPIRED grant is making either a
       mistake or a test of the verifier; both are served by minting exactly
       what was asked for. Clamping it into the future would hide the case
       where a verifier's clock is ahead of the issuer's. */
    if (!(ttl > 0)) {
      const err = new Error("A delegation needs a positive lifetime.");
      err.code = DELEGATION_ERROR.EXPIRED;
      throw err;
    }
    const payload = buildGrantPayload({
      id: this.#mintGrantId("dlg"),
      issuer: issuer ?? parentGrant.subject,
      subject,
      tenant: parentGrant.tenant ?? null,
      parent: parentGrant.id,
      depth,
      scope: canonicalScope(intersectScopes(parentScope, scope)),
      issuedAt,
      expiresAt: new Date(at().getTime() + ttl).toISOString(),
      human: parentGrant.human ?? null,
      purpose,
      policyVersion: parentGrant.policyVersion ?? this.policyVersion ?? null,
      constraints: childConstraints,
      /* A CHILD INHERITS THE ROOT'S HUMAN AUTHORITY, including its issuer and
         its audience, and may only NARROW consumption. A child that could drop
         the issuer would launder authority away from the principal that
         granted it, which is exactly the accountability the root exists for. */
      issuerPrincipalId: parentGrant.issuerPrincipalId ?? null,
      issuerRole: parentGrant.issuerRole ?? null,
      audience: parentGrant.audience ?? null,
      singleUse,
      maxUses,
    });
    const token = signGrant({ grant: payload, privateKey: this.delegation.privateKey, keyId: this.delegation.keyId });
    await this.store.saveToken(token);
    return { grant: payload, token };
  }
}

/* ------------------------------------------------------------------ */
/*  The verifier — public keys only, chains, one-time envelopes        */
/* ------------------------------------------------------------------ */

/**
 * Verifies presented delegations with NO private key material at all: the
 * authority public key (for roots) and the delegation public key (for
 * agent-issued links). Resolves to the same shape DelegationBroker.resolve
 * returns, so `applyDelegation` treats both identically.
 */
export class Ed25519DelegationVerifier {
  constructor({
    stateDir,
    store = null,
    now = () => new Date(),
    nonces = null,
    authorityPublicKey = null,
    delegationPublicKey = null,
    expectedTenant = null,
    expectedPolicyVersion = null,
    /* The audience this boundary IS ("runtime:prod-runner", "agent:worker").
       Pinned boundaries refuse a grant issued for anything else, and refuse an
       unbound grant outright. */
    expectedAudience = null,
    /* A root that names no issuer principal is a root nobody can withdraw.
       Library composition may allow it; every shipped boundary sets this. */
    requireIssuerPrincipal = false,
    principalStore = null,
  } = {}) {
    this.stateDir = stateDir;
    this.store = store ?? new DelegationStore(stateDir);
    this.now = now;
    /* The policy generation this boundary is willing to enforce, when pinned. */
    this.expectedPolicyVersion = expectedPolicyVersion;
    this.expectedAudience = expectedAudience;
    this.requireIssuerPrincipal = Boolean(requireIssuerPrincipal);
    this.principalStore = principalStore;
    // Cross-instance mode: supply the ISSUING instance's public keys directly
    // and no private key material of any kind is needed — or possible.
    this.#authorityPublicKeyOverride = authorityPublicKey;
    this.#delegationPublicKeyOverride = delegationPublicKey;
    /* Tenancy pinned per boundary (INV-007): a chain rooted in another tenant
       authorizes nothing here, even with valid signatures throughout. */
    this.expectedTenant = expectedTenant;
    // Replay protection for presented ENVELOPES (one-time nonces).
    this.nonces = nonces ?? new Map();
  }

  #authorityPublicKeyOverride;
  #delegationPublicKeyOverride;

  async init() {
    this.authority = this.#authorityPublicKeyOverride
      ? { publicKey: this.#authorityPublicKeyOverride }
      : await loadRoleKey(this.stateDir, KEY_ROLE.AUTHORITY);
    this.delegation = this.#delegationPublicKeyOverride
      ? { publicKey: this.#delegationPublicKeyOverride }
      : await loadRoleKey(this.stateDir, KEY_ROLE.DELEGATION);
    await this.store.init();
    return this;
  }

  /**
   * Verifies a chain presented as an ordered list of tokens, child first.
   *
   * Every link is checked: signature, kind, revocation, expiry, and — the
   * invariant — that each child narrows its parent. The effective scope is
   * the INTERSECTION of every link.
   */
  async resolveChain(tokens, presentedBy, { now = null, expectedPolicyVersion = this.expectedPolicyVersion } = {}) {
    const fail = (error, reason) => ({ ok: false, error, reason });
    const at = now ?? this.now().getTime();
    // Revocation is a USE-TIME check: pick up revocations written since this
    // verifier (or another instance) last touched the journal.
    await this.store.refresh();
    if (this.store.rollbackDetected) {
      return fail("rollback", "The revocation journal rolled back; refusing every delegation until the state is restored.");
    }
    if (!Array.isArray(tokens) || tokens.length === 0) return fail(DELEGATION_ERROR.BROKEN_CHAIN, "No delegation was presented.");
    if (tokens.length > MAX_DEPTH + 1) return fail(DELEGATION_ERROR.TOO_DEEP, `A delegation chain may be at most ${MAX_DEPTH} deep.`);

    const grants = [];
    for (const token of tokens) {
      const isRoot = grants.length === tokens.length - 1;
      const key = isRoot ? this.authority?.publicKey : this.delegation?.publicKey;
      if (!key) return fail(DELEGATION_ERROR.BROKEN_CHAIN, "This verifier holds no delegation keys.");
      /* The primary audience is the ROOT's: a child inherits its audience and
         may only narrow it, so checking every link against the boundary's own
         audience would refuse a chain whose leaf is narrower than the root. */
      const check = verifyGrantToken(key, token, { now: at, expectedPolicyVersion, expectedAudience: isRoot ? this.expectedAudience : null });
      if (!check.ok) {
        const error = check.failed === DELEGATION_ERROR.EXPIRED ? DELEGATION_ERROR.EXPIRED : DELEGATION_ERROR.BAD_SIGNATURE;
        return fail(error, check.reason);
      }
      grants.push(check.grant);
    }

    // Child-first order: parent of each link is the previous link's id; the
    // last token must be a root issued by a human.
    const root = grants[grants.length - 1];
    if (root.issuer !== "human" || root.parent !== null) {
      return fail(DELEGATION_ERROR.BROKEN_CHAIN, "The chain does not terminate in a human-issued root grant.");
    }
    if (this.expectedTenant && (root.tenant ?? null) !== this.expectedTenant) {
      return fail(DELEGATION_ERROR.UNKNOWN_TENANT, `This delegation carries tenant "${root.tenant ?? "(none)"}"; this boundary is "${this.expectedTenant}".`);
    }
    /* THE HUMAN SIDE OF THE CHAIN. A root with no issuer principal is refused
       where the boundary requires one, and a root whose principal is revoked,
       suspended or expired stops being authority the moment the principal does
       — the grant does not outlive the human who granted it. */
    if (root.issuerPrincipalId) {
      if (this.principalStore) {
        const record = await this.principalStore.get(root.issuerPrincipalId);
        if (!record) {
          return fail(DELEGATION_ERROR.PRINCIPAL_INVALID, `the issuing principal "${root.issuerPrincipalId}" is not enrolled on this host`);
        }
        if (this.authority?.publicKey && record.record) {
          const hostCheck = verifyProofEnvelope(this.authority.publicKey, record.record);
          if (!hostCheck.ok) return fail(DELEGATION_ERROR.PRINCIPAL_INVALID, "the issuing principal's record is not signed by this host's authority key");
        }
        const state = principalStatusAt(record, at);
        if (state !== "active") {
          return fail(DELEGATION_ERROR.PRINCIPAL_INVALID, `the issuing principal "${root.issuerPrincipalId}" is ${state}`);
        }
        if (this.expectedTenant && (record.tenantId ?? null) !== this.expectedTenant) {
          return fail(DELEGATION_ERROR.PRINCIPAL_INVALID, `the issuing principal belongs to tenant "${record.tenantId ?? "(none)"}", not "${this.expectedTenant}"`);
        }
      }
    } else if (this.requireIssuerPrincipal) {
      return fail(DELEGATION_ERROR.PRINCIPAL_INVALID, "this chain's root names no authenticated issuing principal");
    }

    for (let i = 0; i < grants.length - 1; i++) {
      const child = grants[i];
      const parent = grants[i + 1];
      if (child.parent !== parent.id) return fail(DELEGATION_ERROR.BROKEN_CHAIN, `Link ${child.id} does not follow from ${parent.id}.`);
      if (parent.id !== root.id && parent.issuer === "human") {
        return fail(DELEGATION_ERROR.BROKEN_CHAIN, `Link ${parent.id} is a root and cannot be a parent mid-chain.`);
      }
      // THE INVARIANT, re-checked where it can be enforced.
      if (!isNarrowing(parent.scope, child.scope)) {
        return fail(DELEGATION_ERROR.WIDENED, `Link ${child.id} grants more than ${parent.id} holds.`);
      }
    }

    // Revocation walks the WHOLE chain: a revoked parent revokes its children.
    for (const g of grants) {
      if (this.store.isRevoked(g.id)) return fail(DELEGATION_ERROR.REVOKED, `Link ${g.id} has been revoked.`);
    }

    // The presenter must BE the leaf subject — exactly the binding the local
    // broker enforces. Proving identity is the caller verifier's job; binding
    // the two is what stops token theft.
    if (presentedBy != null && String(presentedBy) !== String(grants[0].subject)) {
      return fail(DELEGATION_ERROR.SUBJECT_MISMATCH, `This delegation was issued to ${grants[0].subject}, and was presented by ${presentedBy}.`);
    }

    /* A nonce identifies one minted grant. The same nonce twice in a chain is
       not a chain this issuer could have produced — a spliced or duplicated
       link looks exactly like that. */
    const nonces = new Set();
    for (const g of grants) {
      if (nonces.has(g.nonce)) return fail(DELEGATION_ERROR.BROKEN_CHAIN, `Link ${g.id} repeats the nonce of another link.`);
      nonces.add(g.nonce);
    }

    let effective = null;
    for (const g of [...grants].reverse()) effective = effective === null ? canonicalScope(g.scope) : canonicalScope(intersectScopes(effective, g.scope));

    return {
      ok: true,
      scope: effective,
      chain: grants.map((g) => g.id).reverse(),
      principals: grants.map((g) => g.subject).reverse(),
      depth: grants[0].depth ?? grants.length - 1,
      tenant: root.tenant ?? null,
      human: root.human ?? null,
      /* Every declared constraint in the chain, leaf-first, for the caller to
         enforce against the ACTUAL call. `applyDelegation` does exactly that:
         a delegated call must satisfy every link's constraints, not just the
         scope intersection. */
      constraints: grants.filter((g) => g.constraints).map((g) => ({ id: g.id, constraints: g.constraints })),
      policyVersions: [...new Set(grants.map((g) => g.policyVersion ?? null))],
      /* The four bindings, resolved and reported: who issued, who may present,
         what it was issued for, and whose authority it carries. */
      issuerPrincipalId: root.issuerPrincipalId ?? null,
      issuerRole: root.issuerRole ?? null,
      audience: root.audience ?? null,
      policyVersion: root.policyVersion ?? null,
      /* Bounded-use links, for the caller to spend. Verification is read-only;
         `applyDelegation` consumes, and only on a call that would otherwise be
         forwarded, so a refused call never burns authority. */
      useLimits: grants
        .filter((g) => g.singleUse === true || Number.isInteger(g.maxUses))
        .map((g) => ({ id: g.id, subject: g.subject, singleUse: g.singleUse === true, maxUses: g.singleUse === true ? 1 : g.maxUses })),
    };
  }

  /**
   * THE MINIMUM SIGNED CROSS-INSTANCE ENVELOPE.
   *
   * A verifier on another instance receives ONE token that carries the whole
   * chain, the presenting agent's verified identity binding, and a one-time
   * nonce. Verifying it here requires only public keys. A captured envelope
   * is dead after first use — the nonce is spent.
   */
  async resolveEnvelope(envelope, presentedBy, { now = null } = {}) {
    const fail = (error, reason) => ({ ok: false, error, reason });
    const check = verifyEnvelopeToken(this.delegation?.publicKey, envelope, { now: now ?? this.now().getTime() });
    if (!check.ok) return fail(DELEGATION_ERROR.BAD_SIGNATURE, check.reason);

    const env = check.envelope;
    if (env.subject !== presentedBy) {
      return fail(DELEGATION_ERROR.SUBJECT_MISMATCH, `This envelope was issued for ${env.subject}, presented by ${presentedBy}.`);
    }
    if (!env.nonce || !Array.isArray(env.chainTokens)) {
      return fail(DELEGATION_ERROR.BROKEN_CHAIN, "This envelope is missing its nonce or chain.");
    }
    // ONE-TIME: the nonce is spent on first presentation, before any scope is
    // returned. A replay dies here.
    if (this.nonces.has(env.nonce)) {
      return fail("replay", "This envelope has already been presented (replay).");
    }
    this.nonces.set(env.nonce, this.now().getTime());

    const inner = await this.resolveChain(env.chainTokens, presentedBy, { now });
    if (!inner.ok) return inner;
    return { ...inner, envelope: env.id, singleUse: true };
  }

  /**
   * The `DelegationBroker.resolve` interface, so `applyDelegation` — and
   * therefore Guard and Pipeline — can accept a token chain (array) or a
   * single envelope token through the same `presented` slot the local broker
   * already fills. A presented STRING is an envelope; an ARRAY is a chain.
   */
  async resolve(presented, presentedBy) {
    if (Array.isArray(presented)) return this.resolveChain(presented, presentedBy);
    if (typeof presented === "string" && presented.includes(".")) {
      return this.resolveEnvelope(presented, presentedBy);
    }
    return { ok: false, error: DELEGATION_ERROR.BROKEN_CHAIN, reason: "No such delegation." };
  }
}

/* ------------------------------------------------------------------ */
/*  Envelope minting (issuer side)                                     */
/* ------------------------------------------------------------------ */

/**
 * Wraps a verified chain into the one-time cross-instance envelope.
 *
 * `nonce` is caller-supplied randomness (16 random bytes are enough); the
 * envelope binds it, the presenting subject, and the full token chain.
 */
export async function buildCrossInstanceEnvelope({ issuer, chainTokens, subject, nonce = null, ttlMs = 120_000, now = () => new Date() }) {
  const payload = {
    v: DELEGATION_TOKEN_VERSION,
    kind: "cirvix-delegation-envelope",
    id: `env_${Date.now().toString(36)}${randomBytes(3).toString("hex")}`,
    subject,
    nonce: nonce ?? randomBytes(16).toString("hex"),
    chainTokens,
    issuedAt: now().toISOString(),
    expiresAt: new Date(now().getTime() + ttlMs).toISOString(),
  };
  const { token } = buildProofEnvelope({ payload, privateKey: issuer.delegation.privateKey, keyId: issuer.delegation.keyId });
  return token;
}
