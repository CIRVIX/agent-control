/**
 * The revocation fabric — durable, signed, monotonic, cross-process, federated.
 *
 * WHAT WAS WRONG. `KillSwitchEngine` is an in-memory `Map`. `cirvix kill`
 * mutated that map inside the CLI process and exited, so the freeze died with
 * the command that armed it: another process running the gateway never saw it,
 * a restart forgot it, and there was no record to audit or to propagate. A
 * kill switch that only works in the process you typed it in is a console, not
 * a control.
 *
 * WHAT THIS MODULE IS. Revocation as SECURITY STATE, not as a flag:
 *
 *   - every revocation is a signed `RevocationEvent` with scope, subject,
 *     tenant, issuer, reason, validity window, epoch, sequence and the hash of
 *     its predecessor — so a state file is a verifiable log, not a set;
 *
 *   - the journal is append-only and DURABLE, and the manifest records the
 *     highest epoch/sequence/hash ever written. A journal that is shorter than
 *     the manifest, or that ends on a different hash, has been rolled back or
 *     truncated: the store says so, and the engine fails closed. This is what
 *     stops `epoch 42 -> epoch 17` from un-killing an agent;
 *
 *   - enforcement is CROSS-PROCESS. `RevocationEngine.evaluate()` re-reads the
 *     journal (cheaply, by size/mtime) before every decision, so a revocation
 *     written by a different process is in force on the next call, without a
 *     restart and without an IPC channel;
 *
 *   - the control plane propagates the SAME signed events. An endpoint accepts
 *     one only if it verifies against the pinned operator key AND its epoch is
 *     ahead of local state, and it records when the event was created, when it
 *     was received and when it became active — so propagation latency is
 *     measured and reportable rather than asserted;
 *
 *   - nothing fails open. An unreadable journal, a bad signature, a broken
 *     hash chain, a rollback, a future-dated event (clock disagreement) or a
 *     stale control-plane feed all resolve to a refusal, with the reason on
 *     the record. `onUnavailable` chooses DENY or HOLD; there is no "allow".
 *
 * SCOPE PRECEDENCE. Scopes are grouped and ranked, and the highest-ranked
 * match is the one the record names:
 *
 *   1. WHO/WHERE  global > tenant > principal > identity > runtime > agent >
 *                 credential > session
 *   2. WHAT AUTHORITY  delegation > capability > mission > approval
 *   3. WHAT SURFACE    tool > resource
 *
 * Precedence is about ATTRIBUTION, not about whether the call is refused:
 * every match refuses. Ranking exists so that "why was I killed" has one
 * answer an operator can act on, and so a tenant-wide freeze is not reported
 * as a single tool being disabled.
 *
 * KEYS. Events are signed with the REVOCATION role key (core/keys.mjs), which
 * is separate from the AUTHORITY, IDENTITY, DELEGATION, RECEIPT and POLICY
 * roles. A verifier needs that public key — and nothing else: no shared secret
 * between the process that killed and the processes that enforce.
 *
 * WHAT THIS IS NOT. The boundary is still COOPERATIVE: the signing key is a
 * 0600 file on the same host, so a same-user process can sign a release. What
 * the fabric guarantees is that revocation is durable, attributable,
 * monotonic and enforced by every process that reads the state directory —
 * not that a root-compromised host cannot undo it. See SECURITY_INVARIANTS.md.
 */

import { appendFile, mkdir, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { createHash, createPublicKey, randomBytes } from "node:crypto";
import { dirname, join } from "node:path";

import { canonicalJson } from "./audit.mjs";
import { buildProofEnvelope, verifyProofEnvelope } from "./proof.mjs";
import { ensureRoleKey, loadRoleKey, loadRolePublicKey, KEY_ROLE } from "./keys.mjs";
import { DECISION } from "./decisions.mjs";
import { NonceCache } from "./identity.mjs";
import { RELEASE_ROLES, authenticatePrincipal, issueChallenge } from "./principal.mjs";

export const REVOCATION_VERSION = 1;
export const REVOCATION_KIND = "cirvix-revocation";

/** Whether an event revokes or releases a subject. */
export const REVOCATION_ACTION = Object.freeze({
  REVOKE: "revoke",
  RELEASE: "release",
});

/**
 * The scopes a revocation can name. The vocabulary is closed on purpose: a
 * typo in a scope must be a refusal at write time, not a revocation that
 * silently matches nothing.
 */
export const REVOCATION_SCOPE = Object.freeze({
  GLOBAL: "global",
  TENANT: "tenant",
  PRINCIPAL: "principal",
  IDENTITY: "identity",
  RUNTIME: "runtime",
  AGENT: "agent",
  CREDENTIAL: "credential",
  SESSION: "session",
  DELEGATION: "delegation",
  CAPABILITY: "capability",
  MISSION: "mission",
  APPROVAL: "approval",
  TOOL: "tool",
  RESOURCE: "resource",
});

export const REVOCATION_SCOPES = Object.freeze(Object.values(REVOCATION_SCOPE));

/**
 * Highest precedence first. `global` outranks everything: a platform-wide
 * freeze is the answer to "why", never a single tool rule.
 */
export const REVOCATION_PRECEDENCE = Object.freeze([
  REVOCATION_SCOPE.GLOBAL,
  REVOCATION_SCOPE.TENANT,
  REVOCATION_SCOPE.PRINCIPAL,
  REVOCATION_SCOPE.IDENTITY,
  REVOCATION_SCOPE.RUNTIME,
  REVOCATION_SCOPE.AGENT,
  REVOCATION_SCOPE.CREDENTIAL,
  REVOCATION_SCOPE.SESSION,
  REVOCATION_SCOPE.DELEGATION,
  REVOCATION_SCOPE.CAPABILITY,
  REVOCATION_SCOPE.MISSION,
  REVOCATION_SCOPE.APPROVAL,
  REVOCATION_SCOPE.TOOL,
  REVOCATION_SCOPE.RESOURCE,
]);

export function revocationRank(scope) {
  const index = REVOCATION_PRECEDENCE.indexOf(scope);
  return index === -1 ? REVOCATION_PRECEDENCE.length : index;
}

export function assertRevocationScope(scope) {
  if (!REVOCATION_SCOPES.includes(scope)) {
    throw new TypeError(`Unknown revocation scope "${scope}". Known scopes: ${REVOCATION_SCOPES.join(", ")}.`);
  }
  return scope;
}

/* ------------------------------------------------------------------ */
/*  Event construction, signing, verification                          */
/* ------------------------------------------------------------------ */

/**
 * The canonical revocation payload.
 *
 * `type` is the ACTION ("revoke" | "release") and `scope` is the target class,
 * which is how an operator reads a line: "revoke the agent worker because…".
 * `previousHash` chains events, so deletions and reorderings are detectable;
 * `epoch`/`sequence` are the monotonic counters the anti-rollback rules use.
 */
export function buildRevocationEvent({
  revocationId,
  action = REVOCATION_ACTION.REVOKE,
  scope,
  subject,
  tenant = null,
  issuer,
  reason = null,
  createdAt,
  effectiveAt = null,
  expiresAt = null,
  epoch,
  sequence,
  principal = null,
  policyVersion = null,
  previousHash = null,
  cascadeOf = null,
  releasedBy = null,
}) {
  assertRevocationScope(scope);
  if (!Object.values(REVOCATION_ACTION).includes(action)) {
    throw new TypeError(`Unknown revocation action "${action}".`);
  }
  if (typeof subject !== "string" || !subject) throw new TypeError("A revocation event needs a subject.");
  if (typeof issuer !== "string" || !issuer) throw new TypeError("A revocation event needs an issuer.");
  if (!Number.isFinite(epoch) || epoch < 0) throw new TypeError("A revocation event needs a non-negative epoch.");
  if (!Number.isFinite(sequence) || sequence < 1) throw new TypeError("A revocation event needs a positive sequence.");
  return {
    v: REVOCATION_VERSION,
    kind: REVOCATION_KIND,
    revocationId: revocationId ?? `rev_${randomBytes(8).toString("hex")}`,
    type: action,
    scope,
    subject: String(subject),
    tenant: tenant ?? null,
    issuer,
    principal: principal ?? null,
    reason: reason ?? null,
    createdAt,
    effectiveAt: effectiveAt ?? null,
    expiresAt: expiresAt ?? null,
    epoch,
    sequence,
    policyVersion: policyVersion ?? null,
    previousHash: previousHash ?? null,
    ...(cascadeOf ? { cascadeOf } : {}),
    /* A release names WHO lifted the containment: principal, role, tenant,
       authentication method, the single-use challenge and the release key id.
       Signed, so it cannot be added after the fact to a revocation that was
       written by someone who had no right to undo it. */
    ...(releasedBy ? { releasedBy } : {}),
  };
}

/** Stable hash of an event payload, used for both chaining and dedupe. */
export function revocationEventHash(event) {
  return createHash("sha256").update(canonicalJson(event)).digest("hex");
}

/** Two-segment base64url envelope, the same artifact shape every other signed object uses. */
export function signRevocationEvent({ event, privateKey, keyId = null }) {
  const { token } = buildProofEnvelope({ payload: event, privateKey, keyId });
  return token;
}

/**
 * Verifies one event against the ISSUER PUBLIC KEY alone.
 *
 * Signature first — a hostile artifact must never steer the verifier — then
 * the field checks, then the validity window. `now` is a parameter for the
 * same reason it is everywhere else: a clock the caller controls is the only
 * way to test skew without waiting for one.
 */
export function verifyRevocationEvent(publicKeyPem, token, { now = Date.now(), skewMs = 60_000 } = {}) {
  const fail = (reason, failed = "revocation") => ({ ok: false, failed, reason });
  const base = verifyProofEnvelope(publicKeyPem, token);
  if (!base.ok) return fail(base.reason ?? "the event does not verify", base.failed ?? "signature");

  const event = base.payload;
  if (event?.kind !== REVOCATION_KIND) return fail(`this is a "${event?.kind}" artifact, not a revocation event`);
  if (event.v !== REVOCATION_VERSION) return fail(`this event is version ${event.v}; this verifier understands ${REVOCATION_VERSION}`);
  for (const field of ["revocationId", "type", "scope", "subject", "issuer", "createdAt", "epoch", "sequence"]) {
    if (event[field] === undefined || event[field] === null) return fail(`the event is missing "${field}"`);
  }
  if (!REVOCATION_SCOPES.includes(event.scope)) return fail(`the event names an unknown scope "${event.scope}"`);
  if (!Object.values(REVOCATION_ACTION).includes(event.type)) return fail(`the event names an unknown action "${event.type}"`);
  if (!Number.isFinite(event.epoch) || event.epoch < 0) return fail("the event has an unusable epoch");
  if (!Number.isFinite(event.sequence) || event.sequence < 1) return fail("the event has an unusable sequence");

  const created = Date.parse(event.createdAt);
  if (!Number.isFinite(created)) return fail("the event has an unreadable creation time");
  for (const field of ["effectiveAt", "expiresAt"]) {
    if (event[field] != null && !Number.isFinite(Date.parse(event[field]))) return fail(`the event has an unreadable ${field}`);
  }
  /* CLOCK DISAGREEMENT IS A REFUSAL, NOT A DELAY. An event dated in the
     future means this host and its issuer do not agree on time, and the
     direction of the uncertainty is "a revocation I should already be
     enforcing has not arrived". Treating it as "not yet" would be a fail-open
     with a plausible excuse. */
  if (created > now + skewMs) {
    return fail(`the event is dated ${new Date(created).toISOString()}, ${Math.round((created - now) / 1000)}s in the future (clock skew)`, "clock_skew");
  }
  return { ok: true, event, hash: revocationEventHash(event), createdAtMs: created };
}

/* ------------------------------------------------------------------ */
/*  Subject matching                                                   */
/* ------------------------------------------------------------------ */

function normalizeValue(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : null;
}

function listOf(value) {
  if (value == null) return [];
  return (Array.isArray(value) ? value : [value]).map(normalizeValue).filter(Boolean);
}

/**
 * The subjects in a decision context that a scope is compared against.
 *
 * Every value is normalized: revocation is matched case-insensitively because
 * `cirvix kill Agent-X` and an agent enrolled as `agent-x` are the same agent,
 * and a mismatch there would be a revocation that silently matches nothing.
 */
export function scopeSubjects(scope, context = {}) {
  switch (scope) {
    case REVOCATION_SCOPE.GLOBAL:
      return ["*"];
    case REVOCATION_SCOPE.TENANT:
      return listOf(context.tenant);
    case REVOCATION_SCOPE.PRINCIPAL:
      return [...listOf(context.principal), ...listOf(context.agentId), ...listOf(context.principals)];
    case REVOCATION_SCOPE.IDENTITY:
      return [...listOf(context.agentId), ...listOf(context.identityKeyId)];
    case REVOCATION_SCOPE.RUNTIME:
      return [...listOf(context.runtime), ...listOf(context.environment)];
    case REVOCATION_SCOPE.AGENT:
      return listOf(context.agentId);
    case REVOCATION_SCOPE.CREDENTIAL:
      return [...listOf(context.credential), ...listOf(context.credentialId), ...listOf(context.keyId)];
    case REVOCATION_SCOPE.SESSION:
      return listOf(context.session);
    case REVOCATION_SCOPE.DELEGATION:
      return [...listOf(context.delegationIds), ...listOf(context.delegationId), ...listOf(context.delegation)];
    case REVOCATION_SCOPE.CAPABILITY:
      return listOf(context.capabilities);
    case REVOCATION_SCOPE.MISSION:
      return listOf(context.missionId);
    case REVOCATION_SCOPE.APPROVAL:
      return listOf(context.approvalId);
    case REVOCATION_SCOPE.TOOL:
      return [...listOf(context.tool), ...listOf(context.rawTool)];
    case REVOCATION_SCOPE.RESOURCE:
      return listOf(context.resource);
    default:
      return [];
  }
}

/** Resource revocations may be written as a prefix with a trailing `*`. */
function subjectMatches(scope, subject, candidate) {
  const want = normalizeValue(subject);
  const got = normalizeValue(candidate);
  if (!want || !got) return false;
  if (scope === REVOCATION_SCOPE.GLOBAL) return true;
  if (scope === REVOCATION_SCOPE.RESOURCE && want.endsWith("*")) return got.startsWith(want.slice(0, -1));
  return want === got;
}

/* ------------------------------------------------------------------ */
/*  Folding and evaluation                                             */
/* ------------------------------------------------------------------ */

function isLive(event, now) {
  if (event.effectiveAt != null) {
    const at = Date.parse(event.effectiveAt);
    if (Number.isFinite(at) && now < at) return false;
  }
  if (event.expiresAt != null) {
    const at = Date.parse(event.expiresAt);
    if (Number.isFinite(at) && now > at) return false;
  }
  return true;
}

/**
 * Folds the journal into the currently-active revocations, one per
 * `scope:subject`, by SEQUENCE — a later `release` for the same subject
 * outranks the revocation it answers, which is what makes `--release` durable
 * rather than a process-local `delete`.
 */
export function foldRevocations(events, { now = Date.now() } = {}) {
  const active = new Map();
  const ordered = [...events].sort((a, b) => a.sequence - b.sequence);
  for (const entry of ordered) {
    const event = entry.event ?? entry;
    const key = `${event.scope}:${normalizeValue(event.subject)}`;
    if (event.type === REVOCATION_ACTION.RELEASE) {
      active.delete(key);
      continue;
    }
    if (!isLive(event, now)) continue;
    const existing = active.get(key);
    if (!existing || existing.sequence < event.sequence) active.set(key, event);
  }
  return active;
}

/**
 * Evaluates a decision context against active revocations.
 *
 * Returns the FIRST match in precedence order; within a scope, the newest
 * sequence wins. Every match is a refusal — precedence decides attribution,
 * not outcome.
 */
export function evaluateRevocations(active, context = {}, { now = Date.now() } = {}) {
  if (!active || active.size === 0) return { killed: false };
  const matches = [];
  for (const event of active.values()) {
    if (!isLive(event, now)) continue;
    if (event.tenant && context.tenant && normalizeValue(event.tenant) !== normalizeValue(context.tenant)) continue;
    const candidates = scopeSubjects(event.scope, context);
    if (candidates.some((candidate) => subjectMatches(event.scope, event.subject, candidate))) {
      matches.push(event);
    }
  }
  if (matches.length === 0) return { killed: false };
  matches.sort((a, b) => {
    const rank = revocationRank(a.scope) - revocationRank(b.scope);
    if (rank !== 0) return rank;
    return b.sequence - a.sequence;
  });
  const winner = matches[0];
  return {
    killed: true,
    scope: winner.scope,
    subject: winner.subject,
    reason: winner.reason ?? `Subject ${winner.subject} is revoked (${winner.scope}).`,
    event: winner,
    matched: matches.map((e) => ({ scope: e.scope, subject: e.subject, revocationId: e.revocationId })),
  };
}

/* ------------------------------------------------------------------ */
/*  The durable, monotonic journal                                     */
/* ------------------------------------------------------------------ */

/**
 * Append-only signed revocation journal with a manifest high-water mark.
 *
 * The manifest is the anti-rollback anchor: it holds the highest epoch,
 * sequence, count and last hash ever written. Restoring an older
 * `events.jsonl` — the classic "un-revoke by backup restore" attack — leaves
 * the journal SHORTER than the manifest says it should be, or ending on a
 * different hash, and the store reports `rollbackDetected` so every decision
 * fails closed until an operator resolves it.
 */
export class RevocationStore {
  #dir;
  #manifest = { v: REVOCATION_VERSION, epoch: 0, sequence: 0, count: 0, lastHash: null };
  #entries = [];
  #fingerprint = null;

  constructor(stateDir) {
    if (typeof stateDir !== "string" || !stateDir) throw new TypeError("RevocationStore needs a state directory.");
    this.#dir = join(stateDir, "revocations");
    this.rollbackDetected = false;
    this.integrity = { ok: true, invalid: [] };
    /* WHICH KEYS MAY LIFT A CONTAINMENT. Empty means none: a journal that
       accepts a RELEASE signed by the ordinary revocation key would make the
       separation of authority decorative, because the containment could be
       undone by whoever holds the key that imposed it. The engine registers the
       release authority's public half here at init. */
    this.releasePublicKeys = [];
  }

  /** Registers the key(s) whose RELEASE events this store will accept. */
  trustReleaseKey(publicKey) {
    if (typeof publicKey !== "string" || !publicKey) return;
    if (!this.releasePublicKeys.includes(publicKey)) this.releasePublicKeys.push(publicKey);
  }

  get dir() {
    return this.#dir;
  }
  get eventsPath() {
    return join(this.#dir, "events.jsonl");
  }
  get manifestPath() {
    return join(this.#dir, "manifest.json");
  }

  get epoch() {
    return this.#manifest.epoch;
  }
  get sequence() {
    return this.#manifest.sequence;
  }
  get lastHash() {
    return this.#manifest.lastHash;
  }
  get count() {
    return this.#manifest.count;
  }

  async init() {
    await mkdir(this.#dir, { recursive: true });
    await this.refresh();
    return this;
  }

  /**
   * Re-reads disk state. Cheap when nothing changed (stat first), because this
   * runs before every decision — the price of cross-process enforcement
   * without an IPC channel.
   */
  async refresh({ force = false } = {}) {
    let info = null;
    try {
      info = await stat(this.eventsPath);
    } catch {
      info = null;
    }
    const fingerprint = info ? `${info.size}:${info.mtimeMs}` : "absent";
    if (!force && fingerprint === this.#fingerprint) return this;
    this.#fingerprint = fingerprint;

    const beforeCount = this.#entries.length;
    const beforeHash = this.#manifest.lastHash;
    const parsed = await this.#readEntries();

    /* A journal that SHRANK since we last read it is a rollback, whatever the
       manifest says: the only legitimate way entries disappear is a wipe, and
       a wipe is exactly what must not be believed. */
    if (parsed.entries.length < beforeCount) this.rollbackDetected = true;

    this.#entries = parsed.entries;
    this.integrity = { ok: parsed.invalid.length === 0, invalid: parsed.invalid };
    if (!parsed.integrityOk) this.rollbackDetected = true;

    let manifest = null;
    try {
      manifest = JSON.parse(await readFile(this.manifestPath, "utf8"));
    } catch {
      manifest = null;
    }
    if (manifest && Number.isFinite(manifest.count)) {
      if (manifest.count > parsed.entries.length) this.rollbackDetected = true;
      if (manifest.lastHash && parsed.entries.length > 0 && manifest.lastHash !== parsed.entries[parsed.entries.length - 1].hash) {
        this.rollbackDetected = true;
      }
      this.#manifest = {
        v: REVOCATION_VERSION,
        epoch: Math.max(manifest.epoch ?? 0, this.#manifest.epoch),
        sequence: Math.max(manifest.sequence ?? 0, this.#manifest.sequence),
        count: Math.max(manifest.count, parsed.entries.length),
        lastHash: manifest.lastHash ?? beforeHash ?? null,
      };
    } else {
      this.#manifest = { ...this.#manifest, count: Math.max(this.#manifest.count, parsed.entries.length), lastHash: parsed.lastHash ?? this.#manifest.lastHash };
    }
    if (this.#manifest.count < parsed.entries.length) this.#manifest.count = parsed.entries.length;
    return this;
  }

  async #readEntries() {
    let text;
    try {
      text = await readFile(this.eventsPath, "utf8");
    } catch (err) {
      if (err.code === "ENOENT") return { entries: [], invalid: [], integrityOk: true, lastHash: null };
      /* An UNREADABLE journal is not an empty one. The caller must fail closed,
         so this is reported as an integrity failure and the engine refuses. */
      return { entries: [], invalid: [{ line: -1, reason: `the journal could not be read: ${err.message}` }], integrityOk: false, lastHash: null };
    }
    const entries = [];
    const invalid = [];
    let previousHash = null;
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      let record;
      try {
        record = JSON.parse(line);
      } catch {
        invalid.push({ line: i, reason: "not valid JSON" });
        continue;
      }
      if (typeof record?.token !== "string" || typeof record?.hash !== "string") {
        invalid.push({ line: i, reason: "not a revocation record" });
        continue;
      }
      const payload = decodePayload(record.token);
      if (!payload) {
        invalid.push({ line: i, reason: "the token is not decodable" });
        continue;
      }
      const expected = revocationEventHash(payload);
      if (expected !== record.hash) {
        invalid.push({ line: i, reason: "the recorded hash does not match the payload" });
        continue;
      }
      if ((record.previousHash ?? null) !== previousHash) {
        invalid.push({ line: i, reason: "the hash chain is broken" });
        continue;
      }
      previousHash = record.hash;
      entries.push({ event: payload, token: record.token, hash: record.hash, previousHash: record.previousHash ?? null });
    }
    return { entries, invalid, integrityOk: invalid.length === 0, lastHash: previousHash };
  }

  /**
   * Appends a SIGNED event. The signature is verified here, at write time, so
   * a journal can never contain something this host cannot vouch for.
   *
   * The append is serialized through a lock file: two processes killing at the
   * same instant must not both chain onto the same predecessor and leave a
   * journal whose hash chain cannot be verified. A lock that cannot be
   * acquired is a refusal — the caller tries again rather than writing
   * unverifiable state.
   */
  async append({ event, token, publicKey, now = Date.now(), skewMs = 60_000 }) {
    if (typeof token !== "string") throw new TypeError("append needs a signed token.");
    const verified = verifyRevocationEvent(publicKey, token, { now, skewMs });
    if (!verified.ok) {
      const err = new Error(`Refusing to record an unverifiable revocation event: ${verified.reason}.`);
      err.code = verified.failed ?? "invalid_event";
      throw err;
    }
    const recorded = verified.event;
    if (event && recorded.revocationId !== event.revocationId) {
      throw new Error("The token does not carry the event it was presented with.");
    }
    /* RELEASE MUST BE SIGNED BY THE RELEASE AUTHORITY. `append` is the only
       write path into the journal, so without this check a caller holding the
       revocation key could write a release directly and skip `release()`
       entirely — the check belongs here, at the choke point, not only at the
       convenient entry point. */
    if (recorded.type === REVOCATION_ACTION.RELEASE) {
      const trusted = (this.releasePublicKeys ?? []).some((key) => key === publicKey);
      if (!trusted) {
        const err = new Error(
          "Refusing a RELEASE event that is not signed by this host's registered release authority: lifting a containment requires the release key and an authenticated release principal.",
        );
        err.code = "release_requires_authorization";
        throw err;
      }
    }
    return this.#withLock(async () => {
      // Monotonic guard at write time: local state never goes backwards.
      if (recorded.epoch < this.#manifest.epoch) {
        const err = new Error(`Refusing an event with epoch ${recorded.epoch}; local state is at epoch ${this.#manifest.epoch}.`);
        err.code = "stale_epoch";
        throw err;
      }
      await this.refresh({ force: true });
      const entry = { token, hash: verified.hash, previousHash: this.#manifest.lastHash ?? null };
      await appendFile(this.eventsPath, JSON.stringify(entry) + "\n", "utf8");
      this.#entries.push({ event: recorded, ...entry });
      this.#manifest = {
        v: REVOCATION_VERSION,
        epoch: Math.max(this.#manifest.epoch, recorded.epoch),
        sequence: Math.max(this.#manifest.sequence, recorded.sequence),
        count: this.#entries.length,
        lastHash: verified.hash,
        updatedAt: new Date(now).toISOString(),
      };
      this.#fingerprint = null; // force a re-stat on the next refresh
      await this.#writeManifest();
      return { event: recorded, hash: verified.hash };
    });
  }

  /**
   * A cross-process mutex around the append. Advisory and short-lived: the
   * point is that two writers cannot interleave, not that a hostile process
   * cannot ignore it (a hostile process with write access to this directory
   * can already corrupt the journal, which is why verification — not locking —
   * is the security boundary).
   */
  async #withLock(fn, { attempts = 50, waitMs = 4 } = {}) {
    const lockPath = join(this.#dir, "journal.lock");
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
      const err = new Error("The revocation journal is locked by another writer.");
      err.code = "journal_locked";
      throw err;
    }
    try {
      return await fn();
    } finally {
      await handle.close().catch(() => {});
      await rm(lockPath, { force: true }).catch(() => {});
    }
  }

  async #writeManifest() {
    await mkdir(this.#dir, { recursive: true });
    const tmp = this.manifestPath + ".tmp-" + randomBytes(4).toString("hex");
    await writeFile(tmp, JSON.stringify(this.#manifest, null, 2), "utf8");
    await rename(tmp, this.manifestPath);
  }

  /** Identifies the current on-disk state; used to cache expensive checks. */
  get fingerprint() {
    return this.#fingerprint;
  }

  /** Every recorded entry, oldest first. */
  entries() {
    return [...this.#entries];
  }

  /**
   * Verifies the SIGNATURE of every entry against any of the trusted keys.
   *
   * The hash chain alone is not enough: an attacker who edits a line can
   * recompute the chain hashes locally, and only a signature they cannot
   * produce stands in the way. One missing key is an empty list, which is not
   * a verification — the caller decides (the engine refuses).
   */
  verifySignatures(publicKeys = []) {
    /* An EMPTY journal is trivially verified: there is nothing to trust yet, so
       "no key" is not an integrity failure. The moment an event exists, a
       trusted key is required to believe it. */
    if (this.#entries.length === 0) return { ok: true, invalid: [] };
    const keys = (Array.isArray(publicKeys) ? publicKeys : [publicKeys]).filter((k) => typeof k === "string" && k);
    if (keys.length === 0) {
      return { ok: false, reason: "no verification key is available for the revocation journal", invalid: [] };
    }
    const invalid = [];
    this.#entries.forEach((entry, index) => {
      const ok = keys.some((key) =>
        verifyRevocationEvent(key, entry.token, { now: Date.now(), skewMs: Number.MAX_SAFE_INTEGER }).ok,
      );
      if (!ok) invalid.push({ index, revocationId: entry.event?.revocationId ?? null, reason: "no trusted key signs this event" });
    });
    return { ok: invalid.length === 0, invalid };
  }

  events() {
    return this.#entries.map((e) => e.event);
  }

  /** The active revocations right now, folded by sequence. */
  active({ now = Date.now() } = {}) {
    return foldRevocations(this.#entries, { now });
  }

  /**
   * Full integrity report: chain, count, manifest agreement. Anything other
   * than `ok: true` means the engine refuses to authorize.
   */
  verification() {
    return {
      ok: this.integrity.ok && !this.rollbackDetected,
      count: this.#entries.length,
      epoch: this.#manifest.epoch,
      sequence: this.#manifest.sequence,
      lastHash: this.#manifest.lastHash,
      rollbackDetected: this.rollbackDetected,
      invalid: this.integrity.invalid,
    };
  }
}

function decodePayload(token) {
  try {
    return JSON.parse(Buffer.from(String(token).split(".")[0], "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/*  The enforcement engine                                             */
/* ------------------------------------------------------------------ */

export const REVOCATION_UNAVAILABLE = Object.freeze({
  DENY: "deny",
  HOLD: "hold",
});

/**
 * The enforcement-side engine: a durable read view plus fail-closed policy.
 *
 * Construct one per process and hand it to `Guard`, `Pipeline` or the
 * gateway. It re-reads the journal before each evaluation, so state written by
 * another process is live here on the next call.
 */
export class RevocationEngine {
  #lastVerifiedAt = 0;
  #lastError = null;

  constructor({
    stateDir,
    store = null,
    publicKey = null,
    /* Additional trusted verification keys (a control plane's pinned key).
       Verification succeeds if ANY trusted key signs an event: an endpoint
       trusts its own operator key and the control plane it is enrolled with,
       and nothing else. */
    publicKeys = [],
    /* Staleness is about the CONTROL-PLANE feed: with only a local journal
       there is nothing to be stale about, because the journal is read on
       demand. With `federation`, an endpoint that has not heard from the
       control plane in `maxStalenessMs` is, by policy, unwilling to authorize. */
    maxStalenessMs = 15 * 60 * 1000,
    onUnavailable = REVOCATION_UNAVAILABLE.DENY,
    onClockSkew = REVOCATION_UNAVAILABLE.DENY,
    federation = null,
    /* Release is a separate authority: its key, the principal store used to
       authenticate the release officer, and the roles allowed to release. */
    releaseKey = null,
    /* The release key's PUBLIC half. A host that may not mint releases still
       needs this to VERIFY them, so a release written by the release officer is
       accepted after the fact and does not look like a forged journal. */
    releasePublicKey = null,
    principalStore = null,
    releaseRoles = null,
    principalAuthorityPublicKey = null,
    now = () => new Date(),
    log = () => {},
  } = {}) {
    if (!stateDir && !store) throw new TypeError("RevocationEngine needs a state directory.");
    this.stateDir = stateDir ?? null;
    this.store = store ?? new RevocationStore(stateDir);
    this.publicKeyOverride = publicKey;
    this.extraPublicKeys = Array.isArray(publicKeys) ? publicKeys.filter(Boolean) : [publicKeys].filter(Boolean);
    this.maxStalenessMs = maxStalenessMs;
    this.onUnavailable = onUnavailable === REVOCATION_UNAVAILABLE.HOLD ? REVOCATION_UNAVAILABLE.HOLD : REVOCATION_UNAVAILABLE.DENY;
    this.onClockSkew = onClockSkew === REVOCATION_UNAVAILABLE.HOLD ? REVOCATION_UNAVAILABLE.HOLD : REVOCATION_UNAVAILABLE.DENY;
    this.federation = federation;
    this.releaseKey = releaseKey;
    this.releasePublicKey = releasePublicKey ?? releaseKey?.publicKey ?? null;
    this.principalStore = principalStore;
    this.releaseRoles = releaseRoles;
    this.principalAuthorityPublicKey = principalAuthorityPublicKey;
    this.releaseNonces = new NonceCache({ ttlMs: 15 * 60 * 1000, max: 1000 });
    this.now = now;
    this.log = log;
    this.key = null;
    /* Set when a control plane's checkpoint shows this endpoint's local epoch
       went BACKWARDS: state restored from an older snapshot than the fleet has
       already acknowledged. Local detection cannot see that (journal and
       manifest would agree with each other); an external checkpoint can. */
    this.externalRollback = null;
  }

  async init() {
    if (!this.publicKeyOverride && this.stateDir) {
      this.key = (await loadRoleKey(this.stateDir, KEY_ROLE.REVOCATION)) ?? null;
      /* A release authority registered by public half only: this host accepts
         releases it did not mint. Absent means the host has no release
         authority at all, which is the safe default. */
      if (!this.releasePublicKey) {
        const registered = await loadRolePublicKey(this.stateDir, KEY_ROLE.RELEASE).catch(() => null);
        this.releasePublicKey = registered?.publicKey ?? null;
      }
    }
    await this.store.init();
    /* A release authorization is checked against the AUTHORITY key, because
       that is what signs a principal record — not the revocation key. Resolved
       once, here, so the release path never falls back to verifying a
       principal with a key that cannot have signed it. */
    if (this.principalStore && !this.principalAuthorityPublicKey && this.stateDir) {
      const authorityPublic = await loadRolePublicKey(this.stateDir, KEY_ROLE.AUTHORITY).catch(() => null);
      this.principalAuthorityPublicKey = authorityPublic?.publicKey ?? null;
    }
    /* The keys this engine will accept an event from. Its OWN key is always
       one of them; a pinned operator key is an addition, never a replacement —
       if it replaced, a control-plane override could silently invalidate every
       local kill on the host. */
    this.verificationKeys = this.#trusted(this.key?.publicKey);
    /* A registered release authority is trusted for verification AND for
       writing a release; anything else that appears in the journal claiming to
       be a release is refused at the write. */
    if (this.releasePublicKey) this.store.trustReleaseKey(this.releasePublicKey);
    this.#lastVerifiedAt = this.now().getTime();
    return this;
  }

  /**
   * The keys this engine accepts an event from: its own revocation key, any
   * pinned control-plane keys, and the release authority's public half. A
   * release is a different signer from a revocation by design, so it has to be
   * trusted explicitly rather than inherited.
   */
  #trusted(...extra) {
    return [
      ...this.extraPublicKeys,
      ...(this.releasePublicKey ? [this.releasePublicKey] : []),
      ...(this.publicKeyOverride ? [this.publicKeyOverride] : []),
      ...extra.filter(Boolean),
    ];
  }

  get verificationKeyCount() {
    return this.verificationKeys?.length ?? 0;
  }

  /** The signing key, generated on first use. Killing is an operator act. */
  async signingKey() {
    if (!this.stateDir) throw new Error("This engine has no state directory to hold a revocation key.");
    const record = await ensureRoleKey(this.stateDir, KEY_ROLE.REVOCATION);
    this.key = record;
    /* The key the engine signs with is a key it also TRUSTS: otherwise the
       first kill in a fresh process would write an event its own verifier
       could not check, and the boundary would refuse every call until
       restart. */
    this.verificationKeys = this.#trusted(record?.publicKey);
    this.#verifiedFingerprint = null;
    return record;
  }

  get publicKey() {
    return this.publicKeyOverride ?? this.key?.publicKey ?? null;
  }

  /**
   * Signatures are verified only when the on-disk state CHANGED (the store's
   * fingerprint), so the per-decision cost stays one `stat`, while an edit to
   * the journal — or a new event from another process — is fully checked
   * before it is believed.
   */
  async #verifyIfChanged() {
    const fingerprint = this.store.fingerprint;
    if (fingerprint === this.#verifiedFingerprint) return { ok: true };
    let result = this.store.verifySignatures(this.verificationKeys ?? []);
    /* A process that started BEFORE any revocation existed has no key yet: the
       first `cirvix kill` on the host generates one. Adopt the local
       revocation key and re-verify, so a running gateway picks up the kill
       instead of refusing everything as unverifiable.

       Adoption is permitted ONLY when this engine trusts no key at all — it
       cannot weaken a process that already has one. If events exist that a
       trusted key does not sign, that is a refusal, not a reason to start
       trusting whatever appeared in the directory. */
    if (!result.ok && this.stateDir && (this.verificationKeys ?? []).length === 0) {
      const adopted = await loadRoleKey(this.stateDir, KEY_ROLE.REVOCATION);
      if (adopted?.publicKey) {
        this.key = this.key ?? adopted;
        this.verificationKeys = [...(this.verificationKeys ?? []), adopted.publicKey];
        result = this.store.verifySignatures(this.verificationKeys);
      }
    }
    if (result.ok) this.#verifiedFingerprint = fingerprint;
    return result;
  }

  #verifiedFingerprint = null;

  /**
   * Records a revocation (or a release) durably.
   *
   * `cascade` optionally names related authorities to revoke with it —
   * delegations derived from an agent, for instance — so a kill does not leave
   * usable downstream authority alive.
   */
  async revoke({
    scope,
    subject,
    tenant = null,
    reason = null,
    issuer = null,
    principal = null,
    ttlMs = null,
    effectiveAt = null,
    policyVersion = null,
    action = REVOCATION_ACTION.REVOKE,
    cascade = [],
    /* Set when this event is a CONSEQUENCE of another one (a delegation revoked
       because the agent that issued it was revoked). Carried into the signed
       payload so the journal explains itself without a second lookup. */
    cascadeOf = null,
  } = {}) {
    /* RELEASING is not a kind of revoking. If the action were reachable here it
       would let anyone who can call `revoke` undo a containment with the local
       revocation key — the exact downgrade `release()` exists to prevent. The
       signed release event is written by `release()` instead, under the release
       key and an authenticated principal. */
    if (action === REVOCATION_ACTION.RELEASE) {
      const err = new Error(
        "A release cannot be written through revoke(): lifting a containment requires the release authority and an authenticated release principal.",
      );
      err.code = "release_requires_authorization";
      throw err;
    }
    const key = await this.signingKey();
    const now = this.now().getTime();
    const events = [];
    const targets = [{ scope, subject, cascadeOf }, ...cascade.map((c) => ({ ...c, cascadeOf: c.cascadeOf ?? cascadeOf }))];
    for (const target of targets) {
      const event = buildRevocationEvent({
        action,
        scope: target.scope,
        subject: target.subject,
        tenant,
        issuer: issuer ?? principal ?? "operator",
        principal,
        reason,
        createdAt: new Date(now).toISOString(),
        effectiveAt,
        expiresAt: ttlMs == null ? null : new Date(now + ttlMs).toISOString(),
        epoch: Math.floor(now / 1000),
        sequence: this.store.sequence + events.length + 1,
        policyVersion,
        previousHash: this.store.lastHash,
        cascadeOf: target.cascadeOf ?? null,
      });
      const token = signRevocationEvent({ event, privateKey: key.privateKey, keyId: key.keyId });
      const recorded = await this.store.append({ event, token, publicKey: key.publicKey, now, skewMs: Number.MAX_SAFE_INTEGER });
      events.push(recorded.event);
    }
    this.#lastVerifiedAt = now;
    this.log(`revocation recorded: ${events.map((e) => `${e.type} ${e.scope}:${e.subject}`).join(", ")}`);
    return events;
  }

  /**
   * RELEASE — undoing a containment. Deliberately harder than imposing one.
   *
   * Imposing a revocation needs the local revocation key on the host. RELEASING
   * needs THREE things that a same-user process holding only that key does not
   * have:
   *
   *   1. the RELEASE role key, which is NOT generated in the state directory —
   *      it is supplied by the release officer and registered here by public
   *      half only, so a compromised runtime cannot mint a well-formed release;
   *   2. an AUTHENTICATED PRINCIPAL holding a release role (owner or
   *      release-officer) — possession of that person's key over a fresh
   *      challenge, checked against the host-signed principal record;
   *   3. an explicit scope and reason, recorded on the signed event, plus a
   *      single-use challenge — so a captured authorization cannot be replayed
   *      to release something else later.
   *
   * If no release authority is registered, release is IMPOSSIBLE. That is the
   * intended failure direction: containment that cannot be undone locally is a
   * smaller problem than containment that can be undone by anyone with read
   * access to the state directory.
   */
  async release({ revocationId, reason = "released by operator", authorization = null, scope = null, now = null } = {}) {
    const target = this.store.events().find((e) => e.revocationId === revocationId);
    if (!target) {
      const err = new Error(`No revocation event ${revocationId} in this state directory.`);
      err.code = "unknown_revocation";
      throw err;
    }
    const releaseKey = this.releaseKey ?? (this.stateDir ? await loadRoleKey(this.stateDir, KEY_ROLE.RELEASE) : null);
    /* A release officer's key is supplied as a FILE, not as a state-directory
       record (that is the difference between possessing release authority and
       being the runtime). The public half is derived from the private half so
       the journal can verify what it just wrote. */
    if (releaseKey?.privateKey && !releaseKey.publicKey) {
      releaseKey.publicKey = createPublicKey(releaseKey.privateKey).export({ type: "spki", format: "pem" });
    }
    if (!releaseKey?.privateKey) {
      const err = new Error(
        "No release authority is available on this host: releasing a revocation requires the release key, which is not kept in the state directory.",
      );
      err.code = "release_authority_missing";
      throw err;
    }
    /* Trust the release signer before writing with it, or the engine would
       refuse its own journal on the next read. */
    this.releasePublicKey = this.releasePublicKey ?? releaseKey.publicKey ?? null;
    this.verificationKeys = this.#trusted(this.key?.publicKey);
    if (this.releasePublicKey) this.store.trustReleaseKey(this.releasePublicKey);
    this.#verifiedFingerprint = null;
    const check = await this.authorizeRelease({ revocationId, action: `release:${scope ?? target.scope}:${target.subject}`, authorization, now });
    if (!check.authorized) {
      const err = new Error(`Release refused: ${check.reason}`);
      err.code = check.code ?? "release_unauthorized";
      throw err;
    }

    const at = now ?? this.now().getTime();
    const event = buildRevocationEvent({
      action: REVOCATION_ACTION.RELEASE,
      scope: scope ?? target.scope,
      subject: target.subject,
      tenant: target.tenant,
      issuer: target.issuer,
      principal: check.principal.principalId,
      reason,
      createdAt: new Date(at).toISOString(),
      epoch: Math.floor(at / 1000),
      sequence: this.store.sequence + 1,
      policyVersion: target.policyVersion,
      previousHash: this.store.lastHash,
      releasedBy: {
        principalId: check.principal.principalId,
        role: check.principal.role,
        tenantId: check.principal.tenantId,
        authenticationMethod: check.principal.authenticationMethod,
        challenge: check.challenge,
        releaseKeyId: releaseKey.keyId ?? null,
      },
    });
    const token = signRevocationEvent({ event, privateKey: releaseKey.privateKey, keyId: releaseKey.keyId });
    const recorded = await this.store.append({ event, token, publicKey: releaseKey.publicKey, now: at, skewMs: Number.MAX_SAFE_INTEGER });
    this.log(`release recorded: ${event.scope}:${event.subject} by ${check.principal.principalId} (${check.principal.role})`);
    return recorded.event;
  }

  /**
   * The authorization half of release, in one place so the CLI, a library
   * caller and a control plane cannot each invent their own weaker check.
   */
  async authorizeRelease({ revocationId, action, authorization = null, now = null }) {
    if (!authorization) {
      return { authorized: false, code: "release_unauthorized", reason: "no authenticated release authorization was presented" };
    }
    if (!this.principalStore) {
      return { authorized: false, code: "release_unauthorized", reason: "this host has no principal store, so no principal can be authenticated" };
    }
    const requiredRoles = this.releaseRoles ?? RELEASE_ROLES;
    const check = await authenticatePrincipal({
      store: this.principalStore,
      authorityPublicKey: this.principalAuthorityPublicKey ?? null,
      principalId: authorization.principalId,
      action,
      nonce: authorization.nonce,
      signature: authorization.signature,
      requiredRoles: [...requiredRoles],
      expectedTenant: authorization.tenantId ?? null,
      nonces: this.releaseNonces,
      now: () => new Date(now ?? this.now().getTime()),
    });
    if (!check.authenticated) return { authorized: false, code: check.code, reason: check.reason };
    if (!authorization.nonce || typeof authorization.nonce !== "string") {
      return { authorized: false, code: "release_unauthorized", reason: "a release authorization must carry a single-use nonce" };
    }
    return { authorized: true, principal: check.principal, challenge: authorization.nonce, action, revocationId };
  }

  /**
   * An authorization for a release, as a release officer would present it: the
   * principal, a single-use nonce and a signature over
   * `cirvix-principal/1|<principalId>|release:<scope>:<subject>|<nonce>`.
   * Exposed so a CLI and a control plane produce exactly the same artifact.
   */
  async issueReleaseChallenge({ principalId, revocationId, scope, subject, nonce = null } = {}) {
    const target = this.store.events().find((e) => e.revocationId === revocationId);
    if (!target) {
      const err = new Error(`No revocation event ${revocationId} in this state directory.`);
      err.code = "unknown_revocation";
      throw err;
    }
    const action = `release:${scope ?? target.scope}:${subject ?? target.subject}`;
    return issueChallenge({ principalId, action, nonce, now: this.now });
  }

  /** Active revocations, newest first within a scope. */
  list({ now = null } = {}) {
    const active = this.store.active({ now: now ?? this.now().getTime() });
    return [...active.values()].sort((a, b) => revocationRank(a.scope) - revocationRank(b.scope) || b.sequence - a.sequence);
  }

  /**
   * Checks a context, refreshing from disk first.
   *
   * Fail-closed contract: any integrity problem, unreadable state, clock
   * disagreement or stale federation feed returns `unavailable: true` with a
   * reason — never `killed: false`.
   */
  async evaluate(context = {}, { now = null } = {}) {
    const at = now ?? this.now().getTime();
    const unavailable = (reason, mode = this.onUnavailable, extra = {}) => ({
      killed: false,
      unavailable: true,
      mode,
      reason,
      ...extra,
    });
    try {
      await this.store.refresh();
    } catch (err) {
      this.#lastError = err;
      return unavailable(`revocation state could not be read: ${err.message}`);
    }
    const signatures = await this.#verifyIfChanged();
    if (!signatures.ok) {
      return unavailable(`the revocation journal is not signed by a trusted key: ${signatures.reason ?? "signature verification failed"}`, REVOCATION_UNAVAILABLE.DENY, {
        invalid: signatures.invalid ?? [],
      });
    }
    const verification = this.store.verification();
    if (!verification.ok) {
      return unavailable(
        verification.rollbackDetected
          ? "the revocation journal rolled back or its hash chain is broken"
          : "the revocation journal failed verification",
        REVOCATION_UNAVAILABLE.DENY,
        { verification },
      );
    }
    /* EXTERNAL (fleet) ROLLBACK DETECTION. Local detection compares the journal
       with the manifest in the same directory, so it cannot see a restore of
       BOTH. A control plane that has already acknowledged an epoch ahead of
       this manifest can: state that went backwards relative to a checkpoint the
       fleet issued is exactly that attack. Only enforced when a checkpoint has
       actually been received. */
    if (this.externalRollback) {
      const { acknowledgedEpoch, acknowledgedSequence, source } = this.externalRollback;
      if (verification.epoch >= acknowledgedEpoch) {
        this.externalRollback = null;
      } else {
        return unavailable(
          `this endpoint's revocation state is epoch ${verification.epoch}/seq ${verification.sequence}, behind the checkpoint ${source ?? "the control plane"} already acknowledged (epoch ${acknowledgedEpoch}/seq ${acknowledgedSequence ?? "?"}) — local state was rolled back`,
          REVOCATION_UNAVAILABLE.DENY,
          { verification, externalRollback: this.externalRollback },
        );
      }
    }
    /* Clock disagreement: a recorded event dated in the future means this host
       cannot tell whether a revocation it should enforce has arrived. Refusing
       is the only direction that cannot un-revoke something. */
    const skewed = this.store.events().some((e) => Date.parse(e.createdAt) > at + 60_000);
    if (skewed) {
      return unavailable("a revocation event is dated in the future (clock skew)", this.onClockSkew);
    }
    if (this.federation) {
      const age = at - this.#lastVerifiedAt;
      if (Number.isFinite(this.maxStalenessMs) && age > this.maxStalenessMs) {
        return unavailable(`the revocation feed has not been verified for ${Math.round(age / 1000)}s (stale)`, this.onUnavailable, {
          stateAgeMs: age,
        });
      }
    }
    this.#lastVerifiedAt = at;
    const result = evaluateRevocations(this.store.active({ now: at }), context, { now: at });
    return { ...result, state: { epoch: verification.epoch, sequence: verification.sequence, count: verification.count } };
  }

  /** Synchronous view for callers that already refreshed (tests, reporting). */
  evaluateLocal(context = {}, { now = null } = {}) {
    const at = now ?? this.now().getTime();
    return evaluateRevocations(this.store.active({ now: at }), context, { now: at });
  }

  /**
   * Pulls signed events from the control plane, verifies them against the
   * PINNED operator key, and only then appends what is genuinely newer.
   *
   * Anti-rollback at the federation edge: an event whose epoch is not ahead of
   * local state is ignored (it cannot un-revoke anything), and an event that
   * VERIFIES but conflicts with an equal-epoch local event is refused and
   * reported rather than silently replacing local state.
   *
   * Latency is MEASURED: creation → receipt → activation, per event.
   */
  async sync({ fetchImpl = globalThis.fetch, url, apiKey = null, operatorPublicKey = null, timeoutMs = 10_000 } = {}) {
    if (typeof fetchImpl !== "function") throw new TypeError("sync needs a fetch implementation.");
    if (!url) throw new TypeError("sync needs a control-plane URL.");
    const key = operatorPublicKey ?? this.publicKey;
    if (!key) throw new Error("sync needs an operator public key to verify events with.");
    const since = this.store.epoch;
    const receivedAt = this.now().getTime();
    const response = await fetchImpl(`${url}${url.includes("?") ? "&" : "?"}since=${encodeURIComponent(since)}`, {
      headers: apiKey ? { authorization: `Bearer ${apiKey}` } : {},
      signal: AbortSignal.timeout ? AbortSignal.timeout(timeoutMs) : undefined,
    });
    if (!response?.ok) throw new Error(`The revocation feed returned ${response?.status ?? "no response"}.`);
    const body = await response.json();
    const tokens = Array.isArray(body?.events) ? body.events : [];
    /* The checkpoint is the fleet's view of THIS endpoint's high-water mark. A
       later honest sync that reports a higher acknowledged epoch than local
       state means local state went backwards — restoring journal + manifest
       together, which local verification cannot see. */
    const checkpoint = body?.checkpoint ?? null;
    if (checkpoint && Number.isFinite(checkpoint.acknowledgedEpoch)) {
      if (checkpoint.acknowledgedEpoch > this.store.epoch) {
        this.externalRollback = {
          detectedAt: new Date(receivedAt).toISOString(),
          acknowledgedEpoch: checkpoint.acknowledgedEpoch,
          acknowledgedSequence: checkpoint.acknowledgedSequence ?? null,
          acknowledgedHash: checkpoint.acknowledgedHash ?? null,
          source: checkpoint.source ?? url,
        };
      } else if (this.externalRollback && checkpoint.acknowledgedEpoch <= this.store.epoch) {
        this.externalRollback = null;
      }
    }
    const measurements = [];
    let accepted = 0;
    for (const token of tokens) {
      const verified = verifyRevocationEvent(key, token, { now: receivedAt, skewMs: 120_000 });
      if (!verified.ok) {
        measurements.push({ status: "rejected", reason: verified.reason });
        continue;
      }
      const event = verified.event;
      if (event.epoch <= this.store.epoch) {
        measurements.push({ revocationId: event.revocationId, status: "ignored_stale_epoch", epoch: event.epoch });
        continue;
      }
      try {
        await this.store.append({ event, token, publicKey: key, now: receivedAt, skewMs: Number.MAX_SAFE_INTEGER });
      } catch (err) {
        measurements.push({ revocationId: event.revocationId, status: "refused", reason: err.message });
        continue;
      }
      accepted += 1;
      const activatedAt = this.now().getTime();
      measurements.push({
        revocationId: event.revocationId,
        scope: event.scope,
        subject: event.subject,
        status: "applied",
        createdMs: Date.parse(event.createdAt),
        receivedMs: receivedAt,
        activatedMs: activatedAt,
        propagationMs: activatedAt - Date.parse(event.createdAt),
      });
    }
    this.#lastVerifiedAt = this.now().getTime();
    return {
      accepted,
      considered: tokens.length,
      measurements,
      epoch: this.store.epoch,
      sequence: this.store.sequence,
      checkpoint: checkpoint
        ? {
            acknowledgedEpoch: checkpoint.acknowledgedEpoch ?? null,
            acknowledgedSequence: checkpoint.acknowledgedSequence ?? null,
            source: checkpoint.source ?? url,
            rollbackDetected: Boolean(this.externalRollback),
          }
        : null,
      externalRollback: this.externalRollback,
    };
  }
}

/* ------------------------------------------------------------------ */
/*  Cascade                                                            */
/* ------------------------------------------------------------------ */

/**
 * Revokes the downstream authority that depends on a revoked subject.
 *
 * The fabric is the source of truth, so a cascade is written as events, not
 * as an in-memory mutation: revoking agent X writes DELEGATION revocations for
 * every grant X was the subject of, and marks the enrolled agent record
 * REVOKED so the identity boundary refuses its credentials. A restart, another
 * process, or a different instance reading the same journal sees all of it.
 */
export async function cascadeRevocation({ engine, event, delegationStore = null, agentStore = null, reason = null, issuer = null }) {
  const derived = [];
  const subject = normalizeValue(event.subject);
  const isWho = [REVOCATION_SCOPE.IDENTITY, REVOCATION_SCOPE.AGENT, REVOCATION_SCOPE.PRINCIPAL, REVOCATION_SCOPE.GLOBAL].includes(event.scope);

  if (isWho && agentStore && event.scope !== REVOCATION_SCOPE.GLOBAL) {
    /* The enrolled record is what the identity boundary reads: without this,
       the agent's credential would keep verifying and INV-006 would hold only
       on the delegation path. */
    const record = await agentStore.setStatus(subject, "revoked", { reason: reason ?? event.reason ?? "revoked" });
    if (record) derived.push({ kind: "identity-revoked", agentId: subject });
  }

  if (isWho && delegationStore) {
    const grants = await delegationStore.listGrants();
    for (const grant of grants) {
      if (normalizeValue(grant.subject) !== subject) continue;
      if (delegationStore.isRevoked(grant.id)) continue;
      /* Durable in BOTH stores: the delegation store's own journal (which the
         verifier checks at use time) and the revocation fabric (which every
         process reads), so neither can be forgotten by the other. `revoke`
         returns the whole derived cascade, so the fabric records an event for
         every descendant too — a child whose parent was killed is itself
         revoked state, not an implied consequence. */
      const cascade = await delegationStore.revoke(grant.id, reason ?? "parent authority revoked");
      for (const id of cascade) {
        const [written] = await engine.revoke({
          scope: REVOCATION_SCOPE.DELEGATION,
          subject: id,
          tenant: grant.tenant ?? null,
          reason: reason ?? `derived from revoked ${event.scope} ${event.subject}`,
          issuer: issuer ?? event.issuer,
          cascadeOf: event.revocationId,
        });
        derived.push({ kind: "delegation-revoked", id, revocationId: written?.revocationId ?? null });
      }
    }
  }
  return derived;
}

/* ------------------------------------------------------------------ */
/*  Decision integration                                               */
/* ------------------------------------------------------------------ */

/**
 * Applies revocation state to a decision. Mirrors `enforceKillSwitch`, and is
 * called beside it on the one decision path so no surface can enforce one and
 * not the other.
 */
export function enforceRevocation(decision, engine, context = {}) {
  if (!engine) return decision;
  let result;
  try {
    result = typeof engine.evaluateSync === "function" ? engine.evaluateSync(context) : engine.evaluate(context);
  } catch (err) {
    return {
      ...decision,
      decision: DECISION.DENY,
      verdict: "deny",
      rule: "revocation-unavailable",
      reason: `The revocation state could not be evaluated: ${err.message}`,
      enforced: true,
      risk: "critical",
    };
  }
  if (result && typeof result.then === "function") {
    /* An async engine reached a synchronous call site: refuse rather than
       authorize on a state that has not been read. The Guard/Pipeline call
       sites await `enforceRevocationAsync`. */
    return {
      ...decision,
      decision: DECISION.DENY,
      verdict: "deny",
      rule: "revocation-unavailable",
      reason: "The revocation state is asynchronous and was not awaited; refusing rather than authorizing on unread state.",
      enforced: true,
      risk: "critical",
    };
  }
  return applyRevocationResult(decision, result);
}

/** The async form, used by Guard and Pipeline (both are async). */
export async function enforceRevocationAsync(decision, engine, context = {}) {
  if (!engine) return decision;
  try {
    const result = await engine.evaluate(context);
    return applyRevocationResult(decision, result);
  } catch (err) {
    return {
      ...decision,
      decision: DECISION.DENY,
      verdict: "deny",
      rule: "revocation-unavailable",
      reason: `The revocation state could not be evaluated: ${err.message}`,
      enforced: true,
      risk: "critical",
    };
  }
}

function applyRevocationResult(decision, result) {
  if (!result) return decision;
  if (result.unavailable) {
    const hold = result.mode === REVOCATION_UNAVAILABLE.HOLD;
    return {
      ...decision,
      decision: hold ? DECISION.REQUIRE_APPROVAL : DECISION.DENY,
      verdict: hold ? "hold" : "deny",
      rule: hold ? "revocation-state-stale" : "revocation-unavailable",
      reason: `The revocation state could not be trusted: ${result.reason}.`,
      enforced: true,
      ...(hold ? {} : { risk: "critical" }),
      revocation: { unavailable: true, reason: result.reason },
    };
  }
  if (result.killed) {
    return {
      ...decision,
      decision: DECISION.DENY,
      verdict: "deny",
      rule: `revoked-${String(result.scope).replace(/_/g, "-")}`,
      reason: result.reason,
      remediation: "The authority this call depends on has been revoked. Ask an operator to release it before retrying.",
      enforced: true,
      risk: "critical",
      revocation: {
        scope: result.scope,
        subject: result.subject,
        revocationId: result.event?.revocationId ?? null,
        issuer: result.event?.issuer ?? null,
        matched: result.matched ?? [],
      },
    };
  }
  return decision;
}

/** The context the engines and the CLI both build, from one place. */
export function revocationContextFor({
  agentId = null,
  tenant = null,
  runtime = null,
  environment = null,
  tool = null,
  rawTool = null,
  resource = null,
  session = null,
  approvalId = null,
  missionId = null,
  capabilities = [],
  delegationIds = [],
  principals = [],
  credential = null,
  keyId = null,
  identityKeyId = null,
} = {}) {
  return {
    agentId,
    tenant,
    runtime,
    environment,
    tool,
    rawTool,
    resource,
    session,
    approvalId,
    missionId,
    capabilities,
    delegationIds,
    principals,
    credential,
    keyId,
    identityKeyId,
  };
}
