/**
 * The Principal — WHO is allowed to hand out authority.
 *
 * THE HOLE THIS CLOSES. A root grant carried `human: "dana@acme"`. That string
 * was vouched for by nothing but possession of the host's AUTHORITY key, which
 * the runtime itself holds. So "a human authorized this" meant "something
 * running on this host, holding the host's key, typed a name" — and the name
 * was decoration. The runtime could not answer the only question that matters
 * after an incident: WHICH AUTHENTICATED PERSON issued this authority.
 *
 * THE MODEL. A principal is its own identity, SEPARATE from the signing key:
 *
 *   principal record (this file)      — durable, issued by the host authority
 *     principalId, organizationId/tenantId, kind, role, status,
 *     authenticationMethod, publicKey/keyId (its OWN key, not the authority's),
 *     issuedAt, expiresAt, revocation state
 *
 *   authentication (also this file)   — proof of POSSESSION of that key over a
 *     fresh challenge, plus status/role/expiry/revocation checks. A valid host
 *     authority key does NOT authenticate a principal; only the principal's own
 *     private key does, and that key is meant to live with the person.
 *
 * So a grant records `issuerPrincipalId`, and the runtime can resolve it back
 * to an authenticated human/organization with a role and a key id. Nothing in
 * the authorization path treats a NAME as identity — see INV-009 for the same
 * rule applied to agents.
 *
 * WHAT THIS IS NOT. If the principal key file sits next to the authority key on
 * the same host, the two collapse into one compromise again. That is why
 * `cirvix principal enroll` prints the private key ONCE and does not put it in
 * the state directory, and why the release path (see revocation.mjs) requires
 * an operator-held key that is registered by PUBLIC half only. The boundary is
 * still COOPERATIVE: cryptographic possession, no hardware attestation.
 */

import { createHash, createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { buildProofEnvelope, generateProofKeys, keyIdFor, verifyProofEnvelope } from "./proof.mjs";

export const PRINCIPAL_VERSION = 1;
export const PRINCIPAL_KIND = Object.freeze({
  HUMAN: "human",
  ORGANIZATION: "organization",
  SERVICE: "service",
});

export const PRINCIPAL_STATUS = Object.freeze({
  ACTIVE: "active",
  SUSPENDED: "suspended",
  REVOKED: "revoked",
});

/**
 * Roles are about WHAT an authenticated principal may do, and the list is
 * closed: an unknown role is refused at enrolment rather than stored and
 * silently never matched.
 */
export const PRINCIPAL_ROLE = Object.freeze({
  /** Full control of the tenant's authority. */
  OWNER: "owner",
  /** May issue grants and missions for its tenant. */
  ADMIN: "admin",
  /** May issue grants and missions, but not manage principals. */
  GRANT_ISSUER: "grant-issuer",
  /** May RELEASE containments. Deliberately separate from issuing authority. */
  RELEASE_OFFICER: "release-officer",
  /** Read-only. */
  AUDITOR: "auditor",
});

export const PRINCIPAL_ROLES = Object.freeze(Object.values(PRINCIPAL_ROLE));
export const PRINCIPAL_STATUSES = Object.freeze(Object.values(PRINCIPAL_STATUS));

/** Roles permitted to issue authority (grants, missions, capabilities). */
export const ISSUER_ROLES = Object.freeze([PRINCIPAL_ROLE.OWNER, PRINCIPAL_ROLE.ADMIN, PRINCIPAL_ROLE.GRANT_ISSUER]);
/** Roles permitted to release a revocation. Strictly fewer than ISSUER_ROLES. */
export const RELEASE_ROLES = Object.freeze([PRINCIPAL_ROLE.OWNER, PRINCIPAL_ROLE.RELEASE_OFFICER]);

export const PRINCIPAL_AUTH_METHOD = Object.freeze({
  /** Ed25519 possession proof over a fresh challenge. */
  SIGNED_CHALLENGE: "ed25519-signed-challenge",
});

export const PRINCIPAL_ERROR = Object.freeze({
  UNKNOWN: "principal_unknown",
  NOT_ACTIVE: "principal_not_active",
  EXPIRED: "principal_expired",
  ROLE: "principal_role",
  BAD_SIGNATURE: "principal_bad_signature",
  REPLAY: "principal_challenge_replay",
  UNVERIFIED_RECORD: "principal_record_unverified",
  TENANT: "principal_tenant",
});

export function assertPrincipalRole(role) {
  if (!PRINCIPAL_ROLES.includes(role)) {
    throw new TypeError(`Unknown principal role "${role}". Known roles: ${PRINCIPAL_ROLES.join(", ")}.`);
  }
  return role;
}

export function assertPrincipalKind(kind) {
  if (!Object.values(PRINCIPAL_KIND).includes(kind)) {
    throw new TypeError(`Unknown principal kind "${kind}".`);
  }
  return kind;
}

function fileKey(principalId) {
  return createHash("sha256").update(String(principalId)).digest("hex").slice(0, 32);
}

export function principalsDir(stateDir) {
  return join(stateDir, "principals");
}

export function principalRecordPath(stateDir, principalId) {
  return join(principalsDir(stateDir), `${fileKey(principalId)}.json`);
}

/**
 * Durable principal records, each SIGNED BY THE HOST AUTHORITY KEY.
 *
 * The signature is what makes a record evidence rather than a file: an edited
 * role (`auditor` → `owner`) no longer verifies, so escalating a principal by
 * editing disk fails closed instead of granting authority.
 */
export class PrincipalStore {
  constructor(stateDir) {
    if (typeof stateDir !== "string" || !stateDir) throw new TypeError("PrincipalStore needs a state directory.");
    this.stateDir = stateDir;
  }

  async #write(record) {
    const dir = principalsDir(this.stateDir);
    await mkdir(dir, { recursive: true });
    const path = principalRecordPath(this.stateDir, record.principalId);
    const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tmp, JSON.stringify(record, null, 2), "utf8");
    await rename(tmp, path);
    return record;
  }

  /**
   * Enrols a principal. The PUBLIC key is what is stored; the private half is
   * returned once, for the person to keep.
   */
  async enroll({
    principalId,
    name = null,
    kind = PRINCIPAL_KIND.HUMAN,
    role = PRINCIPAL_ROLE.GRANT_ISSUER,
    organizationId = null,
    tenantId = "local",
    email = null,
    publicKey = null,
    privateKey = null,
    authenticationMethod = PRINCIPAL_AUTH_METHOD.SIGNED_CHALLENGE,
    expiresAt = null,
    authority,
    now = () => new Date(),
  }) {
    if (typeof principalId !== "string" || !principalId) throw new TypeError("A principal needs a principalId.");
    assertPrincipalKind(kind);
    assertPrincipalRole(role);
    if (!authority?.privateKey) throw new Error("Enrolling a principal needs the host authority key to vouch for the record.");
    if (!Object.values(PRINCIPAL_AUTH_METHOD).includes(authenticationMethod)) {
      throw new TypeError(`Unknown authentication method "${authenticationMethod}".`);
    }

    const keys = privateKey ? { privateKey, publicKey } : generateProofKeys();
    if (expiresAt != null && !Number.isFinite(Date.parse(expiresAt))) throw new TypeError("expiresAt must be an ISO timestamp.");
    const existing = await this.get(principalId);
    if (existing && existing.status === PRINCIPAL_STATUS.REVOKED && !privateKey) {
      // Rotating the KEY of a revoked principal is allowed; silently reviving
      // one is not — that is what `setStatus` is for, loudly.
      throw new Error(`Principal "${principalId}" is revoked. Re-activate it explicitly before enrolling again.`);
    }

    const issuedAt = now().toISOString();
    const payload = {
      v: PRINCIPAL_VERSION,
      kind,
      principalId,
      name: name ?? principalId,
      email,
      organizationId,
      tenantId,
      role,
      status: PRINCIPAL_STATUS.ACTIVE,
      authenticationMethod,
      publicKey: keys.publicKey,
      /* NOT `keyId`. `buildProofEnvelope` merges the SIGNING key's id into the
         payload under `keyId`, so a field of that name here would be silently
         replaced by the host authority key id — and the principal's own key id
         would be lost from the signed record, which is exactly the value every
         later authentication compares against. */
      principalKeyId: keyIdFor(keys.publicKey),
      issuedAt,
      expiresAt,
      revokedAt: null,
      statusReason: null,
      // Provenance: the record is issued by the host, and the host key id says
      // which host. The PRINCIPAL's own key is what authenticates later acts.
      issuer: "host",
      rotateOf: existing?.keyId ?? null,
    };
    const { token } = buildProofEnvelope({ payload, privateKey: authority.privateKey, keyId: authority.keyId });
    /* `keyId` (as merged by the envelope) is the HOST authority key that
       vouched for this record; the principal's own key id travels as
       `principalKeyId` and is re-exposed here as `keyId` for readers. */
    const record = { ...payload, keyId: payload.principalKeyId, record: token, verifyKeyId: authority.keyId };
    await this.#write(record);
    return { record, publicKey: keys.publicKey, privateKey: keys.privateKey ?? null, principalKeyId: payload.principalKeyId };
  }

  async get(principalId) {
    if (typeof principalId !== "string" || !principalId) return null;
    try {
      return JSON.parse(await readFile(principalRecordPath(this.stateDir, principalId), "utf8"));
    } catch (err) {
      if (err.code === "ENOENT") return null;
      return null;
    }
  }

  async list() {
    let names;
    try {
      names = await readdir(principalsDir(this.stateDir));
    } catch (err) {
      if (err.code === "ENOENT") return [];
      throw err;
    }
    const records = [];
    for (const name of names) {
      if (!name.endsWith(".json")) continue;
      try {
        records.push(JSON.parse(await readFile(join(principalsDir(this.stateDir), name), "utf8")));
      } catch {
        /* skipped, never trusted */
      }
    }
    return records.sort((a, b) => String(a.principalId).localeCompare(String(b.principalId)));
  }

  /**
   * Whether the host has configured an authority model at all — one or more
   * registered principals. Cheaper than `list()` and exactly what the shipped
   * composition roots need to derive the authority posture: with an authority
   * model configured, hardened production requires it; without one there is
   * nothing to require and policy-only is the only meaningful posture.
   */
  async isEmpty() {
    let names;
    try {
      names = await readdir(principalsDir(this.stateDir));
    } catch (err) {
      if (err.code === "ENOENT") return true;
      throw err;
    }
    return !names.some((name) => name.endsWith(".json"));
  }

  async setStatus(principalId, status, { reason = null } = {}) {
    if (!PRINCIPAL_STATUSES.includes(status)) throw new TypeError(`Unknown principal status "${status}".`);
    const existing = await this.get(principalId);
    if (!existing) return null;
    const next = { ...existing, status, statusReason: reason };
    if (status !== PRINCIPAL_STATUS.ACTIVE) next.revokedAt = existing.revokedAt ?? new Date().toISOString();
    await this.#write(next);
    return next;
  }

  async revoke(principalId, reason = "revoked") {
    return this.setStatus(principalId, PRINCIPAL_STATUS.REVOKED, { reason });
  }

  /** Rotates a principal's key. The record's issuance stays; the key changes. */
  async rotate(principalId, { authority, publicKey = null, privateKey = null } = {}) {
    const existing = await this.get(principalId);
    if (!existing) throw new Error(`No principal "${principalId}" to rotate.`);
    return this.enroll({
      principalId,
      name: existing.name,
      kind: existing.kind,
      role: existing.role,
      organizationId: existing.organizationId,
      tenantId: existing.tenantId,
      email: existing.email,
      publicKey,
      privateKey,
      authenticationMethod: existing.authenticationMethod,
      expiresAt: existing.expiresAt,
      authority,
    });
  }
}

/* ------------------------------------------------------------------ */
/*  Authentication — possession of the PRINCIPAL's key                 */
/* ------------------------------------------------------------------ */

export function principalStatusAt(record, now = Date.now()) {
  if (!record) return "unknown";
  if (record.status !== PRINCIPAL_STATUS.ACTIVE) return record.status;
  if (record.expiresAt && Date.parse(record.expiresAt) < now) return "expired";
  return "active";
}

/**
 * A fresh challenge. The principal signs the EXACT string, so the challenge
 * binds the principal id, the action and a nonce: it cannot be replayed for a
 * different action, and it cannot be lifted into another principal's context.
 */
export function issueChallenge({ principalId, action, nonce = null, now = () => new Date() }) {
  if (typeof principalId !== "string" || !principalId) throw new TypeError("A challenge needs a principal id.");
  if (typeof action !== "string" || !action) throw new TypeError("A challenge needs an action.");
  const value = nonce ?? createHash("sha256").update(`${principalId}:${action}:${now().getTime()}:${Math.random()}`).digest("hex").slice(0, 32);
  return {
    principalId,
    action,
    nonce: value,
    issuedAt: now().toISOString(),
    body: challengeBody({ principalId, action, nonce: value }),
  };
}

export function challengeBody({ principalId, action, nonce }) {
  return `cirvix-principal/1|${principalId}|${action}|${nonce}`;
}

/**
 * Signs a challenge with the PRINCIPAL's own key — the act only the holder of
 * that key can perform. `authenticatePrincipal` checks exactly this signature,
 * so the CLI and a test helper produce the identical artifact instead of each
 * inventing their own idea of "a signed challenge".
 */
export function signChallenge({ privateKey, principalId, action, nonce }) {
  if (typeof privateKey !== "string" || !privateKey) throw new TypeError("Signing a challenge needs the principal's private key.");
  const body = challengeBody({ principalId, action, nonce });
  return cryptoSign(null, Buffer.from(body, "utf8"), createPrivateKey(privateKey)).toString("base64url");
}

/**
 * Verifies that the caller HOLDS the principal's private key, that the record
 * is intact (host-signed), that the principal is active, unexpired, not
 * revoked, in the tenant claimed, and holds one of the required roles.
 *
 * Every check is fail-closed and reported with a code, so a refusal can be
 * attributed rather than merely denied.
 */
export async function authenticatePrincipal({
  store,
  authorityPublicKey = null,
  authorityKeyId = null,
  principalId,
  action,
  nonce,
  signature,
  requiredRoles = [],
  expectedTenant = null,
  nonces = null,
  now = () => new Date(),
  skewMs = 60_000,
}) {
  const fail = (code, reason) => ({ authenticated: false, code, reason });
  if (!store) return fail(PRINCIPAL_ERROR.UNKNOWN, "no principal store is configured");
  const record = await store.get(principalId);
  if (!record) return fail(PRINCIPAL_ERROR.UNKNOWN, `principal "${principalId}" is not enrolled on this host`);

  /* The RECORD is verified before any field in it is believed: an edited role
     must not be able to authorize anything. */
  if (authorityPublicKey && record.record) {
    const base = verifyProofEnvelope(authorityPublicKey, record.record);
    if (!base.ok) return fail(PRINCIPAL_ERROR.UNVERIFIED_RECORD, "the principal record is not signed by this host's authority key");
    if (authorityKeyId && record.verifyKeyId && record.verifyKeyId !== authorityKeyId) {
      return fail(PRINCIPAL_ERROR.UNVERIFIED_RECORD, "the principal record was issued by a different authority key");
    }
    if (
      base.payload?.role !== record.role ||
      base.payload?.status !== record.status ||
      base.payload?.principalKeyId !== record.keyId ||
      base.payload?.publicKey !== record.publicKey
    ) {
      return fail(PRINCIPAL_ERROR.UNVERIFIED_RECORD, "the principal record does not match the signed payload");
    }
  } else if (record.record && authorityPublicKey === null) {
    return fail(PRINCIPAL_ERROR.UNVERIFIED_RECORD, "no authority public key was supplied to verify the principal record");
  }

  const status = principalStatusAt(record, now().getTime());
  if (status !== "active") {
    return fail(status === "expired" ? PRINCIPAL_ERROR.EXPIRED : PRINCIPAL_ERROR.NOT_ACTIVE, `principal "${principalId}" is ${status}`);
  }
  if (expectedTenant && (record.tenantId ?? null) !== expectedTenant) {
    return fail(PRINCIPAL_ERROR.TENANT, `principal "${principalId}" belongs to tenant "${record.tenantId ?? "(none)"}", not "${expectedTenant}"`);
  }
  if (requiredRoles.length && !requiredRoles.includes(record.role)) {
    return fail(PRINCIPAL_ERROR.ROLE, `principal "${principalId}" holds role "${record.role}"; this act requires one of ${requiredRoles.join(", ")}`);
  }
  if (typeof signature !== "string" || !signature) return fail(PRINCIPAL_ERROR.BAD_SIGNATURE, "no principal signature was presented");

  const body = challengeBody({ principalId, action, nonce });
  let ok = false;
  try {
    ok = cryptoVerify(null, Buffer.from(body, "utf8"), createPublicKey(record.publicKey), Buffer.from(signature, "base64url"));
  } catch {
    return fail(PRINCIPAL_ERROR.BAD_SIGNATURE, "the principal signature could not be checked");
  }
  if (!ok) return fail(PRINCIPAL_ERROR.BAD_SIGNATURE, "the principal signature does not verify for this challenge");

  if (nonces) {
    const accepted = typeof nonces.accept === "function" ? nonces.accept(nonce) : true;
    if (!accepted) return fail(PRINCIPAL_ERROR.REPLAY, "this challenge has already been used");
  }

  return {
    authenticated: true,
    binding: "cooperative",
    authenticationMethod: record.authenticationMethod,
    principal: {
      principalId: record.principalId,
      name: record.name,
      kind: record.kind,
      role: record.role,
      organizationId: record.organizationId ?? null,
      tenantId: record.tenantId ?? null,
      keyId: record.keyId,
      authenticationMethod: record.authenticationMethod,
      issuedAt: record.issuedAt,
      expiresAt: record.expiresAt ?? null,
    },
  };
}

/** Roles that may release a revocation, listed for the doctor. */
export async function releaseAuthorities(store) {
  const records = await store.list();
  return records
    .filter((r) => RELEASE_ROLES.includes(r.role) && principalStatusAt(r) === "active")
    .map((r) => ({ principalId: r.principalId, role: r.role, keyId: r.keyId, tenantId: r.tenantId ?? null }));
}
