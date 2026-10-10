/**
 * Authenticated agent identity at the boundary.
 *
 * THE PROBLEM THIS CLOSES.
 *
 * The gateway used to read the caller name out of `params._meta.cirvix.agent`
 * and evaluate `permit agent = "agent-A"` against it. A name proves nothing: an
 * agent (or anything else that could write to the socket or the stdio pipe)
 * could claim to be `agent-A` and inherit every rule written for it. The
 * contract for deciding "may this agent do X" was therefore unenforceable for
 * the one input it depended on.
 *
 * THE MODEL, IN TWO HALVES.
 *
 *   1. An ISSUER-SIGNED CREDENTIAL binds an agent id to a public key. It is
 *      signed by the host authority key (core/keys.mjs, KEY_ROLE.AUTHORITY),
 *      not by the agent. An agent cannot mint one for itself, which is what
 *      makes the binding worth anything.
 *
 *   2. A PER-REQUEST SIGNATURE proves possession of the matching private key.
 *      The agent signs a canonical body over {agentId, method, ts, nonce,
 *      paramsHash}. A stolen credential is useless without the private key, and
 *      a captured request cannot be replayed because the nonce is spent and the
 *      body is bound to a timestamp inside the accepted skew.
 *
 * WHAT THIS IS NOT. The private key is a file the runtime holds. On a platform
 * where that key cannot be bound to the process that holds it, this is strong
 * COOPERATIVE identity, not HARD: a same-user process that can read the key file
 * can sign as that agent. HARD requires OS process binding (peer credentials /
 * SO_PEERCRED, a protected key store, TPM/TEE). `binding` on the result says
 * which one is in force, rather than this module quietly describing 0600 as
 * proof of identity.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as signBytes,
  verify as verifyBytes,
} from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { canonicalJson } from "./audit.mjs";
import { buildProofEnvelope, generateProofKeys, keyIdFor, verifyProofEnvelope } from "./proof.mjs";
import { AGENT_STATUS, AgentStore } from "./identity-store.mjs";
import { ensureRoleKey, loadRoleKey, KEY_ROLE } from "./keys.mjs";

export const IDENTITY_VERSION = 1;

/**
 * Where an enrolled agent's RUNTIME private key lives.
 *
 * One definition, because two places disagreed about it: enrolment wrote the
 * key here, and the caller-side loader had to guess the same path or silently
 * find nothing — which reads at the boundary as "this caller has no identity",
 * the least diagnosable failure an identity system can produce.
 */
export function agentIdentityKeyPath(stateDir, agentId) {
  return join(stateDir, "agents", `${agentId}.identity.key`);
}
export const CREDENTIAL_KIND = "agent-identity";
export const DEFAULT_CLOCK_SKEW_MS = 60_000;
export const DEFAULT_CREDENTIAL_TTL_MS = 12 * 60 * 60 * 1000;

const sha256 = (s) => "sha256:" + createHash("sha256").update(s).digest("hex");

/** What a request proof is bound to: the params with `_meta` removed. */
export function requestDigest(params) {
  const { _meta, ...rest } = params && typeof params === "object" && !Array.isArray(params) ? params : {};
  return sha256(canonicalJson(rest));
}

/** The exact bytes an agent signs for one request. */
export function requestProofBody({ agentId, method, ts, nonce, paramsHash }) {
  return canonicalJson({ v: IDENTITY_VERSION, kind: "agent-request", agentId, method, ts, nonce, paramsHash });
}

/**
 * Client side. Signs one request with the agent identity private key.
 *
 * Returns the `_meta.cirvix` object a caller attaches to an MCP request or the
 * socket `cirvix/authorize` params.
 */
export function signRequest({
  privateKey,
  agentId,
  method = null,
  params = {},
  ts = new Date().toISOString(),
  nonce = randomBytes(16).toString("hex"),
}) {
  if (typeof agentId !== "string" || !agentId) throw new TypeError("A request proof needs an agentId.");
  if (!privateKey) throw new TypeError("A request proof needs the agent identity private key.");
  const paramsHash = requestDigest(params);
  const body = requestProofBody({ agentId, method, ts, nonce, paramsHash });
  const sig = signBytes(null, Buffer.from(body, "utf8"), createPrivateKey(privateKey)).toString("base64url");
  return { agent: agentId, method, ts, nonce, paramsHash, sig };
}

/** Builds an UNSIGNED credential binding an agent id to a public key. */
export function createIdentityCredential({
  agentId,
  publicKey,
  keyId = null,
  name = null,
  owner = null,
  tenant = "local",
  environment = "local",
  runtime = null,
  model = null,
  capabilities = [],
  issuer = "local",
  ttlMs = DEFAULT_CREDENTIAL_TTL_MS,
  status = "active",
  now = () => new Date(),
}) {
  if (typeof agentId !== "string" || !agentId) throw new TypeError("A credential needs an agentId.");
  if (typeof publicKey !== "string" || !publicKey) throw new TypeError("A credential needs the agent public key.");
  const issuedAt = now().toISOString();
  return {
    v: IDENTITY_VERSION,
    kind: CREDENTIAL_KIND,
    agentId,
    name: name ?? agentId,
    owner,
    tenant,
    environment,
    runtime,
    model,
    capabilities,
    issuer,
    publicKey,
    keyId: keyId ?? keyIdFor(publicKey),
    issuedAt,
    expiresAt: new Date(Date.parse(issuedAt) + ttlMs).toISOString(),
    status,
  };
}

/** Signs a credential with the issuer (authority) key. */
export function signIdentityCredential({ credential, privateKey, keyId = null }) {
  if (!privateKey) throw new TypeError("Signing a credential needs the issuer private key.");
  return buildProofEnvelope({ payload: credential, privateKey, keyId });
}

/**
 * Verifies an issuer-signed credential.
 *
 * Signature first, then semantics: a hostile artifact must not steer the
 * verifier through its own contents before the signature is checked.
 */
export function verifyIdentityCredential(issuerPublicKeyPem, token, { now = () => new Date(), skewMs = DEFAULT_CLOCK_SKEW_MS } = {}) {
  const base = verifyProofEnvelope(issuerPublicKeyPem, token);
  if (!base.ok) return base;

  const c = base.payload;
  const bad = (reason) => ({ ok: false, verified: false, reason });
  if (!c || typeof c !== "object" || Array.isArray(c)) return bad("the credential payload must be an object");
  for (const field of ["v", "kind", "agentId", "publicKey", "issuer", "issuedAt", "expiresAt"]) {
    if (c[field] === undefined) return bad(`the credential is missing "${field}"`);
  }
  if (c.kind !== CREDENTIAL_KIND) return bad(`this is a "${c.kind}" artifact, not an agent identity credential`);
  if (c.v !== IDENTITY_VERSION) return bad(`this credential is version ${c.v}; this verifier understands ${IDENTITY_VERSION}`);
  if (typeof c.agentId !== "string" || !c.agentId.trim()) return bad("the credential has no agent id");
  if (c.status !== "active") return bad(`the credential is ${c.status}`);

  const expires = Date.parse(c.expiresAt);
  if (!Number.isFinite(expires)) return bad("the credential has an unreadable expiry");
  if (expires + skewMs < now().getTime()) return bad("the credential has expired");

  try {
    if (createPublicKey(c.publicKey).asymmetricKeyType !== "ed25519") return bad("the credential agent key is not Ed25519");
  } catch {
    return bad("the credential agent public key is unreadable");
  }

  return { ok: true, verified: true, credential: c, agentId: c.agentId, publicKey: c.publicKey, keyId: c.keyId ?? null };
}

/** A bounded in-memory replay guard for request nonces. */
export class NonceCache {
  constructor(opts = {}) {
    const { ttlMs = 5 * 60 * 1000, max = 10_000, now = () => Date.now() } = opts;
    Object.assign(this, { ttlMs, max, now, seen: new Map() });
  }

  sweep() {
    const cutoff = this.now() - this.ttlMs;
    for (const [nonce, at] of this.seen) if (at < cutoff) this.seen.delete(nonce);
  }

  /** True when this nonce is fresh; false when seen inside the window. */
  accept(nonce) {
    this.sweep();
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, this.now());
    while (this.seen.size > this.max) this.seen.delete(this.seen.keys().next().value);
    return true;
  }
}

/**
 * Verifies the identity a request claims, and refuses when it cannot.
 *
 * Every failure returns `{ verified: false, reason }` — never a throw, never a
 * silent pass. A caller that ignores `verified` gets `false`, which the Guard
 * turns into a DENY rather than a default-allow.
 */
export class CallerVerifier {
  constructor({
    issuerPublicKey,
    store = null,
    nonceCache = new NonceCache(),
    skewMs = DEFAULT_CLOCK_SKEW_MS,
    expectedRuntime = null,
    expectedTenant = null,
    binding = "cooperative",
    now = () => new Date(),
  }) {
    if (typeof issuerPublicKey !== "string" || !issuerPublicKey) {
      throw new TypeError("A CallerVerifier needs the issuer public key.");
    }
    Object.assign(this, { issuerPublicKey, store, nonces: nonceCache, skewMs, expectedRuntime, expectedTenant, binding, now });
  }

  async verify({ meta = null, method = null, params = {} } = {}) {
    const deny = (reason) => ({ verified: false, reason, binding: this.binding });

    if (!meta || typeof meta !== "object" || Array.isArray(meta)) {
      return deny("the request carried no identity credential");
    }
    if (typeof meta.credential !== "string") {
      return deny("the request carried no identity credential");
    }

    const credentialCheck = verifyIdentityCredential(this.issuerPublicKey, meta.credential, {
      now: this.now,
      skewMs: this.skewMs,
    });
    if (!credentialCheck.ok) return deny(credentialCheck.reason ?? "the identity credential did not verify");

    const identity = credentialCheck.credential;

    if (this.expectedRuntime && identity.runtime && identity.runtime !== this.expectedRuntime) {
      return deny(`the credential was issued for runtime "${identity.runtime}", not "${this.expectedRuntime}"`);
    }

    /* Tenancy is pinned per boundary. A credential minted for another tenant
       must not authorize anything here even when it carries a valid signature
       from a shared authority — tenancy is who the caller WORKS FOR, and the
       boundary belongs to one. */
    if (this.expectedTenant && (identity.tenant ?? null) !== this.expectedTenant) {
      return deny(`the credential was issued for tenant "${identity.tenant ?? "(none)"}", not "${this.expectedTenant}"`);
    }

    if (this.store) {
      const record = await this.store.get(identity.agentId);
      if (!record) return deny(`agent "${identity.agentId}" is not enrolled on this host`);
      if (record.status !== AGENT_STATUS.ACTIVE) return deny(`agent "${identity.agentId}" is ${record.status}`);
      if (record.publicKey && record.publicKey !== identity.publicKey) {
        return deny("the credential key does not match the enrolled key");
      }
    }

    if (typeof meta.agent === "string" && meta.agent && meta.agent !== identity.agentId) {
      return deny(`the request claims agent "${meta.agent}" but its credential is for "${identity.agentId}"`);
    }

    if (typeof meta.sig !== "string" || !meta.sig) return deny("the request carried no identity signature");

    const paramsHash = requestDigest(params);
    if (typeof meta.paramsHash === "string" && meta.paramsHash !== paramsHash) {
      return deny("the signed request does not match the request that arrived");
    }

    const ts = typeof meta.ts === "string" ? meta.ts : null;
    if (!ts || !Number.isFinite(Date.parse(ts))) return deny("the request carried no readable timestamp");
    if (Math.abs(this.now().getTime() - Date.parse(ts)) > this.skewMs) {
      return deny("the request timestamp is outside the accepted clock skew");
    }

    if (typeof meta.nonce !== "string" || !meta.nonce) return deny("the request carried no nonce");

    const body = requestProofBody({
      agentId: identity.agentId,
      method: method ?? meta.method ?? null,
      ts,
      nonce: meta.nonce,
      paramsHash,
    });

    let sigOk = false;
    try {
      sigOk = verifyBytes(null, Buffer.from(body, "utf8"), createPublicKey(identity.publicKey), Buffer.from(meta.sig, "base64url"));
    } catch {
      return deny("the identity signature could not be checked");
    }
    if (!sigOk) return deny("the identity signature does not verify");

    if (!this.nonces.accept(meta.nonce)) return deny("the request nonce has been seen before (replay)");

    return {
      verified: true,
      agentId: identity.agentId,
      identity,
      issuer: identity.issuer,
      keyId: identity.keyId ?? null,
      tenant: identity.tenant ?? null,
      environment: identity.environment ?? null,
      runtime: identity.runtime ?? null,
      capabilities: identity.capabilities ?? [],
      binding: this.binding,
    };
  }
}

/**
 * Enrols an agent: generates its identity keypair, signs a credential with the
 * host authority key, and persists the record.
 *
 * The returned `identityPrivateKey` belongs to the RUNTIME, not to this
 * function caller. It is returned once, at enrolment, exactly like a device
 * key, and the store keeps only the public half.
 */
export async function enrollAgent({
  stateDir,
  agentId,
  name = null,
  owner = null,
  tenant = "local",
  environment = "local",
  runtime = null,
  model = null,
  capabilities = [],
  ttlMs = DEFAULT_CREDENTIAL_TTL_MS,
  store = null,
  now = () => new Date(),
}) {
  if (typeof agentId !== "string" || !agentId) throw new TypeError("Enrolment needs an agentId.");
  const agents = store ?? new AgentStore(stateDir);

  const existing = await agents.get(agentId);
  if (existing && existing.status === AGENT_STATUS.REVOKED) {
    throw new Error(`Agent "${agentId}" is revoked. Clear the revocation explicitly or enrol a new id.`);
  }

  const identityKeys = generateProofKeys();
  const authority = await ensureRoleKey(stateDir, KEY_ROLE.AUTHORITY);

  const credential = createIdentityCredential({
    agentId,
    publicKey: identityKeys.publicKey,
    keyId: identityKeys.keyId,
    name,
    owner,
    tenant,
    environment,
    runtime,
    model,
    capabilities,
    issuer: "local",
    ttlMs,
    now,
  });

  const { token } = signIdentityCredential({
    credential,
    privateKey: authority.privateKey,
    keyId: authority.keyId,
  });

  /* The runtime's private key is PERSISTED here, next to the record it belongs
     to, with the 0600 posture every other credential in the state directory
     has. It used to be returned and nowhere stored, which made "an agent
     enrolled on this host" a claim no client-side surface could act on: the
     hook, the socket client and any agent runtime had no key to sign with, so
     the identity stage refused them for carrying no credential. Returning it
     as well keeps the one-time-return contract for callers that keep their own
     copy. */
  await mkdir(join(stateDir, "agents"), { recursive: true });
  await writeFile(agentIdentityKeyPath(stateDir, agentId), identityKeys.privateKey, "utf8");
  await chmod(agentIdentityKeyPath(stateDir, agentId), 0o600).catch(() => {});

  const record = await agents.put({
    agentId,
    name: credential.name,
    owner,
    tenant,
    environment,
    runtime,
    model,
    capabilities,
    publicKey: identityKeys.publicKey,
    keyId: identityKeys.keyId,
    status: AGENT_STATUS.ACTIVE,
    issuedAt: credential.issuedAt,
    expiresAt: credential.expiresAt,
    credential: token,
    issuerKeyId: authority.keyId,
    // Stated on the record so the doctor and the audit trail can report it
    // without re-deriving it, and so nobody describes this as HARD identity
    // when the platform gave us no way to bind the key to the process.
    binding: "cooperative",
  });

  return {
    record,
    credential,
    credentialToken: token,
    identityPrivateKey: identityKeys.privateKey,
    identityPublicKey: identityKeys.publicKey,
    identityKeyId: identityKeys.keyId,
    issuerKeyId: authority.keyId,
  };
}

/**
 * The CALLER side of identity, in one place.
 *
 * Every surface that acts as an agent — the Claude Code hook, the socket
 * client, an agent runtime — has to present the SAME proof to the boundary:
 * the enrolled credential, a signature over the exact params being sent, a
 * fresh nonce and a timestamp. A transport that re-implements that sequence is
 * a transport that will get it subtly wrong (wrong `method` in the proof body,
 * a digest taken before the params were finalised, a stale credential), and
 * the failure mode is an unexplained refusal at the boundary.
 *
 * Returns null when this host has no usable enrolment, so the caller can say
 * "there is no identity here" out loud instead of sending a claim.
 *
 * @param {object} opts
 * @param {string} opts.stateDir
 * @param {string} [opts.agentId]  which enrolled agent to act as (default: the
 *                                 single active enrolment, if there is one)
 * @returns {Promise<null | {agentId: string, keyId: string|null, credential: string, tenant: string|null, runtime: string|null, proof: (params: object, method?: string|null) => object, meta: (params: object, method?: string|null) => object}>}
 */
export async function loadCallerIdentity({ stateDir, agentId = null } = {}) {
  if (typeof stateDir !== "string" || !stateDir) throw new TypeError("loadCallerIdentity needs a stateDir.");
  const records = await new AgentStore(stateDir).list();
  const active = records.filter((r) => r.status === AGENT_STATUS.ACTIVE);
  /* Which agent am I? Named if asked. Otherwise only UNAMBIGUOUS: one active
     enrolment is that agent; several means the caller has to say, because
     guessing here would let a hook speak as the wrong principal — and every
     stage downstream would faithfully enforce the wrong identity. */
  const record = agentId
    ? active.find((r) => r.agentId === agentId) ?? null
    : active.length === 1
      ? active[0]
      : null;
  if (!record || typeof record.credential !== "string" || !record.credential) return null;

  let privateKey;
  try {
    privateKey = (await readFile(agentIdentityKeyPath(stateDir, record.agentId), "utf8")).trim();
  } catch {
    return null;
  }
  if (!privateKey) return null;

  const proof = (params, method = null) => signRequest({ privateKey, agentId: record.agentId, method, params });
  return {
    agentId: record.agentId,
    keyId: record.keyId ?? null,
    credential: record.credential,
    tenant: record.tenant ?? null,
    runtime: record.runtime ?? null,
    proof,
    /** The `_meta.cirvix` block: the credential plus a proof over THESE params. */
    meta: (params, method = null) => ({ credential: record.credential, ...proof(params, method) }),
  };
}

/** Builds the boundary verifier from a state directory, or null when nothing is enrolled. */
export async function createCallerVerifier({ stateDir, require = true, expectedRuntime = null, expectedTenant = null, binding = "cooperative" }) {
  const authority = await loadRoleKey(stateDir, KEY_ROLE.AUTHORITY);
  if (!authority) return null;
  return new CallerVerifier({
    issuerPublicKey: authority.publicKey,
    store: new AgentStore(stateDir),
    require,
    expectedRuntime,
    expectedTenant,
    binding,
  });
}
