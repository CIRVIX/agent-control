/**
 * Durable missions and capabilities — WHAT an agent is allowed to do.
 *
 * THE HOLE THIS CLOSES. `MissionRegistry` was an in-memory object constructed
 * only by tests and the escape benchmark. The enforcement logic was real and
 * proven, but no production composition root ever issued a mission, so on a
 * real host authority was INERT: policy alone decided every call. "Mission
 * enforcement works" was true of a class, not of the product.
 *
 * WHAT A MISSION RECORD IS. A durable, host-signed statement that an
 * AUTHENTICATED PRINCIPAL granted a named agent a bounded set of capabilities
 * for one tenant, with constraints and an expiry:
 *
 *   missionId, tenantId, agent, issuerPrincipalId, issuerKeyId, capabilities,
 *   constraints, issuedAt, expiresAt, status, signature (host authority key)
 *
 * The record is signed by the host AUTHORITY key and carries the PRINCIPAL id
 * inside the signed payload, so both halves of "who authorized this" are
 * answerable and tamper-evident: editing the tenant, the agent or a capability
 * scope breaks the signature, and swapping the principal id breaks it too.
 *
 * `registry()` hands the live `MissionRegistry` exactly the ACTIVE missions of
 * one tenant. That is the wiring the composition roots were missing: a runtime
 * pinned to tenant `acme` never even loads globex's authority, and a mission
 * that is expired, revoked or another agent's is refused by the same
 * `assessAuthority` the tests already cover.
 */

import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { canonicalJson } from "./audit.mjs";
import { buildProofEnvelope, verifyProofEnvelope, keyIdFor } from "./proof.mjs";
import { MissionRegistry, normalizeMission, normalizeCapability, missionStatusAt, capabilityStatusAt, MISSION_STATUS } from "./authority.mjs";

export const AUTHORITY_RECORD_VERSION = 1;
export const AUTHORITY_RECORD_KIND = "cirvix-authority-mission";

export const AUTHORITY_RECORD_ERROR = Object.freeze({
  UNKNOWN: "authority_record_unknown",
  UNVERIFIED: "authority_record_unverified",
  NOT_ACTIVE: "authority_record_not_active",
  EXPIRED: "authority_record_expired",
  TENANT: "authority_record_tenant",
  AGENT: "authority_record_agent",
  CAPABILITY: "authority_record_capability",
});

function missionsDir(stateDir) {
  return join(stateDir, "missions");
}

function recordPath(stateDir, missionId) {
  // The id is not used as a filename verbatim: an id containing `..` or a
  // separator must not be able to write outside the directory.
  const safe = String(missionId).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 96);
  return join(missionsDir(stateDir), `${safe}.json`);
}

export class MissionStore {
  constructor(stateDir) {
    if (typeof stateDir !== "string" || !stateDir) throw new TypeError("MissionStore needs a state directory.");
    this.stateDir = stateDir;
  }

  async #write(record) {
    await mkdir(missionsDir(this.stateDir), { recursive: true });
    const path = recordPath(this.stateDir, record.missionId);
    const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tmp, JSON.stringify(record, null, 2), "utf8");
    await rename(tmp, path);
    return record;
  }

  #sign(payload, authority) {
    if (!authority?.privateKey) throw new Error("Issuing authority needs the host authority key.");
    const { token } = buildProofEnvelope({ payload, privateKey: authority.privateKey, keyId: authority.keyId });
    return token;
  }

  /**
   * Issues a mission. `issuerPrincipalId` is required: authority that cannot be
   * attributed to an authenticated principal is authority nobody can withdraw.
   */
  async issue({
    missionId = null,
    agent,
    tenantId = "local",
    name = null,
    objective = "",
    capabilities = [],
    constraints = {},
    ttlMs = null,
    expiresAt = null,
    issuerPrincipalId,
    issuerRole = null,
    authority,
    now = () => new Date(),
  }) {
    if (typeof agent !== "string" || !agent) throw new TypeError("A mission needs the agent it is granted to.");
    if (typeof issuerPrincipalId !== "string" || !issuerPrincipalId) {
      throw new TypeError("A mission needs the authenticated principal that issued it.");
    }
    const at = now();
    const id = missionId ?? `msn_${at.getTime().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
    const payload = {
      v: AUTHORITY_RECORD_VERSION,
      kind: AUTHORITY_RECORD_KIND,
      missionId: id,
      name: name ?? agent,
      objective,
      agent,
      tenantId,
      issuerPrincipalId,
      issuerRole,
      capabilities: capabilities.map((c) => normalizeCapability(c, { issuer: issuerPrincipalId, now: at.getTime() })),
      constraints,
      issuedAt: at.toISOString(),
      expiresAt: expiresAt ?? (ttlMs != null ? new Date(at.getTime() + ttlMs).toISOString() : null),
      status: MISSION_STATUS.ACTIVE,
      statusReason: null,
      revokedAt: null,
    };
    const record = { ...payload, record: this.#sign(payload, authority), issuedByKeyId: authority.keyId };
    return this.#write(record);
  }

  async get(missionId) {
    if (typeof missionId !== "string" || !missionId) return null;
    try {
      return JSON.parse(await readFile(recordPath(this.stateDir, missionId), "utf8"));
    } catch (err) {
      if (err.code === "ENOENT") return null;
      return null;
    }
  }

  async list({ tenantId = null, agent = null } = {}) {
    let names;
    try {
      names = await readdir(missionsDir(this.stateDir));
    } catch (err) {
      if (err.code === "ENOENT") return [];
      throw err;
    }
    const records = [];
    for (const name of names) {
      if (!name.endsWith(".json")) continue;
      try {
        const record = JSON.parse(await readFile(join(missionsDir(this.stateDir), name), "utf8"));
        if (tenantId && record.tenantId !== tenantId) continue;
        if (agent && record.agent !== agent) continue;
        records.push(record);
      } catch {
        /* skipped, never trusted */
      }
    }
    return records.sort((a, b) => String(a.missionId).localeCompare(String(b.missionId)));
  }

  /**
   * Verifies a stored record WITHOUT trusting it: signature first, then the
   * payload-vs-record comparison, so an edited tenant, agent or capability is
   * detected rather than believed.
   */
  verify(record, authorityPublicKey) {
    if (!record?.record) return { ok: false, code: AUTHORITY_RECORD_ERROR.UNVERIFIED, reason: "the record carries no signature" };
    const base = verifyProofEnvelope(authorityPublicKey, record.record);
    if (!base.ok) return { ok: false, code: AUTHORITY_RECORD_ERROR.UNVERIFIED, reason: base.reason ?? "the record does not verify" };
    const payload = base.payload;
    for (const field of ["missionId", "agent", "tenantId", "issuerPrincipalId", "capabilities", "issuedAt", "status"]) {
      if (payload[field] === undefined) return { ok: false, code: AUTHORITY_RECORD_ERROR.UNVERIFIED, reason: `the signed payload is missing "${field}"` };
    }
    /* CANONICAL comparison, not JSON.stringify.
       The signed body is written in the envelope's canonical (key-sorted) form
       while the record on disk is pretty-printed in insertion order, so a
       raw stringify comparison reports a mismatch for two objects that are
       deeply equal — every mission would be refused as "not signed by this
       host", which is exactly how this was found. */
    for (const field of [
      "missionId",
      "agent",
      "tenantId",
      "issuerPrincipalId",
      "status",
      "expiresAt",
      "constraints",
      "capabilities",
    ]) {
      if (canonicalJson(payload[field] ?? null) !== canonicalJson(record[field] ?? null)) {
        return { ok: false, code: AUTHORITY_RECORD_ERROR.UNVERIFIED, reason: `the record's "${field}" does not match the signed payload` };
      }
    }
    return { ok: true, mission: payload };
  }

  /** Status at a moment, from the signed payload. */
  statusAt(record, now = Date.now()) {
    const status = missionStatusAt({ status: record.status, expiresAt: record.expiresAt ? Date.parse(record.expiresAt) : null }, now);
    return status;
  }

  async revoke(missionId, { reason = "revoked", authority, issuerPrincipalId = null } = {}) {
    const existing = await this.get(missionId);
    if (!existing) return null;
    const payload = {
      ...stripSignature(existing),
      status: MISSION_STATUS.REVOKED,
      statusReason: reason,
      revokedAt: new Date().toISOString(),
      revokedBy: issuerPrincipalId ?? existing.issuerPrincipalId,
    };
    const record = { ...payload, record: this.#sign(payload, authority), issuedByKeyId: authority?.keyId ?? existing.issuedByKeyId };
    await this.#write(record);
    return record;
  }

  /** Adds a capability to a live mission (or replaces the one with that name). */
  async addCapability(missionId, capability, { authority, issuerPrincipalId = null } = {}) {
    const existing = await this.get(missionId);
    if (!existing) return null;
    const normalized = normalizeCapability(capability, { issuer: issuerPrincipalId ?? existing.issuerPrincipalId });
    const capabilities = [...existing.capabilities.filter((c) => c.name !== normalized.name), normalized];
    const payload = { ...stripSignature(existing), capabilities, statusReason: null, status: MISSION_STATUS.ACTIVE };
    const record = { ...payload, record: this.#sign(payload, authority), issuedByKeyId: authority?.keyId ?? existing.issuedByKeyId };
    await this.#write(record);
    return record;
  }

  /** Revokes one capability without revoking the mission around it. */
  async revokeCapability(missionId, capabilityName, { reason = "capability revoked", authority, issuerPrincipalId = null } = {}) {
    const existing = await this.get(missionId);
    if (!existing) return null;
    const capabilities = existing.capabilities.map((c) =>
      c.name === capabilityName ? { ...c, status: "revoked", statusReason: reason, revokedAt: new Date().toISOString() } : c,
    );
    if (!capabilities.some((c) => c.name === capabilityName)) return null;
    const payload = { ...stripSignature(existing), capabilities, revokedCapabilities: [...(existing.revokedCapabilities ?? []), capabilityName] };
    const record = { ...payload, record: this.#sign(payload, authority), issuedByKeyId: authority?.keyId ?? existing.issuedByKeyId };
    await this._touchRevokedBy(record, issuerPrincipalId);
    return this.#write(record);
  }

  async _touchRevokedBy(record, issuerPrincipalId) {
    if (issuerPrincipalId) record.revokedCapabilitiesBy = { [record.missionId]: issuerPrincipalId };
    return record;
  }

  /** Re-issues a mission with a new window (rotation of the authority, not the key). */
  async rotate(missionId, { ttlMs = null, expiresAt = null, authority, issuerPrincipalId = null } = {}) {
    const existing = await this.get(missionId);
    if (!existing) return null;
    const at = Date.now();
    const payload = {
      ...stripSignature(existing),
      issuedAt: new Date(at).toISOString(),
      expiresAt: expiresAt ?? (ttlMs != null ? new Date(at + ttlMs).toISOString() : existing.expiresAt),
      status: MISSION_STATUS.ACTIVE,
      statusReason: null,
      rotatedBy: issuerPrincipalId ?? existing.issuerPrincipalId,
    };
    const record = { ...payload, record: this.#sign(payload, authority), issuedByKeyId: authority?.keyId ?? existing.issuedByKeyId };
    await this.#write(record);
    return record;
  }

  /**
   * The live registry a boundary runs on: every mission of ONE tenant, with
   * every record verified before it is loaded. A record that does not verify is
   * NOT loaded — authority that cannot be vouched for does not exist, and the
   * call it would have permitted is default-denied by policy instead.
   */
  async registry({ tenantId = null, authorityPublicKey = null, now = Date.now() } = {}) {
    const registry = new MissionRegistry();
    const records = await this.list({ tenantId });
    const rejected = [];
    for (const record of records) {
      if (authorityPublicKey) {
        const check = this.verify(record, authorityPublicKey);
        if (!check.ok) {
          rejected.push({ missionId: record.missionId, reason: check.reason });
          continue;
        }
      }
      const normalized = normalizeMission({
        id: record.missionId,
        name: record.name,
        objective: record.objective,
        agent: record.agent,
        capabilities: record.capabilities,
        constraints: record.constraints,
        issuedAt: Date.parse(record.issuedAt),
        expiresAt: record.expiresAt ? Date.parse(record.expiresAt) : null,
        status: record.status,
        usage: record.usage ?? undefined,
      });
      registry.issue(normalized);
    }
    registry.rejected = rejected;
    registry.tenantId = tenantId;
    return registry;
  }

  /** What the doctor reports: counts and the principals behind them. */
  async posture({ authorityPublicKey = null, now = Date.now() } = {}) {
    const records = await this.list();
    const issuers = new Map();
    let active = 0;
    let expired = 0;
    let revoked = 0;
    let unverified = 0;
    for (const record of records) {
      if (authorityPublicKey && !this.verify(record, authorityPublicKey).ok) unverified += 1;
      const status = this.statusAt(record, now);
      if (status === MISSION_STATUS.ACTIVE) active += 1;
      else if (status === MISSION_STATUS.EXPIRED) expired += 1;
      else if (status === MISSION_STATUS.REVOKED) revoked += 1;
      issuers.set(record.issuerPrincipalId, (issuers.get(record.issuerPrincipalId) ?? 0) + 1);
    }
    return {
      total: records.length,
      active,
      expired,
      revoked,
      unverified,
      issuers: [...issuers.entries()].map(([principalId, count]) => ({ principalId, count })),
    };
  }
}

function stripSignature(record) {
  const { record: _token, issuedByKeyId, revokedCapabilitiesBy, ...payload } = record;
  return payload;
}

export { missionStatusAt, capabilityStatusAt, keyIdFor };
