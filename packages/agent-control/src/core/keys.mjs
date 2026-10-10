/**
 * Role-separated signing keys.
 *
 * A single key that signs identity credentials, delegations, receipts and
 * policies is a single point of compromise: stealing it lets an attacker mint
 * an identity, grant itself authority, forge evidence and publish policy, all
 * with material every verifier already trusts. Separation bounds that blast
 * radius. Each role gets its own keypair, its own key id, and its own file.
 *
 * The signing itself is NOT reimplemented here. proof.mjs already owns "sign
 * this object" and "check these bytes" (buildProofEnvelope / verifyProofEnvelope);
 * a second signing scheme in one product is how a verifier ends up trusting one
 * format and checking another. This module only decides WHICH key material a
 * role uses and where it lives.
 *
 * KEYS ARE NOT CREATED IMPLICITLY BY A VERIFIER. `loadRoleKey` returns null
 * when a role has no key, so a host that never ran enrolment reports a visible
 * "unverified identity" rather than a freshly generated key that silently makes
 * every credential verify against material nobody vouched for.
 */

import { chmod, mkdir, open, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { buildProofEnvelope, generateProofKeys, keyIdFor, verifyProofEnvelope } from "./proof.mjs";

export const KEY_ROLE = Object.freeze({
  /** Proves which enrolled runtime is acting. */
  IDENTITY: "identity",
  /** Proves who granted authority (a human or an organisation). */
  AUTHORITY: "authority",
  /** Proves who delegated authority between agents (P0-B delegation). */
  DELEGATION: "delegation",
  /** Proves the provenance of an evidence artifact (audit / receipt). */
  RECEIPT: "receipt",
  /** Signs revocation/kill events (P0-C revocation fabric). */
  REVOCATION: "revocation",
  /**
   * Signs RELEASE of a revocation — deliberately a DIFFERENT role from
   * REVOCATION, because undoing an emergency containment is a higher-risk act
   * than imposing one. The runtime holds the revocation key; a release key is
   * meant to live with a release officer and is registered here by PUBLIC half
   * only (see core/revocation.mjs).
   */
  RELEASE: "release",
  /** Proves the authenticity of a published policy. */
  POLICY: "policy",
});

export const KEY_ROLES = Object.freeze(Object.values(KEY_ROLE));

export function assertKeyRole(role) {
  if (!KEY_ROLES.includes(role)) {
    throw new TypeError(`Unknown key role "${role}". Known roles: ${KEY_ROLES.join(", ")}.`);
  }
  return role;
}

export function roleKeyDir(stateDir) {
  return join(stateDir, "keys");
}

export function roleKeyPath(stateDir, role) {
  return join(roleKeyDir(stateDir), `${assertKeyRole(role)}.json`);
}

/** Reads a role key, or null when the role has none. Never generates. */
export async function loadRoleKey(stateDir, role) {
  assertKeyRole(role);
  let raw;
  try {
    raw = await readFile(roleKeyPath(stateDir, role), "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw err;
  }
  let record;
  try {
    record = JSON.parse(raw);
  } catch {
    throw new Error(`The ${role} key at ${roleKeyPath(stateDir, role)} is not valid JSON.`);
  }
  if (typeof record?.publicKey !== "string" || typeof record?.privateKey !== "string") {
    throw new Error(`The ${role} key at ${roleKeyPath(stateDir, role)} is missing its key material.`);
  }
  return record;
}

/**
 * Reads a role key, generating and persisting one on first use. Written 0600.
 *
 * THE CLAIM IS ATOMIC, because "ensure" is not a read followed by a write when
 * two processes can run it at once. The previous version loaded, found nothing,
 * generated a key and wrote it — so two processes starting together (the same
 * operator running two `cirvix kill` commands, or a fleet booting) each minted
 * a DIFFERENT key for the same role and the last writer won. The consequence is
 * not a lost file: events signed by the loser's key can never be verified by
 * anybody, so a revocation written by one process becomes unenforceable and the
 * fabric fail-closes. A role key is a TRUST ANCHOR; creating one must be
 * exclusive (`wx`), and a process that loses the race must adopt the winner's
 * key rather than overwrite it.
 */
export async function ensureRoleKey(stateDir, role) {
  assertKeyRole(role);
  let existing = null;
  try {
    existing = await loadRoleKey(stateDir, role);
  } catch {
    /* A record that is empty or unparseable is not yet a verdict: another
       process may be mid-claim, having created the file and not written it.
       The atomic claim below tells the two apart — it wins and writes fresh
       material, or finds EEXIST, waits for the record to become readable, and
       names the path if it never does. Reporting "not valid JSON" from here
       instead would surface the other writer's timing as this process's
       corruption. */
    existing = null;
  }
  if (existing) return existing;

  const generated = generateProofKeys();
  const record = {
    role,
    publicKey: generated.publicKey,
    privateKey: generated.privateKey,
    keyId: generated.keyId,
    createdAt: new Date().toISOString(),
  };
  await mkdir(roleKeyDir(stateDir), { recursive: true });
  const path = roleKeyPath(stateDir, role);

  let handle;
  try {
    /* `wx` creates or throws EEXIST — no window in which two writers both
       believe they created the role. 0600 is applied AT CREATION so the file is
       never readable at the default mode, even briefly. */
    handle = await open(path, "wx", 0o600);
  } catch (err) {
    if (err.code !== "EEXIST") throw err;
    /* Another process claimed this role. Its key is the host's key. The winner
       may still be writing it, so an unreadable or half-written file is
       retried rather than reported as corruption. */
    const adopted = await adoptRoleKey(stateDir, role);
    if (adopted) return adopted;
    throw new Error(
      `The ${role} key was claimed by another process but never became readable. Remove ${path} only if no key material was ever used with it.`,
    );
  }
  try {
    await handle.writeFile(JSON.stringify(record, null, 2), "utf8");
  } finally {
    await handle.close().catch(() => {});
  }
  await chmod(path, 0o600).catch(() => {});
  return record;
}

/** Waits for another process's freshly claimed role key to become readable. */
async function adoptRoleKey(stateDir, role, { attempts = 100, waitMs = 10 } = {}) {
  for (let i = 0; i < attempts; i++) {
    try {
      const winner = await loadRoleKey(stateDir, role);
      if (winner) return winner;
    } catch {
      /* Mid-write. Not corruption until the writer has stopped trying. */
    }
    await new Promise((r) => setTimeout(r, waitMs));
  }
  return null;
}

/**
 * Where a role's PUBLIC half is registered.
 *
 * Some roles are held by someone other than the runtime — the release authority
 * is the clearest case: the runtime must be able to VERIFY a release without
 * being able to MINT one. Those roles publish a public key here, and the file
 * deliberately contains no private material, so copying the whole state
 * directory does not hand someone the power to undo a containment.
 */
export function rolePublicKeyPath(stateDir, role) {
  return join(roleKeyDir(stateDir), `${assertKeyRole(role)}.pub.json`);
}

/** Reads a registered PUBLIC half for a role, or null. Never generates. */
export async function loadRolePublicKey(stateDir, role) {
  assertKeyRole(role);
  let raw;
  try {
    raw = await readFile(rolePublicKeyPath(stateDir, role), "utf8");
  } catch (err) {
    if (err.code !== "ENOENT") throw err;
    /* Fall back to a full key record, if this host holds one: the local
       revocation key's own public half is registered the moment it is used. */
    const full = await loadRoleKey(stateDir, role);
    return full ? publicRoleKey(full) : null;
  }
  let record;
  try {
    record = JSON.parse(raw);
  } catch {
    throw new Error(`The ${role} public key at ${rolePublicKeyPath(stateDir, role)} is not valid JSON.`);
  }
  if (typeof record?.publicKey !== "string" || !record.publicKey) {
    throw new Error(`The ${role} public key record is missing its public key.`);
  }
  return { role, publicKey: record.publicKey, keyId: record.keyId ?? keyIdFor(record.publicKey), registeredAt: record.registeredAt ?? null };
}

/** Registers a role's public half for verification. Writes no private material. */
export async function registerRolePublicKey(stateDir, role, publicKey, { keyId = null } = {}) {
  assertKeyRole(role);
  if (typeof publicKey !== "string" || !publicKey.includes("PUBLIC KEY")) {
    throw new TypeError(`Registering the ${role} role needs a PEM public key.`);
  }
  const record = { role, publicKey, keyId: keyId ?? keyIdFor(publicKey), registeredAt: new Date().toISOString() };
  await mkdir(roleKeyDir(stateDir), { recursive: true });
  const path = rolePublicKeyPath(stateDir, role);
  await writeFile(path, JSON.stringify(record, null, 2), "utf8");
  return record;
}

/** The public half of a role key, for handing to a verifier. */
export function publicRoleKey(record) {
  if (!record?.publicKey) throw new TypeError("A role key record is required.");
  return { role: record.role, publicKey: record.publicKey, keyId: record.keyId ?? keyIdFor(record.publicKey) };
}

export { buildProofEnvelope, keyIdFor, verifyProofEnvelope };
