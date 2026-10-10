/**
 * The enrolled-agent store.
 *
 * An identity credential only means something against a record the host
 * actually vouched for: this agent id, bound to this public key, in this
 * status. Without that record a valid signature proves only that *somebody*
 * holding *some* issuer-signed credential asked, which is exactly the
 * "a name proves nothing" failure the boundary exists to close.
 *
 * One file per agent, written atomically (temp + rename) so a crash mid-write
 * cannot leave a half-record that a later verifier reads as enrolled. The
 * filename is a hash of the agent id, so an id containing `/`, `..` or a NUL
 * cannot escape the directory.
 *
 * A record that cannot be parsed is SKIPPED by `list()` and treated as absent
 * by `get()` — never merged, never trusted. An unreadable identity record is a
 * denial, not a default.
 */

import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

export const AGENT_STATUS = Object.freeze({
  ACTIVE: "active",
  SUSPENDED: "suspended",
  REVOKED: "revoked",
});

function fileKey(agentId) {
  return createHash("sha256").update(String(agentId)).digest("hex").slice(0, 32);
}

export function agentsDir(stateDir) {
  return join(stateDir, "agents");
}

export function agentRecordPath(stateDir, agentId) {
  return join(agentsDir(stateDir), `${fileKey(agentId)}.json`);
}

export class AgentStore {
  constructor(stateDir) {
    if (typeof stateDir !== "string" || !stateDir) throw new TypeError("AgentStore needs a state directory.");
    this.stateDir = stateDir;
  }

  async #write(record) {
    const dir = agentsDir(this.stateDir);
    await mkdir(dir, { recursive: true });
    const path = agentRecordPath(this.stateDir, record.agentId);
    const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tmp, JSON.stringify(record, null, 2), "utf8");
    await rename(tmp, path);
    return record;
  }

  /** Inserts or updates an agent record, preserving first-seen timestamps. */
  async put(record) {
    if (!record || typeof record.agentId !== "string" || !record.agentId) {
      throw new TypeError("An agent record needs a nonempty agentId.");
    }
    const existing = await this.get(record.agentId);
    const now = new Date().toISOString();
    return this.#write({
      ...existing,
      ...record,
      createdAt: existing?.createdAt ?? record.createdAt ?? now,
      updatedAt: now,
    });
  }

  /** The record for an agent id, or null when there is none. */
  async get(agentId) {
    if (typeof agentId !== "string" || !agentId) return null;
    try {
      return JSON.parse(await readFile(agentRecordPath(this.stateDir, agentId), "utf8"));
    } catch (err) {
      if (err.code === "ENOENT") return null;
      return null;
    }
  }

  /** Every readable agent record, sorted by agent id. */
  async list() {
    let names;
    try {
      names = await readdir(agentsDir(this.stateDir));
    } catch (err) {
      if (err.code === "ENOENT") return [];
      throw err;
    }
    const records = [];
    for (const name of names) {
      if (!name.endsWith(".json")) continue;
      try {
        records.push(JSON.parse(await readFile(join(agentsDir(this.stateDir), name), "utf8")));
      } catch {
        /* skipped, never trusted */
      }
    }
    return records.sort((a, b) => String(a.agentId).localeCompare(String(b.agentId)));
  }

  /** Changes an agent's lifecycle status. */
  async setStatus(agentId, status, { reason = null } = {}) {
    if (!Object.values(AGENT_STATUS).includes(status)) {
      throw new TypeError(`Unknown agent status "${status}".`);
    }
    const existing = await this.get(agentId);
    if (!existing) return null;
    const record = { ...existing, status, statusReason: reason, updatedAt: new Date().toISOString() };
    if (status !== AGENT_STATUS.ACTIVE) record.revokedAt = existing.revokedAt ?? new Date().toISOString();
    return this.#write(record);
  }

  async revoke(agentId, reason = "revoked") {
    return this.setStatus(agentId, AGENT_STATUS.REVOKED, { reason });
  }

  async touch(agentId) {
    const existing = await this.get(agentId);
    if (!existing) return null;
    return this.#write({ ...existing, lastSeen: new Date().toISOString() });
  }
}
