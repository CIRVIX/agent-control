/**
 * The audit chain.
 *
 * Append-only JSONL where every record commits to the hash of its
 * predecessor. Editing or removing any record breaks verification from that
 * point forward, and `verify()` reports exactly where.
 *
 * What this does and does not prove — stated here because the distinction is
 * the whole value and it is routinely overstated by vendors:
 *
 *   PROVES:      no record was altered or removed after it was written,
 *                assuming any published checkpoint root is trusted.
 *   DOES NOT:    prove a record was written truthfully in the first place.
 *                That property comes from the enforcement path, not the log.
 *   DOES NOT:    prevent destruction. Someone with disk access can delete the
 *                file. The chain guarantees that doing so is *visible*.
 *
 * Hashes are SHA-256 over a canonical JSON serialization — key order is fixed
 * before hashing, because `JSON.stringify` preserves insertion order and two
 * semantically identical records would otherwise hash differently.
 */

import { createHash } from "node:crypto";
import { appendFile, readFile } from "node:fs/promises";

const GENESIS = "sha256:" + "0".repeat(64);

/** Deterministic serialization — sorted keys, all the way down. */
export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
    .join(",")}}`;
}

export function hashRecord(record) {
  const { hash: _ignored, ...rest } = record;
  return "sha256:" + createHash("sha256").update(canonicalJson(rest)).digest("hex");
}

export class AuditChain {
  #path;
  #seq = 0;
  #prev = GENESIS;
  /** Serializes appends. See `append` for why this is not optional. */
  #tail = Promise.resolve();

  constructor(path) {
    this.#path = path;
  }

  /** Reads the tail so appends continue an existing chain rather than forking it. */
  async open() {
    const records = await this.read();
    const last = records[records.length - 1];
    if (last) {
      this.#seq = last.seq;
      this.#prev = last.hash;
    }
    return this;
  }

  async read() {
    let text = "";
    try {
      text = await readFile(this.#path, "utf8");
    } catch {
      return [];
    }
    return text
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return { malformed: true, raw: line };
        }
      });
  }

  /**
   * Appends a decision. `ts` is injected rather than read from the clock so
   * the chain is reproducible in tests and identical inputs hash identically.
   *
   * APPENDS ARE SERIALIZED, AND THAT IS LOAD-BEARING.
   *
   * The obvious implementation advances `#prev` synchronously and awaits the
   * write. Under concurrency that is wrong in a way that is invisible until it
   * matters: forty in-flight `append()` calls compute a correct chain in call
   * order, then their writes land in whatever order the filesystem returns
   * them, and the on-disk sequence no longer matches the hashes.
   *
   * The result is a chain that fails `verify()` on a run where nothing was
   * tampered with. That is worse than having no chain at all — an operator
   * investigating an incident sees "chain broken at record 5" and cannot tell
   * it from an attacker having edited the log. The one signal the audit trail
   * exists to provide is destroyed by ordinary load.
   *
   * Found by the consistency oracle under twenty concurrent calls.
   */
  async append(entry, ts) {
    const queued = this.#tail.then(
      () => this.#appendSerially(entry, ts),
      () => this.#appendSerially(entry, ts),
    );
    // The queue must not break on one failed write, so the tail swallows the
    // rejection. Callers still see it — `queued` is what they await.
    this.#tail = queued.then(
      () => undefined,
      () => undefined,
    );
    return queued;
  }

  /**
   * The critical section: build the record, write it, and only then advance.
   *
   * In-memory state is committed AFTER the write resolves. A failed append
   * therefore leaves the chain where it was, so the next record continues from
   * the last durable one rather than from a hash that was never persisted.
   */
  async #appendSerially(entry, ts) {
    const seq = this.#seq + 1;
    const record = {
      seq,
      ts: ts ?? new Date().toISOString(),
      prev_hash: this.#prev,
      ...entry,
    };
    record.hash = hashRecord(record);

    await appendFile(this.#path, JSON.stringify(record) + "\n", "utf8");

    this.#seq = seq;
    this.#prev = record.hash;
    return record;
  }

  /** Resolves once every queued append has been written. */
  async flush() {
    await this.#tail;
  }

  /**
   * Recomputes the chain. Returns the first break rather than a boolean, so an
   * operator learns *where* tampering starts, not merely that it happened.
   */
  async verify() {
    const records = await this.read();
    let prev = GENESIS;

    for (let i = 0; i < records.length; i++) {
      const r = records[i];
      if (r.malformed) {
        return { ok: false, records: records.length, brokenAt: i, reason: "Malformed record — line is not valid JSON." };
      }
      if (r.prev_hash !== prev) {
        return {
          ok: false,
          records: records.length,
          brokenAt: r.seq,
          reason: `Record ${r.seq} does not follow its predecessor. A record was altered or removed before this point.`,
        };
      }
      if (hashRecord(r) !== r.hash) {
        return {
          ok: false,
          records: records.length,
          brokenAt: r.seq,
          reason: `Record ${r.seq} has been modified — its contents no longer match its hash.`,
        };
      }
      prev = r.hash;
    }

    return { ok: true, records: records.length, head: prev };
  }
}
