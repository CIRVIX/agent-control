/**
 * A minimal in-memory audit sink for tests that need to observe exactly what
 * was appended, without a file on disk. Same async `append` contract as
 * AuditChain, so anything that accepts an AuditChain accepts this.
 */
export class CaptureAudit {
  #records = [];

  get records() {
    return this.#records;
  }

  async append(record) {
    this.#records.push(record);
  }

  async verify() {
    return { ok: true, records: this.#records.length, brokenAt: null };
  }
}
