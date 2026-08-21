/**
 * Human-in-the-loop approvals, locally.
 *
 * A REQUIRE_APPROVAL decision suspends a call for a person. This is the local
 * queue that person works from — a JSONL file next to the audit chain, plus
 * `cirvix approvals` / `cirvix approve` / `cirvix deny` to work it.
 *
 * WHY THE DEFAULT IS NON-BLOCKING
 *
 * The obvious design has `request()` wait until somebody answers. It is wrong
 * for the common case: the agent is a subprocess of an editor, nobody is
 * watching a second terminal, and a blocking hold looks exactly like a hung
 * tool call. The agent sits there until it times out, and the operator's
 * conclusion is that Cirvix broke their editor.
 *
 * So by default `request()` records the approval and returns `pending`
 * immediately. The gateway renders that as a readable tool result naming the
 * approval id — the agent learns the call is waiting on a named human, and can
 * say so or work on something else. `--wait` opts into blocking for the case
 * where somebody genuinely is watching, and it always has a timeout.
 *
 * THE STATE MACHINE IS DELIBERATELY SMALL
 *
 *   pending ──approve──▶ approved   (terminal)
 *           ──deny─────▶ denied     (terminal)
 *           ──expire───▶ expired    (terminal)
 *
 * Terminal means terminal: an approved request cannot later be denied, and a
 * decided request cannot be decided twice. Without that, "who approved this"
 * has more than one answer and the record stops being evidence.
 */

import { appendFile, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";

import { requestId } from "./normalize.mjs";

export const STATE = {
  PENDING: "pending",
  APPROVED: "approved",
  DENIED: "denied",
  EXPIRED: "expired",
  /** Approved, and the call it authorized has since run. */
  CONSUMED: "consumed",
};

const TERMINAL = new Set([STATE.APPROVED, STATE.DENIED, STATE.EXPIRED, STATE.CONSUMED]);

/** Default lifetime of an unanswered approval. */
const DEFAULT_TTL_MS = 15 * 60 * 1000;

/**
 * How long an approval stays spendable after a person grants it.
 *
 * Shorter than the pending TTL on purpose. "Yes, do that" means yes to the
 * thing in front of the approver now — not to the same call at 3am next
 * Tuesday, by which time the state it was reasoning about has changed.
 */
const DEFAULT_GRANT_TTL_MS = 10 * 60 * 1000;

/**
 * What an approval is an approval OF.
 *
 * This is the difference between a working control and a confused deputy. An
 * approval bound to a *tool* means approving `database.write` on `audit_log`
 * also authorizes `database.write` on `salaries` — the agent asks once,
 * gets a yes, and spends it on something else. So the grant is bound to the
 * exact call: agent, action, canonical resource, command, and a hash of the
 * arguments.
 *
 * The ARGUMENTS ARE HASHED, NEVER STORED. They routinely contain credential
 * material, and an approval queue is a file an operator reads and a console
 * displays. A hash binds precisely and discloses nothing.
 *
 * THE CHAIN OF CUSTODY IS PART OF WHAT WAS APPROVED.
 *
 * It was not, and the gap was approval laundering. An operator approves a
 * database write and is shown `planner → worker`. The same agent, tool and
 * arguments then arrive under `planner → attacker → worker`, and every check
 * passes: identity really is `worker`, the chain really does narrow correctly,
 * and policy really did ask for an approval that really was granted. Four
 * subsystems agreeing about four different operations.
 *
 * The inverse mattered just as much: get the approval while acting under a
 * narrow delegation, then present none at all. Without a delegation the call is
 * governed by policy alone — which is wider — so the yes would be released into
 * a larger authority than the one it was granted under.
 *
 * `null` for a call made with no delegation, which keeps single-agent
 * deployments byte-identical to before.
 */
export function approvalFingerprint(call) {
  const canonical = JSON.stringify({
    agent: call.agent ?? null,
    action: call.action ?? call.tool ?? null,
    resource: call.resource ?? "",
    command: call.command ?? null,
    delegation: call.delegation?.principals ?? null,
    args: stableStringify(call.arguments ?? {}),
  });
  return "sha256:" + createHash("sha256").update(canonical).digest("hex").slice(0, 32);
}

/** Key-sorted serialization, so argument order cannot change the fingerprint. */
function stableStringify(value, depth = 0) {
  if (depth > 12 || value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => stableStringify(v, depth + 1)).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${stableStringify(value[k], depth + 1)}`)
    .join(",")}}`;
}

export class ApprovalStore {
  /** id → record, rebuilt from the log on open. */
  #byId = new Map();

  /**
   * @param {string} path        JSONL log; every state transition is appended
   * @param {object} [opts]
   * @param {number} [opts.ttlMs]
   * @param {(e:object)=>void} [opts.onEvent]
   */
  constructor(path, { ttlMs = DEFAULT_TTL_MS, grantTtlMs = DEFAULT_GRANT_TTL_MS, onEvent = () => {} } = {}) {
    this.path = path;
    this.ttlMs = ttlMs;
    /** How long a granted approval stays spendable. See DEFAULT_GRANT_TTL_MS. */
    this.grantTtlMs = grantTtlMs;
    this.onEvent = onEvent;
  }

  /**
   * Replays the log to rebuild current state.
   *
   * Append-only with replay, rather than rewriting a state file: the history of
   * who decided what and when is the point, and a mutable file loses it on the
   * first concurrent write.
   */
  async open() {
    let text = "";
    try {
      text = await readFile(this.path, "utf8");
    } catch {
      return this;
    }
    for (const line of text.split("\n").filter(Boolean)) {
      let entry;
      try {
        entry = JSON.parse(line);
      } catch {
        continue;
      }
      if (entry.type === "request") {
        this.#byId.set(entry.id, { ...entry, state: STATE.PENDING });
      } else if (entry.type === "decision") {
        const existing = this.#byId.get(entry.id);
        if (!existing) continue;

        // Spending a grant is the one transition allowed out of a terminal
        // state, because APPROVED is terminal for *deciding* and not for
        // *using*. Replayed explicitly so a restart mid-run cannot resurrect a
        // grant that was already spent — otherwise a crash between execution
        // and the next start turns a single-use approval into a reusable one.
        if (entry.state === STATE.CONSUMED) {
          if (existing.state === STATE.APPROVED) {
            existing.state = STATE.CONSUMED;
            existing.consumedAt = entry.ts;
            existing.consumedBy = entry.consumedBy ?? null;
          }
          continue;
        }

        // Any other decision for an already-terminal request is ignored, so a
        // hand-edited log cannot rewrite history by appending a second verdict.
        if (!TERMINAL.has(existing.state)) {
          existing.state = entry.state;
          existing.decidedBy = entry.decidedBy;
          existing.decidedAt = entry.ts;
          existing.note = entry.note ?? null;
        }
      }
    }
    return this;
  }

  /**
   * Records a call waiting on a human.
   *
   * Returns immediately with `pending` unless `wait` is set. Identical calls do
   * NOT deduplicate: two attempts to deploy to production are two decisions a
   * person should make, even if the arguments match.
   *
   * @returns {Promise<{id:string,state:string,decidedBy?:string}>}
   */
  async request(fields, { wait = 0, pollMs = 500 } = {}) {
    const id = fields.approval_id ?? requestId("apr");
    const record = {
      type: "request",
      id,
      ts: new Date().toISOString(),
      expiresAt: new Date(Date.now() + this.ttlMs).toISOString(),
      request_id: fields.request_id ?? null,
      agent: fields.agent ?? null,
      tool: fields.tool ?? null,
      resource: fields.resource ?? null,
      risk: fields.risk ?? null,
      rule: fields.rule ?? null,
      reason: fields.reason ?? null,
      approvers: fields.approvers ?? [],
      // What this approval is an approval OF. Without it a grant is bound to a
      // tool rather than to a call, and one yes authorizes every later use of
      // that tool.
      fingerprint: fields.fingerprint ?? null,
    };

    this.#byId.set(id, { ...record, state: STATE.PENDING });
    await this.#write(record);
    this.onEvent({ kind: "approval_requested", ...record });

    if (!wait) return { id, state: STATE.PENDING };

    // Polling rather than watching the file: a watcher is one more failure mode
    // across three platforms, and an approval is a human-scale event where a
    // 500ms poll is imperceptible.
    const deadline = Date.now() + wait;
    while (Date.now() < deadline) {
      const current = this.get(id);
      if (current && TERMINAL.has(current.state)) {
        return { id, state: current.state, decidedBy: current.decidedBy };
      }
      await new Promise((r) => setTimeout(r, pollMs));
      await this.open();
    }
    return { id, state: STATE.PENDING };
  }

  /**
   * Decides a pending approval.
   *
   * @param {string} id
   * @param {"approved"|"denied"} state
   * @param {string} decidedBy   who is accountable — never defaulted silently
   */
  async decide(id, state, decidedBy, note = null) {
    if (state !== STATE.APPROVED && state !== STATE.DENIED) {
      throw new Error(`Approvals are approved or denied, not "${state}".`);
    }
    if (!decidedBy) {
      throw new Error("An approval decision must name who made it.");
    }

    const record = this.get(id);
    if (!record) throw new Error(`No approval with id ${id}.`);
    if (TERMINAL.has(record.state)) {
      throw new Error(
        `Approval ${id} is already ${record.state}${record.decidedBy ? ` (by ${record.decidedBy})` : ""}. A decided approval cannot be decided again.`,
      );
    }
    if (this.#isExpired(record)) {
      await this.#expire(record);
      throw new Error(`Approval ${id} expired at ${record.expiresAt} and can no longer be decided.`);
    }

    const entry = {
      type: "decision",
      id,
      ts: new Date().toISOString(),
      state,
      decidedBy,
      note,
    };
    record.state = state;
    record.decidedBy = decidedBy;
    record.decidedAt = entry.ts;
    record.note = note;

    await this.#write(entry);
    this.onEvent({ kind: "approval_decided", id, state, decidedBy });
    return record;
  }

  get(id) {
    const record = this.#byId.get(id);
    if (record && record.state === STATE.PENDING && this.#isExpired(record)) {
      record.state = STATE.EXPIRED;
    }
    return record ?? null;
  }

  /**
   * An approved, unspent grant for exactly this call — or null.
   *
   * THIS METHOD IS THE ENTIRE POINT OF THE APPROVAL FEATURE, AND IT DID NOT
   * EXIST.
   *
   * Without it there is no path from "a person said yes" to "the call runs":
   * every submission created a fresh pending request, so an approved approval
   * released nothing and the agent retried into a new queue entry forever. A
   * hold that can never be released is a denial with extra steps, and the
   * human-in-the-loop feature was decorative. The state-machine tests found it.
   *
   * Three properties, each load-bearing:
   *
   *   MATCHED BY FINGERPRINT, not by tool. Approving `database.write` on
   *   `audit_log` must not release `database.write` on `salaries`.
   *
   *   SINGLE USE. A grant authorizes one execution. Otherwise one yes
   *   authorizes an unbounded number of identical calls, forever, which is not
   *   what anybody means when they click approve.
   *
   *   SEPARATELY EXPIRING. A grant goes stale faster than a pending request,
   *   because "yes, do that" refers to the situation the approver was looking
   *   at.
   */
  findGrant(fingerprint) {
    if (!fingerprint) return null;
    for (const record of this.#byId.values()) {
      if (record.state !== STATE.APPROVED) continue;
      if (record.fingerprint !== fingerprint) continue;
      if (this.#grantExpired(record)) continue;
      return record;
    }
    return null;
  }

  #grantExpired(record) {
    if (!record.decidedAt) return false;
    return Date.now() - new Date(record.decidedAt).getTime() > this.grantTtlMs;
  }

  /**
   * Spends a grant, recording which call spent it.
   *
   * Append-only like every other transition, so "what did that approval
   * authorize" has an answer after the fact — which is the question asked in
   * the incident review, not during the run.
   */
  async consume(id, requestIdentifier) {
    const record = this.get(id);
    if (!record) throw new Error(`No approval with id ${id}.`);
    if (record.state !== STATE.APPROVED) {
      throw new Error(`Approval ${id} is ${record.state}, not approved; it cannot be spent.`);
    }
    if (this.#grantExpired(record)) {
      throw new Error(`Approval ${id} was granted too long ago to spend.`);
    }

    const entry = {
      type: "decision",
      id,
      ts: new Date().toISOString(),
      state: STATE.CONSUMED,
      decidedBy: record.decidedBy,
      consumedBy: requestIdentifier ?? null,
    };
    record.state = STATE.CONSUMED;
    record.consumedAt = entry.ts;
    record.consumedBy = entry.consumedBy;

    await this.#write(entry);
    this.onEvent({ kind: "approval_consumed", id, requestId: requestIdentifier ?? null });
    return record;
  }

  /** Everything still waiting on somebody, oldest first. */
  pending() {
    return [...this.#byId.values()]
      .filter((r) => this.get(r.id)?.state === STATE.PENDING)
      .sort((a, b) => a.ts.localeCompare(b.ts));
  }

  all() {
    return [...this.#byId.values()].map((r) => this.get(r.id));
  }

  #isExpired(record) {
    return Boolean(record.expiresAt && Date.now() > new Date(record.expiresAt).getTime());
  }

  async #expire(record) {
    record.state = STATE.EXPIRED;
    await this.#write({ type: "decision", id: record.id, ts: new Date().toISOString(), state: STATE.EXPIRED, decidedBy: null });
  }

  async #write(entry) {
    await appendFile(this.path, JSON.stringify(entry) + "\n", "utf8");
  }
}
