/**
 * JSON-RPC 2.0 framing for MCP over stdio.
 *
 * MCP stdio transport is newline-delimited JSON. The subtlety that breaks
 * naive implementations: a chunk from a pipe is NOT a message. A single read
 * can deliver half a message, three messages, or a message split mid-UTF-8
 * character. This buffers until a newline and decodes incrementally, which is
 * the difference between a proxy that works and one that corrupts payloads
 * under load.
 */

import { StringDecoder } from "node:string_decoder";

/**
 * Splits a byte stream into JSON-RPC messages.
 *
 * `onMessage` receives parsed objects. Lines that fail to parse are passed to
 * `onInvalid` rather than thrown — a proxy that dies on one malformed frame
 * takes the agent down with it, and a hostile upstream could do that
 * deliberately.
 */
export class MessageFramer {
  #buffer = "";
  #decoder = new StringDecoder("utf8");
  #onMessage;
  #onInvalid;

  #bytes = 0;
  #discarding = false;
  #maxFrameBytes;

  constructor({ onMessage, onInvalid = () => {}, maxFrameBytes = 8 * 1024 * 1024 }) {
    if (!Number.isSafeInteger(maxFrameBytes) || maxFrameBytes < 1) throw new RangeError("Invalid frame limit.");
    this.#onMessage = onMessage;
    this.#onInvalid = onInvalid;
    this.#maxFrameBytes = maxFrameBytes;
  }

  push(chunk) {
    const text = this.#decoder.write(chunk);
    let start = 0;
    while (start < text.length) {
      const end = text.indexOf("\n", start);
      const part = text.slice(start, end === -1 ? text.length : end);
      if (!this.#discarding) {
        this.#bytes += Buffer.byteLength(part);
        if (this.#bytes > this.#maxFrameBytes) {
          this.#buffer = "";
          this.#discarding = true;
          this.#onInvalid("", new RangeError("JSON-RPC frame exceeds the byte limit."));
        } else {
          this.#buffer += part;
        }
      }
      if (end === -1) break;
      if (!this.#discarding) this.#emit(this.#buffer.trim());
      this.#buffer = "";
      this.#bytes = 0;
      this.#discarding = false;
      start = end + 1;
    }
  }

  #emit(line) {
    if (!line) return;
    let message;
    try {
      message = JSON.parse(line);
    } catch (err) {
      this.#onInvalid(line, err);
      return;
    }
    this.#onMessage(message);
  }

  /** Flush any trailing partial character at end-of-stream. */
  end() {
    const tail = this.#decoder.end();
    if (!this.#discarding) {
      this.#buffer += tail;
      if (this.#bytes + Buffer.byteLength(tail) > this.#maxFrameBytes) {
        this.#onInvalid("", new RangeError("JSON-RPC frame exceeds the byte limit."));
      } else this.#emit(this.#buffer.trim());
    }
    this.#buffer = "";
    this.#bytes = 0;
    this.#discarding = false;
  }
}

export function serialize(message) {
  return JSON.stringify(message) + "\n";
}

/* -------------------------------------------------------------------------- */
/*  Message shapes                                                             */
/* -------------------------------------------------------------------------- */

const envelope = (m) => Boolean(m && typeof m === "object" && !Array.isArray(m) && m.jsonrpc === "2.0");
const validId = (id) => id === null || typeof id === "string" || (typeof id === "number" && Number.isFinite(id));
const methodShape = (m) => envelope(m) && typeof m.method === "string" && m.method.length > 0 &&
  !Object.hasOwn(m, "result") && !Object.hasOwn(m, "error") &&
  (m.params === undefined || (m.params !== null && typeof m.params === "object"));
export const isRequest = (m) => methodShape(m) && Object.hasOwn(m, "id") && validId(m.id);
export const isNotification = (m) => methodShape(m) && !Object.hasOwn(m, "id");
export const isResponse = (m) => envelope(m) && Object.hasOwn(m, "id") && validId(m.id) &&
  !Object.hasOwn(m, "method") && (Object.hasOwn(m, "result") !== Object.hasOwn(m, "error")) &&
  (!Object.hasOwn(m, "error") || (m.error !== null && typeof m.error === "object" && Number.isInteger(m.error.code) && typeof m.error.message === "string"));

/**
 * JSON-RPC application error codes. -32000..-32099 is the reserved
 * implementation-defined range; MCP leaves it to the server.
 */
export const ERROR_CODE = {
  PARSE: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL: -32603,
  /** Cirvix: the policy set denied this call. */
  POLICY_DENIED: -32001,
  /** Cirvix: the call is held awaiting human approval. */
  POLICY_HOLD: -32002,
  /** Cirvix: the upstream server is not registered or is quarantined. */
  UPSTREAM_UNAVAILABLE: -32003,
};

export function errorResponse(id, code, message, data) {
  return { jsonrpc: "2.0", id, error: { code, message, ...(data ? { data } : {}) } };
}

/**
 * A denial rendered as a *tool result* rather than a protocol error.
 *
 * This matters more than it looks. A JSON-RPC error is a transport failure —
 * many agent runtimes surface it as a crash and abort the run. A tool result
 * with `isError: true` is data the model reads, so the agent sees the refusal,
 * the policy that caused it, and the suggested alternative, and re-plans.
 * That single choice is the difference between a control plane and a kill
 * switch.
 */
export function deniedToolResult(id, decision) {
  const lines = [
    `Denied by policy: ${decision.rule ?? "default-deny"}`,
    decision.reason,
    decision.remediation ? `Try instead: ${decision.remediation}` : null,
    `Decision id: ${decision.decisionId ?? "—"}`,
  ].filter(Boolean);

  return {
    jsonrpc: "2.0",
    id,
    result: {
      isError: true,
      content: [{ type: "text", text: lines.join("\n") }],
      _meta: {
        "cirvix/verdict": "deny",
        "cirvix/rule": decision.rule,
        "cirvix/decision_id": decision.decisionId,
        "cirvix/appealable": true,
      },
    },
  };
}

export function heldToolResult(id, decision) {
  const lines = [
    `Held for human approval: ${decision.rule}`,
    decision.reason,
    decision.approvers?.length ? `Waiting on: ${decision.approvers.join(", ")}` : null,
    `Approval id: ${decision.approvalId ?? "—"}`,
  ].filter(Boolean);

  return {
    jsonrpc: "2.0",
    id,
    result: {
      isError: true,
      content: [{ type: "text", text: lines.join("\n") }],
      _meta: {
        "cirvix/verdict": "hold",
        "cirvix/rule": decision.rule,
        "cirvix/approval_id": decision.approvalId,
      },
    },
  };
}
