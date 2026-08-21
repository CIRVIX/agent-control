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

  constructor({ onMessage, onInvalid = () => {} }) {
    this.#onMessage = onMessage;
    this.#onInvalid = onInvalid;
  }

  push(chunk) {
    this.#buffer += this.#decoder.write(chunk);

    let index;
    while ((index = this.#buffer.indexOf("\n")) !== -1) {
      const line = this.#buffer.slice(0, index).trim();
      this.#buffer = this.#buffer.slice(index + 1);
      if (!line) continue;
      try {
        this.#onMessage(JSON.parse(line));
      } catch (err) {
        this.#onInvalid(line, err);
      }
    }
  }

  /** Flush any trailing partial character at end-of-stream. */
  end() {
    this.#buffer += this.#decoder.end();
    const line = this.#buffer.trim();
    this.#buffer = "";
    if (!line) return;
    try {
      this.#onMessage(JSON.parse(line));
    } catch (err) {
      this.#onInvalid(line, err);
    }
  }
}

export function serialize(message) {
  return JSON.stringify(message) + "\n";
}

/* -------------------------------------------------------------------------- */
/*  Message shapes                                                             */
/* -------------------------------------------------------------------------- */

export const isRequest = (m) => m && m.jsonrpc === "2.0" && m.method && m.id !== undefined;
export const isNotification = (m) => m && m.jsonrpc === "2.0" && m.method && m.id === undefined;
export const isResponse = (m) => m && m.jsonrpc === "2.0" && m.id !== undefined && !m.method;

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
