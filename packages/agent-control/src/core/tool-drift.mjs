/**
 * TOOL-DEFINITION DRIFT, AS AN AUTHORIZATION INPUT (P0-D §13).
 *
 * A tool the operator approved and a tool that answers to the same name are not
 * the same tool. The MCP gateway has always known this — it fingerprints a tool
 * definition at `tools/list` and PINS it — but the check lived only in the
 * gateway's own listing code, so the answer was a *withholding* decision made
 * outside the authorization core. That has two consequences a governance
 * product cannot live with:
 *
 *   1. The socket surface had no drift check at all, so "we pin tool
 *      definitions" was true of one transport.
 *   2. Even on the gateway, a drifted tool was simply not advertised. If the
 *      client already knew the name — a cached tool list, a hardcoded call, a
 *      second client — the definition that reached execution was never
 *      compared against its pin on the decision path.
 *
 * This module is the one place that decides what a tool's definition status is,
 * so the gateway can withhold it AND the canonical core can refuse it, from the
 * same answer.
 *
 * TRUST
 *
 * The pin is operator state (or a durable file), not a value derived from the
 * server's own response — otherwise a server could re-pin itself by declaring a
 * new definition. `observe` sets a pin only where none exists (trust on first
 * use, which is what the gateway already did) and NEVER overwrites one.
 */

import { createHash } from "node:crypto";
import { canonicalJson } from "./audit.mjs";

export const TOOL_DRIFT_STATUS = Object.freeze({
  /** The definition matches its pin, or is being pinned for the first time. */
  IN_PIN: "in-pin",
  /** The definition differs from its pin. An approved tool changed. */
  DRIFTED: "drifted",
  /** This tool/server pair has never been seen, so there is no pin to honor. */
  UNKNOWN: "unknown",
  /** No server context: a local tool, where drift pins do not apply. */
  NOT_APPLICABLE: "not-applicable",
});

/** Stable fingerprint of a tool definition. Key order must not matter. */
export function fingerprintToolDefinition(tool) {
  const shape = {
    name: tool?.name ?? null,
    description: tool?.description ?? null,
    inputSchema: tool?.inputSchema ?? tool?.input_schema ?? null,
  };
  return "sha256:" + createHash("sha256").update(canonicalJson(shape)).digest("hex").slice(0, 32);
}

/**
 * The pin registry.
 *
 * `pins` may be supplied so the gateway keeps using the exact Map it already
 * exposes (`gateway.pins`), rather than a copy of it — two maps would be two
 * answers to "is this tool approved".
 */
export class ToolPinRegistry {
  /**
   * @param {object} [opts]
   * @param {Map}    [opts.pins]        the pin map (shared, never copied)
   * @param {string} [opts.separator]   the server/tool join used in keys
   * @param {(tool:object)=>string} [opts.fingerprint]  the fingerprint in use.
   *   Injected so a boundary that already persists pins keeps the SAME
   *   algorithm: changing the fingerprint function silently re-pins every tool,
   *   which is exactly the drift this module exists to catch.
   */
  constructor({ pins = new Map(), separator = "__", fingerprint = fingerprintToolDefinition } = {}) {
    this.pins = pins;
    this.separator = separator;
    this.fingerprint = fingerprint;
  }

  key(server, tool) {
    return server ? `${server}${this.separator}${tool}` : String(tool);
  }

  /**
   * Records a definition seen in a listing, and says whether it drifted.
   *
   * A pin is SET here and never changed: that is what makes drift detectable.
   */
  observe(server, tool, definition = { name: tool }) {
    const key = this.key(server, tool);
    const fingerprint = this.fingerprint(definition);
    const pin = this.pins.get(key);
    if (!pin) {
      this.pins.set(key, fingerprint);
      return { key, fingerprint, pinned: true, status: TOOL_DRIFT_STATUS.IN_PIN, expected: fingerprint, actual: fingerprint };
    }
    const drifted = pin !== fingerprint;
    return {
      key,
      fingerprint,
      pinned: false,
      drifted,
      status: drifted ? TOOL_DRIFT_STATUS.DRIFTED : TOOL_DRIFT_STATUS.IN_PIN,
      expected: pin,
      actual: fingerprint,
    };
  }

  /** The status of a tool at DECISION time, from the pin and the live definition. */
  status({ server = null, tool = null, definition = undefined } = {}) {
    if (!server) return { status: TOOL_DRIFT_STATUS.NOT_APPLICABLE, key: null, reason: null };
    const key = this.key(server, tool);
    const pin = this.pins.get(key);
    if (!pin) {
      return {
        status: TOOL_DRIFT_STATUS.UNKNOWN,
        key,
        reason: `No approved definition is pinned for ${key}.`,
      };
    }
    if (definition === undefined) {
      /* The caller has no live definition to compare (the tool was not in the
         last listing) — that is itself a reason to refuse, not to assume the
         pin still holds. */
      return {
        status: TOOL_DRIFT_STATUS.UNKNOWN,
        key,
        expected: pin,
        actual: null,
        reason: `${key} is pinned but was not present in the last tool listing.`,
      };
    }
    const actual = this.fingerprint(definition);
    if (actual === pin) return { status: TOOL_DRIFT_STATUS.IN_PIN, key, expected: pin, actual };
    return {
      status: TOOL_DRIFT_STATUS.DRIFTED,
      key,
      expected: pin,
      actual,
      reason: `The definition of ${key} does not match the approved pin (approved ${pin.slice(0, 15)}…, live ${actual.slice(0, 15)}…).`,
    };
  }

  /** True when the status is one the canonical core refuses by default. */
  static isRefusal(status) {
    return status === TOOL_DRIFT_STATUS.DRIFTED;
  }
}
