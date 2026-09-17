/**
 * TerminalUI facade — auto-disables for non-TTY/NO_COLOR/CI/json.
 */

export * from "./controller.mjs";
export * from "./theme.mjs";
export * from "./primitives.mjs";
export * from "./decisions.mjs";
export * from "./intercept.mjs";
export * from "./live.mjs";

import { shouldAnimate } from "./controller.mjs";
import { brandHeader, panel } from "./primitives.mjs";
import { bold, dim, green, red, amber, blue } from "../format.mjs";

export function createUI({ stream = process.stdout, pace, json } = {}) {
  const enabled = shouldAnimate({ pace, json });
  return {
    enabled,
    brandHeader,
    panel,
    write(s) {
      try {
        stream.write(s);
      } catch {}
    },
    writeln(s = "") {
      try {
        stream.write(s + "\n");
      } catch {}
    },
  };
}

/** Small helper to render a status dot with color, but text label always present. */
export function statusDot(ok, tone) {
  const dot = "●";
  return tone ? tone(`${dot}`) : dot;
}

/** Format a count line: "0 blocked · 0 approvals · 0 violations" */
export function countsLine({ blocked = 0, approvals = 0, violations = 0, sanitized = 0 } = {}) {
  const parts = [];
  parts.push(`${blocked} blocked`);
  if (sanitized) parts.push(`${sanitized} sanitized`);
  parts.push(`${approvals} approvals`);
  parts.push(`${violations} violations`);
  return dim(parts.join("  ·  "));
}
