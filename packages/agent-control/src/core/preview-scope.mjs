/**
 * PREVIEW MARKING for the surfaces that evaluate a SUBSET of the canonical
 * stages (P0-D exit-gate, remaining-work item 1).
 *
 * `cirvix console --eval` / `cirvix policy explain` (simulate.mjs),
 * `cirvix shadow` (shadow.mjs) and `cirvix policy test` (policy.mjs) answer
 * their question by calling `policy.evaluate`, `risk.classify` and
 * `intent.evaluateIntent` directly. That is the right scope for what they are
 * FOR — policy authoring and review — but it is not the authorization answer:
 * identity, delegation/authority, revocation, kill, session, baseline, drift,
 * approval, credential, sanitization and audit are not evaluated, because none
 * of that state belongs to a preview.
 *
 * The failure mode this module exists to prevent is a preview verdict being
 * READ as THE verdict: "the simulator said allow" quoted after an incident as
 * though the boundary had said it. Everything a preview prints therefore
 * carries the same unmistakable marking, derived from ONE definition of what a
 * preview does not evaluate.
 */

import { CANONICAL_STAGES } from "./authorize.mjs";

/** The stages a preview evaluates, by canonical name. */
export const PREVIEW_EVALUATED_STAGES = Object.freeze(["policy", "risk", "intent"]);

/**
 * The stages a preview does NOT evaluate: every canonical stage that is not in
 * `PREVIEW_EVALUATED_STAGES`. Derived, not listed, so a stage added to the
 * canonical order cannot silently vanish from this disclosure.
 */
export const PREVIEW_OMITTED_STAGES = Object.freeze(
  CANONICAL_STAGES.filter((s) => !PREVIEW_EVALUATED_STAGES.includes(s)),
);

/** The one-line banner every preview output carries. */
export const PREVIEW_BANNER =
  "PREVIEW — policy/risk/intent only. Not an authorization decision: identity, authority, revocation, session, approval, credential and audit were NOT evaluated.";

/** The compact banner for shadow/policy-test rows where width is tight. */
export const PREVIEW_SHORT_BANNER = "PREVIEW (policy/risk/intent only — not an authorization decision)";

/** Machine-readable scope block for JSON output. */
export function previewScope() {
  return {
    kind: "preview",
    evaluated: [...PREVIEW_EVALUATED_STAGES],
    omitted: [...PREVIEW_OMITTED_STAGES],
    notice: PREVIEW_BANNER,
  };
}

/**
 * The authoritative answer for a preview asker. Routes the SAME call through
 * the canonical core with no boundary dependencies, so "what would the
 * boundary do about policy?" and "what did the preview say?" can be compared
 * in one place — and differ, loudly, in the report.
 *
 * @param {{ call: object, deps?: object }} input
 */
export async function previewThroughCore({ call, deps = null }) {
  const { authorize } = await import("./authorize.mjs");
  return authorize(
    call,
    { agent: call.agent, identityMode: "dev-insecure" },
    deps ?? {},
  );
}
