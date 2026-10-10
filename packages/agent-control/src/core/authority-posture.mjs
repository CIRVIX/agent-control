/**
 * THE AUTHORITY POSTURE IS DERIVED ONCE, HERE, AND STATED — NEVER ASSUMED.
 *
 * Two postures exist and they are very different products: REQUIRED refuses a
 * governed call that carries no signed human authority (`delegation-required`);
 * policy-only decides a call by policy alone, with one exception that matters —
 * a grant that IS presented is still verified, because presenting authority can
 * only narrow, never widen.
 *
 * The P0-D exit-gate criterion is that hardened production is never silently
 * policy-only. The posture is therefore DERIVED from what the host actually has:
 *
 *   --authority-policy required|policy-only      explicit selection, wins
 *   --require-authority / CIRVIX_REQUIRE_AUTHORITY
 *                                                explicit, wins over the default
 *   authority model configured (≥1 registered principal)
 *                                                REQUIRED — the hardened default
 *   no authority model configured                policy-only, and NOT silently:
 *                                                it is logged as the
 *                                                compatibility posture and
 *                                                reported by doctor and status
 *
 * The last row is the entire point. A host with a delegation verifier and
 * registered principals that never passed a flag used to be decided by policy
 * alone — exactly the downgrade an attacker routes around a signature. A host
 * with NO authority model has nothing to require; policy-only there is not a
 * fallback, it is the only meaningful posture, and it says so.
 */

/** A posture this host selected explicitly, kept only for compatibility. */
export const AUTHORITY_POLICY = Object.freeze({
  REQUIRED: "required",
  POLICY_ONLY: "policy-only",
});

/**
 * Resolves the authority posture. Pure with respect to its inputs; the only
 * asynchrony is the principal-store read, so every branch is directly testable
 * and no composition root can quietly re-implement the rule.
 *
 * @returns {Promise<{required: boolean, source: string, hasAuthorityModel: boolean}>}
 */
export async function resolveAuthorityPosture({
  requireAuthority = false,
  authorityPolicy = null,
  principalStore,
  log = () => {},
} = {}) {
  const policy = typeof authorityPolicy === "string" ? authorityPolicy.trim().toLowerCase() : null;
  if (policy && policy !== AUTHORITY_POLICY.REQUIRED && policy !== AUTHORITY_POLICY.POLICY_ONLY) {
    throw new Error(`--authority-policy must be "${AUTHORITY_POLICY.REQUIRED}" or "${AUTHORITY_POLICY.POLICY_ONLY}" (got "${authorityPolicy}").`);
  }
  const hasAuthorityModel = principalStore ? !(await principalStore.isEmpty()) : false;
  if (policy === AUTHORITY_POLICY.REQUIRED) {
    return { required: true, source: "--authority-policy=required", hasAuthorityModel };
  }
  if (policy === AUTHORITY_POLICY.POLICY_ONLY) {
    return {
      required: false,
      source: "--authority-policy=policy-only (explicit compatibility)",
      hasAuthorityModel,
      note: "policy-only is a compatibility posture: presented authority is verified, but none is required",
    };
  }
  if (requireAuthority) {
    return { required: true, source: "--require-authority", hasAuthorityModel };
  }
  if (hasAuthorityModel) {
    log("authority posture: an authority model is configured — hardened default REQUIRES signed human authority.");
    return { required: true, source: "hardened default (authority model configured)", hasAuthorityModel };
  }
  return {
    required: false,
    source: "compatibility default (no authority model configured)",
    hasAuthorityModel,
    note: "policy-only because nothing on this host can issue a grant; not a silent fallback — doctor and status report it",
  };
}

/** The one-line statement both composition roots and doctor log or print. */
export function describeAuthorityPosture({ required, source }) {
  return required
    ? `authority posture = REQUIRED (via ${source}): a governed call carrying no signed human authority is refused (delegation-required).`
    : `authority posture = POLICY-ONLY (compatibility, via ${source}): a grant that is presented is always verified, but none is required. Pass --require-authority or --authority-policy=required to require one.`;
}
