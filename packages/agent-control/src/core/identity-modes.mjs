/**
 * Explicit identity modes for a boundary — and the end of silent fallback.
 *
 * THE BUG CLASS THIS CLOSES. Identity enforcement used to switch itself on
 * from enrolment state: "verify callers once at least one agent is enrolled".
 * Both directions of that inference are wrong, and one is dangerous:
 *
 *   - A host with one enrolled agent had identity enforcement its operator
 *     never asked for: every caller suddenly needs a credential because SOME
 *     agent enrolled.
 *
 *   - Worse, the reverse: an empty production host behaved exactly like an
 *     unauthenticated one. `permit agent = "x"` evaluated whatever name the
 *     caller typed, so a fresh install was an unauthenticated authorization
 *     endpoint until somebody happened to enrol. A security posture that
 *     depends on which OPTIONAL setup steps have run is not a posture.
 *
 * THE RULE NOW. A boundary's mode is a constructor decision, resolved through
 * `normalizeIdentityMode`, and it is NEVER inferred from enrolment state:
 *
 *   PRODUCTION   identity required. A caller that cannot prove who it is —
 *                including one that arrives with no verifier configured at
 *                all — is refused before any authorization stage runs. The
 *                CLI gateway and runtime default to this.
 *
 *   BOOTSTRAP    an explicitly activated enrollment window. Unverified
 *                callers are accepted ONLY while no identity verifier exists
 *                on the host, every decision record says so, and doctor
 *                reports the mode. The moment a verifier exists, bootstrap
 *                refuses unverified callers exactly like production. A claim
 *                is still never trusted: the caller's stated agent name stays
 *                metadata.
 *
 *   DEV-INSECURE the developer compatibility profile, reachable ONLY through
 *                an explicit flag — never by default, never by inference.
 *                Still not a trust upgrade: claimed names stay metadata and
 *                every record is loudly marked.
 *
 *   COMPAT       the library default for in-process SDK use, where there is
 *                no transport boundary to guard: the historic behaviour
 *                (verify when configured, otherwise legacy claim semantics),
 *                silent, and not selectable from the CLI. A boundary that
 *                faces callers over a transport should never run COMPAT.
 */

export const IDENTITY_MODE = Object.freeze({
  PRODUCTION: "production",
  BOOTSTRAP: "bootstrap",
  DEV_INSECURE: "dev-insecure",
  COMPAT: "compat",
});

export const IDENTITY_MODES = Object.freeze(Object.values(IDENTITY_MODE));

/**
 * Normalizes operator input into a mode, pairing the open modes with the
 * notice an operator (and every decision record) should see.
 */
export function normalizeIdentityMode(value) {
  if (value === undefined || value === null || value === "") {
    return { mode: IDENTITY_MODE.COMPAT, notice: null };
  }
  const mode = String(value).trim().toLowerCase();
  switch (mode) {
    case IDENTITY_MODE.PRODUCTION:
      return { mode, notice: null };
    case IDENTITY_MODE.BOOTSTRAP:
      return {
        mode,
        notice:
          "IDENTITY MODE = bootstrap: unverified callers are accepted until an identity verifier is configured. Run `cirvix enroll` to close this window.",
      };
    case IDENTITY_MODE.DEV_INSECURE:
      return {
        mode,
        notice:
          "IDENTITY MODE = dev-insecure: callers are NOT verified. Never run this on a host you did not set up yourself.",
      };
    case IDENTITY_MODE.COMPAT:
      return { mode, notice: null };
    default:
      throw new TypeError(`Unknown identity mode "${value}". Known modes: ${IDENTITY_MODES.join(", ")}.`);
  }
}

/**
 * Resolves the mode for a shipped production boundary (the CLI gateway and
 * runtime): explicit flag first, then environment, then PRODUCTION.
 *
 * The default is the strict mode. Nothing about an unenrolled host relaxes it
 * — opening one is always an operator's explicit choice.
 */
export function resolveIdentityMode({ flag = undefined, env = undefined } = {}) {
  const raw = flag ?? env ?? undefined;
  if (raw === undefined || raw === null || raw === "") return IDENTITY_MODE.PRODUCTION;
  const { mode } = normalizeIdentityMode(raw);
  return mode;
}
