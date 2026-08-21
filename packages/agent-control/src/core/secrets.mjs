/**
 * The secrets edge — substitution at the boundary, and the return path.
 *
 * The control plane holds the material and decides who may spend a handle.
 * This module is the half that runs next to the agent, and it exists so the
 * credential passes through exactly one place: the moment a permitted call is
 * written to an upstream.
 *
 *   agent  ─▶  Authorization: Bearer sec_handle_a89f…      (opaque, in context)
 *   edge   ─▶  resolve(handle, destination) ─▶ control plane
 *   edge   ─▶  Authorization: Bearer rk_live_…             (real, on the wire)
 *   result ◀─  scanned for resolved material, redacted back to the handle
 *
 * FOUR DECISIONS WORTH THE COMMENT:
 *
 * 1. AN UNRESOLVABLE HANDLE FAILS THE CALL. It is never forwarded as a literal
 *    string. Forwarding it would hand the handle to an upstream that has no
 *    business seeing it, and would produce a 401 the agent cannot diagnose —
 *    a silent failure where a legible refusal belongs.
 *
 * 2. SUBSTITUTION DOES NOT TAINT THE SESSION. The `touchedSecret` flag exists
 *    because an agent that *read* raw credential material can exfiltrate it.
 *    An agent holding a handle never held the material, which is the entire
 *    point, so brokering must not trip the egress rule that the raw-read path
 *    trips. Tainting here would make the documented flow — resolve, call the
 *    API, call it again — fail on the second call.
 *
 * 3. LEAK DETECTION COVERS MATERIAL THIS SESSION RESOLVED, AND SAYS SO.
 *    The edge cannot recognise a credential it was never told about. That is
 *    stated in the product's own limits, and this implementation matches it
 *    rather than implying broader coverage.
 *
 * 4. REDACTION PUTS THE HANDLE BACK, NOT A PLACEHOLDER. Replacing a leaked
 *    value with `[REDACTED]` tells the model something was removed and nothing
 *    about what to do next. Replacing it with the handle it already holds
 *    leaves the run coherent.
 */

/**
 * The canonical handle shape. The control plane imports these; nothing
 * redefines them.
 *
 * Two bodies, one format. A brokered handle is 32 hex characters, minted by the
 * control plane and unguessable. A locally-vaulted handle is a short ordinal —
 * `sec_handle_01` — because it never leaves the machine, and because an
 * operator watching a demo has to be able to read it off the screen and see
 * that it is not a credential.
 *
 * The short form is not a weaker secret: it is not a secret at all. A handle's
 * security comes from the broker refusing to resolve it off-path, not from
 * being hard to type. Making the local form guessable is therefore free, and
 * making it legible is worth something.
 */
export const HANDLE_PREFIX = "sec_handle_";
const HANDLE_BODY = "(?:[0-9a-f]{32}|[0-9]{2,8}(?![0-9a-f]))";

/**
 * Values shorter than this are never used for return-path matching.
 *
 * A short secret appears inside unrelated text by coincidence, and redacting
 * on a coincidence corrupts a tool result the agent depends on. Substitution
 * is unaffected — this guards only the scan direction.
 */
const MIN_SCANNABLE_LENGTH = 8;

/** Depth cap on the structure walk. MCP payloads are JSON; this is insurance. */
const MAX_DEPTH = 12;

export const isHandle = (value) =>
  typeof value === "string" && new RegExp(`^${HANDLE_PREFIX}${HANDLE_BODY}$`).test(value);

/**
 * Every handle appearing anywhere in a value, including inside longer strings
 * (`"Bearer sec_handle_…"`), which is where they usually appear.
 *
 * Builds a fresh regex per call: a shared `/g` regex carries `lastIndex`
 * between calls and silently skips matches on every other invocation.
 */
export function findHandles(value, depth = 0) {
  const found = new Set();
  if (depth > MAX_DEPTH) return found;

  if (typeof value === "string") {
    for (const m of value.matchAll(new RegExp(`${HANDLE_PREFIX}${HANDLE_BODY}`, "g"))) {
      found.add(m[0]);
    }
    return found;
  }
  if (Array.isArray(value)) {
    for (const item of value) for (const h of findHandles(item, depth + 1)) found.add(h);
    return found;
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) for (const h of findHandles(item, depth + 1)) found.add(h);
  }
  return found;
}

/** Rewrites every string in a structure, returning a copy. */
function mapStrings(value, fn, depth = 0) {
  if (depth > MAX_DEPTH) return value;
  if (typeof value === "string") return fn(value);
  if (Array.isArray(value)) return value.map((v) => mapStrings(v, fn, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, mapStrings(v, fn, depth + 1)]),
    );
  }
  return value;
}

/* -------------------------------------------------------------------------- */

/**
 * @typedef {object} Substitution
 * @property {boolean} ok
 * @property {any} value            the arguments with handles replaced
 * @property {string[]} substituted names of the secrets that were spent
 * @property {string} [reason]      why it failed, safe to show the agent
 * @property {string} [outcome]     the control plane's refusal outcome
 */

export class SecretsClient {
  /** handle → { value, secretId, name }, for the life of this session only. */
  #resolved = new Map();

  /**
   * @param {object} opts
   * @param {string} opts.apiUrl      control-plane base URL
   * @param {string} opts.apiKey      `cvx_…`
   * @param {string} [opts.agent]     recorded against every resolution
   * @param {typeof fetch} [opts.fetchImpl] injected for tests
   * @param {(m:string,extra?:object)=>void} [opts.log]
   */
  constructor({ apiUrl, apiKey, agent = "local", fetchImpl = globalThis.fetch, log = () => {} }) {
    this.apiUrl = String(apiUrl ?? "").replace(/\/$/, "");
    this.apiKey = apiKey;
    this.agent = agent;
    this.fetch = fetchImpl;
    this.log = log;
    this.stats = { requested: 0, substituted: 0, refused: 0, leaksCaught: 0 };
  }

  async #api(path, body) {
    const res = await this.fetch(this.apiUrl + path, {
      method: "POST",
      headers: { authorization: `Bearer ${this.apiKey}`, "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });
    const payload = await res.json().catch(() => ({}));
    return { status: res.status, payload };
  }

  /**
   * Asks the control plane for a handle to a named secret.
   *
   * Returns the opaque string the agent is allowed to hold. This is what
   * `secrets.get("STRIPE_RESTRICTED_KEY")` returns to a caller.
   */
  async get(name, { ttlSeconds, maxUses } = {}) {
    this.stats.requested++;
    const { status, payload } = await this.#api("/v1/secrets/handles", {
      name,
      agent: this.agent,
      ttlSeconds,
      maxUses,
    });
    if (status !== 201) {
      throw new Error(payload.error ?? `Could not issue a handle for "${name}".`);
    }
    return payload.handle;
  }

  /**
   * Replaces every handle in `args` with the material it stands for.
   *
   * Fails closed: if any handle in the payload cannot be resolved for this
   * destination, nothing is substituted and the caller must refuse the call.
   * Partial substitution would send a real credential alongside a literal
   * handle, which is the worst of both.
   *
   * @returns {Promise<Substitution>}
   */
  async substitute(args, { destination } = {}) {
    const handles = [...findHandles(args)];
    if (handles.length === 0) return { ok: true, value: args, substituted: [] };

    if (!destination) {
      this.stats.refused++;
      return {
        ok: false,
        value: args,
        substituted: [],
        outcome: "no_destination",
        reason:
          "This call carries a secret handle but names no destination the broker can authorize. A handle resolves only against a destination.",
      };
    }

    const replacements = new Map();
    const names = [];
    for (const handle of handles) {
      const resolved = await this.#resolve(handle, destination);
      if (!resolved.ok) {
        this.stats.refused++;
        return {
          ok: false,
          value: args,
          substituted: [],
          outcome: resolved.outcome,
          reason: resolved.reason,
        };
      }
      replacements.set(handle, resolved.value);
      names.push(resolved.name);
    }

    const value = mapStrings(args, (s) => {
      let out = s;
      for (const [handle, real] of replacements) out = out.split(handle).join(real);
      return out;
    });

    this.stats.substituted += replacements.size;
    return { ok: true, value, substituted: names };
  }

  async #resolve(handle, destination) {
    const { status, payload } = await this.#api("/v1/secrets/resolve", {
      handle,
      destination,
      agent: this.agent,
    });

    if (status !== 200 || typeof payload.value !== "string") {
      return {
        ok: false,
        outcome: payload.outcome ?? "unresolved",
        reason: payload.error ?? "This handle does not resolve for that destination.",
      };
    }

    // Remembered so the return path can recognise it coming back. Held for the
    // life of the session and nowhere else — never written to disk, never in a
    // decision record, never in the audit chain.
    this.#resolved.set(handle, {
      value: payload.value,
      secretId: payload.secretId,
      name: payload.name,
    });
    return { ok: true, value: payload.value, name: payload.name };
  }

  /**
   * Finds material this session resolved appearing in a return payload.
   *
   * A well-behaved upstream never echoes a credential back. A misbehaving or
   * compromised one does, and if that reaches the model the handle indirection
   * has bought nothing.
   */
  scan(payload) {
    const findings = [];
    if (this.#resolved.size === 0) return findings;

    const text = typeof payload === "string" ? payload : JSON.stringify(payload ?? "");
    for (const [handle, entry] of this.#resolved) {
      if (entry.value.length < MIN_SCANNABLE_LENGTH) continue;
      if (text.includes(entry.value)) {
        findings.push({ handle, secretId: entry.secretId, name: entry.name });
      }
    }
    return findings;
  }

  /**
   * Returns `payload` with any resolved material swapped back to its handle.
   *
   * @returns {{payload:any, findings:Array<{handle:string,secretId:string,name:string}>}}
   */
  redact(payload) {
    const findings = this.scan(payload);
    if (findings.length === 0) return { payload, findings };

    this.stats.leaksCaught += findings.length;
    const redacted = mapStrings(payload, (s) => {
      let out = s;
      for (const finding of findings) {
        const entry = this.#resolved.get(finding.handle);
        if (entry) out = out.split(entry.value).join(finding.handle);
      }
      return out;
    });
    return { payload: redacted, findings };
  }

  /**
   * Drops every resolved value.
   *
   * Called when a session ends. The material is process memory for the life of
   * a run and no longer — a laptop with a root-level compromise is outside any
   * userspace product's threat model, but a long-lived process holding every
   * credential it ever brokered is a self-inflicted one.
   */
  forget() {
    this.#resolved.clear();
  }

  get held() {
    return this.#resolved.size;
  }
}
