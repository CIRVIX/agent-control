/**
 * The local credential vault.
 *
 * The demo everyone remembers is this one: the agent asks for a secret, gets
 * `sec_handle_01`, uses it, the call succeeds — and the agent's context window
 * never contains the credential. Not redacted afterwards. Never present.
 *
 *   OPENAI_API_KEY  ──issue──▶  sec_handle_01     ← what the agent holds
 *                                    │
 *                              (vault, in this process)
 *                                    │
 *   permitted call ──substitute──▶ sk-proj-…      ← what goes on the wire
 *   tool result   ──redact─────▶ sec_handle_01    ← what comes back
 *
 * WHY THIS EXISTS WHEN `SecretsClient` ALREADY DOES THIS
 *
 * `SecretsClient` brokers against the control plane: the material lives on a
 * server, resolution is audited centrally, and a handle can be revoked
 * organisation-wide. It is the right answer for a team, and it needs an
 * account, a deployment, and a network round trip per resolution.
 *
 * This is the same contract with the server removed. It runs on one machine,
 * holds material in process memory for the life of a run, and requires nothing.
 * A developer gets the property that matters — *the agent never receives the
 * raw value* — during `cirvix init`, not after procurement.
 *
 * The two are deliberately interface-compatible (`get`, `substitute`, `redact`,
 * `forget`, `held`). `Guard` takes either without knowing which, so moving from
 * local to brokered is a configuration change and not a code change.
 *
 * WHAT THIS DOES NOT CLAIM
 *
 * Plaintext lives in ordinary process memory while a call is in flight. Node
 * cannot `mlock`, cannot prevent a core dump, and cannot stop a debugger
 * attached to its own process. Anything with code execution as this user has
 * already won. The threat this actually addresses is the one that keeps
 * happening: a credential entering a model's context, then a transcript, a
 * trace, a support ticket, and a training set.
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { HANDLE_PREFIX, findHandles } from "./secrets.mjs";
import { redact as redactSecrets } from "./secret-detect.mjs";

/** Handles issued locally are short and readable: `sec_handle_01`. */
const LOCAL_HANDLE_DIGITS = 2;

/** Values shorter than this are never used for return-path matching. */
const MIN_SCANNABLE_LENGTH = 8;

const MAX_DEPTH = 12;

/* -------------------------------------------------------------------------- */

/** Rewrites every string in a structure, returning a copy. */
function mapStrings(value, fn, depth = 0) {
  if (depth > MAX_DEPTH) return value;
  if (typeof value === "string") return fn(value);
  if (Array.isArray(value)) return value.map((v) => mapStrings(v, fn, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, mapStrings(v, fn, depth + 1)]));
  }
  return value;
}

/** Constant-time string compare, for handle lookup. */
function sameString(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}

/* -------------------------------------------------------------------------- */
/*  Vault                                                                      */
/* -------------------------------------------------------------------------- */

export class Vault {
  /** handle → entry. The only place raw material is held. */
  #entries = new Map();
  /** name → handle, so `get` is idempotent. */
  #byName = new Map();
  #next = 1;

  /**
   * @param {object} [opts]
   * @param {string} [opts.agent]           recorded against every resolution
   * @param {(m:string,extra?:object)=>void} [opts.log]
   * @param {(event:object)=>void} [opts.onEvent] resolution telemetry
   */
  constructor({ agent = "local", log = () => {}, onEvent = () => {} } = {}) {
    this.agent = agent;
    this.log = log;
    this.onEvent = onEvent;
    this.stats = { issued: 0, requested: 0, substituted: 0, refused: 0, leaksCaught: 0 };
  }

  /**
   * Puts material under a handle.
   *
   * @param {string} name                    what the operator calls it
   * @param {string} value                   the material — never leaves this object
   * @param {object} [opts]
   * @param {string[]} [opts.destinations]   hosts this handle resolves for; empty means any
   * @param {number} [opts.maxUses]          resolutions before it stops working
   * @param {number} [opts.ttlSeconds]       lifetime from issue
   * @param {string} [opts.subject]          the only agent that may spend it
   * @returns {string} the handle
   */
  issue(name, value, { destinations = [], maxUses = Infinity, ttlSeconds = null, subject = null } = {}) {
    if (typeof value !== "string" || !value.length) {
      throw new Error(`Cannot issue a handle for "${name}": no value.`);
    }

    // Re-issuing a name returns the existing handle rather than minting a
    // second one for the same material. Two handles for one secret means the
    // return-path scan reports whichever it happens to match and the operator
    // cannot tell they are the same credential.
    //
    // The subject must match too: returning a handle bound to one agent because
    // a different agent asked for the same name would hand over the binding
    // along with the handle.
    const existing = this.#byName.get(name);
    const previous = existing ? this.#entries.get(existing) : null;
    if (previous && previous.value === value && (previous.subject ?? null) === (subject ?? null)) {
      return existing;
    }

    const handle = `${HANDLE_PREFIX}${String(this.#next++).padStart(LOCAL_HANDLE_DIGITS, "0")}`;
    this.#entries.set(handle, {
      name,
      value,
      destinations: destinations.map((d) => String(d).toLowerCase()),
      maxUses,
      uses: 0,
      subject: subject === null || subject === undefined ? null : String(subject),
      expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : null,
      issuedAt: Date.now(),
    });
    this.#byName.set(name, handle);
    this.stats.issued++;
    this.log(`vault: issued ${handle} for ${name}`);
    return handle;
  }

  /**
   * The handle for a named secret — the call an agent makes.
   *
   * Async and returning only the handle, matching `SecretsClient.get`, so the
   * two are substitutable at the call site.
   */
  async get(name) {
    this.stats.requested++;
    const handle = this.#byName.get(name);
    if (!handle) throw new Error(`No secret named "${name}" is loaded in this vault.`);
    return handle;
  }

  /** Every handle this vault has issued, with no material attached. */
  inventory() {
    return [...this.#entries.entries()].map(([handle, e]) => ({
      handle,
      name: e.name,
      destinations: e.destinations,
      uses: e.uses,
      maxUses: e.maxUses === Infinity ? null : e.maxUses,
      expiresAt: e.expiresAt ? new Date(e.expiresAt).toISOString() : null,
      expired: this.#isExpired(e),
    }));
  }

  #isExpired(entry) {
    return Boolean(entry.expiresAt && Date.now() > entry.expiresAt);
  }

  /**
   * Whether a handle may be spent against a destination.
   *
   * Scoping is the property that makes a leaked handle far less useful than a
   * leaked key: a handle bound to `api.stripe.com` sent to `attacker.example`
   * resolves to nothing. An unscoped handle (empty `destinations`) is
   * deliberately allowed, because forcing scope at issue time makes people skip
   * the vault entirely — but `cirvix status` reports how many are unscoped.
   */
  #authorize(entry, destination, subject) {
    if (this.#isExpired(entry)) {
      return { ok: false, outcome: "expired", reason: "This handle has expired." };
    }
    if (entry.uses >= entry.maxUses) {
      return { ok: false, outcome: "exhausted", reason: "This handle has been used the maximum number of times." };
    }

    /*
     * POSSESSION OF A HANDLE IS NOT AUTHORITY TO SPEND IT.
     *
     * A handle is deliberately not a secret — that is the whole design. It goes
     * in arguments, it is printed in audit records, it is safe to paste into a
     * ticket, and it can come back inside a tool result another agent reads.
     *
     * Which means that without a subject check, a handle appearing in any
     * shared surface IS the credential, laundered. Every property the vault
     * claims would still hold — the material never enters a model's context —
     * for the wrong agent. In a multi-agent deployment that is the whole attack:
     * `payments-agent` holds the Stripe key, `summariser` reads a transcript
     * containing `sec_handle_01`, and charges cards.
     *
     * Binding is per handle and opt-in, because a single-agent install has no
     * boundary to enforce and must not be made to declare one.
     */
    if (entry.subject !== null && String(subject ?? "") !== entry.subject) {
      return {
        ok: false,
        outcome: "wrong_subject",
        reason:
          `This handle was issued to ${entry.subject} and was presented by ` +
          `${subject ? String(subject) : "an unidentified caller"}. Holding a handle is not authority to spend it.`,
      };
    }

    if (!entry.destinations.length) return { ok: true };

    let host = null;
    try {
      host = new URL(destination).hostname.toLowerCase();
    } catch {
      return {
        ok: false,
        outcome: "no_destination",
        reason: "A scoped handle resolves only against an absolute http(s) destination, and this call names none.",
      };
    }
    const allowed = entry.destinations.some((d) => host === d || host.endsWith(`.${d}`));
    return allowed
      ? { ok: true }
      : {
          ok: false,
          outcome: "destination_not_allowed",
          reason: `This handle is scoped to ${entry.destinations.join(", ")} and this call targets ${host}.`,
        };
  }

  /**
   * Replaces every handle in `args` with the material it stands for.
   *
   * Fails closed: if any handle cannot be resolved for this destination,
   * NOTHING is substituted and the caller must refuse the call. Partial
   * substitution would put a real credential on the wire alongside a literal
   * handle string — the worst of both outcomes.
   */
  async substitute(args, { destination, subject = null } = {}) {
    const handles = [...findHandles(args)];
    if (handles.length === 0) return { ok: true, value: args, substituted: [] };

    const replacements = new Map();
    const names = [];

    for (const handle of handles) {
      const entry = this.#lookup(handle);
      if (!entry) {
        this.stats.refused++;
        return {
          ok: false,
          value: args,
          substituted: [],
          outcome: "unknown_handle",
          reason: `${handle} is not a handle this vault issued. It was not forwarded as a literal string.`,
        };
      }
      const authorized = this.#authorize(entry, destination, subject);
      if (!authorized.ok) {
        this.stats.refused++;
        this.onEvent({
          kind: "secret_refused",
          handle,
          name: entry.name,
          outcome: authorized.outcome,
          subject: subject ?? null,
        });
        return { ok: false, value: args, substituted: [], ...authorized };
      }
      replacements.set(handle, entry.value);
      names.push(entry.name);
      entry.uses++;
    }

    const value = mapStrings(args, (s) => {
      let out = s;
      for (const [handle, real] of replacements) out = out.split(handle).join(real);
      return out;
    });

    this.stats.substituted += replacements.size;
    this.onEvent({ kind: "secret_substituted", names, destination: destination ?? null });
    return { ok: true, value, substituted: names };
  }

  #lookup(handle) {
    for (const [h, entry] of this.#entries) {
      if (sameString(h, handle)) return entry;
    }
    return null;
  }

  /**
   * Finds material this vault holds appearing in a payload.
   *
   * Unlike `SecretsClient`, which can only recognise what a session resolved,
   * the vault knows everything it holds — so it catches a credential echoed
   * back even on a call that never spent a handle.
   */
  scan(payload) {
    const findings = [];
    if (this.#entries.size === 0) return findings;
    const text = typeof payload === "string" ? payload : JSON.stringify(payload ?? "");
    for (const [handle, entry] of this.#entries) {
      if (entry.value.length < MIN_SCANNABLE_LENGTH) continue;
      if (text.includes(entry.value)) findings.push({ handle, name: entry.name });
    }
    return findings;
  }

  /**
   * Returns `payload` with any held material swapped back to its handle.
   *
   * Two passes, and the second one matters. The first puts handles back over
   * material this vault knows. The second runs the pattern detectors over
   * what remains, so a credential the vault never held — one the tool result
   * happened to contain — is still masked before it reaches the model.
   */
  redact(payload) {
    const known = this.scan(payload);
    let out = payload;

    if (known.length) {
      this.stats.leaksCaught += known.length;
      out = mapStrings(payload, (s) => {
        let text = s;
        for (const finding of known) {
          const entry = this.#lookup(finding.handle);
          if (entry) text = text.split(entry.value).join(finding.handle);
        }
        return text;
      });
    }

    // The second pass, and it must REDACT rather than merely report.
    //
    // An earlier version scanned for pattern-detected credentials and returned
    // the findings alongside the untouched payload — so a key the vault never
    // held was faithfully listed in the log and forwarded to the model anyway.
    // Detection without redaction on the return path is a leak with a receipt.
    const swept = redactSecrets(out);
    if (swept.findings.length) this.stats.leaksCaught += swept.findings.length;

    return {
      payload: swept.value,
      findings: known.map((k) => ({ ...k, source: "vault" })),
      detected: swept.findings,
    };
  }

  /** Drops every value. Called when a session ends. */
  forget() {
    this.#entries.clear();
    this.#byName.clear();
  }

  get held() {
    return this.#entries.size;
  }

  /* ------------------------------------------------------------------------ */
  /*  Loading                                                                  */
  /* ------------------------------------------------------------------------ */

  /**
   * Loads credential-shaped environment variables.
   *
   * Only variables whose *name* claims credential are taken, and the value is
   * moved into the vault rather than copied: `process.env[name]` is replaced
   * with the handle. A child process the agent spawns therefore inherits the
   * handle, not the key — which is the difference between protecting the agent
   * and protecting everything the agent starts.
   *
   * @param {object} [opts]
   * @param {boolean} [opts.replaceEnv] default true — see above
   * @returns {Array<{name:string, handle:string}>}
   */
  loadFromEnv({ env = process.env, replaceEnv = true, pattern = /(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CLIENT[_-]?SECRET|CREDENTIAL)/i } = {}) {
    const loaded = [];
    for (const [name, value] of Object.entries(env)) {
      if (!pattern.test(name)) continue;
      if (typeof value !== "string" || value.length < 8) continue;
      // Never vault our own control-plane key: the daemon needs it literally.
      if (/^CIRVIX_/.test(name)) continue;
      const handle = this.issue(name, value);
      if (replaceEnv) env[name] = handle;
      loaded.push({ name, handle });
    }
    return loaded;
  }

  /**
   * Loads a `.env`-shaped file without the values ever reaching a log.
   *
   * Deliberately does not use `process.env` as an intermediary — writing them
   * there first, even briefly, means anything that dumps the environment in
   * between captures the lot.
   */
  async loadFromFile(path, { pattern } = {}) {
    let text;
    try {
      text = await readFile(path, "utf8");
    } catch {
      return [];
    }
    const loaded = [];
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq === -1) continue;
      const name = trimmed.slice(0, eq).trim().replace(/^export\s+/, "");
      let value = trimmed.slice(eq + 1).trim();
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }
      if (!value || value.length < 8) continue;
      if (pattern && !pattern.test(name)) continue;
      loaded.push({ name, handle: this.issue(name, value) });
    }
    return loaded;
  }

  /* ------------------------------------------------------------------------ */
  /*  Sealing                                                                  */
  /* ------------------------------------------------------------------------ */

  /**
   * Writes the vault to disk sealed with AES-256-GCM.
   *
   * The passphrase is stretched with scrypt. GCM's tag is verified on open, so
   * a tampered file fails to decrypt rather than yielding altered material —
   * which matters here because the "material" is what gets sent to a bank's
   * API.
   *
   * Persisting is opt-in. The default vault holds material for the life of a
   * process and writes nothing, because a file full of credentials is a new
   * asset to defend and most runs do not need one.
   */
  async seal(path, passphrase) {
    if (typeof passphrase !== "string" || passphrase.length < 12) {
      throw new Error("Sealing needs a passphrase of at least 12 characters.");
    }
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = scryptSync(passphrase, salt, 32);
    const cipher = createCipheriv("aes-256-gcm", key, iv);

    const plain = JSON.stringify(
      [...this.#entries.entries()].map(([handle, e]) => ({
        handle,
        name: e.name,
        value: e.value,
        destinations: e.destinations,
        maxUses: e.maxUses === Infinity ? null : e.maxUses,
        expiresAt: e.expiresAt,
      })),
    );

    const body = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
    const payload = {
      version: 1,
      kdf: "scrypt",
      cipher: "aes-256-gcm",
      salt: salt.toString("base64"),
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      body: body.toString("base64"),
    };

    await mkdir(dirname(path), { recursive: true }).catch(() => {});
    await writeFile(path, JSON.stringify(payload), "utf8");
    // Best effort: a no-op on Windows, and the file is sealed regardless.
    await chmod(path, 0o600).catch(() => {});
    return { path, entries: this.#entries.size };
  }

  /** Opens a sealed vault. A wrong passphrase fails the GCM tag check. */
  async unseal(path, passphrase) {
    const payload = JSON.parse(await readFile(path, "utf8"));
    if (payload.version !== 1) throw new Error(`Unsupported vault version ${payload.version}.`);

    const key = scryptSync(passphrase, Buffer.from(payload.salt, "base64"), 32);
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(payload.iv, "base64"));
    decipher.setAuthTag(Buffer.from(payload.tag, "base64"));

    let plain;
    try {
      plain = Buffer.concat([
        decipher.update(Buffer.from(payload.body, "base64")),
        decipher.final(),
      ]).toString("utf8");
    } catch {
      throw new Error("Could not open the vault: wrong passphrase, or the file has been altered.");
    }

    for (const e of JSON.parse(plain)) {
      this.#entries.set(e.handle, {
        name: e.name,
        value: e.value,
        destinations: e.destinations ?? [],
        maxUses: e.maxUses ?? Infinity,
        uses: 0,
        expiresAt: e.expiresAt ?? null,
        issuedAt: Date.now(),
      });
      this.#byName.set(e.name, e.handle);
      const n = Number(String(e.handle).slice(HANDLE_PREFIX.length));
      if (Number.isFinite(n) && n >= this.#next) this.#next = n + 1;
    }
    return { entries: this.#entries.size };
  }
}
