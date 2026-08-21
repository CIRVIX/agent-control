/**
 * The endpoint daemon.
 *
 * A long-running service on every governed machine. It registers with the
 * control plane, heartbeats, pulls policy when it falls behind, and ships
 * decision telemetry in batches.
 *
 * OFFLINE-FIRST, AND THAT IS THE WHOLE DESIGN.
 *
 * A control plane that stops enforcing when the network blips is worse than no
 * control plane, because the failure is invisible: agents keep working and
 * nobody learns that governance stopped. So:
 *
 *   - Policy is cached on disk and enforced from the cache. The daemon never
 *     needs the network to make a decision.
 *   - Telemetry is buffered on disk and drained when connectivity returns.
 *     A day offline produces a backlog, not a gap in the audit record.
 *   - A failed sync is logged and retried with backoff. It never blocks, and
 *     it never escalates into a request being permitted that would otherwise
 *     have been denied.
 *
 * The daemon holds NO inbound port. It polls outward, which is what makes it
 * deployable on a laptop behind NAT and inside a locked-down VPC without a
 * firewall exception.
 */

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { hostname, platform } from "node:os";
import { dirname, join } from "node:path";

const VERSION = "0.1.0";

/** Exponential backoff with a ceiling — a dead control plane must not become
 *  a self-inflicted denial-of-service against itself. */
function backoff(attempt) {
  return Math.min(30_000 * 2 ** Math.min(attempt, 5), 15 * 60_000);
}

export class Daemon {
  #timer = null;
  #stopping = false;
  #attempt = 0;

  /**
   * @param {object} opts
   * @param {string} opts.apiUrl      control-plane base URL
   * @param {string} opts.apiKey      `cvx_…`
   * @param {string} opts.stateDir    where policy cache + spool live
   * @param {number} [opts.intervalMs]
   * @param {(m:string,extra?:object)=>void} [opts.log]
   * @param {typeof fetch} [opts.fetchImpl] injected for tests
   */
  constructor({
    apiUrl,
    apiKey,
    stateDir,
    intervalMs = 30_000,
    log = () => {},
    fetchImpl = globalThis.fetch,
  }) {
    this.apiUrl = apiUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
    this.stateDir = stateDir;
    this.intervalMs = intervalMs;
    this.log = log;
    this.fetch = fetchImpl;

    this.policyPath = join(stateDir, "policy.json");
    this.spoolPath = join(stateDir, "spool.jsonl");
    this.identityPath = join(stateDir, "endpoint.json");

    this.policy = { version: 0, rules: [] };
    this.endpointId = null;
    /** The session currently being recorded, if a control plane opened one. */
    this.runId = null;
    this.online = false;
    this.stats = { syncs: 0, failures: 0, shipped: 0, spooled: 0 };
  }

  /* -- lifecycle ---------------------------------------------------------- */

  async start() {
    await mkdir(this.stateDir, { recursive: true });
    await this.#loadIdentity();
    await this.#loadPolicy();

    // Enforce immediately from cache; do not wait for the first successful
    // sync. A daemon that is useless until it reaches the network is a daemon
    // that is useless exactly when the network is the problem.
    this.log(`daemon started · policy v${this.policy.version} · ${this.policy.rules.length} rules`);

    await this.tick();
    this.#schedule();
    return this;
  }

  stop() {
    this.#stopping = true;
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = null;
  }

  /**
   * Stops and makes a final attempt to ship whatever is spooled.
   *
   * Without this, a short-lived process — a CI job, a one-off `cirvix gateway`, a
   * developer closing their editor — exits between ticks and its decisions sit
   * on disk until the next time a daemon happens to start in that state
   * directory. The records are not lost, but they arrive late or never, and an
   * audit trail that arrives late is one nobody trusts.
   *
   * Always resolves: a failed flush leaves the spool intact for next time,
   * which is the correct direction to err.
   */
  async shutdown() {
    this.stop();
    try {
      if (!this.endpointId) return false;
      await this.#drainSpool();
      return true;
    } catch (err) {
      this.log(`final flush failed, ${this.stats.spooled - this.stats.shipped} records remain spooled: ${err.message}`);
      return false;
    }
  }

  #schedule() {
    if (this.#stopping) return;
    const delay = this.online ? this.intervalMs : backoff(this.#attempt);
    this.#timer = setTimeout(async () => {
      await this.tick();
      this.#schedule();
    }, delay);
    // Never hold the process open on our account.
    this.#timer.unref?.();
  }

  /** One sync cycle. Always resolves — a throw here would kill the loop. */
  async tick() {
    try {
      if (!this.endpointId) await this.#register();
      const hb = await this.#heartbeat();
      if (hb?.policyStale) await this.#pullPolicy();
      await this.#drainSpool();
      this.online = true;
      this.#attempt = 0;
      this.stats.syncs++;
    } catch (err) {
      this.online = false;
      this.#attempt++;
      this.stats.failures++;
      this.log(`sync failed (attempt ${this.#attempt}): ${err.message}`, { offline: true });
    }
  }

  /* -- control-plane calls ------------------------------------------------ */

  async #api(method, path, body) {
    const res = await this.fetch(this.apiUrl + path, {
      method,
      headers: {
        authorization: `Bearer ${this.apiKey}`,
        ...(body ? { "content-type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`${method} ${path} → ${res.status} ${text.slice(0, 200)}`);
    }
    return res.status === 204 ? null : res.json();
  }

  /**
   * Registers the agent identity this endpoint is running.
   *
   * Without this the console shows decisions attributed to an agent that does
   * not appear in the inventory — "4 calls, 0 agents" — which reads as a bug
   * and undermines the one claim the Agents screen makes.
   *
   * Best-effort: a failure here must never stop enforcement.
   */
  async registerAgent(agent) {
    try {
      const created = await this.#api("POST", "/v1/agents", {
        name: agent.name,
        framework: agent.framework ?? "mcp-gateway",
        environment: agent.environment ?? "local",
        endpointId: this.endpointId,
      });
      this.agentId = created?.id ?? null;
      this.log(`registered agent ${agent.name}`);
      return created;
    } catch (err) {
      this.log(`agent registration failed (enforcement unaffected): ${err.message}`);
      return null;
    }
  }

  /**
   * Opens a run and returns its id.
   *
   * Best-effort, like agent registration: a control plane that is unreachable
   * must not stop the gateway enforcing. The cost of failing is that this
   * session's decisions arrive without a run to belong to — they are still
   * individually valid, which is the right way to degrade.
   */
  async openRun({ agent, environment }) {
    try {
      const run = await this.#api("POST", "/v1/runs", {
        agent,
        environment,
        endpointId: this.endpointId,
      });
      this.runId = run?.id ?? null;
      if (this.runId) this.log(`run ${this.runId} started`);
      return this.runId;
    } catch (err) {
      this.log(`could not open a run (enforcement unaffected): ${err.message}`);
      return null;
    }
  }

  /** Closes the run with its final counts. Never throws. */
  async closeRun(counts = {}) {
    if (!this.runId) return false;
    try {
      await this.#api("POST", `/v1/runs/${this.runId}/close`, counts);
      return true;
    } catch (err) {
      // A run left open is swept to `abandoned` by the control plane, which is
      // the honest outcome for a session that stopped reporting.
      this.log(`could not close run ${this.runId}: ${err.message}`);
      return false;
    }
  }

  async #register() {
    const ep = await this.#api("POST", "/v1/endpoints", {
      hostname: hostname(),
      platform: platform(),
      version: VERSION,
    });
    this.endpointId = ep.id;
    await this.#atomicWrite(this.identityPath, JSON.stringify({ endpointId: ep.id }, null, 2));
    this.log(`registered endpoint ${ep.id}`);
  }

  async #heartbeat() {
    return this.#api("POST", `/v1/endpoints/${this.endpointId}/heartbeat`, {
      policyVersion: this.policy.version,
      status: "healthy",
    });
  }

  async #pullPolicy() {
    const policy = await this.#api("GET", "/v1/policy");
    if (!Array.isArray(policy?.rules)) throw new Error("Control plane returned a malformed policy.");
    // Only adopt a policy that is newer. A control plane that rolls back
    // should do so by publishing a new version, never by us accepting a
    // lower one — that would let a replayed response weaken enforcement.
    if (policy.version <= this.policy.version) return;
    this.policy = policy;
    await this.#atomicWrite(this.policyPath, JSON.stringify(policy, null, 2));
    this.log(`policy updated to v${policy.version} (${policy.rules.length} rules)`);
  }

  /* -- telemetry ---------------------------------------------------------- */

  /**
   * Records a decision. Always spools to disk first, then ships. Ship-then-
   * persist would lose the record on a crash mid-flight, and the record is the
   * product.
   */
  async record(decision) {
    await mkdir(this.stateDir, { recursive: true }).catch(() => {});
    const { appendFile } = await import("node:fs/promises");
    await appendFile(this.spoolPath, JSON.stringify(decision) + "\n", "utf8");
    this.stats.spooled++;
  }

  async #drainSpool() {
    let text = "";
    try {
      text = await readFile(this.spoolPath, "utf8");
    } catch {
      return; // nothing spooled
    }
    const lines = text.split("\n").filter(Boolean);
    if (lines.length === 0) return;

    // Batches are capped to match the API's limit; the remainder stays
    // spooled and goes out on the next tick.
    const batch = lines.slice(0, 500);
    const decisions = [];
    for (const line of batch) {
      try {
        decisions.push(JSON.parse(line));
      } catch {
        /* drop a corrupt line rather than wedge the queue forever */
      }
    }

    await this.#api("POST", "/v1/decisions", { decisions });

    // Only truncate what was accepted. If this write fails the records are
    // re-sent next tick — at-least-once, which for an audit trail is the
    // correct direction to err.
    const remaining = lines.slice(batch.length);
    await this.#atomicWrite(this.spoolPath, remaining.length ? remaining.join("\n") + "\n" : "");
    this.stats.shipped += decisions.length;
    if (decisions.length) this.log(`shipped ${decisions.length} decisions`);
  }

  /* -- disk --------------------------------------------------------------- */

  async #loadPolicy() {
    try {
      const cached = JSON.parse(await readFile(this.policyPath, "utf8"));
      if (Array.isArray(cached?.rules)) this.policy = cached;
    } catch {
      /* first run */
    }
  }

  async #loadIdentity() {
    try {
      const saved = JSON.parse(await readFile(this.identityPath, "utf8"));
      if (saved?.endpointId) this.endpointId = saved.endpointId;
    } catch {
      /* first run */
    }
  }

  /**
   * Write-then-rename. A crash partway through a direct write leaves a
   * truncated policy file, and a truncated policy file is an enforcement
   * outage on the next boot.
   */
  async #atomicWrite(path, contents) {
    await mkdir(dirname(path), { recursive: true }).catch(() => {});
    const tmp = `${path}.${process.pid}.tmp`;
    await writeFile(tmp, contents, "utf8");
    await rename(tmp, path);
  }

  /** The rules the gateway should enforce right now. */
  currentRules() {
    return this.policy.rules;
  }
}
