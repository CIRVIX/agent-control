/**
 * The daily decision counter, and the licence it is measured against.
 *
 * Both live in the workspace's `.cirvix/` directory, alongside the audit chain
 * — the same directory `init` creates and the same one a user can inspect.
 * Nothing is sent anywhere: the count is local because the enforcement is
 * local, and a security tool that phones home to decide whether it is allowed
 * to protect you is a worse product than one that does not.
 *
 * WRITES ARE DEBOUNCED, READS ARE NOT
 *
 * The counter is consulted on every decision and the hot path is measured in
 * microseconds, so it is held in memory and flushed on an interval and at
 * exit. Writing synchronously per decision would put a filesystem round trip
 * inside the enforcement path, which is the one place this product cannot
 * afford one.
 *
 * The cost of that choice is honest: a hard kill (SIGKILL, power loss) loses
 * at most one flush interval of counted decisions, and the user gets those
 * back. Losing a few in the customer's favour is the correct direction for
 * rounding error in a quota.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { DEFAULT_TIER, dayKey, tierFor } from "./entitlements.mjs";

const STATE_DIR = ".cirvix";
const METER_FILE = "meter.json";
const LICENCE_FILE = "licence.json";

/** How often the in-memory count is written through. */
const FLUSH_MS = 5_000;

function stateDir(cwd) {
  return join(cwd, STATE_DIR);
}

function readJson(path, fallback) {
  try {
    if (!existsSync(path)) return fallback;
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    return parsed && typeof parsed === "object" ? parsed : fallback;
  } catch {
    // A corrupt state file must not take the runtime down. Losing a count is
    // recoverable; refusing to start because a JSON file is malformed is not.
    return fallback;
  }
}

/**
 * Reads the licence, defaulting to Free.
 *
 * An unreadable, missing, or malformed licence resolves to Free rather than
 * to the last known paid tier. That is deliberate: the failure mode of a
 * corrupt file must not be a free upgrade, and Free is a working product
 * rather than a lockout, so defaulting down costs the user nothing they
 * cannot immediately fix with `cirvix upgrade`.
 */
export function readLicence(cwd = process.cwd()) {
  const raw = readJson(join(stateDir(cwd), LICENCE_FILE), null);
  if (!raw) return { tier: DEFAULT_TIER, seats: 1, source: "default" };
  const tier = tierFor(raw.tier);
  return {
    tier: tier.id,
    seats: Number(raw.seats) > 0 ? Number(raw.seats) : (tier.seatsIncluded ?? 1),
    customerId: raw.customerId ?? null,
    source: "file",
  };
}

export function writeLicence(licence, cwd = process.cwd()) {
  const dir = stateDir(cwd);
  mkdirSync(dir, { recursive: true });
  const tier = tierFor(licence.tier);
  const body = {
    tier: tier.id,
    seats: Number(licence.seats) > 0 ? Number(licence.seats) : (tier.seatsIncluded ?? 1),
    customerId: licence.customerId ?? null,
    updated: new Date().toISOString(),
  };
  writeFileSync(join(dir, LICENCE_FILE), JSON.stringify(body, null, 2) + "\n", "utf8");
  return body;
}

/**
 * The counter.
 *
 * One instance per runtime process. `count()` is the hot path and does no I/O.
 */
export class Meter {
  #cwd;
  #path;
  #day;
  #used;
  #dirty = false;
  #timer = null;
  #nudgedOn = null;

  constructor({ cwd = process.cwd(), now = () => new Date() } = {}) {
    this.#cwd = cwd;
    this.#path = join(stateDir(cwd), METER_FILE);
    this.now = now;

    const stored = readJson(this.#path, null);
    const today = dayKey(this.now());
    // A stored count from a previous day is not carried over — that is what
    // "resets at 00:00 UTC" means, and the copy on the pricing page says so.
    this.#day = today;
    this.#used = stored && stored.day === today ? Number(stored.used) || 0 : 0;
    this.#nudgedOn = stored && stored.day === today ? (stored.nudgedOn ?? null) : null;
  }

  /** Today's count, rolling the day over if the process has outlived it. */
  used() {
    const today = dayKey(this.now());
    if (today !== this.#day) {
      this.#day = today;
      this.#used = 0;
      this.#dirty = true;
    }
    return this.#used;
  }

  /**
   * Whether the one soft nudge for today has yet to be shown, marking it shown.
   *
   * The flag lives beside the count and rolls over with it, so a new day gets
   * exactly one nudge. Asking and marking are the same call deliberately: two
   * calls invite a caller that asks, decides not to print, and leaves the day
   * marked — or worse, prints without marking and nags on every decision.
   */
  shouldNudge() {
    this.used(); // rolls the day over if the process has outlived it
    if (this.#nudgedOn === this.#day) return false;
    this.#nudgedOn = this.#day;
    this.#dirty = true;
    this.#schedule();
    return true;
  }

  /** Records one decision and returns the new total. */
  count(n = 1) {
    const used = this.used();
    this.#used = used + n;
    this.#dirty = true;
    this.#schedule();
    return this.#used;
  }

  #schedule() {
    if (this.#timer) return;
    this.#timer = setTimeout(() => {
      this.#timer = null;
      this.flush();
    }, FLUSH_MS);
    // Never hold the process open for a counter flush.
    this.#timer.unref?.();
  }

  flush() {
    if (!this.#dirty) return;
    try {
      mkdirSync(stateDir(this.#cwd), { recursive: true });
      writeFileSync(
        this.#path,
        JSON.stringify({ day: this.#day, used: this.#used, nudgedOn: this.#nudgedOn }, null, 2) +
          "\n",
        "utf8",
      );
      this.#dirty = false;
    } catch {
      // A read-only or full disk must not break enforcement. The count stays
      // in memory and the process keeps deciding; the quota is simply measured
      // from this process's start rather than from midnight.
    }
  }

  /** Flush and stop. Called on shutdown. */
  close() {
    if (this.#timer) { clearTimeout(this.#timer); this.#timer = null; }
    this.flush();
  }

  /** Test seam: force a specific state without touching disk semantics. */
  set(day, used) {
    this.#day = day;
    this.#used = used;
    this.#dirty = true;
  }
}

/**
 * Concurrent agents.
 *
 * Tracked per process rather than across machines, because that is the only
 * boundary the local runtime can actually see. Two separate installs on two
 * laptops are two Free tiers, which is a licensing question rather than a
 * runtime one, and pretending otherwise would mean building a phone-home this
 * product deliberately does not have.
 */
export class AgentRegistry {
  #active = new Set();

  register(agentId) {
    this.#active.add(String(agentId ?? "local"));
    return this.#active.size;
  }

  release(agentId) {
    this.#active.delete(String(agentId ?? "local"));
    return this.#active.size;
  }

  /** How many distinct agents have been seen this session. */
  size() {
    return this.#active.size;
  }

  /** Whether this agent is already counted — an existing agent is never a new one. */
  has(agentId) {
    return this.#active.has(String(agentId ?? "local"));
  }
}
