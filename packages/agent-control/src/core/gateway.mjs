/**
 * The MCP gateway — the interception layer.
 *
 * This is the product. Everything else describes what this does.
 *
 * The agent connects to Cirvix believing it is talking to an MCP server.
 * Cirvix connects to the real servers. Every `tools/call` crossing the
 * boundary is decoded, evaluated against policy, recorded, and then either
 * forwarded, refused, or held.
 *
 * ARCHITECTURE
 *
 *   agent ──stdio──▶ Gateway ──stdio──▶ upstream server A
 *                       │     ──stdio──▶ upstream server B
 *                       ├─ policy engine
 *                       └─ audit chain
 *
 * Design decisions that matter:
 *
 * - TOOL NAMES ARE NAMESPACED (`server__tool`). Two servers may both expose
 *   `search`. Without namespacing the gateway cannot route the call and,
 *   worse, a policy written for one server silently governs the other.
 *
 * - IDs ARE REWRITTEN. The agent's request ids and each upstream's id space
 *   are independent. Forwarding an id unchanged means two servers can answer
 *   with the same id and the gateway mis-routes a response. Every in-flight
 *   request gets a gateway-owned id mapped back on the way out.
 *
 * - TOOL DEFINITIONS ARE PINNED. A tool's description is instruction text that
 *   enters the model's context with the authority of a system message, and it
 *   is supplied by the server, not by you. The gateway hashes each definition
 *   on first sight; a changed definition is withheld until re-approved.
 *
 * - DENIALS ARE TOOL RESULTS, NOT TRANSPORT ERRORS. See `deniedToolResult`.
 *
 * - ONE UPSTREAM FAILING MUST NOT TAKE DOWN THE SESSION. A dead server's
 *   tools disappear from `tools/list`; calls to it return a clean error.
 *
 * - SECRETS ARE SUBSTITUTED HERE, IF ANYWHERE. When a broker is attached, a
 *   permitted call's arguments are resolved from handles into real material
 *   on the way out, and scanned for that material on the way back. This is
 *   the only point in the process where a credential exists inside a request,
 *   and it sits downstream of the decision that authorized it. See
 *   `./secrets.mjs`.
 */

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

/** Read from the manifest rather than written down twice. See `cirvix --version`. */
const GATEWAY_VERSION = JSON.parse(
  readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
).version;

import { Guard, actionForTool, destinationFor, resourceForCall } from "./guard.mjs";
import { HttpUpstream } from "./http-transport.mjs";
import { DECISION } from "./decisions.mjs";
import {
  ERROR_CODE,
  MessageFramer,
  deniedToolResult,
  errorResponse,
  heldToolResult,
  serialize,
} from "./jsonrpc.mjs";

// Re-exported so existing importers of the gateway keep working; the
// definitions live in guard.mjs because the SDK needs them too, and two
// implementations of "what action is this tool" is two policies.
export { actionForTool, destinationFor, resourceForCall };

const NS = "__";

/**
 * Turns a `file://` URI into the path the filesystem rules are written against.
 *
 * Without this, `resources/read` with `file:///home/u/.aws/credentials` would be
 * canonicalized as a URL — scheme, empty host, path — and a rule written
 * `path = **\/.aws/**` would not match it, because the engine treats anything
 * with a scheme as a URL rather than a path. The rule and the call would be
 * about the same file and disagree about it.
 *
 * A non-file URI is returned unchanged and evaluated as a URL, which is
 * correct: `https://…` as a resource really is an egress.
 */
export function fileUriToPath(uri) {
  const value = String(uri ?? "");
  if (!/^file:\/\//i.test(value)) return value;
  try {
    const url = new URL(value);
    // `file:///C:/x` → `/C:/x`; drop the leading slash so it reads as a drive.
    const decoded = decodeURIComponent(url.pathname);
    return /^\/[A-Za-z]:/.test(decoded) ? decoded.slice(1) : decoded;
  } catch {
    return value.replace(/^file:\/\//i, "");
  }
}

/** Stable fingerprint of a tool definition, used for drift detection. */
export function fingerprintTool(tool) {
  const canonical = JSON.stringify({
    name: tool.name,
    description: tool.description ?? "",
    inputSchema: tool.inputSchema ?? null,
  });
  return "sha256:" + createHash("sha256").update(canonical).digest("hex").slice(0, 16);
}

/* -------------------------------------------------------------------------- */
/*  Upstream                                                                   */
/* -------------------------------------------------------------------------- */

class Upstream {
  constructor(name, spec, { onMessage, onExit, log }) {
    this.name = name;
    this.spec = spec;
    this.alive = false;
    this.tools = new Map();
    this.log = log;
    this.onMessage = onMessage;
    this.onExit = onExit;
    this.pending = new Map();
    this.nextId = 1;
  }

  start() {
    const { command, args = [], env = {} } = this.spec;
    // Windows: Node >= 18.20 throws EINVAL when spawning .cmd/.bat shims
    // (npm, npx, pnpm) without a shell (CVE-2024-27980 mitigation). MCP configs
    // name such shims constantly. Going through the shell only for shims keeps
    // POSIX behaviour unchanged; with shell:true Node joins argv verbatim, so
    // every argument is quoted here to survive spaces and metacharacters.
    const isWindowsShim =
      process.platform === "win32" && /\.(cmd|bat)$/i.test(command);
    const quoted = args.map((a) =>
      /[\s"^&|<>]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a,
    );
    this.proc = isWindowsShim
      ? spawn([command, ...quoted].join(" "), {
          stdio: ["pipe", "pipe", "pipe"],
          env: { ...process.env, ...env },
          shell: true,
          windowsHide: true,
        })
      : spawn(command, args, {
          stdio: ["pipe", "pipe", "pipe"],
          env: { ...process.env, ...env },
          shell: false,
        });

    this.alive = true;

    const framer = new MessageFramer({
      onMessage: (m) => this.onMessage(this, m),
      onInvalid: (line) => this.log(`upstream ${this.name} sent unparseable frame`, { line: line.slice(0, 200) }),
    });

    this.proc.stdout.on("data", (c) => framer.push(c));
    this.proc.stdout.on("end", () => framer.end());
    // Upstream stderr is diagnostic, never protocol. Surfacing it on our own
    // stderr keeps it out of the agent's stdout channel, which would corrupt
    // the JSON-RPC stream.
    this.proc.stderr.on("data", (c) =>
      this.log(`upstream ${this.name}: ${String(c).trim().slice(0, 400)}`),
    );
    this.proc.on("exit", (code) => {
      this.alive = false;
      this.log(`upstream ${this.name} exited`, { code });
      // Fail every in-flight request rather than leaving the agent hanging.
      for (const [, entry] of this.pending) {
        entry.reject(new Error(`upstream ${this.name} exited`));
      }
      this.pending.clear();
      this.onExit(this);
    });
    this.proc.on("error", (err) => {
      this.alive = false;
      this.log(`upstream ${this.name} failed to start: ${err.message}`);
      this.onExit(this);
    });

    return this;
  }

  send(message) {
    if (!this.alive || !this.proc?.stdin.writable) return false;
    this.proc.stdin.write(serialize(message));
    return true;
  }

  /** Sends a request and resolves with the matching response. */
  request(method, params, timeoutMs = 20000) {
    return new Promise((resolve, reject) => {
      if (!this.alive) return reject(new Error(`upstream ${this.name} is not running`));
      const id = `cx-${this.name}-${this.nextId++}`;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`upstream ${this.name} timed out on ${method}`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      this.send({ jsonrpc: "2.0", id, method, params });
    });
  }

  settle(message) {
    const entry = this.pending.get(message.id);
    if (!entry) return false;
    this.pending.delete(message.id);
    if (message.error) entry.reject(Object.assign(new Error(message.error.message), { rpc: message.error }));
    else entry.resolve(message.result);
    return true;
  }

  stop() {
    this.alive = false;
    try {
      this.proc?.kill();
    } catch {
      /* already gone */
    }
  }
}

/* -------------------------------------------------------------------------- */
/*  Gateway                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * The caller's claimed identity and delegation, read from MCP's `_meta`.
 *
 *   params._meta.cirvix = { agent, delegation }
 *
 * `_meta` is the protocol's own extension point, so this rides the standard
 * wire format rather than inventing a parallel one.
 *
 * ON TRUSTING AN UNAUTHENTICATED FIELD
 *
 * Both values are attacker-controlled, and neither is trusted:
 *
 *   · `delegation` is HMAC-signed by the broker and bound to its subject.
 *     Forging one fails the signature; presenting somebody else's fails the
 *     subject check. Its only power is to REMOVE authority, so the worst a
 *     caller achieves by lying is refusing itself.
 *
 *   · `agent` is a name, and a name proves nothing — the delegation suite says
 *     so at length. It selects which agent-scoped rules apply and which
 *     handles resolve. Claiming a privileged name grants nothing, because
 *     nothing is granted BY the name: a claimed name with no matching signed
 *     grant and no handle bound to it is strictly weaker than the default.
 *
 * The honest limit: without delegation configured, `agent` is a self-asserted
 * label suitable for attribution, not for authorization. Rules that key on
 * agent identity in a hostile multi-agent deployment need a grant behind them.
 */
export function callerIdentity(params) {
  const meta = params?._meta?.cirvix;
  if (!meta || typeof meta !== "object") return { agent: null, delegation: null };
  return {
    agent: typeof meta.agent === "string" && meta.agent ? meta.agent : null,
    delegation: meta.delegation ?? null,
  };
}

export class Gateway {
  #agentName = "local";

  /**
   * @param {object} opts
   * @param {Record<string, {command:string,args?:string[],env?:object}>} opts.servers
   * @param {Array} opts.rules              policy rule set
   * @param {object} [opts.audit]           AuditChain (optional)
   * @param {(name:string)=>string[]|null} [opts.scopeFor] per-server tool allowlist
   * @param {(msg:string,extra?:object)=>void} [opts.log]
   * @param {(decision:object)=>void} [opts.onDecision] telemetry sink
   * @param {import("./secrets.mjs").SecretsClient|null} [opts.secrets] handle broker
   */
  constructor({
    servers,
    rules,
    audit = null,
    scopeFor = () => null,
    log = () => {},
    onDecision = () => {},
    cwd = process.cwd(),
    environment = "local",
    pins = new Map(),
    secrets = null,
    delegation = null,
    /* Forwarded straight to the Guard. Absent means unmetered, which is the
       right default for an embedding caller and was the wrong one for the CLI:
       the gateway is the path most Free-tier traffic takes, and it counted
       nothing. */
    licence = null,
    meter = null,
    agents = null,
  }) {
    this.serversSpec = servers;
    this.audit = audit;
    this.scopeFor = scopeFor;
    this.log = log;
    this.onDecision = onDecision;
    this.cwd = cwd;
    /** name → fingerprint captured at approval time. */
    this.pins = pins;

    this.upstreams = new Map();
    /**
     * The session this gateway is recording.
     *
     * Every decision carries it, so the control plane can reconstruct the run
     * in order rather than holding a flat list of tool calls with no notion of
     * what they belonged to. Set by the CLI once a run is opened; a gateway
     * running without a control plane simply leaves it null and the decisions
     * are still individually valid.
     */
    /** gatewayId → { clientId, upstream } for response routing. */
    this.inflight = new Map();
    this.nextGatewayId = 1;

    /**
     * The shared decision core. Built here rather than inlined so the gateway
     * and `guard.wrap()` cannot answer the same question differently.
     */
    this.guard = new Guard({
      rules,
      agent: this.agentName ?? "local",
      environment,
      cwd,
      audit,
      secrets,
      delegation,
      licence,
      meter,
      agents,
      onDecision,
      log,
    });
    this.stats = this.guard.stats;
  }

  /** Session taint, owned by the core. */
  get touchedSecret() {
    return this.guard.touchedSecret;
  }

  set touchedSecret(value) {
    this.guard.touchedSecret = value;
  }

  /**
   * The name this gateway reports for its agent.
   *
   * Assigned after construction by the CLI, so it has to reach the core —
   * a decision attributed to "local" when the operator named the agent is a
   * decision nobody can find later.
   */
  get agentName() {
    return this.guard?.agent ?? this.#agentName;
  }

  set agentName(value) {
    this.#agentName = value;
    if (this.guard) this.guard.agent = value;
  }

  /** The run every decision in this session belongs to. */
  get runId() {
    return this.guard?.runId ?? null;
  }

  set runId(value) {
    if (this.guard) this.guard.runId = value;
  }

  /*
   * Everything a decision depends on is delegated to the core rather than
   * mirrored on the gateway.
   *
   * These are assigned after construction by real callers — the CLI names the
   * agent once the daemon has registered it, and a long-lived gateway adopts a
   * newer rule set after a policy pull. A mirrored copy would mean the gateway
   * reporting one thing and enforcing another, which is the worst available
   * outcome for a field like `environment`.
   */
  get rules() {
    return this.guard?.rules ?? [];
  }

  set rules(value) {
    if (this.guard) this.guard.rules = value ?? [];
  }

  get environment() {
    return this.guard?.environment ?? "local";
  }

  set environment(value) {
    if (this.guard) this.guard.environment = value;
  }

  get secrets() {
    return this.guard?.secrets ?? null;
  }

  set secrets(value) {
    if (this.guard) this.guard.secrets = value;
  }

  start(write) {
    this.write = write;
    for (const [name, spec] of Object.entries(this.serversSpec)) {
      const hooks = {
        onMessage: (u, m) => this.#fromUpstream(u, m),
        onExit: () => {},
        log: this.log,
      };

      // Transport is chosen by the spec's shape, not by a flag: an editor's
      // mcp.json names a `command` for stdio and a `url` for a hosted server,
      // and the gateway reads the file the user already has.
      if (spec?.url) {
        let up;
        try {
          up = new HttpUpstream(name, spec, hooks);
        } catch (err) {
          // A rejected endpoint (link-local, metadata, bad URL) removes that
          // one server and leaves the session running, matching how a dead
          // stdio server behaves.
          this.log(`upstream ${name} not started: ${err.message}`);
          continue;
        }
        this.upstreams.set(name, up);
        // Started asynchronously so one slow HTTP handshake does not delay the
        // gateway coming up; the upstream reports itself alive immediately and
        // demotes itself if the first request fails.
        void up.start().catch((err) => {
          up.alive = false;
          this.log(`upstream ${name} failed to start: ${err.message}`);
        });
        continue;
      }

      const up = new Upstream(name, spec, hooks);
      this.upstreams.set(name, up.start());
    }
    return this;
  }

  stop() {
    for (const up of this.upstreams.values()) up.stop();
  }

  /* ---------------------------------------------------------------------- */
  /*  Agent → gateway                                                        */
  /* ---------------------------------------------------------------------- */

  async handleClientMessage(message) {
    // Notifications are forwarded to every upstream and never answered.
    if (message.id === undefined && message.method) {
      for (const up of this.upstreams.values()) up.send(message);
      return;
    }

    switch (message.method) {
      case "initialize":
        return this.#handleInitialize(message);
      case "tools/list":
        return this.#handleToolsList(message);
      case "tools/call":
        return this.#handleToolsCall(message);

      /*
       * Resources are a read path, and a read path is a policy decision.
       *
       * These were previously handled by the `default` branch, which forwards
       * to the first live upstream unevaluated. That made `resources/read` a
       * complete bypass of the engine: an agent that could not call
       * `filesystem.read` on `~/.aws/credentials` could ask for the same file
       * as a *resource* and get it, with no rule consulted and no decision
       * recorded. The refusal an operator saw in `cirvix logs` was real; the
       * read that succeeded next to it was invisible.
       *
       * `resources/read` is evaluated exactly like a `tools/call` — same
       * engine, same rules, same audit record — because it does the same
       * thing.
       */
      case "resources/read":
        return this.#handleResourcesRead(message);
      case "resources/list":
      case "resources/templates/list":
        return this.#handleResourcesList(message);
      case "resources/subscribe":
      case "resources/unsubscribe":
        return this.#handleResourceSubscription(message);

      case "prompts/list":
        return this.#handlePromptsList(message);

      /*
       * `ping` is answered HERE, by the gateway, and never forwarded.
       *
       * The spec says the receiver must respond promptly with an empty result,
       * and clients use it as a liveness probe. It was falling through to the
       * default branch, which forwards to the first live upstream — and an
       * upstream that does not implement `ping` answers `-32601 Method not
       * found`. The client reads that as a dead server and tears down the
       * session, so a perfectly healthy Cirvix presented as a crash.
       *
       * It is also the wrong question to forward. Ping asks "is the thing I am
       * connected to alive", and the thing the client is connected to is this
       * gateway. Upstream health is a separate concern, already handled by
       * dropping a dead server's tools from `tools/list`.
       */
      case "ping":
        this.write({ jsonrpc: "2.0", id: message.id, result: {} });
        return;

      default:
        // Anything else is broadcast to the first live upstream. The gateway
        // deliberately does not invent behaviour for methods it doesn't model.
        return this.#forwardToAny(message);
    }
  }

  #handleInitialize(message) {
    this.write({
      jsonrpc: "2.0",
      id: message.id,
      result: {
        protocolVersion: message.params?.protocolVersion ?? "2024-11-05",
        // Advertised because the gateway now governs all three, rather than
        // passing two of them through untouched.
        capabilities: { tools: {}, resources: { subscribe: true }, prompts: {} },
        // Same manifest the CLI reports, so an MCP client and `cirvix --version`
        // cannot disagree about which build is running.
        serverInfo: { name: "cirvix-gateway", version: GATEWAY_VERSION },
      },
    });
  }

  /* ---------------------------------------------------------------------- */
  /*  Resources                                                              */
  /* ---------------------------------------------------------------------- */

  /**
   * Aggregates resources from every live upstream.
   *
   * URIs are namespaced the same way tool names are (`server__uri`), and for
   * the same two reasons: two servers may expose the same URI, and a policy
   * written for one must not silently govern the other.
   */
  async #handleResourcesList(message) {
    const key = message.method === "resources/templates/list" ? "resourceTemplates" : "resources";
    const collected = [];

    for (const [name, up] of this.upstreams) {
      if (!up.alive) continue;
      let result;
      try {
        result = await up.request(message.method, message.params ?? {});
      } catch (err) {
        // A server that does not implement resources answers with an error.
        // That is normal, not a failure — skip it and keep the others.
        this.log(`${message.method} skipped for ${name}: ${err.message}`);
        continue;
      }
      for (const entry of result?.[key] ?? []) {
        const original = entry.uri ?? entry.uriTemplate;
        if (!original) continue;
        collected.push({
          ...entry,
          ...(entry.uri ? { uri: `${name}${NS}${entry.uri}` } : {}),
          ...(entry.uriTemplate ? { uriTemplate: `${name}${NS}${entry.uriTemplate}` } : {}),
          _meta: { ...(entry._meta ?? {}), "cirvix/server": name },
        });
      }
    }

    this.write({ jsonrpc: "2.0", id: message.id, result: { [key]: collected } });
  }

  /**
   * The second decision point.
   *
   * A resource URI is a resource in the policy sense: `file:///etc/passwd` and
   * `file:///home/u/.aws/credentials` are exactly the things the filesystem
   * rules exist to protect. The URI is unwrapped from its namespace, passed to
   * the shared core as an `fs.read`, and the result is scrubbed on the way back
   * like any other payload.
   */
  async #handleResourcesRead(message) {
    const fullUri = message.params?.uri ?? "";
    const sep = fullUri.indexOf(NS);
    const server = sep === -1 ? null : fullUri.slice(0, sep);
    const uri = sep === -1 ? fullUri : fullUri.slice(sep + NS.length);
    const up = server ? this.upstreams.get(server) : [...this.upstreams.values()].find((u) => u.alive);

    if (!up || !up.alive) {
      this.write(
        errorResponse(
          message.id,
          ERROR_CODE.UPSTREAM_UNAVAILABLE,
          `No registered server for resource "${fullUri}".`,
        ),
      );
      return;
    }

    // `file://` URIs are unwrapped to their path so the same rules that govern
    // `filesystem.read` govern this. A rule written `path = **/.aws/**` must
    // match whether the agent asked for a file or for a resource that is a
    // file — otherwise the policy has a spelling-dependent hole.
    const resource = fileUriToPath(uri);

    // Identity travels with a resource read for the same reason the rules do:
    // it is the same operation wearing a different method name, and a
    // delegation that binds `tools/call` and not this one is a hole shaped
    // exactly like the ungoverned-`resources/read` bug above.
    const { agent: callerAgent, delegation } = callerIdentity(message.params);

    const { decision } = await this.guard.authorize({
      tool: "resources.read",
      server: server ?? up.name,
      args: { uri, path: resource },
      agent: callerAgent,
      delegation,
    });
    this.stats = this.guard.stats;

    if (decision.verdict === "deny") {
      this.log(`DENY resources/read ${decision.resource} (${decision.rule})`);
      this.write(deniedToolResult(message.id, decision));
      return;
    }
    if (decision.verdict === "hold") {
      decision.approvalId = `apr_${String(decision.decisionId).slice(4, 12)}`;
      this.log(`HOLD resources/read ${decision.resource} (${decision.rule})`);
      this.write(heldToolResult(message.id, decision));
      return;
    }

    const gatewayId = `gw-${this.nextGatewayId++}`;
    this.inflight.set(gatewayId, { clientId: message.id, upstream: up });
    up.send({ jsonrpc: "2.0", id: gatewayId, method: "resources/read", params: { ...message.params, uri } });
  }

  /**
   * A subscription is a standing read.
   *
   * Governed with the same decision as a one-shot read, because a subscription
   * to a resource an agent may not read is a slower version of reading it.
   */
  async #handleResourceSubscription(message) {
    const fullUri = message.params?.uri ?? "";
    const sep = fullUri.indexOf(NS);
    const server = sep === -1 ? null : fullUri.slice(0, sep);
    const uri = sep === -1 ? fullUri : fullUri.slice(sep + NS.length);
    const up = server ? this.upstreams.get(server) : [...this.upstreams.values()].find((u) => u.alive);

    if (!up || !up.alive) {
      this.write(
        errorResponse(message.id, ERROR_CODE.UPSTREAM_UNAVAILABLE, `No registered server for "${fullUri}".`),
      );
      return;
    }

    // Unsubscribing is always permitted: refusing to let an agent stop
    // receiving something is not a security property.
    if (message.method === "resources/unsubscribe") {
      const gatewayId = `gw-${this.nextGatewayId++}`;
      this.inflight.set(gatewayId, { clientId: message.id, upstream: up });
      up.send({ jsonrpc: "2.0", id: gatewayId, method: message.method, params: { ...message.params, uri } });
      return;
    }

    const { decision } = await this.guard.authorize({
      tool: "resources.subscribe",
      server: server ?? up.name,
      args: { uri, path: fileUriToPath(uri) },
    });
    this.stats = this.guard.stats;

    if (decision.verdict !== "permit") {
      this.log(`${decision.verdict.toUpperCase()} resources/subscribe ${decision.resource} (${decision.rule})`);
      this.write(
        decision.verdict === "hold"
          ? heldToolResult(message.id, decision)
          : deniedToolResult(message.id, decision),
      );
      return;
    }

    const gatewayId = `gw-${this.nextGatewayId++}`;
    this.inflight.set(gatewayId, { clientId: message.id, upstream: up });
    up.send({ jsonrpc: "2.0", id: gatewayId, method: message.method, params: { ...message.params, uri } });
  }

  /**
   * Prompt templates are instruction text supplied by the server.
   *
   * Aggregated and namespaced rather than forwarded blind, for the same reason
   * tool definitions are pinned: a prompt is text that enters the model's
   * context with the authority of a system message, and it is written by
   * whoever wrote the server.
   */
  async #handlePromptsList(message) {
    const prompts = [];
    for (const [name, up] of this.upstreams) {
      if (!up.alive) continue;
      let result;
      try {
        result = await up.request("prompts/list", message.params ?? {});
      } catch (err) {
        this.log(`prompts/list skipped for ${name}: ${err.message}`);
        continue;
      }
      for (const prompt of result?.prompts ?? []) {
        prompts.push({ ...prompt, name: `${name}${NS}${prompt.name}` });
      }
    }
    this.write({ jsonrpc: "2.0", id: message.id, result: { prompts } });
  }

  /**
   * Aggregates tools from every live upstream, applies the per-server scope,
   * and withholds any tool whose definition has drifted from its pin.
   */
  async #handleToolsList(message) {
    const tools = [];

    for (const [name, up] of this.upstreams) {
      if (!up.alive) continue;
      let result;
      try {
        result = await up.request("tools/list", {});
      } catch (err) {
        this.log(`tools/list failed for ${name}: ${err.message}`);
        continue;
      }

      const scope = this.scopeFor(name);
      for (const tool of result?.tools ?? []) {
        const fingerprint = fingerprintTool(tool);
        const key = `${name}${NS}${tool.name}`;
        up.tools.set(tool.name, { tool, fingerprint });

        if (scope && !scope.includes(tool.name)) continue;

        const pin = this.pins.get(key);
        if (pin && pin !== fingerprint) {
          this.log(`tool withheld — definition drift: ${key}`, { pin, fingerprint });
          this.onDecision({
            kind: "drift",
            server: name,
            tool: tool.name,
            expected: pin,
            actual: fingerprint,
          });
          continue;
        }
        if (!pin) this.pins.set(key, fingerprint);

        tools.push({
          ...tool,
          name: key,
          description: tool.description,
        });
      }
    }

    this.write({ jsonrpc: "2.0", id: message.id, result: { tools } });
  }

  /** The decision point. */
  async #handleToolsCall(message) {
    const fullName = message.params?.name ?? "";
    const sep = fullName.indexOf(NS);
    const server = sep === -1 ? null : fullName.slice(0, sep);
    const toolName = sep === -1 ? fullName : fullName.slice(sep + NS.length);
    const up = server ? this.upstreams.get(server) : null;

    if (!up || !up.alive) {
      this.write(
        errorResponse(
          message.id,
          ERROR_CODE.UPSTREAM_UNAVAILABLE,
          `No registered server for tool "${fullName}".`,
        ),
      );
      return;
    }

    const args = message.params?.arguments ?? {};
    const { agent: callerAgent, delegation } = callerIdentity(message.params);

    // The decision is made by the shared core, not here.
    //
    // `guard.wrap()` in the SDK runs this same call. If the gateway kept its
    // own copy of the evaluation, the substitution ordering, and the taint
    // rule, the two would drift — and a guard that permits what the gateway
    // denies is a governance product with a documented bypass.
    const { decision, args: outgoingArgs } = await this.guard.authorize({
      tool: toolName,
      server,
      args,
      agent: callerAgent,
      delegation,
    });
    this.stats = this.guard.stats;

    if (decision.verdict === "deny") {
      this.log(`DENY ${decision.action ?? toolName} ${decision.resource} (${decision.rule})`);
      this.write(deniedToolResult(message.id, decision));
      return;
    }

    if (decision.verdict === "hold") {
      decision.approvalId = `apr_${String(decision.decisionId).slice(4, 12)}`;
      this.log(`HOLD ${decision.action ?? toolName} ${decision.resource} (${decision.rule})`);
      this.write(heldToolResult(message.id, decision));
      return;
    }

    // Forward under a gateway-owned id, remembering how to route the answer —
    // and what was decided about it, so the return path can say so.
    const gatewayId = `gw-${this.nextGatewayId++}`;
    this.inflight.set(gatewayId, { clientId: message.id, upstream: up, decision });
    up.send({
      jsonrpc: "2.0",
      id: gatewayId,
      method: "tools/call",
      params: { name: toolName, arguments: outgoingArgs },
    });
  }

  #forwardToAny(message) {
    const up = [...this.upstreams.values()].find((u) => u.alive);
    if (!up) {
      this.write(
        errorResponse(message.id, ERROR_CODE.UPSTREAM_UNAVAILABLE, "No upstream server available."),
      );
      return;
    }
    const gatewayId = `gw-${this.nextGatewayId++}`;
    this.inflight.set(gatewayId, { clientId: message.id, upstream: up });
    up.send({ ...message, id: gatewayId });
  }

  /* ---------------------------------------------------------------------- */
  /*  Upstream → agent                                                       */
  /* ---------------------------------------------------------------------- */

  #fromUpstream(up, message) {
    // Responses to the gateway's own internal requests (tools/list, etc.)
    if (up.settle(message)) return;

    const route = this.inflight.get(message.id);
    if (route) {
      this.inflight.delete(message.id);
      this.write({ ...this.#annotate(this.#scrub(message), route.decision), id: route.clientId });
      return;
    }

    // Server-initiated notifications pass straight through — scrubbed, since
    // a notification reaches the model's context exactly like a result does.
    if (message.id === undefined) this.write(this.#scrub(message));
  }

  /**
   * The return path.
   *
   * A well-behaved upstream never echoes a credential back. A compromised or
   * merely careless one does, and if that reaches the model then the handle
   * indirection bought nothing — the value is in the context window, the
   * trace, and whatever the agent writes next.
   *
   * Only material this session resolved can be recognised. That is a real
   * limit, it is the one the product's own documentation states, and it is
   * why this is a backstop rather than a substitute for scoping handles.
   */
  #scrub(message) {
    return this.guard.scrub(message).payload;
  }

  /**
   * Tells the agent what was done to its result.
   *
   * A SANITIZE decision forwards the call, so without this the agent receives
   * an ordinary success and has no way to know the payload was modified — while
   * the audit record says `sanitize`. The consistency oracle caught exactly
   * that: Cirvix told the agent ALLOW and recorded SANITIZE, which is the
   * product disagreeing with itself about the same call.
   *
   * It also matters on its own terms. The sanitizer's whole design principle is
   * replacement over deletion, because an agent acting on quietly truncated
   * content makes worse decisions than one told a paragraph was withheld. That
   * principle only holds if the *decision* is surfaced too, not just the marker
   * buried in the text.
   */
  #annotate(message, decision) {
    if (!decision || decision.decision !== DECISION.SANITIZE) return message;
    if (!message?.result || typeof message.result !== "object") return message;

    return {
      ...message,
      result: {
        ...message.result,
        _meta: {
          ...(message.result._meta ?? {}),
          "cirvix/verdict": "sanitize",
          "cirvix/rule": decision.rule ?? null,
          "cirvix/decision_id": decision.decisionId ?? null,
          // Named so an agent can distinguish "cleaned" from "refused" without
          // parsing prose: this call succeeded, and its payload is not verbatim.
          "cirvix/sanitized": true,
        },
      },
    };
  }

  /* ---------------------------------------------------------------------- */

  #insideWorkspace(resource) {
    if (!resource) return true;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(resource)) return false;
    const norm = (s) => s.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
    const abs = /^([A-Za-z]:|\/)/.test(resource)
      ? resource
      : `${this.cwd}/${resource}`;
    const parts = [];
    for (const seg of norm(abs).split("/")) {
      if (seg === "..") parts.pop();
      else if (seg !== ".") parts.push(seg);
    }
    const flat = parts.join("/");
    const root = norm(this.cwd);
    return flat === root || flat.startsWith(root + "/");
  }

  #isExternal(resource) {
    if (!/^https?:\/\//i.test(resource)) return false;
    try {
      const host = new URL(resource).hostname;
      return !/^(localhost|127\.|::1|0\.0\.0\.0|.*\.internal|.*\.local)$/i.test(host);
    } catch {
      return true;
    }
  }
}
