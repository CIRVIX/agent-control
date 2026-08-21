/**
 * MCP over HTTP — the second transport.
 *
 * The gateway already governs stdio, which is what editors use for local
 * servers. Hosted MCP servers speak HTTP instead: Streamable HTTP (the current
 * spec) and HTTP+SSE (the earlier one, still widely deployed). A control plane
 * that only sees stdio is blind to exactly the servers a company did not write
 * and cannot audit.
 *
 * ONE INTERFACE, TWO WIRES
 *
 * `HttpUpstream` presents the same surface as the stdio `Upstream` in
 * `gateway.mjs` — `start`, `send`, `request`, `settle`, `stop`, `alive`,
 * `tools` — so the gateway routes, namespaces, pins, and evaluates without
 * knowing which transport a server is on. The decision path must not fork by
 * transport, because two decision paths is two policies.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO
 *
 * It does not follow redirects to a different origin, and it does not accept a
 * server-supplied endpoint that points somewhere else. Both are how a proxy
 * gets turned into an SSRF primitive: the agent asks to call a tool on
 * `mcp.vendor.com`, the vendor answers `302 → http://169.254.169.254/…`, and
 * the request now carries whatever ambient credentials the gateway's network
 * position grants. The endpoint an operator configured is the only endpoint
 * this talks to.
 */

import { MessageFramer } from "./jsonrpc.mjs";

/** How long a single JSON-RPC request may take before it is abandoned. */
const DEFAULT_TIMEOUT_MS = 30_000;

/** Cap on a single response body. A hostile server must not exhaust memory. */
const MAX_BODY_BYTES = 8 * 1024 * 1024;

/**
 * Hosts a gateway will never connect to, whatever the configuration says.
 *
 * Link-local and metadata addresses are not a legitimate MCP endpoint under any
 * deployment, and blocking them here means a typo, a copied config, or a
 * compromised registry entry cannot turn the gateway into a credential thief.
 */
const FORBIDDEN_HOSTS = [
  /^169\.254\./,
  /^metadata\.google\.internal$/i,
  /^metadata\.goog$/i,
  /^100\.100\.100\.200$/,
  /^\[?fd00:ec2::254\]?$/i,
];

export function assertAllowedEndpoint(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`"${url}" is not a valid MCP endpoint URL.`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`MCP over HTTP needs an http(s) URL; got ${parsed.protocol}`);
  }
  const host = parsed.hostname.toLowerCase();
  if (FORBIDDEN_HOSTS.some((re) => re.test(host))) {
    throw new Error(
      `Refusing to connect to ${host}: link-local and cloud-metadata addresses are never a legitimate MCP endpoint.`,
    );
  }
  return parsed;
}

/* -------------------------------------------------------------------------- */

/**
 * An upstream MCP server reached over HTTP.
 *
 * Supports both shapes without the caller choosing:
 *
 *   Streamable HTTP — POST the request, read the answer from the response body,
 *   which may be `application/json` (one message) or `text/event-stream` (a
 *   stream of them). This is the current spec.
 *
 *   HTTP+SSE — GET the endpoint to open an event stream, receive an `endpoint`
 *   event naming where to POST, then POST requests there and read the answers
 *   off the stream. This is the 2024 spec, still deployed.
 *
 * Which one a server speaks is discovered on first contact rather than
 * configured, because operators do not know and should not have to.
 */
export class HttpUpstream {
  #pending = new Map();
  #nextId = 1;
  #abort = null;

  /**
   * @param {string} name
   * @param {{url:string, headers?:object, timeoutMs?:number}} spec
   * @param {{onMessage:Function, onExit:Function, log:Function}} hooks
   */
  constructor(name, spec, { onMessage, onExit, log = () => {} } = {}) {
    this.name = name;
    this.spec = spec;
    this.url = assertAllowedEndpoint(spec.url).toString();
    this.headers = spec.headers ?? {};
    this.timeoutMs = spec.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.onMessage = onMessage;
    this.onExit = onExit;
    this.log = log;

    this.alive = false;
    this.tools = new Map();
    /** Set once the server tells us where to POST (HTTP+SSE mode). */
    this.postUrl = null;
    /** Streamable HTTP sessions are carried in this header. */
    this.sessionId = null;
    this.mode = "unknown";
    this.fetchImpl = spec.fetchImpl ?? globalThis.fetch;
  }

  /**
   * Opens the connection.
   *
   * Streamable HTTP needs no handshake — the first POST is the connection — so
   * `start` only opens a stream when the server turns out to want one. It is
   * marked alive optimistically and demoted on the first failed request, which
   * matches the stdio upstream's behaviour: a dead server's tools disappear
   * from `tools/list` rather than taking down the session.
   */
  async start() {
    this.alive = true;
    this.#abort = new AbortController();

    // Probe for the older HTTP+SSE shape. A server that does not implement GET
    // answers 405 or 404, which is the signal that it is Streamable HTTP.
    try {
      const res = await this.fetchImpl(this.url, {
        method: "GET",
        headers: { accept: "text/event-stream", ...this.headers },
        signal: this.#abort.signal,
      });

      if (res.ok && (res.headers.get("content-type") ?? "").includes("text/event-stream")) {
        this.mode = "sse";
        void this.#pumpEventStream(res);
        this.log(`upstream ${this.name}: HTTP+SSE`);
        return this;
      }
      // Anything else means Streamable HTTP. Drain so the socket is released.
      await res.body?.cancel().catch(() => {});
    } catch (err) {
      if (err?.name === "AbortError") return this;
      this.log(`upstream ${this.name}: SSE probe failed (${err.message}); assuming Streamable HTTP`);
    }

    this.mode = "streamable";
    this.log(`upstream ${this.name}: Streamable HTTP`);
    return this;
  }

  /**
   * Reads an SSE stream, dispatching each `data:` payload as a JSON-RPC
   * message.
   *
   * SSE frames are separated by a blank line and a single event may span
   * several `data:` lines. Treating each chunk as a frame is the bug that makes
   * a proxy corrupt large payloads under load — the same class of bug the stdio
   * framer exists to avoid.
   */
  async #pumpEventStream(response) {
    const reader = response.body?.getReader();
    if (!reader) return;

    const decoder = new TextDecoder();
    let buffer = "";
    let bytes = 0;

    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;

        bytes += value.byteLength;
        if (bytes > MAX_BODY_BYTES) {
          this.log(`upstream ${this.name}: event stream exceeded ${MAX_BODY_BYTES} bytes; closing`);
          break;
        }

        buffer += decoder.decode(value, { stream: true });

        let split;
        while ((split = buffer.search(/\r?\n\r?\n/)) !== -1) {
          const rawEvent = buffer.slice(0, split);
          buffer = buffer.slice(split).replace(/^\r?\n\r?\n/, "");
          this.#handleEvent(rawEvent);
        }
      }
    } catch (err) {
      if (err?.name !== "AbortError") this.log(`upstream ${this.name}: stream error ${err.message}`);
    } finally {
      this.alive = false;
      for (const [, entry] of this.#pending) entry.reject(new Error(`upstream ${this.name} stream closed`));
      this.#pending.clear();
      this.onExit?.(this);
    }
  }

  #handleEvent(raw) {
    let event = "message";
    const data = [];

    for (const line of raw.split(/\r?\n/)) {
      if (line.startsWith(":")) continue; // comment / keep-alive
      const colon = line.indexOf(":");
      const field = colon === -1 ? line : line.slice(0, colon);
      const value = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /, "");
      if (field === "event") event = value;
      else if (field === "data") data.push(value);
    }

    const payload = data.join("\n");
    if (!payload) return;

    if (event === "endpoint") {
      // The server names where to POST. Resolved against the configured URL and
      // re-checked, so a server cannot redirect us to another origin.
      try {
        const resolved = new URL(payload, this.url);
        const configured = new URL(this.url);
        if (resolved.origin !== configured.origin) {
          this.log(
            `upstream ${this.name}: refused an endpoint on a different origin (${resolved.origin}); keeping ${configured.origin}`,
          );
          return;
        }
        assertAllowedEndpoint(resolved.toString());
        this.postUrl = resolved.toString();
      } catch (err) {
        this.log(`upstream ${this.name}: bad endpoint event — ${err.message}`);
      }
      return;
    }

    let message;
    try {
      message = JSON.parse(payload);
    } catch {
      this.log(`upstream ${this.name}: unparseable SSE payload`);
      return;
    }
    this.onMessage?.(this, message);
  }

  /** Fire-and-forget. Mirrors the stdio upstream's `send`. */
  send(message) {
    if (!this.alive) return false;
    void this.#post(message).catch((err) => this.log(`upstream ${this.name}: ${err.message}`));
    return true;
  }

  async #post(message) {
    const target = this.postUrl ?? this.url;
    const timeout = AbortSignal.timeout(this.timeoutMs);

    const res = await this.fetchImpl(target, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        ...(this.sessionId ? { "mcp-session-id": this.sessionId } : {}),
        ...this.headers,
      },
      body: JSON.stringify(message),
      // Same-origin only. A cross-origin redirect is how this becomes an SSRF.
      redirect: "error",
      signal: timeout,
    });

    const session = res.headers.get("mcp-session-id");
    if (session) this.sessionId = session;

    if (!res.ok) {
      throw new Error(`${this.name} answered ${res.status} to ${message.method ?? "a message"}`);
    }

    const contentType = res.headers.get("content-type") ?? "";

    // 202 with no body: the answer will arrive on the event stream.
    if (res.status === 202 || contentType === "") {
      await res.body?.cancel().catch(() => {});
      return;
    }

    if (contentType.includes("text/event-stream")) {
      await this.#pumpResponseStream(res);
      return;
    }

    const text = await res.text();
    if (!text) return;
    try {
      const payload = JSON.parse(text);
      for (const m of Array.isArray(payload) ? payload : [payload]) this.onMessage?.(this, m);
    } catch {
      this.log(`upstream ${this.name}: response body was not JSON`);
    }
  }

  /** A response-scoped SSE stream (Streamable HTTP). Ends with the response. */
  async #pumpResponseStream(response) {
    const reader = response.body?.getReader();
    if (!reader) return;
    const decoder = new TextDecoder();
    let buffer = "";

    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let split;
      while ((split = buffer.search(/\r?\n\r?\n/)) !== -1) {
        const rawEvent = buffer.slice(0, split);
        buffer = buffer.slice(split).replace(/^\r?\n\r?\n/, "");
        this.#handleEvent(rawEvent);
      }
    }
    if (buffer.trim()) this.#handleEvent(buffer);
  }

  /** Sends a request and resolves with the matching response. */
  request(method, params, timeoutMs = this.timeoutMs) {
    return new Promise((resolve, reject) => {
      if (!this.alive) return reject(new Error(`upstream ${this.name} is not running`));

      const id = `cx-${this.name}-${this.#nextId++}`;
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`upstream ${this.name} timed out on ${method}`));
      }, timeoutMs);

      this.#pending.set(id, {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });

      void this.#post({ jsonrpc: "2.0", id, method, params }).catch((err) => {
        const entry = this.#pending.get(id);
        this.#pending.delete(id);
        clearTimeout(timer);
        // A failed request demotes the upstream rather than throwing into the
        // gateway: one dead server must not take down the session.
        this.alive = false;
        entry?.reject(err) ?? reject(err);
      });
    });
  }

  settle(message) {
    const entry = this.#pending.get(message.id);
    if (!entry) return false;
    this.#pending.delete(message.id);
    if (message.error) {
      entry.reject(Object.assign(new Error(message.error.message), { rpc: message.error }));
    } else entry.resolve(message.result);
    return true;
  }

  stop() {
    this.alive = false;
    try {
      this.#abort?.abort();
    } catch {
      /* already closed */
    }
    for (const [, entry] of this.#pending) entry.reject(new Error(`upstream ${this.name} stopped`));
    this.#pending.clear();
  }
}

/* -------------------------------------------------------------------------- */
/*  Serving                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * The gateway's own HTTP face, for agents that connect over HTTP rather than
 * spawning it over stdio.
 *
 * Streamable HTTP only. Implementing the deprecated HTTP+SSE shape on the
 * serving side would mean maintaining a second session model for clients that
 * can all speak the current one.
 *
 * BINDS TO LOOPBACK BY DEFAULT, AND SAYS SO IF YOU CHANGE IT. A policy engine
 * listening on 0.0.0.0 with no authentication is a remote tool-execution
 * service, and the person who set `--host 0.0.0.0` to reach it from a container
 * did not mean to build one.
 */
export class HttpGatewayServer {
  #server = null;
  #sessions = new Map();

  constructor({ gateway, host = "127.0.0.1", port = 8787, token = null, log = () => {} }) {
    this.gateway = gateway;
    this.host = host;
    this.port = port;
    this.token = token;
    this.log = log;
  }

  async start() {
    const { createServer } = await import("node:http");

    if (this.host !== "127.0.0.1" && this.host !== "localhost" && !this.token) {
      throw new Error(
        `Refusing to listen on ${this.host} without a token. A gateway reachable off-host with no authentication is a remote tool-execution service. Pass --token, or bind to 127.0.0.1.`,
      );
    }

    this.#server = createServer((req, res) => void this.#handle(req, res));
    await new Promise((resolve, reject) => {
      this.#server.once("error", reject);
      this.#server.listen(this.port, this.host, () => {
        this.#server.removeListener("error", reject);
        resolve();
      });
    });

    this.log(`http gateway listening on http://${this.host}:${this.port}`);
    return this;
  }

  async #handle(req, res) {
    const send = (status, body, headers = {}) => {
      const payload = typeof body === "string" ? body : JSON.stringify(body);
      res.writeHead(status, {
        "content-type": "application/json",
        "cache-control": "no-store",
        ...headers,
      });
      res.end(payload);
    };

    if (this.token) {
      const auth = req.headers.authorization ?? "";
      if (auth !== `Bearer ${this.token}`) {
        return send(401, { error: "unauthorized" });
      }
    }

    if (req.method === "GET" && req.url === "/health") {
      return send(200, { ok: true, rules: this.gateway.rules.length, stats: this.gateway.stats });
    }

    if (req.method !== "POST") {
      return send(405, { error: "This endpoint speaks Streamable HTTP: POST a JSON-RPC message." });
    }

    let raw = "";
    let bytes = 0;
    for await (const chunk of req) {
      bytes += chunk.length;
      if (bytes > MAX_BODY_BYTES) {
        req.destroy();
        return send(413, { error: "request too large" });
      }
      raw += chunk;
    }

    let message;
    try {
      message = JSON.parse(raw);
    } catch {
      return send(400, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
    }

    // The gateway writes answers through a callback; collect them for this
    // request and answer in one body.
    const outbound = [];
    const previousWrite = this.gateway.write;
    this.gateway.write = (m) => outbound.push(m);

    try {
      await this.gateway.handleClientMessage(message);
    } finally {
      this.gateway.write = previousWrite;
    }

    if (!outbound.length) return send(202, "");
    return send(200, outbound.length === 1 ? outbound[0] : outbound);
  }

  async stop() {
    for (const s of this.#sessions.values()) s.destroy?.();
    this.#sessions.clear();
    await new Promise((resolve) => (this.#server ? this.#server.close(resolve) : resolve()));
  }
}

/** Reads an SSE stream out of a `Response`, for callers that want the frames. */
export function sseFramer(onMessage, onInvalid = () => {}) {
  return new MessageFramer({ onMessage, onInvalid });
}
