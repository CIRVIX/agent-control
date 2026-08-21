/**
 * The local control socket.
 *
 * A Unix Domain Socket (a named pipe on Windows) speaking JSON-RPC, so any
 * process on this machine can ask Cirvix "may I do this" without speaking MCP
 * and without linking the SDK. It is what makes the runtime agent-neutral in
 * practice rather than in principle: a Python agent, a Go CLI, a shell wrapper,
 * or an editor plugin all get the same decision from the same rule set.
 *
 *   client ──▶ {"method":"cirvix/authorize","params":{"tool":"shell.exec",…}}
 *   cirvix ──▶ {"result":{"decision":"deny","policy":"deny-destructive",…}}
 *
 * WHY A SOCKET RATHER THAN A LOCAL HTTP PORT
 *
 * A TCP port on localhost is reachable by every process on the machine, by
 * every container sharing the network namespace, and — via DNS rebinding — by a
 * web page the user has open. A UDS is a filesystem object with an owner and a
 * mode, so "who may ask for decisions" becomes a question the operating system
 * already knows how to answer.
 *
 * THIS SOCKET IS A SECURITY BOUNDARY, NOT A CONVENIENCE
 *
 * Whatever can talk to it can ask for secret substitution. Three things
 * therefore hold, and each is enforced rather than documented:
 *
 *   1. The socket file is created with mode 0600 and in a directory the
 *      current user owns. On POSIX that is the whole access-control story.
 *   2. Every connection must present the session token from `--state`, which
 *      is written 0600. This is what carries the property to Windows, where
 *      named pipes do not inherit filesystem permissions and the default DACL
 *      is more generous than it looks. Without the token nothing is served.
 *   3. `cirvix/vault.issue` is not exposed. A client may spend a handle it was
 *      given; it may never mint one, and it may never read material back. The
 *      socket cannot be used to exfiltrate the vault, because there is no
 *      method that returns a secret.
 */

import { createServer } from "node:net";
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";

import { MessageFramer, serialize } from "./jsonrpc.mjs";
import { DECISION } from "./decisions.mjs";
import { SOURCE } from "./normalize.mjs";

/** JSON-RPC error codes this server returns. */
export const UDS_ERROR = {
  UNAUTHORIZED: -32004,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL: -32603,
};

/**
 * The default endpoint for a state directory.
 *
 * On Windows a named pipe is not a filesystem path, so the socket lives in the
 * pipe namespace and only the token file is on disk. The pipe name is derived
 * from the state directory so two projects on one machine do not collide.
 */
export function defaultEndpoint(stateDir) {
  if (process.platform === "win32") {
    const slug = String(stateDir).replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(-64);
    return `\\\\.\\pipe\\cirvix-${slug || "default"}`;
  }
  // A socket path is capped near 104 bytes on macOS and BSD. A deep project
  // directory blows past that, and the failure is an opaque EINVAL at bind
  // time — so a long path falls back to the temp directory with a stable name.
  const preferred = join(stateDir, "cirvix.sock");
  if (Buffer.byteLength(preferred) < 100) return preferred;
  const slug = String(stateDir).replace(/[^A-Za-z0-9]+/g, "-").slice(-32);
  return join(tmpdir(), `cirvix-${slug}.sock`);
}

export function tokenPath(stateDir) {
  return join(stateDir, "socket.token");
}

/** Mints and persists the session token, 0600. */
export async function writeToken(stateDir) {
  const token = randomBytes(32).toString("hex");
  const path = tokenPath(stateDir);
  await mkdir(dirname(path), { recursive: true }).catch(() => {});
  await writeFile(path, token, "utf8");
  await chmod(path, 0o600).catch(() => {});
  return token;
}

export async function readToken(stateDir) {
  return (await readFile(tokenPath(stateDir), "utf8")).trim();
}

function sameToken(a, b) {
  const x = Buffer.from(String(a ?? ""));
  const y = Buffer.from(String(b ?? ""));
  if (x.length !== y.length || x.length === 0) return false;
  return timingSafeEqual(x, y);
}

/* -------------------------------------------------------------------------- */

export class UdsServer {
  #connections = new Set();

  /**
   * @param {object} opts
   * @param {import("./pipeline.mjs").Pipeline} opts.pipeline
   * @param {string} opts.endpoint
   * @param {string} opts.token
   * @param {(m:string,extra?:object)=>void} [opts.log]
   * @param {() => object} [opts.status]  supplies `cirvix/status`
   * @param {() => Promise<Array>} [opts.recent]  supplies `cirvix/logs`
   */
  constructor({ pipeline, endpoint, token, log = () => {}, status = () => ({}), recent = async () => [] }) {
    this.pipeline = pipeline;
    this.endpoint = endpoint;
    this.token = token;
    this.log = log;
    this.status = status;
    this.recent = recent;
    this.server = null;
    this.stats = { connections: 0, requests: 0, rejected: 0 };
  }

  async start() {
    // A socket file left behind by a killed process makes bind fail with
    // EADDRINUSE even though nothing is listening. Removing it is safe here
    // because the mode-0600 parent directory means only this user could have
    // created it.
    if (process.platform !== "win32") {
      await rm(this.endpoint, { force: true }).catch(() => {});
      await mkdir(dirname(this.endpoint), { recursive: true }).catch(() => {});
    }

    this.server = createServer((socket) => this.#onConnection(socket));

    await new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(this.endpoint, () => {
        this.server.removeListener("error", reject);
        resolve();
      });
    });

    if (process.platform !== "win32") {
      await chmod(this.endpoint, 0o600).catch(() => {});
    }

    this.log(`control socket listening on ${this.endpoint}`);
    return this;
  }

  #onConnection(socket) {
    this.stats.connections++;
    this.#connections.add(socket);

    /** Per-connection: a client is unauthenticated until it presents the token. */
    let authenticated = false;

    const write = (message) => {
      if (socket.writable) socket.write(serialize(message));
    };

    const framer = new MessageFramer({
      onMessage: (message) => {
        void (async () => {
          try {
            const response = await this.#dispatch(message, {
              authenticated,
              authenticate: () => {
                authenticated = true;
              },
            });
            if (response) write(response);
          } catch (err) {
            write({
              jsonrpc: "2.0",
              id: message?.id ?? null,
              error: { code: UDS_ERROR.INTERNAL, message: err.message },
            });
          }
        })();
      },
      onInvalid: (line) => this.log(`control socket: unparseable frame (${line.length} bytes)`),
    });

    socket.on("data", (chunk) => framer.push(chunk));
    socket.on("error", () => {});
    socket.on("close", () => this.#connections.delete(socket));
  }

  async #dispatch(message, session) {
    const id = message?.id ?? null;
    const ok = (result) => ({ jsonrpc: "2.0", id, result });
    const fail = (code, msg) => ({ jsonrpc: "2.0", id, error: { code, message: msg } });

    // Notifications get no reply, by JSON-RPC rule.
    if (id === null && message?.method) return null;

    this.stats.requests++;

    if (message?.method === "initialize" || message?.method === "cirvix/hello") {
      if (!sameToken(message.params?.token, this.token)) {
        this.stats.rejected++;
        this.log("control socket: rejected a connection with a bad or missing token");
        return fail(
          UDS_ERROR.UNAUTHORIZED,
          "This socket requires the session token from <state>/socket.token.",
        );
      }
      session.authenticate();
      return ok({
        protocol: "cirvix/1",
        server: "cirvix-uds",
        methods: ["cirvix/authorize", "cirvix/result", "cirvix/status", "cirvix/logs"],
        mode: this.pipeline.mode,
      });
    }

    if (!session.authenticated) {
      this.stats.rejected++;
      return fail(UDS_ERROR.UNAUTHORIZED, "Call initialize with the session token first.");
    }

    switch (message.method) {
      /* ----------------------------------------------------------------- */
      case "cirvix/authorize": {
        const params = message.params ?? {};
        if (!params.tool) return fail(UDS_ERROR.INVALID_PARAMS, "authorize needs a tool name.");

        const { event, decision, arguments: outgoing } = await this.pipeline.submit(
          { tool: params.tool, server: params.server ?? null, arguments: params.arguments ?? {} },
          {
            agent: params.agent,
            source: params.source ?? SOURCE.UDS,
            environment: params.environment,
            /*
             * The delegation the caller is acting under, if any.
             *
             * This was not forwarded, and the effect was not a missing feature.
             * Delegation only ever NARROWS, so dropping it here handed every
             * caller the full authority policy allowed — an agent delegated
             * `fs.read` could write the database over this socket, and the
             * audit record showed an ordinary permitted write with no chain on
             * it. Presenting a grant is the only way an agent can ask to be
             * held to less than policy permits, and the request was being
             * discarded.
             *
             * Forging it buys nothing: the grant is signed, and `resolve`
             * refuses one presented by anybody but its subject.
             */
            delegation: params.delegation ?? null,
          },
        );

        return ok({
          request_id: event.request_id,
          decision: event.decision,
          // `allowed` is the one-bit answer a shell wrapper needs; everything
          // else is for a client that can render more.
          allowed: event.decision === DECISION.ALLOW || event.decision === DECISION.SANITIZE || event.decision === DECISION.AUDIT_ONLY,
          risk: event.risk,
          policy: event.policy,
          reason: event.reason,
          remediation: decision.remediation ?? null,
          approval_id: event.approval_id ?? null,
          approvers: decision.approvers ?? [],
          latency_ms: event.latency_ms,
          enforced: event.enforced,
          // Substituted arguments go back so the client sends what Cirvix
          // authorized rather than what it proposed.
          arguments: outgoing,
        });
      }

      /* ----------------------------------------------------------------- */
      case "cirvix/result": {
        const params = message.params ?? {};
        const scrubbed = this.pipeline.scrubResult(params.result, params.decision ?? {});
        return ok({
          request_id: params.request_id ?? null,
          result: scrubbed.payload,
          findings: scrubbed.findings.map((f) => ({
            kind: f.kind,
            detector: f.detector ?? f.rule ?? null,
            path: f.path ?? null,
            masked: f.masked ?? null,
          })),
        });
      }

      /* ----------------------------------------------------------------- */
      case "cirvix/status":
        return ok(await this.status());

      case "cirvix/logs": {
        const limit = Number(message.params?.limit ?? 50);
        const risk = message.params?.risk ?? null;
        const events = await this.recent({ limit, risk });
        return ok({ events });
      }

      default:
        return fail(UDS_ERROR.METHOD_NOT_FOUND, `Unknown method "${message.method}".`);
    }
  }

  async stop() {
    for (const socket of this.#connections) socket.destroy();
    this.#connections.clear();
    await new Promise((resolve) => (this.server ? this.server.close(resolve) : resolve()));
    if (process.platform !== "win32") await rm(this.endpoint, { force: true }).catch(() => {});
  }
}

/* -------------------------------------------------------------------------- */
/*  Client                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * A minimal client, used by `cirvix status`, the demo, and the tests.
 *
 * Deliberately one-shot: connect, ask, close. A pooled connection to a local
 * socket saves microseconds and costs a whole class of lifecycle bug.
 */
export class UdsClient {
  constructor({ endpoint, token, timeoutMs = 10_000 }) {
    this.endpoint = endpoint;
    this.token = token;
    this.timeoutMs = timeoutMs;
  }

  async call(method, params = {}) {
    const { connect } = await import("node:net");

    return new Promise((resolve, reject) => {
      const socket = connect(this.endpoint);
      let nextId = 1;
      let settled = false;

      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        fn(value);
      };

      const timer = setTimeout(
        () => finish(reject, new Error(`Timed out talking to ${this.endpoint}.`)),
        this.timeoutMs,
      );

      const pending = new Map();
      const framer = new MessageFramer({
        onMessage: (m) => {
          const entry = pending.get(m.id);
          if (!entry) return;
          pending.delete(m.id);
          if (m.error) finish(reject, new Error(m.error.message));
          else entry(m.result);
        },
      });

      const send = (m, onResult) => {
        const id = nextId++;
        pending.set(id, onResult);
        socket.write(serialize({ jsonrpc: "2.0", id, ...m }));
      };

      socket.on("data", (c) => framer.push(c));
      socket.on("error", (err) => finish(reject, err));

      socket.on("connect", () => {
        send({ method: "initialize", params: { token: this.token } }, () => {
          send({ method, params }, (result) => finish(resolve, result));
        });
      });
    });
  }
}
