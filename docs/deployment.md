# Deployment guide

## What this checkout can run

The public package `@cirvix_ai/agent-control` contains a local Node SDK, MCP gateway, local control socket, and a client daemon. Node 20+ is required. It does **not** contain a deployable control-plane API, console, billing service, Helm chart, or production container image. Local database remnants under `packages/control-plane` are not a server implementation.

Hosted availability and private enterprise artifacts have not been verified. Do not use the historical API or administration documents as deployment instructions for this checkout.

## Local installation

From the repository root:

```bash
npm ci
node packages/agent-control/bin/cirvix.mjs init
node packages/agent-control/bin/cirvix.mjs policy check
node packages/agent-control/bin/cirvix.mjs policy test
```

`init` configures files; it does not leave enforcement running. `init --dry-run` previews without writing. Automatic integration is refused when a generated configuration would retain direct upstream access.

## MCP gateway

Keep upstream definitions in a **separate** file from the client's gateway-only configuration. Start the gateway with explicit workspace and policy paths:

```bash
node packages/agent-control/bin/cirvix.mjs gateway --servers ./mcp-upstreams.json --cwd . --policy ./cirvix.policy
```

The upstream map accepts `mcpServers`, `servers`, or a bare map. Entries use `command`/`args`/`env` for stdio or `url`/`headers` for HTTP upstreams. Supply trusted configurations only. Environment entries are passed to upstream processes; this is not automatic dotenv loading or editor-variable expansion.

Configure the MCP client to launch that command, replacing paths with absolute paths. Remove direct upstream entries from the client. Only calls routed through Cirvix are governed; built-in editor tools and arbitrary host processes are not intercepted.

### Inbound Streamable HTTP

```bash
node packages/agent-control/bin/cirvix.mjs gateway --servers ./mcp-upstreams.json --http --host 127.0.0.1 --port 8787
```

The gateway speaks MCP, **not** a general HTTP egress proxy. Setting `HTTP_PROXY` does not route ordinary agent traffic through its policy engine. HTTP mode stays running when stdin closes. Non-loopback exposure needs authentication and a reviewed TLS/network boundary; do not put an unauthenticated gateway on a public interface. No Docker or Kubernetes deployment is certified by this guide.

## Local control socket

```bash
node packages/agent-control/bin/cirvix.mjs runtime --cwd .
```

This starts a Unix-domain socket or Windows named pipe with a local session token. A cooperating client must use the protocol; merely starting it does not instrument an existing agent. Keep state private and use one writer per audit chain.

## Verification and approvals

```bash
node packages/agent-control/bin/cirvix.mjs logs
node packages/agent-control/bin/cirvix.mjs approvals
node packages/agent-control/bin/cirvix.mjs audit verify
```

Use the same `--cwd`/`--state` as the running process. Approvals are local records with named reviewers and single-use grants, not independently authenticated human signatures. A local proof verifies artifact integrity against the supplied key, not truthfulness or independent compliance.

## Optional external control-plane client

`gateway`, `daemon`, `why`, and `replay` accept `--api` and `--key`, or `CIRVIX_API_URL` and `CIRVIX_API_KEY`. Flags take precedence. Both values are needed for remote use. `why` otherwise reads local history; `replay` requires a remote API.

`login --url` verifies and stores credentials in the user's home. Stored login credentials are not automatically consumed by all command paths; configure the explicit flags or environment for the daemon/gateway. The direct key-verification path requires HTTPS and preserves non-default ports. The browser-flow path is separate and is not covered by that validation claim. This checkout does not implement the server-side login or browser authorization routes.

No `.env` file is automatically loaded by these commands. `CIRVIX_JWT_SECRET`, `CIRVIX_MASTER_KEY`, and `NEXT_PUBLIC_CIRVIX_API` from historical private-product docs do not create a server or console here.

## Feature wiring and release limitations

- The CLI gateway supplies audit, approvals and local commercial metering to Guard. Guard now runs shared in-process kill checks; the CLI still does not supply `SecretsClient`, `Vault`, missions, delegation or Pipeline-only intent/session/baseline controls. Supplying API credentials enables the daemon, not automatic secret brokering.
- `runtime --vault` loads credential-shaped environment variables into an in-memory vault. Without it the runtime does not acquire a broker merely because its startup display says secrets are protected. The standalone `vault` command loads and reports within that one process; its handles are not provisioned into an existing gateway.
- A held call returns to the client; approving records a grant for a later retry. No external effect automatically resumes, and no transaction couples approval consumption to successful tool completion.
- Gateway rules are chosen once during construction. Daemon policy refresh is not wired to replace the active gateway rules. Plan controlled restart and validate the resulting rules; an empty remote cache currently falls back to local policy.
- `--state` is not a universal relocation switch for all local metadata: gateway/runtime metering is constructed from `cwd`. Keep workspace and state configuration consistent and inspect individual stores before planning backup or isolation.
- Do not claim containment from `cirvix kill`: its rule lives only in that invocation's memory. No cross-process/fleet propagation or OS process termination is implemented.

There is no shipped service supervisor, production container/Helm deployment, automatic state migration, tool rollback, shared-file HA scheme or tested disaster recovery guarantee. See [Operations](./operations.md#current-local-operations-and-recovery) before operating persistent state.
