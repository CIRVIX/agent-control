# Deployment guide

Everything here has been run. Commands are copy-pasteable in order.

**What you are deploying:** a control plane that distributes policy, receives
decisions, and backs the console — plus an endpoint daemon and MCP gateway
(`@cirvix_ai/agent-control`) on each machine running agents.

```
  developer laptop / server / CI          your infrastructure
  ┌─────────────────────────────┐         ┌──────────────────────┐
  │ agent → cirvix gateway      │────────▶│  control plane       │
  │           ↓ enforces        │  HTTPS  │  ├─ policy           │
  │         cirvix daemon       │  polls  │  ├─ audit chain      │
  │           ↓ caches policy   │◀────────│  ├─ alerts           │
  │           ↓ spools telemetry│         │  └─ /metrics         │
  └─────────────────────────────┘         └──────────────────────┘
                                                    ▲
                                            console (Next.js)
```

The endpoint holds **no inbound port**. It polls outward, which is why it works
behind NAT and inside a locked-down VPC without a firewall exception.

There is no hosted service. Every deployment is your own.

## Requirements

| | |
|---|---|
| Node | 20+ (24 recommended — the store uses `node:sqlite`) |
| Runtime deps | none. The control plane has zero npm dependencies |
| Disk | the audit chain grows ~1 KB per decision |
| TLS | required in production; the console will not send credentials over plain HTTP from a browser on a secure origin |

## 1. Generate a signing key

The control plane **refuses to start** without one of at least 32 characters.
That is deliberate: a weak or defaulted JWT secret lets anyone mint a session.

```bash
openssl rand -hex 32
```

## 2. Run it

### Docker Compose — smallest real deployment

```bash
cd packages/control-plane/deploy

CIRVIX_BOOTSTRAP_ORG="Acme" \
CIRVIX_BOOTSTRAP_EMAIL="you@acme.com" \
CIRVIX_BOOTSTRAP_PASSWORD="$(openssl rand -base64 24)" \
CIRVIX_JWT_SECRET="$(openssl rand -hex 32)" \
CIRVIX_MASTER_KEY="$(openssl rand -hex 32)" \
docker compose up -d
```

`CIRVIX_MASTER_KEY` is optional — drop it to run without secret brokering.
Everything else is forwarded into the container by `docker-compose.yml`; setting
a variable the compose file does not map does nothing.

The container runs read-only, with `no-new-privileges` and all capabilities
dropped.

Read the API key — printed **once**, not recoverable:

```bash
docker compose logs control-plane | grep 'API key'
```

### Kubernetes with Helm — supported production path

```bash
helm install cirvix ./packages/control-plane/deploy/helm \
  --namespace cirvix --create-namespace \
  --set config.jwtSecret="$(openssl rand -hex 32)" \
  --set config.masterKey="$(openssl rand -hex 32)" \
  --set config.corsOrigin="https://console.example.com" \
  --set config.consoleUrl="https://console.example.com" \
  --set ingress.enabled=true \
  --set ingress.host=api.example.com \
  --set config.bootstrap.org="Acme" \
  --set config.bootstrap.email="you@acme.com" \
  --set config.bootstrap.password="$(openssl rand -base64 24)"
```

```bash
kubectl -n cirvix rollout status deploy/cirvix-cirvix-control-plane
kubectl -n cirvix logs deploy/cirvix-cirvix-control-plane | grep 'API key'
```

Then **remove `config.bootstrap` from your values and upgrade.** It does nothing
on a non-empty database, but it keeps a password in your release values for no
reason.

To supply secrets from an existing Kubernetes Secret instead of Helm values, set
`config.existingSecret` (key `jwt-secret`) and `config.masterKeyFromSecret: true`
(key `master-key`).

Prefer raw manifests? `deploy/k8s/control-plane.yaml` produces the same thing;
edit the Secret and the two hostnames.

### Bare Node

```bash
CIRVIX_JWT_SECRET="$(openssl rand -hex 32)" \
CIRVIX_DATA=/var/lib/cirvix/cirvix.db \
PORT=8787 \
node packages/control-plane/bin/serve.mjs
```

## 3. Verify

```bash
curl -s https://api.example.com/health
# {"status":"ok","version":"0.1.0","uptime":12.4}

curl -s https://api.example.com/v1/org -H "authorization: Bearer cvx_..."
```

The boot log states whether secret brokering is on. It is printed every time
rather than left to be discovered by a `503`, because an operator who believes
secrets are brokered when they are not has agents holding raw credentials and no
indication of it.

## 4. Point the console at it

```bash
# .env.local at the repo root
NEXT_PUBLIC_CIRVIX_API=https://api.example.com
```

Rebuild after changing it — the value is inlined at build time, **and it is also
compiled into the CSP `connect-src`**. If the console reports "could not reach
the control plane" while `curl` works, the origin does not match what was built.

## 5. Govern a machine

```bash
npx @cirvix_ai/agent-control scan          # read-only, no account

cirvix gateway \
  --servers ~/.cursor/mcp.json \
  --api https://api.example.com \
  --key cvx_...
```

The endpoint registers itself, pulls policy, and ships decisions. It appears
under **Runtime** in the console within one heartbeat (30 s).

To run policy sync and telemetry without the gateway — for a host running
`guard.wrap` agents — use `cirvix daemon` with the same flags.

## Configuration

Config comes from the environment only. A container must be configurable
without a rebuild, and a config file baked into an image is a config file
someone will forget to rotate.

### Control plane

| Variable | Required | Default | Notes |
|---|---|---|---|
| `CIRVIX_JWT_SECRET` | **yes** | — | ≥32 chars. Rotating it signs out every session |
| `CIRVIX_MASTER_KEY` | for secrets | — | ≥32 chars. Seals secret material. Absent → `/v1/secrets` is not served |
| `CIRVIX_DATA` | | `./data/cirvix.db` | SQLite database path |
| `PORT` | | `8787` | |
| `CIRVIX_CORS_ORIGIN` | for browsers | none | The console's exact origin. No wildcard mode |
| `CIRVIX_CONSOLE_URL` | | none | Deep links in Slack/Teams alerts; default SSO redirect base |
| `CIRVIX_SSO_REDIRECT_URIS` | for SSO | `<console>/dashboard/sso/callback` | Comma-separated allowlist |
| `CIRVIX_RATE_LIMIT` | | `600` | Requests/min per credential |
| `CIRVIX_METRICS_TOKEN` | | none | Requires a bearer token on `/metrics` |
| `CIRVIX_ALLOW_PRIVATE_EGRESS` | | unset | Permits outbound requests to private ranges — see below |
| `CIRVIX_BOOTSTRAP_ORG` | first boot | — | Ignored once any tenant exists |
| `CIRVIX_BOOTSTRAP_EMAIL` | first boot | `owner@example.com` | |
| `CIRVIX_BOOTSTRAP_PASSWORD` | first boot | — | |

### Private egress

The control plane makes server-side requests to URLs a tenant supplies: alert
webhooks and an SSO issuer. In a multi-tenant deployment "POST this alert to a
URL I choose" is a request-forgery primitive pointed at whatever the control
plane can reach — instance metadata, the Kubernetes API, a database admin port.

By default those requests refuse to resolve to loopback, link-local, private,
carrier-grade-NAT, and other non-routable ranges, plus `localhost` and the known
metadata hostnames.

A **self-hosted** deployment legitimately points at internal hosts — an internal
Slack-compatible endpoint, an IdP on a private network. `CIRVIX_ALLOW_PRIVATE_EGRESS=1`
permits it. Turn it on only when that is what you mean; the default refuses
because a default that fails open is one nobody discovers until it is being used
against them.

This guard does **not** close DNS rebinding, and the code says so. A name can
resolve to a public address at check time and a private one when the socket
opens. The durable control is network egress policy at the boundary — a control
plane that cannot route to `169.254.169.254` does not need this check to be
perfect.

### Endpoint

| Variable | Used by | Notes |
|---|---|---|
| `CIRVIX_API_URL` | `gateway`, `daemon`, `why`, `replay` | Equivalent to `--api` |
| `CIRVIX_API_KEY` | `gateway`, `daemon`, `why`, `replay` | Equivalent to `--key`. `cvx_…` |

### Console

| Variable | Notes |
|---|---|
| `NEXT_PUBLIC_CIRVIX_API` | Control-plane origin. Inlined at build time and compiled into the CSP |

Flags take precedence over environment variables everywhere.

## TLS

Terminate at your ingress or reverse proxy. Two settings are **not optional** if
you want the live console:

```nginx
proxy_buffering off;          # SSE is buffered into uselessness otherwise
proxy_read_timeout 3600s;     # default 60s silently kills the stream
```

The Helm chart sets the nginx-ingress equivalents already. Without them the
console appears connected and silently stops updating.

## What to do next

| | |
|---|---|
| Set up SSO, SCIM, roles, secrets | [Administrator guide](./administration.md) |
| Backups, metrics, upgrades, scaling | [Operations guide](./operations.md) |
| Something is wrong | [Troubleshooting](./troubleshooting.md) |
