# Architecture

Cirvix answers one question, in one place, and records the answer: **may this
agent make this tool call?**

Everything else in the system exists to get that question asked, to distribute
the rules it is asked against, or to keep the answer afterwards.

## The shape

```
                          ┌───────────────────────────────┐
   agent ──stdio──▶  MCP Gateway  ──stdio──▶ upstream MCP servers
                          │                  (github, filesystem, …)
                          ├─ Guard ── policy engine
                          ├─ audit chain (.cirvix/audit.jsonl)
                          └─ Daemon ─────HTTPS─────┐
                                                   ▼
   agent (LangChain/CrewAI) ── guard.wrap ──▶ Guard        Control Plane
                                                   ├─ policy distribution
                                                   ├─ fleet inventory
                                                   ├─ decisions + runs
                                                   ├─ approvals
                                                   ├─ secret broker
                                                   ├─ audit chain (per tenant)
                                                   ├─ SSO / SCIM
                                                   └─ compliance evidence
                                                          ▲
                                        console  ──────────┘
```

Two enforcement paths, **one decision core**.

## One decision core, two transports

The MCP gateway and `guard.wrap()` are two transports for one question. They
**must not** be two implementations of the answer — a guard that permits what
the gateway denies is worse than having no SDK at all, because it is a
governance product with a documented bypass.

Both call `Guard.authorize()` in
[`core/guard.mjs`](../packages/agent-control/src/core/guard.mjs), which calls
`evaluate()` in [`core/policy.mjs`](../packages/agent-control/src/core/policy.mjs).
The gateway was refactored onto this shared core specifically so the two cannot
drift.

The Python engine is a separate implementation of `evaluate()`, held in
agreement by a [shared conformance fixture](./policy.md).

| | Gateway | `guard.wrap` |
|---|---|---|
| Governs tools added after deployment | **yes** — sits on the wire | no — wraps a list |
| Requires the agent to speak MCP | yes | no |
| Same engine, rules, decision record | yes | yes |
| Secret brokering | yes | Node only |
| Audit chain | yes | Node only |

## The decision path

For one `tools/call` crossing the gateway:

1. **Decode.** The JSON-RPC frame is parsed. Tool names are namespaced
   `server__tool`.
2. **Map to policy vocabulary.** `actionForTool` normalizes the tool name to an
   action (`fs.read`, `shell.exec`, …); `resourceForCall` extracts the resource
   from the arguments.
3. **Canonicalize.** The resource is resolved — traversal collapsed, case
   normalized, URLs reduced to scheme/host/path.
4. **Assemble context.** `environment`, `path.insideWorkspace`,
   `egress.external`, `session.touchedSecret`, `mcp.server`, `mcp.tool`.
5. **Evaluate.** Ordered rules; forbid short-circuits, hold outranks permit,
   default deny.
6. **Broker.** On a permit, secret handles in the arguments are substituted for
   real material — all or nothing. A broker refusal turns the permit into a
   deny.
7. **Record.** One decision record, appended to the hash chain and handed to
   `onDecision`.
8. **Forward, refuse, or hold.**
9. **Scrub the return path.** The result is scanned for material this session
   resolved, and handles are put back.

Latency is measured around step 5 only. The tool round trip is orders of
magnitude larger and including it would flatter the number dishonestly.

## Why the gateway is built the way it is

The gateway is the product; everything else describes what it does. Six
decisions in it are load-bearing.

**Tool names are namespaced.** Two servers may both expose `search`. Without
namespacing the gateway cannot route the call and — worse — a policy written for
one server silently governs the other.

**Request ids are rewritten.** The agent's id space and each upstream's are
independent. Forwarding an id unchanged means two servers can answer with the
same id and the gateway mis-routes a response.

**Tool definitions are pinned.** A tool's description is instruction text that
enters the model's context with the authority of a system message, and it is
supplied by the server, not by you. The gateway hashes each definition on first
sight; a changed definition is withheld until re-approved. This is the defence
against a rug-pulled MCP server.

**Denials are tool results, not transport errors.** A transport error tells the
agent the plumbing broke, and it retries. A tool result carrying a refusal and a
remediation tells it what happened and what to do instead.

**One upstream failing does not take down the session.** A dead server's tools
disappear from `tools/list`; calls to it return a clean error.

**Secrets are substituted here, if anywhere.** This is the only point in the
process where a credential exists inside a request, and it sits downstream of
the decision that authorized it.

## Enforcement does not depend on the control plane

The gateway and both SDKs evaluate **locally**, against rules already on the
machine. The control plane distributes rules and collects what happened.

A control-plane outage must not become an enforcement outage. The daemon caches
the last known rule set in its state directory and keeps enforcing it; telemetry
spools to disk and ships when the connection returns.

This is also why `cirvix scan`, `check`, `policy`, `gateway` and `audit verify`
all work with no account at all. Only `why` and `replay` require the control
plane, because they ask about something recorded somewhere else.

## The audit chain

Append-only JSONL where every record commits to the hash of its predecessor.
SHA-256 over a **canonical** JSON serialization — keys sorted all the way down,
because `JSON.stringify` preserves insertion order and two semantically
identical records would otherwise hash differently.

Stated precisely, because the distinction is the whole value and is routinely
overstated:

| | |
|---|---|
| **Proves** | No record was altered or removed after it was written, assuming any published checkpoint root is trusted |
| **Does not prove** | That a record was written truthfully in the first place. That property comes from the enforcement path, not the log |
| **Does not prevent** | Destruction. Someone with disk access can delete the file. The chain guarantees that doing so is *visible* |

`cirvix audit verify` prints that caveat on every successful run.

The control plane keeps a **per-tenant** chain of its own. Appending reads the
previous hash and inserts the next row inside one `IMMEDIATE` transaction —
without that, two concurrent writers both read the same predecessor and fork the
chain.

## The control plane

Zero-dependency Node HTTP server over SQL. 110 routes. Two invariants are
enforced structurally rather than by discipline:

- **`orgId` is never read from a body, query, or path.** It comes only from the
  authenticated principal, so the parameter that would allow cross-tenant
  addressing does not exist in the routing layer.
- **Every route declares its permission** or `null` for an explicitly public
  one. `route()` throws at startup otherwise, so an endpoint cannot be added
  unauthenticated by omission — the most common way an API grows a hole.

Storage preserves the method surface of the original in-memory store, so
persistence can be swapped again (Postgres) without touching routing, auth, or
RBAC.

### Subsystems

| Module | Responsibility |
|---|---|
| `api.mjs` | Routing, RBAC, rate limiting, dispatch |
| `auth.mjs` | Sessions, JWT (HS256, hand-rolled), refresh rotation with reuse detection |
| `store-sql.mjs` | Tenanted persistence, roles, permissions, audit chain |
| `db/migrations.mjs` | 8 versioned migrations |
| `governance.mjs` | Draft → review → publish, hash-bound approvals |
| `runs.mjs` | Runs, steps, replay |
| `secrets.mjs` | Envelope encryption, handles, destination binding, usage log |
| `sso.mjs` / `oidc.mjs` | OIDC for Google, Entra, Okta, generic |
| `scim.mjs` | SCIM 2.0 Users and Groups |
| `alerts.mjs` | Slack, Teams, webhook, email dispatch |
| `compliance.mjs` | SOC 2 / ISO 27001 evidence |
| `metrics.mjs` | Prometheus |
| `events.mjs` | Tenant-scoped SSE bus |
| `egress.mjs` | Outbound request guarding (SSRF) |

JWT is implemented in-repo rather than pulled from npm. It is ~60 lines of HMAC
and base64url, and a control plane taking a dependency for its own token
verification is taking a dependency on someone else's release process for its
most security-critical path.

## Identity

Three credential types with deliberately different blast radius:

| | Lifetime | Scope | Storage |
|---|---|---|---|
| API key `cvx_` | until revoked | one org, one role | SHA-256 |
| Session JWT | 15 min | one org, role re-read per request | not stored |
| Refresh `cvr_` | 30 days, rotating | one session family | SHA-256 |
| SCIM `scim_` | until revoked | provisioning only | SHA-256 |

Federated identity is `(issuer, subject)`, **never email**. An email address is
a display attribute a directory administrator can reassign, and treating it as
identity means reassigning an address hands over the account.

## Scaling boundary

The control plane is a single Node process over SQLite. That is a real
boundary, and [Operations](./operations.md#scaling-boundary) states where it
sits and what to do at it rather than leaving it to be discovered under load.

Enforcement scales independently and horizontally: every gateway and every
wrapped agent decides locally, so adding agents adds no load to the control
plane beyond telemetry ingest.

## Dependencies

| Package | Runtime dependencies |
|---|---|
| `@cirvix/agent-control` | none |
| `cirvix` (PyPI) | none |
| `@cirvix/control-plane` | `@cirvix/agent-control` only |

The console is a Next.js app and does have dependencies. Nothing on the
enforcement path does.
