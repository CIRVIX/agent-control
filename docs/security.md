# Security and threat model

The full threat model, the adversarial review, and its findings live in
**[`SECURITY.md`](../SECURITY.md)** at the repository root — the location GitHub
and most scanners expect. This page places it in the documentation set and links
each part of the model to the mechanism that implements it.

Nothing here is a certification claim. There is no SOC 2, ISO 27001, or FedRAMP
certification. Cirvix produces [evidence](./administration.md#compliance-evidence)
for those audits; it does not assert an outcome.

## What is being protected

| Asset | Mechanism | Documented in |
|---|---|---|
| The rule set | Versioning, hash-bound approvals, structural validation before publish | [Governance](./administration.md#policy-governance) |
| The decision record | Per-tenant SHA-256 hash chain over canonical JSON | [Architecture](./architecture.md#the-audit-chain) |
| Secret material | AES-256-GCM envelope encryption, handles, destination binding | [Secret brokering](./administration.md#secret-brokering) |
| The tenant boundary | `orgId` from the principal only; `org_id = ?` in every tenant query | [API](./api.md#two-invariants-enforced-structurally) |
| Session and key material | Everything hashed; rotation with reuse detection | [Authentication](./api.md#authentication) |

## Who the adversary is

Four, in descending order of how much the system is designed around them.

### 1. A compromised or prompt-injected agent

The adversary the product exists for. Holds an endpoint API key, **controls the
arguments of every tool call**, and is trying to read a credential, reach
outside its workspace, or get material off the machine.

What stands in the way:

| Defence | Where |
|---|---|
| Default deny — nothing runs unless a rule permits it | [Policy](./policy.md#2-default-deny) |
| `forbid` cannot be overridden by any `permit` | [Policy](./policy.md#1-forbid-always-wins) |
| Resources canonicalized before matching, so traversal does not bypass a rule | [Policy](./policy.md#3-resources-are-canonicalized-before-matching) |
| Non-backtracking glob matcher — the agent picks the input, so a hung evaluator would be a hung gateway | [Policy](./policy.md#glob-matching) |
| `session.touchedSecret` blocks egress for the rest of a session that read a credential | [Policy](./policy.md#the-evaluation-context) |
| Handles, not credentials, so the agent never holds the material | [Secrets](./administration.md#secret-brokering) |
| Return-path scrubbing catches material coming back | [Node SDK](./sdk-node.md#secret-handles) |
| Tool definitions pinned by hash — a rug-pulled MCP server is withheld | [Architecture](./architecture.md#why-the-gateway-is-built-the-way-it-is) |
| Conditions are data, never `eval` | [Policy](./policy.md#conditions-when) |

### 2. An authenticated principal of one tenant

A member, an admin, or a stolen API key, trying to exceed their role or reach
another tenant.

| Defence | Where |
|---|---|
| `orgId` never comes from client input — the parameter does not exist in routing | [API](./api.md#two-invariants-enforced-structurally) |
| Every route declares a permission; `route()` throws at startup otherwise | [API](./api.md#two-invariants-enforced-structurally) |
| A role can only be granted by someone who holds it | [Roles](./administration.md#the-grant-ceiling) |
| `sso:manage` and `policy:settings` are owner-only | [Roles](./administration.md#three-placements-worth-understanding) |
| SCIM tokens cannot reach `/v1`; console credentials cannot reach `/scim/v2` | [SCIM](./administration.md#directory-provisioning-scim-20) |
| Role re-read per request, so a demotion takes effect immediately | [API](./api.md#authentication) |
| A directory group cannot grant `owner` | [SSO](./administration.md#four-behaviours-to-know-before-switching-it-on) |

The admin→owner escalation path was a **real finding** in the review, not a
hypothetical. See `SECURITY.md`.

### 3. An unauthenticated network attacker

| Defence | Where |
|---|---|
| Sliding-window rate limiting; 10/min per IP on login, SSO, invitations | [API](./api.md#rate-limiting) |
| Uniform failure messages — no user enumeration | [API](./api.md#public) |
| SSO discovery answers `200` either way, so it is not a customer oracle | [API](./api.md#public) |
| Refresh rotation with reuse detection revokes the whole family | [API](./api.md#authentication) |
| `alg` is never read from the token; only HS256 is accepted | [Architecture](./architecture.md#the-control-plane) |
| Body capped at 1 MiB | [API](./api.md#conventions) |
| Refuses to boot on a weak signing key | [Deployment](./deployment.md#1-generate-a-signing-key) |
| Egress guard on tenant-supplied URLs | [Deployment](./deployment.md#private-egress) |

An unauthenticated denial of service was also a real finding. It is fixed.

### 4. An insider with database read access

Cannot obtain a usable credential from it. API keys, refresh tokens, invitation
tokens, and SCIM tokens are stored as SHA-256. Secret values are sealed under a
key that is **not in the database**.

This is why [Operations](./operations.md#what-is-not-in-the-database) says never
to back the master key up in the same place as the database. A backup containing
both is not a backup, it is a copy of the secrets.

## Explicitly out of scope

Stated so nobody mistakes silence for coverage.

- **Root on the endpoint.** The gateway holds resolved secret material in
  process memory for the life of a request. A machine compromised at root is
  outside any userspace product's threat model.
- **A malicious operator of the control plane.** Someone who can edit the
  database and recompute the chain can rewrite history. The chain proves
  tampering to anyone who kept an earlier head, not to someone who did not.
- **The identity provider.** If a directory account is compromised, the approval
  authority attached to it is compromised. Cirvix does not replace an IdP.
- **Network egress policy.** The SSRF defences raise the cost of the easy
  attack; a control plane that cannot route to `169.254.169.254` is the durable
  control.
- **DNS rebinding.** The egress guard resolves and checks, but Node's `fetch`
  does not expose address pinning. See the note in `egress.mjs`.

## What the audit chain does and does not prove

Routinely overstated, so stated precisely:

| | |
|---|---|
| **Proves** | No record was altered or removed after it was written, assuming a published checkpoint root is trusted |
| **Does not prove** | That a record was written truthfully. That property comes from the enforcement path, not the log |
| **Does not prevent** | Destruction. The chain guarantees deletion is *visible*, not impossible |

`cirvix audit verify` prints this caveat on every successful run.

## What enforcement does not claim

- Cirvix does not prevent prompt injection. It constrains what an injected agent
  can **do**, according to configured runtime policies.
- A permissive rule you wrote yourself is honoured exactly as written. Policy
  quality is the operator's responsibility.
- `guard.wrap` governs the tools you hand it. A tool the agent reaches directly
  is never evaluated — only the gateway has that property, because it sits on
  the wire.
- Policy decides authorization, not payload semantics. A permitted query
  returning more rows than intended is a query design problem.

## The review

An adversarial review on 2026-08-07 found and fixed **eight real
vulnerabilities**, including an admin→owner privilege escalation and an
unauthenticated denial of service. `SECURITY.md` records each one, the items
that were checked and found clean, and the risks that were accepted with the
trigger for revisiting them written down.

The suite grew from 285 to 327 tests in that pass; every finding has a test that
fails without the fix.

## Hardening checklist

| | |
|---|---|
| `CIRVIX_JWT_SECRET` ≥32 random chars, not in the database backup | [Deployment](./deployment.md#1-generate-a-signing-key) |
| `CIRVIX_MASTER_KEY` backed up separately from the database | [Operations](./operations.md#what-is-not-in-the-database) |
| `CIRVIX_CORS_ORIGIN` set to the console's exact origin | [Deployment](./deployment.md#configuration) |
| `CIRVIX_METRICS_TOKEN` set if `/metrics` is reachable off the private network | [Operations](./operations.md#monitoring) |
| `CIRVIX_ALLOW_PRIVATE_EGRESS` left **unset** unless internal endpoints are required | [Deployment](./deployment.md#private-egress) |
| TLS terminated, with SSE buffering and timeouts corrected | [Deployment](./deployment.md#tls) |
| Bootstrap variables removed after first boot | [Deployment](./deployment.md#kubernetes-with-helm--supported-production-path) |
| Endpoint API keys scoped `member`, never `admin` | [Administration](./administration.md#members-invitations-api-keys) |
| Policy review required, self-approval off | [Governance](./administration.md#policy-governance) |
| Alerts on chain verification and stale endpoints | [Operations](./operations.md#the-three-alerts-that-matter) |
| Backups verified with `/v1/audit/verify`, not just restored | [Operations](./operations.md#verify-the-restore) |

## Reporting

See the reporting section of [`SECURITY.md`](../SECURITY.md).
`/.well-known/security.txt` is served by the site.
