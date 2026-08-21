# API reference

The control plane is a zero-dependency Node HTTP server exposing **110 routes**.
Multi-tenant, RBAC-enforced, SQL-backed.

Base URL is whatever you deploy it at. There is no hosted `api.cirvix.com` —
every deployment is your own.

```bash
export CIRVIX_API=https://cirvix.internal.example.com
curl -s $CIRVIX_API/health
# {"status":"ok","version":"0.1.0","uptime":12.4}
```

## Two invariants, enforced structurally

**`orgId` is never read from a body, query, or path.** It comes only from the
authenticated principal, so a client cannot address another tenant's data even
by guessing ids — the parameter that would allow it does not exist in the
routing layer.

**Every route declares the permission it needs**, or `null` for an explicitly
public one. `route()` throws at startup otherwise, so an endpoint cannot be
added unauthenticated by omission.

## Authentication

Three credential types, deliberately separate.

| Credential | Prefix | Lifetime | Used by | Header |
|---|---|---|---|---|
| API key | `cvx_` | Until revoked | Endpoint daemon, CI, SDKs | `authorization: Bearer cvx_…` |
| Session access token | JWT (HS256) | 15 minutes | The console | `authorization: Bearer eyJ…` |
| SCIM token | `scim_` | Until revoked | Your identity provider | `authorization: Bearer scim_…` |

Refresh tokens are prefixed `cvr_` and last 30 days. They are **rotated on every
refresh with reuse detection**: presenting an already-rotated token revokes the
entire session family, on the assumption that a rotated token being replayed
means it was stolen.

A validly-signed access token whose session has been revoked does **not**
authenticate. Roles are re-read from the database on every request rather than
trusted from the token, so a demotion takes effect immediately.

A SCIM token can only reach `/scim/v2/*`, and a console credential can only
reach `/v1/*`. This is structural: a SCIM principal carries no role, so the
permission check could never be satisfied by one.

## Roles and permissions

Four roles, ordered. A role holds every permission of the roles beneath it.

```
owner  >  admin  >  member  >  viewer
```

| Permission | Minimum role |
|---|---|
| `org:read`, `agent:read`, `decision:read`, `audit:read`, `alert:read` | `viewer` |
| `decision:write`, `agent:write`, `policy:read`, `secret:use`, `policy:draft` | `member` |
| `approval:decide`, `policy:review`, `policy:write`, `member:manage`, `apikey:manage`, `alert:manage`, `secret:manage`, `invite:manage` | `admin` |
| `org:delete`, `billing:manage`, `policy:settings`, `sso:manage` | `owner` |

Three of those placements are deliberate and worth reading:

- **`policy:draft` is `member`, `policy:write` is `admin`.** Proposing a change
  is not the same authority as making one. A security engineer drafts; an admin
  approves and publishes.
- **`policy:settings` is `owner`.** Whether review is required at all, and how
  many approvals it takes, is the setting that governs everyone else's authority
  over policy.
- **`sso:manage` is `owner`.** An SSO connection decides who can obtain a
  session at all, which makes it strictly more powerful than member management:
  an admin who could point a connection at a directory they control could admit
  themselves as an owner by any other name.

**A role can only be granted by someone who holds it.** `member:manage`,
`apikey:manage` and `invite:manage` are all admin-level, and without this
ceiling each is privilege escalation with one extra step.

## Conventions

Every response is `application/json; charset=utf-8` with `x-content-type-options:
nosniff` and `cache-control: no-store`. Errors are `{ "error": "message" }`,
sometimes with extra fields.

| Status | Meaning |
|---|---|
| `200` / `201` / `204` | Success |
| `400` | Malformed body, or a validation failure |
| `401` | Missing or invalid credentials |
| `403` | Authenticated, but the role is insufficient. Body carries `required` |
| `404` | No such route, or no such resource in this tenant |
| `409` | Conflict — a stale version, or an unmet governance precondition |
| `413` | Body over 1 MiB |
| `429` | Rate limited. Body carries `retryInSeconds` |
| `503` | A subsystem is not configured (e.g. secrets without `CIRVIX_MASTER_KEY`) |

### Rate limiting

A **sliding window**, not a fixed one — a fixed window lets a caller spend the
full budget at the end of one window and again at the start of the next, so the
real ceiling is 2× the configured limit across the boundary.

| Bucket | Default | Keyed by |
|---|---|---|
| General | 600/min (`CIRVIX_RATE_LIMIT`) | API key id or session id |
| Login, SSO, invitations | 10/min | IP |
| SCIM | 600/min | SCIM token id |

Successful responses carry `x-ratelimit-remaining`. A refused request still
counts against the budget. `/v1/stream` is exempt — SSE connections are
long-lived and must not consume a request budget.

---

# Routes

## Public

| Method | Path | Notes |
|---|---|---|
| `GET` | `/health` | `{ status, version, uptime }` |
| `GET` | `/metrics` | Prometheus text. Requires a token if `CIRVIX_METRICS_TOKEN` is set; `503` if metrics are disabled |
| `POST` | `/v1/auth/login` | `{ email, password, orgId? }` → session |
| `POST` | `/v1/auth/refresh` | `{ refreshToken }` → session. `401` carries `reuseDetected` |
| `POST` | `/v1/auth/logout` | `{ refreshToken }` |
| `GET` | `/v1/auth/sso/discover?email=` | `{ sso: {…} \| null }` — always `200` |
| `POST` | `/v1/auth/sso/start` | `{ connectionId?, email?, redirectUri, inviteToken? }` |
| `POST` | `/v1/auth/sso/callback` | `{ state, code }` → session |
| `GET` | `/v1/invitations/peek?token=` | Reads an invitation without spending it |
| `POST` | `/v1/invitations/accept` | `{ token, password?, name? }` → session |

`/v1/auth/sso/discover` answers `200` whether or not a connection exists. A
`404` for "no SSO here" is an oracle for "which domains use this product",
walkable at network speed.

`redirectUri` must be in `CIRVIX_SSO_REDIRECT_URIS`. An unvalidated
`redirect_uri` is an authorization-code delivery service for whoever asks, and
"the identity provider will catch it" is not a control this side gets to rely
on.

### Session response

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…",
  "refreshToken": "cvr_9f2c…",
  "expiresIn": 900,
  "user": { "id": "usr_…", "email": "eng@example.com", "name": "Eng" },
  "org":  { "id": "org_…", "name": "Example", "role": "admin" },
  "orgs": [ … ]
}
```

## Organisation and members

| Method | Path | Permission |
|---|---|---|
| `GET` | `/v1/me` | `org:read` |
| `GET` | `/v1/org` | `org:read` |
| `GET` | `/v1/overview` | `org:read` |
| `GET` | `/v1/members` | `org:read` |
| `POST` | `/v1/members` | `member:manage` |
| `PATCH` | `/v1/members/:userId` | `member:manage` |
| `DELETE` | `/v1/members/:userId` | `member:manage` |
| `GET` | `/v1/subscription` | `org:read` |
| `POST` | `/v1/subscription` | `billing:manage` |

## Invitations and API keys

| Method | Path | Permission |
|---|---|---|
| `GET` | `/v1/invitations` | `invite:manage` |
| `POST` | `/v1/invitations` | `invite:manage` |
| `DELETE` | `/v1/invitations/:inviteId` | `invite:manage` |
| `GET` | `/v1/api-keys` | `apikey:manage` |
| `POST` | `/v1/api-keys` | `apikey:manage` |
| `DELETE` | `/v1/api-keys/:keyId` | `apikey:manage` |

`POST /v1/api-keys` returns the secret **once**. Only a SHA-256 hash is stored.

```bash
curl -X POST $CIRVIX_API/v1/api-keys \
  -H "authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"name":"ci","role":"member"}'
```

The `role` requested cannot exceed the caller's own.

## Single sign-on

| Method | Path | Permission |
|---|---|---|
| `GET` | `/v1/sso/connections` | `sso:manage` |
| `POST` | `/v1/sso/connections` | `sso:manage` |
| `PATCH` | `/v1/sso/connections/:connectionId` | `sso:manage` |
| `DELETE` | `/v1/sso/connections/:connectionId` | `sso:manage` |
| `GET` | `/v1/sso/identities` | `member:manage` |

OIDC only. Providers: `google`, `entra`, `okta`, and generic `oidc`. **SAML is
deliberately not implemented** — see [administration](./administration.md#single-sign-on).

Identity is `(issuer, subject)`, never email. An email address is a display
attribute that a directory administrator can reassign; treating it as identity
means reassigning an address hands over the account.

Role mappings cannot grant `owner`. A directory group must not be able to mint
an owner of your control plane.

## Directory provisioning (SCIM 2.0)

Authenticated by a `scim_` token, not a console credential.

| Method | Path |
|---|---|
| `GET` | `/scim/v2/ServiceProviderConfig` |
| `GET` | `/scim/v2/ResourceTypes` |
| `GET` `POST` | `/scim/v2/Users` |
| `GET` `PUT` `PATCH` `DELETE` | `/scim/v2/Users/:scimId` |
| `GET` `POST` | `/scim/v2/Groups` |
| `GET` `PATCH` `DELETE` | `/scim/v2/Groups/:groupId` |

Errors answer in SCIM's own envelope — an identity provider parses `detail` out
of them and shows it to whoever configured the integration, so a plain
`{ error }` body surfaces as "provisioning failed" with no reason attached.

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "404",
  "detail": "No such user."
}
```

Console-side management of provisioning:

| Method | Path | Permission |
|---|---|---|
| `GET` | `/v1/scim` | `sso:manage` |
| `POST` | `/v1/scim/tokens` | `sso:manage` |
| `DELETE` | `/v1/scim/tokens/:tokenId` | `sso:manage` |
| `POST` | `/v1/scim/settings` | `sso:manage` |
| `PATCH` | `/v1/scim/groups/:groupId` | `sso:manage` |

**Deprovisioning revokes sessions, not just membership.** Setting `active:
false` ends every session the user holds; removing the row while a 15-minute
access token is still live would leave a window after offboarding.

## Fleet

| Method | Path | Permission |
|---|---|---|
| `POST` | `/v1/endpoints` | `agent:write` |
| `GET` | `/v1/endpoints` | `agent:read` |
| `POST` | `/v1/endpoints/:endpointId/heartbeat` | `agent:write` |
| `GET` | `/v1/agents` | `agent:read` |
| `POST` | `/v1/agents` | `agent:write` |

An endpoint that stops heartbeating is marked `stale` and raises an
`endpoint_offline` alert — the failure mode that matters most, because it means
an agent may be running with no enforcement, and it is the one condition nothing
else can detect.

## Policy

| Method | Path | Permission |
|---|---|---|
| `GET` | `/v1/policy` | `policy:read` |
| `GET` | `/v1/policy/versions` | `policy:read` |
| `GET` | `/v1/policy/versions/:version` | `policy:read` |
| `POST` | `/v1/policy` | `policy:write` |
| `POST` | `/v1/policy/rollback/:version` | `policy:write` |
| `POST` | `/v1/policy/validate` | `policy:read` |
| `POST` | `/v1/policy/simulate` | `policy:read` |
| `GET` | `/v1/policy/settings` | `policy:read` |
| `POST` | `/v1/policy/settings` | `policy:settings` |

`POST /v1/policy` takes `{ rules }` and is structurally validated before
anything is written — publishing a malformed rule set fans it out to the entire
fleet. See [validation](./policy.md#validation).

```bash
curl -X POST $CIRVIX_API/v1/policy \
  -H "authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d @cirvix.policy.json
```

`POST /v1/policy/simulate` re-decides recorded traffic under a candidate rule
set without publishing it.

## Policy governance

The draft → review → publish workflow. Whether it is mandatory is a
`policy:settings` decision.

| Method | Path | Permission |
|---|---|---|
| `GET` | `/v1/policy/drafts` | `policy:read` |
| `POST` | `/v1/policy/drafts` | `policy:draft` |
| `GET` | `/v1/policy/drafts/:draftId` | `policy:read` |
| `PATCH` | `/v1/policy/drafts/:draftId` | `policy:draft` |
| `POST` | `/v1/policy/drafts/:draftId/submit` | `policy:draft` |
| `POST` | `/v1/policy/drafts/:draftId/review` | `policy:review` |
| `POST` | `/v1/policy/drafts/:draftId/publish` | `policy:write` |
| `POST` | `/v1/policy/drafts/:draftId/close` | `policy:draft` |
| `POST` | `/v1/policy/drafts/:draftId/comments` | `policy:draft` |
| `POST` | `/v1/policy/comments/:commentId/resolve` | `policy:draft` |
| `POST` | `/v1/policy/drafts/:draftId/simulate` | `policy:read` |

**Approvals are bound to a content hash.** Editing a draft after it is approved
un-approves it — otherwise "approved" means "approved at some point, contents
since unknown".

**One reviewer requesting changes is not outvoted.** A `changes_requested`
verdict blocks publication regardless of how many approvals follow it.

## Decisions and runs

| Method | Path | Permission |
|---|---|---|
| `POST` | `/v1/decisions` | `decision:write` |
| `GET` | `/v1/decisions` | `decision:read` |
| `GET` | `/v1/decisions/:decisionId` | `decision:read` |
| `POST` | `/v1/runs` | `decision:write` |
| `GET` | `/v1/runs` | `decision:read` |
| `GET` | `/v1/runs/:runId` | `decision:read` |
| `POST` | `/v1/runs/:runId/close` | `decision:write` |
| `POST` | `/v1/runs/:runId/replay` | `policy:read` |
| `GET` | `/v1/analytics` | `decision:read` |
| `GET` | `/v1/stream` | `decision:read` |

`GET /v1/decisions/:decisionId` is what `cirvix why` reads.
`POST /v1/runs/:runId/replay` is what `cirvix replay` calls; it takes an
optional `{ rules }` and **re-evaluates without re-executing anything**.

`replay` requires `policy:read` rather than `decision:read` because it accepts a
candidate rule set — it is a policy operation that happens to read decisions.

`GET /v1/stream` is Server-Sent Events, scoped to the caller's tenant.

## Approvals

| Method | Path | Permission |
|---|---|---|
| `GET` | `/v1/approvals` | `decision:read` |
| `POST` | `/v1/approvals` | `decision:write` |
| `POST` | `/v1/approvals/:approvalId/decide` | `approval:decide` |

Raising an approval is `decision:write` (an agent does it); deciding one is
`approval:decide`, admin-level. A forgotten approval expires rather than hanging.

## Secrets

Available only when `CIRVIX_MASTER_KEY` is set. Without it these routes are not
registered and the server says so on boot.

| Method | Path | Permission |
|---|---|---|
| `GET` | `/v1/secrets` | `secret:manage` |
| `POST` | `/v1/secrets` | `secret:manage` |
| `PATCH` | `/v1/secrets/:secretId` | `secret:manage` |
| `POST` | `/v1/secrets/:secretId/rotate` | `secret:manage` |
| `DELETE` | `/v1/secrets/:secretId` | `secret:manage` |
| `GET` | `/v1/secrets/handles` | `secret:manage` |
| `POST` | `/v1/secrets/handles` | `secret:use` |
| `POST` | `/v1/secrets/handles/revoke` | `secret:use` |
| `POST` | `/v1/secrets/resolve` | `secret:use` |
| `GET` | `/v1/secrets/usages` | `secret:manage` |

The split matters. `secret:use` (member) can request a handle and resolve it at
a sanctioned destination. `secret:manage` (admin) can store, rotate, and read
the usage log. An agent's credential holds the former only.

Handles are `sec_handle_…`. Resolution is refused, recorded, and alerted when the
destination is not one the secret sanctions — that is what exfiltration looks
like from here: the agent holds a capability and is trying to spend it off-path.

## Alerts

| Method | Path | Permission |
|---|---|---|
| `GET` | `/v1/alerts` | `alert:read` |
| `POST` | `/v1/alerts/:alertId/ack` | `alert:read` |
| `GET` | `/v1/alert-channels` | `alert:manage` |
| `POST` | `/v1/alert-channels` | `alert:manage` |
| `DELETE` | `/v1/alert-channels/:channelId` | `alert:manage` |
| `POST` | `/v1/alert-channels/:channelId/test` | `alert:manage` |
| `GET` | `/v1/alert-deliveries` | `alert:manage` |

Channel kinds: `slack`, `teams`, `webhook`, `email`. A `webhook` without a
supplied secret is given one (`whsec_…`) — a webhook that cannot be
authenticated by the receiver is a webhook anyone can forge.

Only the **origin** of a webhook URL is ever logged or returned; a webhook URL's
path is frequently the credential.

## Audit and compliance

| Method | Path | Permission |
|---|---|---|
| `GET` | `/v1/audit` | `audit:read` |
| `GET` | `/v1/audit/verify` | `audit:read` |
| `GET` | `/v1/compliance/frameworks` | `audit:read` |
| `GET` | `/v1/compliance/summary` | `audit:read` |
| `GET` | `/v1/compliance/report` | `audit:read` |
| `GET` | `/v1/compliance/package` | `audit:read` |
| `GET` | `/v1/export` | `audit:read` |

`GET /v1/export` emits decisions for SIEM ingest. CEF output is ArcSight-format
and is ingested by every SIEM without a custom parser.

Frameworks: `soc2`, `iso27001`. **No report claims compliance** — the coverage
vocabulary has no word for "pass", and a test enforces that. Out-of-scope
controls are listed as out of scope rather than omitted, because an auditor who
finds a gap you did not disclose stops trusting the parts you did.

---

## Errors worth recognising

| Situation | Status | Body |
|---|---|---|
| Wrong role | `403` | `{ error: "Role \"member\" cannot policy:write.", required: "admin" }` |
| Refresh token replayed | `401` | `{ error: "Session expired. Sign in again.", reuseDetected: true }` |
| Draft edited after approval | `409` | Publication refused; the draft is no longer approved |
| Reviewer requested changes | `409` | `A reviewer has requested changes on this revision.` |
| Handle spent off-path | `403` | Recorded as `destination_denied`, raises a high-severity alert |
| Secrets not configured | `503` | The route is absent; the server logs this on boot |

## CORS

Off unless `CIRVIX_CORS_ORIGIN` is set. When set, that exact origin is allowed
for `GET,POST,PATCH,DELETE,OPTIONS` with `authorization` and `content-type`.
There is no wildcard mode.
