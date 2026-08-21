# Administrator guide

For whoever owns a Cirvix tenant: roles, access, policy governance, secrets,
alerting, and audit evidence.

Assumes a control plane is already running — see [Deployment](./deployment.md).

## Roles

Four, ordered. A role holds every permission of the roles beneath it.

| Role | Holds |
|---|---|
| `viewer` | Read the org, agents, decisions, audit, alerts |
| `member` | The above, plus record decisions, register agents, read policy, use secrets, draft policy |
| `admin` | The above, plus decide approvals, review and publish policy, manage members, API keys, alerts, secrets, invitations |
| `owner` | Everything, plus billing, org deletion, policy settings, SSO and SCIM |

### Three placements worth understanding

**Drafting is `member`; publishing is `admin`.** Proposing a change is not the
same authority as making one. A security engineer drafts; an admin approves and
publishes.

**Policy settings are `owner`.** Whether review is required at all, and how many
approvals it takes, is the setting that governs everyone else's authority over
policy. An admin who could turn review off has no meaningful review.

**SSO is `owner`, not `admin`.** An SSO connection decides who can obtain a
session at all, which makes it strictly more powerful than member management: an
admin who could point a connection at a directory they control could admit
themselves as an owner by any other name.

### The grant ceiling

**A role can only be granted by someone who holds it.** Without this,
`member:manage` and `apikey:manage` — both admin-level — are privilege
escalation with one extra step: an admin mints an owner-scoped API key, or
promotes themselves, or invites themselves back at an address they control as an
owner.

It is a ceiling, not a ban. An owner can still grant owner, deliberately.

## Members, invitations, API keys

**Invitations** carry the role they will grant, and that role is capped by the
inviter's. An invitation to a domain claimed by an SSO connection can only be
accepted through the provider, so a tenant does not accumulate credentials that
bypass its own MFA and offboarding.

**API keys** are `cvx_…`, shown once, stored as SHA-256. Give an endpoint daemon
a `member` key — it needs `decision:write` and `agent:write`, nothing more. A key
scoped `admin` on a laptop is an admin credential on a laptop.

```bash
curl -X POST $CIRVIX_API/v1/api-keys \
  -H "authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"name":"laptop-fleet","role":"member"}'
```

Revoking a key takes effect immediately; there is no cache.

**Sessions** are a 15-minute access token plus a 30-day rotating refresh token.
A revoked session stops authenticating at once — a validly-signed access token
whose session was revoked is refused, or logout would do nothing for up to
fifteen minutes, which is exactly when it matters.

Changing a password terminates every session that user holds.

## Single sign-on

Optional, per organisation, configured by an **owner** in **Settings → Single
sign-on**. Google Workspace, Microsoft Entra ID, Okta, and any compliant OpenID
Connect provider.

One control-plane setting is needed first — where the provider is allowed to
send the browser back to:

```bash
CIRVIX_SSO_REDIRECT_URIS=https://console.example.com/dashboard/sso/callback
```

An unregistered redirect URI is refused. The provider holds an allowlist too,
but provider allowlists are routinely registered with a wildcard path, and that
is not a control this side gets to rely on.

**What to register with the provider.** An authorization-code client with the
redirect URI above, exactly — including the scheme and with no trailing slash.
The console prints the string to copy.

**What to enter in the console.** Whatever the provider's admin screen gave you;
the issuer is derived:

| Provider | You enter | Issuer becomes |
|---|---|---|
| Google Workspace | your domain (for reference) | `https://accounts.google.com` |
| Microsoft Entra ID | directory (tenant) ID | `https://login.microsoftonline.com/<id>/v2.0` |
| Okta | `acme.okta.com` | `https://acme.okta.com/oauth2/default` |
| Other | the full issuer URL | as entered |

**Group claims.** Role mapping reads a claim from the ID token. Neither Entra
nor Okta emits groups by default:

- **Entra** — app registration → *Token configuration → Add groups claim*. Emit
  **group names** rather than object ids, or your mapping values must be GUIDs.
- **Okta** — add a `groups` claim to the authorization server, filtered to the
  groups you intend to map.
- **Google** — emits no group claim. Use the connection's default role.

### Four behaviours to know before switching it on

1. **Identity is `(issuer, subject)`, not the email address.** A renamed address
   stays the same person. An address released and reassigned to somebody new is
   refused rather than linked, and needs an administrator to remove the old
   member first.
2. **An unverified email provisions nothing.** If the provider does not assert
   `email_verified`, sign-in is refused rather than trusted.
3. **A directory group cannot grant `owner`.** Owner controls billing and
   deletion; it is granted by an owner, in the console. The directory also
   cannot *remove* it, or a group change would lock a tenant out of itself.
4. **A federated domain gets no passwords.** See invitations above.

**SAML is not implemented.** Google, Entra, and Okta all provide OIDC natively,
which is what this build speaks. The connection model carries a `protocol`
column and a SAML connection is **refused with that reason** rather than
accepted and quietly ignored.

## Directory provisioning (SCIM 2.0)

Optional, per organisation, configured by an **owner** in **Settings → Directory
provisioning**. Joiners get accounts without anyone asking; leavers lose access
without anyone remembering.

Two values go into the provider:

| | |
|---|---|
| Tenant URL | `https://api.example.com/scim/v2` |
| Secret token | created in the console, shown once |

**The token is not a console key.** It authenticates `/scim/v2` and nothing
else — an owner API key cannot drive provisioning, and a provisioning token
cannot read a decision, publish a policy, or resolve a secret. Whoever
administers your directory ends up holding it, and they should not thereby hold
the console. A test enforces this separation.

**Supported:** `/Users` and `/Groups` with create, read, list (filtered on
`userName`, `externalId`, `displayName`), replace, patch, and delete;
`/ServiceProviderConfig` and `/ResourceTypes` for discovery.

### Four behaviours to know

1. **Deprovisioning ends sessions, not just membership.** `active: false`
   removes the membership *and* revokes every access and refresh token that user
   holds. Removing membership alone would leave a leaver with a working refresh
   token for thirty days.
2. **A group grants nothing until you say what it means.** Groups sync in with
   no role. An owner assigns one in the console, and `owner` is not on the list.
3. **A deprovisioned user is deactivated, not deleted.** Audit records name
   them; deleting the row would turn a year of evidence into dangling
   references.
4. **The directory cannot remove the last owner.** That request is refused with
   a `409` the provider surfaces, so a directory misconfiguration cannot lock an
   organisation out of itself.

Every provisioning action is written to the audit chain, attributed to
`scim:<token name>`.

## Policy governance

The draft → review → publish workflow. Whether it is mandatory, and how many
approvals a publish needs, is a `policy:settings` (owner) decision.

```
draft ──submit──▶ in review ──approve×N──▶ publish ──▶ live version N+1
   ▲                    │
   └── edit (un-approves) ┘
```

| Step | Permission | Endpoint |
|---|---|---|
| Create / edit a draft | `policy:draft` (member) | `POST` / `PATCH /v1/policy/drafts` |
| Submit for review | `policy:draft` | `POST /v1/policy/drafts/:id/submit` |
| Approve or request changes | `policy:review` (admin) | `POST /v1/policy/drafts/:id/review` |
| Publish | `policy:write` (admin) | `POST /v1/policy/drafts/:id/publish` |
| Roll back | `policy:write` | `POST /v1/policy/rollback/:version` |

### Two rules that make review mean something

**Approvals are bound to a content hash.** Editing a draft after it is approved
un-approves it. Otherwise "approved" means "approved at some point, contents
since unknown", which is not a control.

**One reviewer requesting changes is not outvoted.** A `changes_requested`
verdict blocks publication regardless of how many approvals follow. One reviewer
saying "not like this" is not outvoted by three people saying "fine".

### Before you publish

Simulate against recorded traffic:

```bash
curl -X POST $CIRVIX_API/v1/policy/drafts/$DRAFT/simulate \
  -H "authorization: Bearer $TOKEN"
```

Or replay one recorded run against the candidate:

```bash
cirvix replay run_01JQ8F2K7M --policy candidate.json --diff
```

Rolling back publishes the old version as a **new** version rather than
rewinding, so the history stays append-only and an auditor can see that a
rollback happened.

## Secret brokering

Optional. Without `CIRVIX_MASTER_KEY` the control plane runs normally — policy,
telemetry, approvals, and audit are unaffected — and the secret routes are not
served.

### The model

An agent never holds a credential. It holds a **handle** (`sec_handle_…`),
which is opaque and useless anywhere the secret does not sanction. The real
value is substituted into the outbound request at the gateway, *after* policy
authorized that destination, and scanned for on the way back.

```bash
curl -X POST $CIRVIX_API/v1/secrets \
  -H "authorization: Bearer cvx_..." -H "content-type: application/json" \
  -d '{"name":"STRIPE_RESTRICTED_KEY","value":"rk_live_...","destinations":["api.stripe.com"]}'
```

`secret:use` (member) can request and spend a handle. `secret:manage` (admin)
can store, rotate, and read the usage log. An agent's credential holds the
former only.

### Three things to know before enabling it

1. **Losing the key loses every secret.** Values are sealed with AES-256-GCM
   under a key derived from `CIRVIX_MASTER_KEY`. There is no recovery path and
   deliberately no escrow — back the key up wherever you keep the JWT secret,
   and never in the same place as the database.
2. **Rotating the key invalidates every stored value.** Ciphertext sealed under
   the old key will not open under the new one. Plan it as a maintenance window,
   not a config change.
3. **A secret with no destinations resolves nowhere.** The allowlist is
   fail-closed, and issuing a handle against an unscoped secret is refused at
   issue time rather than silently at use time.

A handle presented for a destination its secret does not sanction is refused,
recorded as `destination_denied`, and raises a **high-severity** alert. That is
what exfiltration looks like from here: the agent holds a capability and is
trying to spend it off-path.

Reading a secret taints the session (`session.touchedSecret`). Spending a handle
does **not** — the agent never held the material, which is the entire point.

Review spending at `GET /v1/secrets/usages`.

## Alerting

Channels: `slack`, `teams`, `webhook`, `email`.

```bash
curl -X POST $CIRVIX_API/v1/alert-channels \
  -H "authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"kind":"slack","target":"https://hooks.slack.com/services/..."}'
```

A `webhook` with no supplied secret is given one (`whsec_…`) — a webhook the
receiver cannot authenticate is a webhook anyone can forge. Only the **origin**
of a webhook URL is ever logged or returned; the path is frequently the
credential.

Test a channel before relying on it: `POST /v1/alert-channels/:id/test`.

### What raises an alert

| Kind | Severity | Raised when |
|---|---|---|
| `tampering` | critical | An audit chain fails verification |
| `endpoint_offline` | high | An endpoint stopped heartbeating |
| `suspicious_activity` | high | A denial on a credential/egress/escalation rule, or a handle spent off-path |
| `denied_call` | medium | An ordinary denial |
| `policy_violation` | low | A handle expired or was exhausted |

Severity escalates on the rules that only fire when something is actually
reaching for credentials. A single denial is routine; a burst is the signal.

A permanently dead host raises one `endpoint_offline` alert, not one per sweep.

## Compliance evidence

```bash
curl -s "$CIRVIX_API/v1/compliance/report?framework=soc2&since=2026-01-01" \
  -H "authorization: Bearer $TOKEN"
```

Frameworks: `soc2`, `iso27001`. Also available as CSV, Markdown, and a full
package.

**No report claims compliance.** The coverage vocabulary has no word for
"pass", and a test enforces that. What a report says is what evidence exists: a
control is `covered`, `partial`, or `not-covered` by observable configuration
and audit records.

**Out-of-scope controls are listed as out of scope** rather than omitted. An
auditor who finds a gap you did not disclose stops trusting the parts you did.

## Fleet hygiene

An endpoint that stops heartbeating is the failure mode that matters most: it
means an agent may be running with **no enforcement**, and it is the one
condition nothing else can detect, because the endpoint cannot report that it
stopped reporting.

Watch `cirvix_endpoints{state="stale"}` and treat a sustained non-zero as an
incident, not a warning. See [Operations](./operations.md#monitoring).

## Verifying the record

```bash
curl -s $CIRVIX_API/v1/audit/verify -H "authorization: Bearer $TOKEN"
# {"ok":true,"records":43675}
```

Verification proves records were not altered after they were written. It does
not attest to their content, and it does not prevent destruction — someone with
disk access can delete the file. The chain guarantees that doing so is
*visible*.

The control plane sweeps every tenant's chain and raises a `critical` alert on a
break. Tamper-evidence is only useful if someone is told.
