# Security

The threat model this system is built against, the review it has had, and what
that review found.

Nothing here is a certification claim. `RELEASE.soc2` in `src/config/site.ts`
is `"not-started"` and stays that way until it is not.

---

## Threat model

### What is being protected

| Asset | Where it lives | Loss looks like |
|---|---|---|
| The rule set | `policy_versions` | An agent does something nobody authorized |
| The decision record | `audit_records`, `decisions` | Nobody can prove what happened |
| Secret material | `secrets`, sealed | A credential reaches a model's context |
| Tenant boundary | every `org_id` predicate | One customer reads another's fleet |
| Session and key material | `sessions`, `api_keys`, hashed | Impersonation |

### Who the adversary is

Four, in descending order of how much this system is designed around them:

1. **A compromised or prompt-injected agent.** Holds an endpoint API key,
   controls the *arguments* of every tool call, and is trying to read a
   credential, reach outside its workspace, or get material off the machine.
   This is the adversary the product exists for.
2. **An authenticated principal of one tenant** — member, admin, or a stolen
   API key — trying to exceed their role or reach another tenant.
3. **An unauthenticated network attacker** with reachability to the control
   plane: brute force, replay, enumeration, denial of service.
4. **An insider with database read access.** Cannot obtain a usable credential
   from it: keys, refresh tokens, invitation tokens, and secret handles are all
   stored hashed, and secret values are sealed under a key that is not in the
   database.

### Explicitly out of scope

Stated so nobody mistakes silence for coverage:

- **Root on the endpoint.** The gateway holds resolved secret material in
  process memory for the life of a request. A machine compromised at root is
  outside any userspace product's threat model.
- **A malicious operator of the control plane.** Someone who can edit the
  database and recompute the audit chain can rewrite history. The chain proves
  tampering to anyone who kept an earlier head, not to someone who did not.
- **The identity provider.** If a directory account is compromised, the
  approval authority attached to it is compromised. Cirvix does not replace an
  IdP.
- **Network egress policy.** SSRF defences here raise the cost of the easy
  attack; a control plane that cannot route to `169.254.169.254` is the durable
  control.

---

## Review, 2026-08-07

Adversarial, against the running system. Every attack below is a test in
`packages/control-plane/test/security.test.mjs`, written from the attacker's
side so it fails loudly if the property regresses.

### Found and fixed

**1 · Privilege escalation: any admin could become an owner.** *(critical)*

Four routes assigned a role without checking the caller held it. The cleanest
path was one request:

```
POST /v1/api-keys  {"name":"x","role":"owner"}   → an owner-scoped credential
```

`POST /v1/members`, `PATCH /v1/members/:id`, and `POST /v1/invitations` were
the same bug wearing different hats — an admin could create an owner account
with a password they chose, promote themselves, or invite themselves back at an
address they controlled. Owner controls billing, tenant deletion, and SSO
connections, so this was a full compromise of a tenant by any of its admins.

Fixed with a ceiling: a role can only be granted by someone who holds it, and
a member who outranks you cannot be demoted or removed by you. Owners can still
grant owner — it is a ceiling, not a ban.

**2 · Unauthenticated denial of service: a `null` body hung the connection.**
*(high)*

`JSON.parse("null")` returns `null`, and `null` was also the dispatcher's
sentinel for "a body error has already been reported". So a body of literally
`null` made the request handler **return without writing a response**, and the
socket stayed open until the peer gave up. It worked on `/v1/auth/login`, so it
needed no credentials, and each request cost the attacker nothing while holding
one of the server's connections.

Fixed by removing the ambiguity: body parsing signals failure by control flow,
never by a value a client can also send, and any non-object body normalizes to
`{}`.

**3 · ReDoS in the policy engine.** *(high)*

Globs compiled to a backtracking regular expression. `*a*a*a*a*b` against a
long run of `a` is exponential — a fuzz test written for this hung the test
runner for ten minutes before it was killed. The pattern comes from a rule and
the *input* comes from whatever resource an agent named, so the party choosing
the pathological input is on the far side of the enforcement boundary, and a
hung evaluator is a hung gateway.

Fixed by replacing the regex with a two-pointer wildcard matcher: O(n·m) worst
case, no pathological input. Semantics are unchanged and covered by tests.

**4 · Server-side request forgery via alert webhooks and SSO issuers.**
*(high)*

Both take a URL from a tenant and fetch it server-side. An admin could point a
webhook at `http://169.254.169.254/latest/meta-data/…` and make the control
plane call cloud instance metadata, the Kubernetes API, or any internal service
it can reach.

Fixed with an outbound guard (`src/egress.mjs`) that resolves the destination
and refuses loopback, link-local, private, CGNAT, multicast, and reserved
ranges, checked on **every** request rather than once at configuration time.
`CIRVIX_ALLOW_PRIVATE_EGRESS=1` opts a self-hosted deployment back in.

The first implementation had a bypass its own test caught:
`http://[::ffff:169.254.169.254]/` is normalized by the URL parser to
`[::ffff:a9fe:a9fe]`, which a dotted-quad string check passes straight through.
Rebuilt on `node:net`'s `BlockList`, which compares numerically and resolves
IPv4-mapped IPv6 against the IPv4 rules.

**5 · Rate limiting doubled at the window boundary.** *(medium)*

The limiter was a fixed window, so a caller could spend the full budget at the
end of one window and again at the start of the next — twenty password attempts
a minute where ten were configured, at a moment findable from the
`x-ratelimit-remaining` header. Replaced with a sliding-window counter;
refused requests still count toward the total.

**6 · Mutations reported success for things that did not happen.** *(medium)*

`DELETE /v1/members/:id` and `PATCH /v1/members/:id` returned 200 when the id
belonged to another tenant or to nobody — the `org_id` predicate correctly
matched zero rows, and zero rows was reported as success. No data crossed a
boundary, but "I revoked their access" was false, which matters during an
incident. Both now 404.

**7 · A non-string `email` produced a 500.** *(low)*

`{"email":{"$ne":null}}` reached `email.toLowerCase()`. Not injection — the SQL
layer is parameterized throughout — but an unhandled error where a 400 belongs.
Fixed at the route (typed validation) and in the store (coercion), because the
storage layer should not throw whatever reaches it.

**8 · Attacker-authored text rendered in the product's own chrome.** *(low)*

`/dashboard/sso/callback` rendered `error_description` straight from the query
string. React escapes it, so not script injection — but anyone can send a
victim to that URL with any sentence they like and have it appear inside
Cirvix's own UI, which is a phishing primitive. Now only the provider's
machine-readable error code is shown, character-filtered.

### Checked, no finding

- **SQL injection** — every statement is prepared; no query is built by
  interpolation. Verified by grep and by driving metacharacter payloads through
  every write path.
- **Tenant isolation** — `orgId` is read only from the authenticated principal
  and never from a body, query, or path, so the parameter that would allow
  cross-tenant addressing does not exist in the routing layer. Eighteen read
  routes asserted against a second tenant's canary data.
- **JWT** — algorithm pinned to HS256 and everything else refused, including
  `none` and asymmetric confusion; signature compared in constant time;
  expiry enforced; session revocation and role membership re-read from the
  database on every request, so a forged `org` or a borrowed `sid` fails.
- **Session handling** — refresh rotation with reuse detection that revokes the
  whole descendant family; logout invalidates the access token immediately
  rather than at expiry; no session fixation (every issue mints a new id).
- **Enumeration** — one message for every login failure mode; unknown and
  cross-tenant secret handles are indistinguishable; SSO discovery returns the
  IdP vendor's name and never the tenant's.
- **Timing** — password verification burns comparable time for an unknown user;
  all secret comparisons are `timingSafeEqual`; keys, tokens, and handles are
  looked up by hash.
- **Cryptography** — AES-256-GCM with the tenant and secret id as additional
  authenticated data, so a ciphertext cannot be moved between rows or tenants;
  scrypt (N=2¹⁵) for passwords; SHA-256 hash chain over canonical JSON for the
  audit record.
- **Fuzzing** — eighteen malformed bodies (including prototype-pollution and
  NoSQL-operator shapes) against fifteen mutating routes, plus random bytes at
  the public routes. No 500s, no pollution, chain still verifies.
- **CSRF** — not applicable by construction: authentication is `Authorization`
  bearer only, never a cookie, so a cross-site request carries no credential.
  CORS sends no `access-control-allow-origin` unless one is configured.
- **XSS** — no `dangerouslySetInnerHTML` anywhere; React escaping is the
  primary control.

### Accepted, with the trigger written down

- **`script-src 'unsafe-inline'`** in the CSP. Next's App Router streams its
  flight payload as inline scripts; nonces would make every static page a
  per-request render. The reasoning is recorded in full in `next.config.ts`,
  including the fact that the original justification ("no user-generated
  content, no reflected parameters") expired when the console arrived. Revisit
  on the first `dangerouslySetInnerHTML` over untrusted input or the first
  third-party script origin.
- **DNS rebinding against the egress guard.** A name can resolve public at
  check time and private when the socket opens. Closing it needs the resolved
  address pinned into the connection, which Node's `fetch` does not expose.
  Network egress policy is the durable control.
- **`sharp`, 3 high advisories** (transitive, via `next`). The fix is
  `next@16.3.0`, outside the stated range. Not on the attack path here: there
  is no `next/image` usage and no image-optimization configuration, so the
  vulnerable code is never invoked. Revisit at the next Next upgrade.
- **`node:sqlite` is experimental.** Confined to `src/db/index.mjs`; the schema
  is portable SQL.

### Dependencies

The two shipped packages have **zero** runtime npm dependencies —
`@cirvix/control-plane` depends only on `@cirvix/agent-control`, which depends
on nothing. The audit surface is the website's build-time tree.

---

## Review, 2026-08-13 — cross-boundary identity

Scoped to `@cirvix/agent-control`, and specifically to what happens when
authority crosses a **transport** as well as an agent:

```
A ──delegation──▶ B ──MCP──▶ C ──delegation──▶ D ──▶ tool
```

The invariant under test:

> Identity, delegation, policy, and approval must all describe the same
> operation.

Four subsystems each answer a different question — who is calling, what were
they lent, what is permitted, and who said yes. The system is secure when all
four answers refer to one operation, so every attack tries to make two of them
refer to different ones.

37 attacks in `packages/agent-control/test/adversarial/cross-boundary.test.mjs`.
**16 landed on first run.** Four defects, all now fixed and each covered by the
attack that found it.

### Found and fixed

**1 · A2A delegation was unenforced on every transport.** *(critical)*

`Pipeline.submit()` accepted a presented grant and narrowed by it. Nothing else
did:

| Surface | Reaches | Delegation |
|---|---|---|
| `Pipeline.submit()` | direct calls, unit tests | enforced |
| `UdsServer` → `Pipeline` | the local socket, the daemon | **field dropped** |
| `Gateway` → `Guard` | MCP | **no such concept** |
| `guard.wrap()` → `Guard` | the SDK | **no such concept** |

The UDS handler built its context as `{ agent, source, environment }` and never
forwarded `params.delegation`. `Guard` — the shared decision core behind both
MCP and the SDK — contained no reference to delegation at all. So the feature
was reachable only from a unit test: **there was no path in the product through
which a delegation could actually be presented.**

The failure direction is what makes this critical rather than cosmetic.
Delegation only ever *narrows*, so a surface that ignores it does not lose a
feature — it grants everything policy allows. A worker delegated `fs.read` got
full database authority the moment its call arrived over MCP instead of the
socket, and the audit record showed an ordinary permitted write with no chain
on it. Presenting a grant is the only way an agent can ask to be held to *less*
than policy permits, and the request was being discarded.

This is the third instance of one shape in this codebase — risk rules that
fired over the socket and never over MCP, an approval feature with no release
path, and now this. So the fix is structural rather than local: `applyDelegation`
in `core/delegation.mjs` is a single implementation that both engines call, and
a test asserts `Guard` and `Pipeline` return the same rule for the same call.
Identity now travels over MCP in `params._meta.cirvix` — the protocol's own
extension point — on `tools/call` and on `resources/read`, because the second is
the same operation wearing a different method name.

**2 · Cross-tenant delegation was recorded, not refused.** *(high)*

`acme-planner` could delegate to `globex-worker`. The grant was signed, the
scope narrowed correctly, tenancy was inherited from the parent, and the audit
record honestly showed acme's tenancy on a globex agent's call. Every check
passed, and one customer's agent ended up acting inside another customer's
authority.

`DELEGATION_ERROR.UNKNOWN_TENANT` had been declared from the start and was
**never raised anywhere in the codebase** — the error code for this existed and
the check did not. The pre-existing test asserted the weaker property, that the
cross-tenant delegation *resolved* and was visible in the log. A record of a
breach is not a control against one.

Fixed by learning each agent's tenancy from its root grant and refusing a
mismatch at both issue and presentation — twice, because tenancy can be
registered *after* a grant is minted. Re-rooting a known agent into a second
tenant now throws, since that is the same escalation written as configuration.

Deliberately **not** refused: an agent with no registered tenancy. Delegating to
an agent that has no root of its own is the ordinary case — a planner spawning a
helper — and refusing it would break normal single-tenant use to defend a
boundary nobody crossed. It also defends nothing, because presenting a grant
requires being its signed subject, so an invented agent name is only usable if
someone inside the tenant already minted a grant for it.

**3 · Approval laundering across delegation chains.** *(high)*

`approvalFingerprint` bound an approval to agent, action, resource, command, and
arguments — but not to the chain of custody. An operator approves a database
write having been shown `planner → worker`; the same call then arrives under
`planner → attacker → worker` and spends it. Identity is satisfied, the chain
narrows correctly, policy asked for an approval and got one — four subsystems
agreeing about four different operations.

The inverse mattered equally: obtain the approval under a narrow delegation,
then present none at all. Without a delegation the call is governed by policy
alone, which is *wider*, so the yes was released into a larger authority than
the one it was granted under.

Fixed by including the resolved principal chain in the fingerprint. `null` for a
call made with no delegation, so single-agent deployments are byte-identical.

**4 · Secret handles had no subject binding.** *(high)*

`Vault#authorize` checked expiry, use count, and destination. It never checked
*who was spending the handle*.

A handle is deliberately not a secret — that is the entire design. It travels in
arguments, is printed in audit records, is safe to paste into a ticket, and can
come back inside a tool result another agent reads. Without a subject check, a
handle appearing in any shared surface **is the credential, laundered**: every
property the vault claims still holds, for the wrong agent. `payments-agent`
holds the Stripe key; `summariser` reads a transcript containing
`sec_handle_01` and charges cards.

Fixed with an opt-in per-handle `subject`, enforced in `Vault#authorize` and
supplied by both engines as the calling agent. Binding is per handle because a
single-agent install has no boundary to enforce and must not be made to declare
one. A delegation of *action* explicitly does not carry credential ownership
with it — otherwise every delegation quietly hands over every key the issuer
holds.

### Attacked and already correct

Recorded because a passing attack is evidence, not a non-event: forged issuer,
forged subject, swapped parent (chain re-parenting onto a richer root), spliced
signature from a sibling grant, id-collision grants, revoked parent mid-chain,
stale child outliving a lapsed parent, upward revocation, depth exhaustion past
`MAX_DEPTH`, circular delegation, policy reload in both directions, process
restart, and approval replay after revocation. All refused before the fixes and
after them.

### Known limits, stated rather than implied

- **A grant has no server axis.** It constrains actions and resources, so a
  grant for `fs.read` on `**` works against any MCP server exposing a read
  tool. Confining an agent to one server is the resource glob's job or policy's,
  not the grant's. Both the limit and its mitigation are asserted as tests so
  the guidance is checkable rather than advisory.
- **`_meta.cirvix.agent` is a self-asserted label.** It selects which
  agent-scoped rules apply and which handles resolve; it grants nothing, because
  nothing is granted *by* a name. In a hostile multi-agent deployment, rules
  keyed on agent identity need a signed grant behind them. Suitable for
  attribution, not for authorization.
- **Grants are local to one runtime.** The signing key is per-process, so two
  Cirvix instances cannot verify each other's grants, and a restart invalidates
  every outstanding delegation. That is the safe direction — a grant cannot
  outlive the process that could revoke it — and fleet-wide issuance is the
  control plane's job.

---

## Review, 2026-08-13 — commercial controls and install path

The security engine can be perfect while the entitlement system is completely
bypassable. Those are independent properties, and until now only one had been
attacked.

### The entitlement system, stated plainly

`subscriptions(org_id, plan, seats, status)`, `GET/POST /v1/subscription`, and a
seat check. **That is all of it.** There is no metering, no usage quota, no
overage, no license, and no payment integration anywhere in this repository.

Kill-tests are in `packages/control-plane/test/entitlements.test.mjs`. They split
deliberately into controls that exist and controls that do not, because a gap
nobody has written down is a gap a customer discovers.

**Found and fixed — over-seating by mixing two paths.** *(medium)*

The two endpoints counted seats differently:

```
POST /v1/invitations    members + pending  >= seats    → refuses
POST /v1/members        members            >= seats    → refuses
```

The invitation path deliberately counted outstanding invitations; the direct-add
path did not count them at all. So a seat claimed by an invitation was invisible
to the path that never looked for it: on a two-seat plan, hold the last seat with
an invitation, add a member directly into it, and the org exceeds its plan the
moment the invitee accepts. One resource, two counters, and the lower one wins.
Both paths now call one `seatsInUse()`.

Attacked and already correct: a member-scoped key cannot raise its own seat
count, and concurrent adds cannot both take the last seat — `node:sqlite` is
synchronous and the check-then-write is not interleaved.

### Absent controls — two of these have since been built

Each had a test asserting the behaviour at the time, with the instruction to
invert the test once the control existed. **Re-verified 2026-08-21; the first
two are now built and the entries are kept rather than deleted, because a
reader who saw the earlier version is entitled to know what changed.**

- **~~A cancelled or past-due subscription authorizes everything.~~ BUILT.**
  `billingState()` in `store-sql.mjs` is the single answer to "is this customer
  paid up", and it is called in the central request dispatcher rather than on
  one route, so every authenticated permission-bearing request passes through
  it. `active` and `trialing` entitle writes; anything else answers `402` with
  the status, the reason and the period end. The read-only grace was built as
  specified — reads and the billing routes stay reachable, so a lapsed card
  never costs a customer access to their own audit history, and they can always
  reach the page that fixes it. A null period end reads as fine rather than as
  expired, so deploying it cannot lock out tenants predating the column.
- **~~Usage is unmetered, so a fixed-price plan has no ceiling.~~ BUILT.**
  `POST /v1/decisions` checks `usageState` before the batch and answers `402`
  with the reset hint when the plan's daily allowance is spent. The limit is
  checked before the batch rather than per decision, because refusing halfway
  through would leave the caller unable to say what was stored. The
  transactional requirement was honoured: `recordDecision` meters inside the
  same statement path as the insert and only when the insert actually wrote, so
  a replayed batch counts once and the boundary race the note warned about does
  not exist.

  The local engine is metered separately and on different terms. See the note
  below.
- **Plan changes need no payment and do not reconcile.** `POST /v1/subscription`
  is the entire commercial surface. Downgrading does not reconcile existing
  members against the new seat count; a 25-seat org drops to 2 seats and keeps
  all 25, with only the next add refused.
- **A local licence file now exists, and it is honour-system by design.**
  The engine reads `.cirvix/licence.json` and meters against `.cirvix/meter.json`
  on the user's own machine. Both are editable by whoever owns the machine, the
  source says so in as many words, and the Apache 2.0 licence on the engine
  explicitly permits modifying them. "Modified local licence", "replayed
  licence" and "clock manipulation" are therefore not defended against and are
  not claimed to be.

  This is deliberate rather than unfinished. The local counter exists because
  the prompt at the limit is the conversion moment, not because it is a control.
  Everything that genuinely cannot be faked locally — shared policy, team
  approvals, the org vault, hosted audit retention and export — is enforced by
  the control plane, on the far side of a boundary that editing a JSON file does
  not reach. Anyone reading this to decide whether the free tier can be abused
  should read it as: yes, trivially, and the business does not depend on it not
  being.

### Install path — clean-machine gate

Verified in a stock `node:24-slim` container with **no repository present**, from
a packed tarball, and separately on Windows into an isolated npm prefix.

`npm install -g` → `cirvix init` → `cirvix status` works end to end on both.
`init` writes `cirvix.policy` (42 rules, 10 tests) and a hash-chained audit log,
detects Claude Code's config on Windows, and refuses to edit an editor config on
the user's behalf. Exit codes carry meaning: 0 permitted, 1 denied, 2 misuse —
so `cirvix check … || fail` behaves in CI.

**Found and fixed — the binary reported a version npm had never published.**
`bin/cirvix.mjs` hardcoded `"0.2.0"` while `package.json` said `0.1.0`, and the
MCP `serverInfo` hardcoded it a third time. Both now read the manifest, so the
first bug report cannot cite a release that does not exist.

### MCP client compatibility

`packages/agent-control/test/mcp-compat.test.mjs` — 12 tests covering what real
clients do that a mock does not: version negotiation, `notifications/initialized`
answered with silence, `ping`, `resources/templates/list`, `inputSchema` on every
advertised tool, unknown methods, `_meta` namespaces owned by other tools,
upstream stderr under load, and concurrent id routing.

**Found and fixed — `ping` was forwarded upstream and answered `-32601`.** It
fell through to the default branch, which forwards to the first live upstream;
an upstream that does not implement `ping` returns "Method not found", and a
client using ping as a liveness probe reads that as a dead server and tears down
the session. A healthy Cirvix presented as a crash. It is also the wrong question
to forward — ping asks whether the thing the client is connected to is alive, and
that is the gateway. Answered locally now.

---

## Reporting

Email `security@cirvix.com`. Please include a proof of concept. There is no
bounty programme yet, and we will say so rather than let you assume otherwise.
