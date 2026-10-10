# Security Invariants

The properties this package is supposed to hold, stated so they can be
checked. Every invariant here has at least one test that fails if the code
stops holding it; the registry exists so that a reviewer can ask "which
invariant does this change touch?" instead of re-deriving the threat model
from scratch each time.

An invariant that is aspirational — wanted but not yet true — is not listed
here. The roadmap at the bottom tracks those.

## INV-001 — One decision path, and it default-denies

`Guard.authorize`, the MCP gateway and the local socket answer "may this agent
do X" through ONE engine. Policy evaluation is deterministic, forbidden
outcomes short-circuit, `hold` beats `permit`, and an unmatched call is
DENIED. A surface that can permit what the engine would deny is a bypass, not
a feature.

*Tests:* `test/conformance.test.mjs`, `test/e2e-mcp.test.mjs`,
`test/guard.test.mjs`.

## INV-002 — Delegation only narrows

`child authority ⊆ parent authority` at every hop of a delegation chain. A
delegation is a constraint ANDed with policy, never a grant ORed with it; a
scope that widens is refused at issue time and at presentation time. The
effective authority of a chain is the intersection of every link.

*Tests:* `test/adversarial/cross-boundary.test.mjs`.

## INV-003 — Authority is subtractive

Missions, capabilities and constraints can only take away what policy already
allows. Nothing an agent presents — passport, delegation, mission — can make a
denied call permitted. A refused call is never charged to a mission budget, or
every constraint becomes a denial-of-service against the agent's own work.

*Tests:* `test/mission-security.test.mjs`.

## INV-004 — Every decision is recorded, and an unrecordable permit is refused

Decisions append to a hash-chained journal. If the journal cannot be written,
a PERMIT is downgraded to a refusal; a deny is still recorded best-effort. No
call executes without its record existing first.

*Tests:* `test/audit.test.mjs`, `test/hook-fail-closed.test.mjs`.

## INV-005 — Secrets are brokered as handles

Policy decisions and audit records reference secret FINDINGS (path, detector,
fingerprint), never values. Substitution happens at one point, after
authorization, and the agent holds handles rather than material.

*Tests:* `test/secret-detect.test.mjs`, `test/secrets.test.mjs`.

## INV-006 — Revocation cascades and is checked at use time

Revoking a delegation, an agent or a mission takes effect at the next
presentation, not at the next issuance, and revoking a link revokes everything
derived from it. A still-valid child of a revoked parent authorizes nothing.

*Tests:* `test/adversarial/cross-boundary.test.mjs`, `test/identity.test.mjs`.

## INV-007 — Tenancy is a boundary, not a label

A grant carrying tenant X presented by an agent known to belong to tenant Y is
REFUSED, not merely recorded. An agent belongs to exactly one tenant; no
delegation crosses the line.

*Tests:* `test/adversarial/cross-boundary.test.mjs`,
`test/identity-matrix.test.mjs` (wrong-tenant row).

## INV-008 — Identity never widens authority

A verified identity is who is asking, never what is allowed. Verification
replaces the claimed name in the trusted context and in every record, but the
rules that apply are still exactly the rules policy gives that principal.
Identity cannot turn a deny into a permit, and the sandboxed principal used
for planned evaluations of refused callers matches nothing by construction.

*Tests:* `test/identity-ordering.test.mjs`, `test/identity-matrix.test.mjs`.

## INV-009 — Identity precedes authorization

Inside `Guard.authorize` the order is: transport authentication (upstream of
the call) → cryptographic verification → enrolment/status/revocation/replay
checks → a trusted principal → request normalization → authorization. A
claimed agent name NEVER enters the trusted context: an unverified caller is
denied by a short-circuit before any identity-dependent stage runs, the
would-be policy outcome is evaluated under a sandboxed principal, and no later
stage can convert the refusal into a permit. Verified callers replace claimed
names everywhere.

*Tests:* `test/identity-ordering.test.mjs`, `test/identity-matrix.test.mjs`.

### Where the trusted principal comes from

Exactly three sources, in precedence order — everything else is a claim:

1. a PROVEN identity: the credential's `agentId`, which replaces every name
   anybody typed;
2. the authenticated host context (`ctx.agent`) — the channel
   `Pipeline.submit` has always used and `Guard.authorize` now accepts too,
   supplied by the trusted embedder and NEVER copied from a request payload or
   from tool arguments;
3. the operator-configured agent (`this.agent`).

A request's own `agent` field is not on that list. It is recorded as
`claimed_agent` whenever it is not the principal the call is evaluated under,
and it is never what a delegation's subject binding is compared against: a
typed name can present somebody else's chain and bind nothing. A transport
that filled `ctx.agent` from its own payload would hand the trust of channel 2
back to the caller — the MCP gateway deliberately does not, passing the claim
as the request's `agent` and the proof as `callerMeta`.

*Tests:* `test/identity-ordering.test.mjs`; `test/delegation-ed25519.test.mjs`
(the Guard and Pipeline paths narrow identically against a PROVEN principal,
and a typed name binds no delegation subject).

## INV-011 — Revocation is durable, signed, monotonic state (P0-C)

Revoking something is an OPERATOR ACT THAT IS RECORDED, not a variable that is
set. `cirvix kill` writes a signed `RevocationEvent` (scope, subject, tenant,
issuer, reason, validity window, epoch, sequence, previous hash) into an
append-only journal under the state directory, with the entry signed by the
REVOCATION role key and chained to its predecessor by hash.

* **Every process enforces it.** `RevocationEngine.evaluate()` re-reads the
  journal before each decision (one `stat` when nothing changed), so a
  revocation written by a DIFFERENT process is in force on the next call, with
  no IPC channel and no restart. This is the property the in-process
  `KillSwitchEngine` never had.
* **It survives restarts.** The journal is the state; memory is a cache.
* **It cannot be moved backwards.** The manifest records the highest epoch,
  sequence, count and hash ever written. A journal that is shorter than the
  manifest, ends on a different hash, or fails a signature check puts the store
  into `rollbackDetected` and EVERY decision refuses until an operator resolves
  it. A write whose epoch is behind local state is refused outright.
* **Nothing fails open.** An unreadable journal, a corrupt line, an unsigned
  event, a rolled-back file, a future-dated event (clock disagreement, i.e.
  clock skew) and a stale control-plane feed all resolve to DENY — or to HOLD
  when the operator selected `onUnavailable: "hold"`. There is no "allow"
  branch, and `doctor` reports which policy is in force.
* **Scopes are closed and ranked.** Fourteen scopes (global, tenant, principal,
  identity, runtime, agent, credential, session, delegation, capability,
  mission, approval, tool, resource) with an explicit precedence list, so a
  refusal names the highest-ranked match and reports every match.
* **Cascades are state, not labels.** Revoking an agent marks its enrolled
  record revoked (the identity boundary then refuses its credentials) and
  writes revocation events for every grant it issued AND every grant derived
  from those, so a "killed" agent has no usable downstream authority.

*Tests:* `test/revocation.test.mjs` (including a cross-process kill proven with
an independent execution oracle, a restart test, a rollback test, a
clock-skew test and a two-writer journal-integrity test).

### Fleet propagation is MEASURED, not instant

The control-plane path applies the SAME signed events: an endpoint verifies
them against a PINNED operator key, accepts only epochs ahead of local state,
and records event creation → receipt → activation per event, so propagation
latency is measured and reportable. Nothing here claims that a revocation
reaches every endpoint at the same moment: an offline endpoint knows only what
it has received, `maxStalenessMs` bounds how long an endpoint will act on a
feed it has not re-verified, and past that bound it DENIES (or HOLDS) rather
than assuming nothing changed.

### RELEASE is a separate authority (INV-013)

Imposing a containment and lifting one are not the same act, and they no longer
share a key, a role or a code path:

* the REVOCATION role key stays on the host, so `cirvix kill` works offline;
* the RELEASE role key is **not kept in the state directory**. It is supplied by
the release officer and registered here by PUBLIC HALF only
(`cirvix authority release-key register`), so copying the state directory does
not confer the power to undo a containment;
* a release additionally requires an AUTHENTICATED PRINCIPAL holding
`owner` or `release-officer` (a fresh single-use challenge signed with the
officer's own key), and the event records the principal, role, tenant,
authentication method, the challenge nonce and the release key id;
* `revoke({ action: "release" })` is refused outright, and the JOURNAL WRITE
itself refuses a RELEASE event whose signer is not the registered release
authority — the choke point, not just the convenient entry point;
* a host with no registered release authority cannot release AT ALL
(`release_authority_missing`). Containment that cannot be undone locally is a
smaller problem than containment anyone can undo.

`cirvix doctor` reports who and what can issue a release, and says
"releases are IMPOSSIBLE" when nothing can.

### What revocation cannot do (recorded, not hidden)

* A same-user process that can write the state directory can still write a
  REVOCATION event: the signature proves an operator key signed it, and that
  key is a 0600 file on the host. Imposing containment is deliberately cheap;
  that asymmetry is the design. This is the cooperative boundary, unchanged.
* **LOCAL rollback detection**: the journal is compared against the manifest in
  the same directory (shorter journal, different final hash, broken link ⇒
  every decision refuses).
* **EXTERNAL/fleet rollback detection**: restoring the journal AND the manifest
  together is locally indistinguishable from honest state. A control-plane
  checkpoint that reports an epoch ahead of local state is the only detector
  (`sync` records it and every decision refuses until an operator resolves it);
  when no control plane is configured, the local behaviour is unchanged and the
  guarantee is LOCAL only. There is no claim of filesystem immutability.
* Already-issued EXTERNAL credentials (an AWS STS token, for instance) cannot be
  revoked instantly if the provider offers no such API; they remain valid until
  their own TTL. Revocation of the authority that minted them stops the next
  mint, not the last one.

## INV-012 — Authority is issued by an AUTHENTICATED principal, never a name (P0-B)

A grant's `human` field is a display name and establishes nothing. What
establishes authority is `issuerPrincipalId`, resolved against a durable
principal record that the host signed:

```
principal = principalId, organizationId/tenantId, kind, role, status,
            authenticationMethod, its OWN public key + key id, issuedAt,
            expiresAt, revocation state
```

The principal's identity is SEPARATE from every signing key the runtime holds:
the host authority key only vouches for the record, and only POSSESSION of the
principal's own private key (a signature over
`cirvix-principal/1|<principalId>|<action>|<nonce>`) authenticates its acts. A
key file meant to live with the person is printed once by
`cirvix authority principal enroll` and never written into the state directory.

Enforced downstream, on the same decision path as everything else: a root whose
issuing principal is missing, revoked, suspended, expired or in another tenant
is refused (`principal_invalid`), and a boundary built with
`requireIssuerPrincipal` refuses a root that names no principal at all. Every
mutating lifecycle act is authenticated against the live record, including
`principal revoke` itself — so withdrawing someone's authority is attributable.

*Production path:* `cirvix authority principal enroll|list|show|revoke|rotate`,
`cirvix authority challenge`, `cirvix authority grant issue|list|show|revoke`,
`cirvix authority mission create|list|show|revoke|rotate|capability …`,
`cirvix authority verify`, `cirvix authority release-key register|show`.

*Tests:* `test/p0b-authority.test.mjs`, `test/p0b-exit-audit.test.mjs`.

## INV-014 — Boundaries pin WHAT they are: audience, tenant, policy generation

Tenant alone is not enough. A grant is issued FOR something —
`audience: "agent:worker"`, `"runtime:prod-runner"` — and a boundary that
knows what it is refuses a grant issued for anything else, INCLUDING a grant
that names no audience at all (`delegation-audience_mismatch`). Issuer,
subject, audience and tenant are four distinct bindings, all reported on the
resolved chain. The gateway derives `agent:<name>` and the socket runtime
`runtime:<env>` when the operator names none, and `doctor` shows the value.

Two further postures are explicit, never inferred:

| Posture | Selected by | Effect |
| --- | --- | --- |
| authority-required | `--require-authority` / `CIRVIX_REQUIRE_AUTHORITY` | a governed call presenting no signed authority is REFUSED (`delegation-required`) instead of decided by policy alone |
| default | neither | policy alone decides a call that presents none, but authority that IS presented is always verified |

Both postures refuse a chain the boundary cannot verify
(`delegation-unverifiable`): ignoring presented authority would let a caller
believe it was acting under a grant while the call ran on policy alone.

Consumption is bounded and durable where the grant says it is: `singleUse` and
`maxUses` are taken from an append-only usage ledger under an advisory lock, so
two concurrent calls cannot both spend one use, and a use survives a restart.
Unbounded grants carry no counters — a meaningless counter is worse than none.

*Tests:* `test/p0b-authority.test.mjs` (audience/tenant/subject/issuer/expiry/
revocation/replay rows, a concurrent single-use race, a durable-use restart).

## INV-010 — Boundary classes are stated, never implied

Every boundary is classified as one of:

* **HARD** — enforced by the execution path itself: an attacker who controls
  the agent process can neither bypass the decision nor forge identity, and
  the OS/hardware mediates both. Nothing in this package is HARD yet.
* **COOPERATIVE (strong)** — cryptographically verified identity and
  fail-closed enforcement, where the trust anchor is a key file the runtime
  holds. The current boundary: Ed25519 credentials + per-request signatures,
  authenticated principal-issued authority (INV-012), audience/tenant/policy
  pinning (INV-014), and durable signed revocation with a separately keyed
  release authority (INV-011/INV-013). A same-user process that can read a key
  file can still sign as that holder, so a stolen key file is a stolen
  identity — which is why every shipped boundary is still classified
  COOPERATIVE and never described as HARD, and why `cirvix doctor` prints the
  binding strength in plain words.
* **COOPERATIVE (metadata)** — self-asserted names, kept out of the trusted
  context by INV-009.

Upgrading a boundary to HARD requires BOTH execution-path control AND
identity/process binding. The roadmap below is the order they arrive in.

*Tests:* `test/identity-ordering.test.mjs` (INV-010 binding assertions),
`test/identity.test.mjs`.

## Modes — no silent fallback (serves INV-009)

A boundary's posture is an explicit decision, never inferred from enrolment
state:

| Mode           | Selected by                                   | Unverified caller                    | Marked on record |
| -------------- | --------------------------------------------- | ------------------------------------ | ---------------- |
| `production`   | CLI default; `--identity-mode production`     | REFUSED (even with no verifier)      | `identity_mode`  |
| `bootstrap`    | `--identity-mode bootstrap`                   | accepted ONLY while no verifier exists; window closes itself the moment one does | `identity_mode` + `claimed_agent` |
| `dev-insecure` | `--identity-mode dev-insecure` only           | accepted; identity enforcement OFF   | `identity_mode` + `claimed_agent` + `identity.reason` |
| `compat`       | library/SDK default only, never the CLI       | historic behaviour (no verifier, no refusal) | `identity_mode` |

A fresh production install refuses callers until an agent is enrolled; it does
not quietly become an unauthenticated authorization endpoint. `cirvix doctor`
reports the active mode and the enrolment state separately.

## INV-015 — ONE authorization pipeline (P0-D)

There is exactly one implementation of authorization semantics:
`src/core/authorize.mjs`. Every production enforcement surface — the MCP
gateway, the local socket, the SDK/`Guard` wrapper, the Claude Code hook — is a
transport adapter over it that owns only its own protocol concerns (parsing,
transport authentication, rendering the decision back out).

What this replaced was two engines with two different stage sets, each correct
by its own tests:

| | before P0-D | after P0-D |
| --- | --- | --- |
| MCP gateway / SDK | identity, delegation, authority, policy | the same, PLUS session tracking, behavioural baseline, engine mode, tool drift, intent, policy generation |
| local socket | policy, session, baseline, drift | the same, PLUS identity verification (the socket authenticated the caller and then handed the engine a bare name) |

The invariant is testable rather than architectural: for the SAME logical
request, the transports must agree on the DECISION and on the RULE that produced
it. Where two surfaces differ, the difference must be explainable as a
difference in trusted input — never as a stage one of them does not have.

*Tests:* `test/p0d-parity.test.mjs` (parity rows over allow, deny, malformed,
identity, delegation, authority, expiry, revocation, session, intent, baseline
drift and stale policy, cross-checked between `Guard` and `Pipeline`, and
between a live MCP gateway and a live socket).

## INV-016 — The stage order is a contract, and each stage has one

Twenty-five stages, evaluated in one fixed order: request, identity, normalize,
secrets, risk, policy, delegation, authority, capability, revocation, kill,
trifecta, policy-version, mode, entitlements, intent, session, baseline, drift,
validation, approval, credential, sanitize, final-tighten, evidence.

The ORDER is a security property, not a convenience: identity precedes policy so
a claimed name cannot select the rule set that judges it; normalize precedes risk
and policy so a decision is never taken on unnormalised input; revocation
precedes approval so authority withdrawn during an approval wait cannot be spent;
evidence is last so it records a decision that already happened.

Each stage also declares a contract — its input, its output, how it fails, what
it TRUSTS, and what it can only NARROW. A stage that narrows can never widen a
decision; the ones that can produce one are enumerated, and the machinery that
has no producer (REAUTHENTICATE, STEP_UP, ISSUE_CAPABILITY) is documented as
unreachable rather than left to look enforced.

*Tests:* `test/p0d-parity.test.mjs` (the exact stage list, the contract fields,
and the ordering constraints above).

## INV-017 — A boundary reports which stages are wired, and "not wired" is not "passed"

`stagePlan()`/`describeCanonicalPosture()` answer "what is actually in force on
this boundary" from the Dependencies the boundary supplies, and `doctor` prints
it. A stage with nothing to give is INERT; one the operator selected off is
PROFILE-DISABLED; one that cannot exist on that surface is NOT-APPLICABLE.

None of those three is a pass, and the report says so in those words. Two
boundaries given the SAME dependencies produce the SAME plan on every surface —
which is what makes a difference between surfaces a finding instead of an
assumption. Where a stage can only be evaluated by one KIND of surface, the
exception is declared in `SURFACE_BOUND_STAGES` rather than inferred from a
stage's name (tool drift is surface-bound to the MCP gateway because only a
boundary that owns upstream tool definitions has a definition to compare).

*Tests:* `test/p0d-parity.test.mjs` (INERT vs MANDATORY rows, identical plans
from identical dependencies).

## INV-018 — Caller-controlled fields never become trusted context

Identity comes from a PROVEN credential, then from the authenticated host
context the transport supplies, then from the operator default. A request's own
`agent`/`principal`/`tenant`/`audience` are CLAIMS: recorded as `claimed_agent`
whenever they differ from the principal, and never what a decision is evaluated
against. `Guard.authorize` fills the host context from its embedder, never from
the request; a transport that copied a payload field into it would hand the
trust back to the caller.

When the transport authenticated the peer, the RESULT of that verification is
handed to the core (`ctx.identityVerification`) so the core does not re-derive
the answer or lose it: the socket verifies the credential and proof, and the
engine that decides now knows who was proven. The identity MODE is resolved as
the STRICTER of the transport's and the core's, so a boundary cannot weaken its
mode by stating it twice.

*Tests:* `test/p0d-parity.test.mjs` (claims that never establish context),
`test/identity-ordering.test.mjs`, `test/hook-identity.test.mjs` (the Claude Code
hook now presents a proof instead of a name, and an un-enrolled host is refused
in production).

## INV-019 — Revocation is enforced across process AND transport

The durable revocation fabric (INV-011) is consumed by every surface through the
canonical core, so an event written by ANOTHER process refuses the call on the
next one — including on the MCP path, which previously had no revocation stage
at all. The refusal names the event and the issuer, and the record carries them.

*Tests:* `test/p0d-parity.test.mjs` (the same revocation refusing both surfaces),
`test/revocation.test.mjs`.

## INV-020 — No silent downgrade

A hardened boundary reports itself hardened. The reverse also holds: a boundary
that stated NEITHER a mode nor an incompatibility is reported as the
compatibility profile it is, and is not called production. A DEV-INSECURE
profile is explicit, is NEVER reported as hardened, and is visible on every
decision.

Two downgrades are additionally closed on the stage path itself: engine AUDIT
mode may downgrade a computed permit to a record-only observation, but a mission
allowance refusal is re-applied afterwards with `enforced: true` — a budget is
not a rule set, and spending somebody else's allowance is not an observation.

*Tests:* `test/p0d-parity.test.mjs` (profile reporting both ways, dev-insecure
marked on the decision), `test/identity-matrix.test.mjs`.

## INV-021 — The policy a boundary CLAIMS is the policy it ENFORCES

The rules in force are hashed (`policyStamp`) and compared against the published
stamp (`<state>/policy.stamp.json`: version + hash). A boundary whose published
policy is a DIFFERENT hash than the one it is running refuses with
`stale-policy` — or holds for approval, when the operator selected `onStalePolicy:
"hold"`. Reporting an older generation as current is the failure mode: a caller
and an audit reader would both be told a generation that no boundary is running.
A runtime with nothing published reports inert rather than pretending to compare.

*Tests:* `test/p0d-parity.test.mjs` (stale-policy row), and `cirvix doctor`
reports the enforced hash, the published hash and the verdict.

## INV-022 — A decision that cannot be recorded does not stand

Evidence is a stage, and it is mandatory wherever an audit chain is configured:
every stage's status and latency, the policy stamp, the principal, the tenant,
the runtime and the audience ride the record. If the audit append fails for a
decision that would have been FORWARDED, the decision flips to DENY
(`audit-unavailable`) — a permitted effect with no record is indistinguishable
from a permitted effect nobody can explain, and the audit trail is what makes
"who authorized this" answerable after the fact.

*Tests:* `test/p0d-parity.test.mjs` (the audit-failure row, and per-stage statuses
present on every transport's record).

## Roadmap to HARD identity (tracked, not claimed)

Each step is a separate, testable upgrade. The boundary stays COOPERATIVE
until the step that binds identity to the process; only then does
`binding` become `hard` — and every record produced before that point keeps
the `cooperative` classification it was created with.

1. **Unix peer credentials / SO_PEERCRED** — the socket kernel-verifies the
   connected process's uid/pid, so "which process is asking" stops being a
   claim. Windows equivalent: named-pipe client process information.
2. **Process/runtime binding** — the identity private key is bound to the
   enrolled runtime process (same-user + executable attestation), so a stolen
   key file cannot sign from an arbitrary process.
3. **OS keychain** — the authority and identity keys move into the platform
   key store (DPAPI, Keychain, libsecret); file-system 0600 stops being the
   last line of defence.
4. **TPM/TEE where available** — keys are non-exportable and signing happens
   inside the secure element; key extraction requires hardware attack.
5. **Platform-specific isolation** — per-OS hardening (AppContainer,
   sandbox-exec profiles, seccomp profiles for the runtime) closing the gap
   between "the agent is governed" and "the agent cannot reach the governor".

After step 2 the boundary meets the HARD definition for the local-socket
transport; steps 3–5 remove the remaining same-user compromise paths. Until
each lands, the honest classification is the one INV-010 records.
