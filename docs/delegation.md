# Agent-to-agent delegation

```
Agent A ──▶ Agent B ──▶ tool
```

One invariant, and everything here exists to enforce it:

> **An agent cannot gain authority merely because another agent has it.**

The failure this prevents is the confused deputy, and in a multi-agent system it
is the default outcome rather than an edge case. A planner holds database
authority; a summariser does not. The planner asks the summariser to "just run
this one query". If the summariser's call is evaluated against the *planner's*
authority, the summariser now has database access — permanently, invisibly, and
by design rather than by bug.

## The three rules

**Scope only narrows.** A delegation is a subset of what the issuer holds. Never
a superset, never a sideways set. The effective authority of a chain is the
intersection of every link, so going one hop deeper can only reduce what is
reachable — which is what makes the depth of a chain irrelevant to its danger.

**Delegation is a constraint, not a grant.** The effective scope is ANDed with
policy, never ORed. There is deliberately no path by which presenting a token
makes a denied call permitted. If there were, the token would be a capability,
and a capability that leaks is authority that leaks.

**Identity is not a name.** A grant is bound to `(issuer, subject)` and signed.
An agent claiming to be `planner` proves nothing; a grant that verifies under
the runtime's key and names it as subject proves exactly one thing, which is
what it says. Names are attacker-controlled strings and are treated as such.

## Issuing

```js
import { DelegationBroker } from "@cirvix_ai/agent-control/delegation";

const broker = new DelegationBroker();

// A root is what an agent holds on its own. Only an operator creates one;
// nothing an agent does can mint one.
const planner = broker.root("planner", { actions: ["*"], resources: ["*"] });

// A delegation is refused, not clamped, if it would widen.
const result = broker.delegate(planner, "summariser", {
  actions: ["fs.read"],
  resources: ["/workspace/**"],
});

if (!result.ok) throw new Error(result.reason);
const grant = result.grant;
```

Widening is **refused rather than silently clamped**, because clamping hides the
attempt and an agent trying to widen its authority is exactly the event an
operator wants in the log.

| Option | Default | Meaning |
|---|---|---|
| `ttlMs` | 15 min | Delegation is for a task, not for a quarter |
| `tenant` (on `root`) | `null` | Which tenant this agent belongs to |

## Presenting

A grant is only authority when the agent making the call presents it. Every
surface takes it the same way.

**Local socket** — `params.delegation`:

```json
{
  "method": "cirvix/authorize",
  "params": {
    "agent": "summariser",
    "tool": "read_file",
    "arguments": { "path": "/workspace/src/app.ts" },
    "delegation": { "id": "dlg_2", "subject": "summariser", "...": "the grant" }
  }
}
```

**MCP** — `params._meta.cirvix`, the protocol's own extension point. Honoured on
`tools/call` and on `resources/read`:

```json
{
  "method": "tools/call",
  "params": {
    "name": "files__read_file",
    "arguments": { "path": "/workspace/src/app.ts" },
    "_meta": { "cirvix": { "agent": "summariser", "delegation": { "...": "" } } }
  }
}
```

**SDK / `Guard`**:

```js
const guard = new Guard({ rules, cwd, delegation: broker });
await guard.authorize({ tool: "read_file", args, agent: "summariser", delegation: grant });
```

Both engines route through one implementation (`applyDelegation`), and a test
asserts `Guard` and `Pipeline` produce the same rule for the same call.

## What refusal looks like

The decision carries a rule naming the failure, so an operator can tell a
narrowing from a forgery:

| `policy` | Meaning |
|---|---|
| `delegation-out-of-scope` | Policy permits it; the delegation does not |
| `delegation-subject_mismatch` | Presented by somebody other than its subject |
| `delegation-bad_signature` | Forged, or any field edited |
| `delegation-revoked` | The grant or an ancestor was revoked |
| `delegation-expired` | The grant or an ancestor lapsed |
| `delegation-unknown_tenant` | The presenter belongs to a different tenant |
| `delegation-broken_chain` | The chain does not terminate in a root |
| `delegation-cycle` / `-too_deep` | Refused at issue |

A refusal names the chain — `planner → researcher → summariser` — so the deputy
is identifiable. The audit record carries `delegation.principals` for the same
reason: who authorized this must be answerable after the fact.

## Revocation

```js
broker.revoke(grant.id);   // cascades to everything derived from it
```

Cascading downward, because revoking a link and leaving its children usable
revokes nothing — the authority simply flows around the hole. It does **not**
travel upward: an agent at the bottom of a chain must not be able to disable the
agent above it.

## Tenancy

An agent's tenant comes from its root grant, and authority does not cross a
tenant boundary — refused at both issue and presentation, because tenancy can be
registered after a grant is minted.

An agent with **no** registered tenancy is deliberately allowed to act under a
grant issued to it. Delegating to an agent that has no root of its own is the
ordinary case — a planner spawning a helper for one task — and presenting a
grant requires being its signed subject, so an invented name is only usable if
someone inside the tenant already minted a grant for it. See
[SECURITY.md](../SECURITY.md#review-2026-08-13--cross-boundary-identity).

## Secret handles are separate authority

A delegation of *action* does not carry credential ownership with it. A handle
bound to a subject is spendable only by that subject, however widely its holder
delegates:

```js
const handle = vault.issue("STRIPE_KEY", material, { subject: "payments-agent" });
```

Binding is opt-in per handle, because a single-agent install has no boundary to
enforce. Where it is set, possession of the handle string is not authority to
spend it — which matters because a handle is deliberately not a secret: it
appears in arguments, in audit records, and in results other agents read.

## Limits

- **A grant has no server axis.** It constrains actions and resources, so a
  grant for `fs.read` on `**` works against any MCP server exposing a read tool.
  Confine by resource glob or by policy.
- **`_meta.cirvix.agent` is self-asserted.** It selects which agent-scoped rules
  apply and which handles resolve; it grants nothing. Rules keyed on agent
  identity in a hostile deployment need a signed grant behind them.
- **Grants are local to one runtime.** The signing key is per-process, so two
  Cirvix instances cannot verify each other's grants and a restart invalidates
  every outstanding delegation. That is the safe direction; fleet-wide issuance
  is the control plane's job.
- **Chains are bounded at depth 8.** Not a security boundary — narrowing already
  makes depth harmless — but an unbounded chain is an unbounded verification
  loop over attacker-supplied data.

## The attacks this is tested against

`packages/agent-control/test/adversarial/delegation.test.mjs` (41) and
`cross-boundary.test.mjs` (37) attack the invariant directly: impersonation,
forged issuer and subject, swapped parent, spliced signatures, stale and revoked
links, cross-tenant grants, approval laundering across chains, credential
laundering across agents, depth exhaustion, cycles, policy reload, and process
restart — over the socket, over MCP, and through the SDK.
