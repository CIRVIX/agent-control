# Policy reference

A Cirvix policy is an **ordered array of data rules**, commonly stored as
`cirvix.policy.json`. Node also supplies a `cirvix.policy` DSL compiler (`compilePolicy` / `core/policy-dsl.mjs`) and CLI validation/testing. Conditions are data, not executable expressions. The JSON evaluator is
[`packages/agent-control/src/core/policy.mjs`](../packages/agent-control/src/core/policy.mjs)
(Node) and [`packages/cirvix-python/cirvix/policy.py`](../packages/cirvix-python/cirvix/policy.py)
(Python).

```json
{
  "rules": [
    {
      "name": "deny-dotenv-read",
      "effect": "forbid",
      "actions": ["fs.read", "fs.*"],
      "resources": ["**/.env", "**/.env.*"],
      "reason": "Reading .env files is denied outside an approved secrets flow.",
      "remediation": "Request the value as a handle: secrets.get(\"STRIPE_KEY\")"
    }
  ]
}
```

A bare array is also accepted: `[ { … }, { … } ]`.

## The three properties that matter

These are load-bearing, tested, and identical in both engines.

### 1. Forbid always wins

A matching `forbid` cannot be overridden by any `permit`, regardless of order or
specificity. `forbid` short-circuits evaluation the moment it matches.

This is what makes a rule set safe to extend. Adding a permissive rule can never
silently punch a hole through an existing prohibition, so a team can grant new
capability without re-reading every guardrail first.

### 2. Default deny

A request that matches no rule is denied, with `rule: null`. An empty rule set
denies everything.

Fail-open is how a control plane becomes decorative the first time a rule file
fails to parse.

### 3. Resources are canonicalized before matching

`./x/../.env`, `.env`, and an absolute path to the same file are one resource.
Traversal is collapsed and case is normalized before any pattern is compared.

Rules that match on raw strings are bypassed by the first attacker who tries a
traversal, and by the first agent that happens to use a relative path.

A fourth, smaller rule follows from the first two: **a `hold` outranks a
`permit`.** If any rule says a human must see this call, the presence of some
other permissive rule must not quietly skip them.

## Rule fields

| Field | Type | Required | Meaning |
|---|---|---|---|
| `name` | string | yes | Unique identifier. Appears in every decision, alert, and audit record. |
| `effect` | `"permit"` \| `"forbid"` \| `"hold"` \| `"sanitize"` \| `"audit_only"` | yes | What happens on a match. |
| `agents` | string \| string[] | no | Glob(s) matched against the agent name. Omitted means any. |
| `actions` | string \| string[] | no | Glob(s) matched against the action. Omitted means any. |
| `resources` | string \| string[] | no | Glob(s) matched against the canonical resource. Omitted means any. |
| `when` | condition[] | no | Every condition must hold. See below. |
| `reason` | string | no | Shown to the agent and recorded. Defaults to `"Denied by <name>."` etc. |
| `remediation` | string | no | The legitimate path. Frequently what lets an agent re-plan instead of retrying. |
| `approvers` | string[] | `hold` only | Who may release the call. Required by `validateRules` when `effect` is `hold`. |

`agents`, `actions` and `resources` all treat an omitted field, `"*"`, and an
empty array as "matches anything".

## Effects and verdicts

They are not the same vocabulary, and the distinction is deliberate.

| Rule `effect` | Resulting `verdict` | Meaning |
|---|---|---|
| `permit` | `permit` | The call proceeds. |
| `forbid` | `deny` | The call is refused. Re-planning is the only recovery. |
| `hold` | `hold` | The call is refused pending approval; a configured store may allow a later retry. |
| `sanitize` | `permit` only with a matching permit | Adds sanitization requirements; does not authorize on its own. |
| `audit_only` | Does not authorize | Annotation only; distinct from Pipeline's runtime audit mode, which may forward otherwise blocked calls. |

An agent that treats `hold` as failure learns to give up on work a person was
about to approve, which is why the SDKs raise a distinct `CirvixHeld` type.

## Glob matching

Patterns use a non-regex wildcard matcher. Standalone `*` and `**` are universal special cases; the segment restrictions below apply when a star appears within a larger pattern.

| Token | Matches |
|---|---|
| `*` | Any run of characters **within** one `/`-separated segment |
| `**` | Any run of characters **across** segments |
| `?` | Exactly one character that is not `/` |
| anything else | Itself, literally |

Matching is case-insensitive. Every other character is a literal — a `.` in a
rule means a dot, not "any character", or `**/.env` would also match `xenv`.

> **Why not a regex.** The obvious implementation compiles the glob to a
> `RegExp`, and this one did. It is also exponential: `*a*a*a*a*b` against a long
> run of `a` makes a backtracking matcher explore every way of splitting the
> input. That matters more here than in most places, because the pattern comes
> from a policy rule and the *input* comes from whatever resource an agent named
> — so a caller on the far side of the enforcement boundary picks the input that
> triggers it, and a hung evaluator is a hung gateway. The current matcher is
> O(n·m) worst case with no pathological input at all.

## Conditions (`when`)

Conditions are plain data, never expressions. `eval` and `new Function` are
deliberately absent: a policy file is exactly the kind of thing that gets
templated by a script, and turning it into an execution surface would make the
security product the vulnerability.

```json
{
  "name": "require-approval-destructive",
  "effect": "hold",
  "actions": ["fs.delete", "db.write", "db.migrate", "k8s.apply", "shell.exec"],
  "resources": ["*"],
  "when": [{ "path": "environment", "op": "in", "value": ["production", "prod"] }],
  "approvers": ["platform-oncall"],
  "reason": "Destructive action in production. Held for a named human."
}
```

Each condition is `{ path, op, value }`. `path` is a dotted lookup into the
evaluation context. Every condition in the array must hold. `parseRules` rejects unknown operators. Raw evaluation treats an unknown comparator as non-matching; that can suppress a forbid as well as a permit, so it is not a substitute for validating loaded rules.

### Operators

| `op` | Holds when |
|---|---|
| `eq` | `context[path] === value` |
| `ne` | `context[path] !== value` |
| `in` | `value` is an array containing `context[path]` |
| `nin` | `value` is an array **not** containing `context[path]` |
| `gt` / `gte` | `context[path]` is a number and is `>` / `>=` `value` |
| `lt` / `lte` | `context[path]` is a number and is `<` / `<=` `value` |
| `matches` | `context[path]` is a string matching the glob in `value` |
| `exists` | `value: true` → path is set; `value: false` → path is unset |
| `contains` | `context[path]` is an array containing `value` |
| `supersetOf` | `context[path]` is an array containing every element of `value` |

## The evaluation context

This is what `when` can read. It is assembled by the caller, not by the engine,
which is what keeps the engine pure and identically testable in both languages.

| Path | Type | Set by |
|---|---|---|
| `agent` | string | The request's agent name |
| `action` | string | The request's action |
| `environment` | string | CLI `--env` or the Guard's `environment`; SDK examples may explicitly read `CIRVIX_ENV`, but it is not automatically loaded |
| `path.insideWorkspace` | boolean | Whether the canonical resource resolves inside the workspace root |
| `egress.external` | boolean | Whether the resource is an http(s) URL to a non-local host |
| `egress.allowlisted` | boolean | Whether the destination is on an egress allowlist |
| `session.touchedSecret` | boolean | Whether this session has already read secret-shaped material |
| `mcp.server` | string \| null | The upstream MCP server, when the call came through the gateway |
| `mcp.tool` | string | The tool name, when the call came through the gateway |
| `consequence` | string | What the call would effect in the world, derived by the Node boundary. See [Consequences](#consequences). |

`session.touchedSecret` is the one to understand. It is set once a session
successfully reads something matching `/secret|credential|token|password|\.env/i`,
and it never resets. It is what makes "read a credential, then post it
somewhere" fail even when both calls are individually allowed — see
`deny-external-egress-after-secret` in the starter rules.

A brokered [secret handle](./administration.md#secret-brokering) deliberately
does **not** taint the session: the agent never held the material, which is the
entire point of a handle.

## Consequences

A consequence is **what happens in the world if the call succeeds** — money
moves, a message reaches a person, a credential is disclosed, a process
advances. It is deliberately a different axis from `risk` (how dangerous this
looks) and from `actions` (what the tool does to a file or a process): reading a
local file and reading a production credential are the same action and
different consequences.

The Node boundary derives it from the call — the canonical action, the tool
name, the destination, and the environment — never from argument *values*, which
are attacker-controlled. The Python evaluator has no derivation layer: it can
only read what the caller puts in the context, so a rule keyed on `consequence`
must either run on the Node boundary or be handed the value explicitly. See
[Conformance](./conformance.md).

Twelve kinds, in significance order:

| Kind | What it means |
|---|---|
| `none` | Nothing leaves the machine — computation, local state. |
| `data_read` | Data is read out of the environment. |
| `data_write` | Data changes within the environment. |
| `data_export` | Data leaves the environment to an external destination. |
| `communication` | A human-facing message is sent — email, Slack, SMS, push. |
| `financial_transfer` | Money moves — payments, transfers, charges, refunds. |
| `credential_disclosure` | Credentials or secrets are read, created, rotated, or disclosed. |
| `privilege_change` | Who may do what changes — roles, grants, permissions. |
| `infrastructure_change` | Infrastructure is created, destroyed, or reconfigured. |
| `code_execution` | Code that was not present before runs. |
| `impersonation` | The agent acts as a specific human or system identity. |
| `process_advance` | A workflow or business process advances to a new state. |

They form a lattice, not a line. Each kind from `credential_disclosure` onward
is **dominant** and outranks the entire chain above it, but no two dominant
kinds are comparable — being able to change privileges says nothing about being
able to execute code. So `consequence >= data_write` matches `data_write` and
everything that outranks it, while `consequence >= credential_disclosure`
matches only `credential_disclosure`.

Two spellings, in both formats:

- **JSON** — `{ "when": [{ "path": "consequence", "op": "eq", "value": "financial_transfer" }] }`,
  or `op: "in"` with an explicit list of kinds.
- **DSL** — `consequence = financial_transfer` and `consequence >= data_export`.
  The other comparisons (`>`, `<`, `<=`, `!=`, `~`, `~=`) are a compile error, and
  an unknown kind is one too. A `>=` compiles to an `in` over the kinds that are
  at least as significant, exactly the way `risk >= HIGH` compiles to a tail —
  the engine keeps no ordinal logic of its own.

The same lattice bounds delegated authority. A mission or a grant may declare
`constraints: { maxConsequence: "data_write" }`, which refuses any call whose
consequence is above the named kind; a delegation can narrow that ceiling but
never widen it (see [Delegation](./delegation.md)).

> **Derived, not declared.** A tool whose name and destination give no signal is
> `none`, and a tool that looks financial is `financial_transfer` whether or not
> it moves money. Consequence is a coarse filter — name the action, the resource,
> or the destination for anything finer.

A misspelled kind is never read as "no limit": policy rejects it at compile
time, `maxConsequence` refuses it where it is written (a mission is flagged by
`lintMission`; a delegation broker throws), and a signed grant carrying one is
refused at verification.

## Actions

Node `actionForTool` delegates to `classifyTool` in `core/normalize.mjs`. Exact taxonomy names and aliases are checked before camel-case splitting, network/file subject rules and ordered taxonomy patterns. For example, `fetch_file` is a filesystem read while `web_search` is a network request. Unknown names retain `mcp.<server>.<tool>` or `tool.<name>` identity.

Classification is heuristic, not an understanding of actual tool behavior. Inspect normalized actions/resources for your specific schemas and compare Python behavior where applicable; a simple verb table is not the complete contract.

Because unmatched tools fall through to `mcp.*` and `tool.*`, you can always
write a rule against one specific tool by name.

## Resources

`resourceForCall` extracts the resource from a call's arguments by trying these
keys in order:

`path`, `file`, `filename`, `filepath`, `uri`, `url`, `resource`, `target`,
`query`, `sql`

If none is present, the first string-valued argument is used. If there is no
string argument at all, the resource is `""` — the call is still evaluated
rather than skipped.

Canonicalization then applies:

- **URLs** (`scheme://…`) → lowercased scheme and host, fragment stripped, trailing slash removed
- **Anything containing `/` or `\`, or starting with `.`** → resolved against `cwd`, traversal collapsed
- **Everything else** → left alone

Path resolution is deliberately **not** `path.resolve`. That function is
platform-aware, and on Windows it prepends the current drive to a drive-less
absolute path — so `/etc/passwd` became `C:/etc/passwd` there and `/etc/passwd`
everywhere else. A rule written `resources: ["/etc/**"]` then matched on a Linux
runner and silently did not match on a developer's Windows laptop, which is the
machine the rule was most likely written to protect. The conformance suite
caught this; it is exactly the class of bug two implementations would have
disagreed about forever.

## The decision

`evaluate()` returns:

```json
{
  "verdict": "deny",
  "rule": "deny-dotenv-read",
  "reason": "Reading .env files is denied outside an approved secrets flow.",
  "remediation": "Request the value as a handle: secrets.get(\"STRIPE_KEY\")",
  "considered": [
    { "rule": "deny-dotenv-read", "effect": "forbid", "matched": true }
  ],
  "resource": "/workspace/.env"
}
```

`approvers` is present on a `hold`. `considered` is the full trace of every rule
examined and whether it matched — the explanation is a first-class output, not a
log line, because a refusal an agent cannot read is a refusal it cannot recover
from.

## The starter rule set

`STARTER_RULES` is the fallback when no explicit or discovered workspace policy is loaded. It currently has nine rules, chosen so a
developer working normally is not interrupted while the handful of actions that
actually cause incidents are stopped or held.

| Rule | Effect | What it does |
|---|---|---|
| `deny-dotenv-read` | forbid | Blocks reads of `**/.env` and `**/.env.*` |
| `deny-credential-files` | forbid | Blocks `.aws/`, `.ssh/`, `.kube/config`, `.npmrc`, `.netrc`, `.docker/config.json` |
| `deny-workspace-escape` | forbid | Blocks any `fs.*` whose resolved path is outside the workspace |
| `require-approval-destructive` | hold | Holds `fs.delete`, `db.write`, `db.migrate`, `k8s.apply`, `shell.exec` in production for `platform-oncall` |
| `deny-external-egress-after-secret` | forbid | Blocks external egress for the rest of a session that read secret material |
| `allow-workspace-read` | permit | Permits `fs.read`, `fs.list`, `fs.stat` inside the workspace |
| `allow-workspace-write` | permit | Permits `fs.write` inside the workspace |
| `allow-allowlisted-egress` | permit | Permits egress to an allowlisted destination |
| `allow-read-only-tools` | permit | Permits `*.read`, `*.list`, `*.search`, `*.get`, `*.query` |

Print the active set at any time:

```bash
cirvix policy --json
```

## Validation

Two validators, at different boundaries.

**`parseRules(json)`** — used by the CLI and SDKs when loading a file. Throws on
the first problem: a missing `name`, an unsupported `effect`, or
a `when` condition using an unknown operator.

**`validateRules(rules)`** reports validation errors/warnings, including duplicate names and a hold without approvers. It is available locally; a control-plane validation endpoint is not shipped here.

```bash
cirvix policy check --policy cirvix.policy.json
```

## Testing a rule set

Rules are code. Test them in CI next to everything else — see
[Node SDK](./sdk-node.md#testing-a-policy) and
[Python SDK](./sdk-python.md#testing-a-policy).

## What policy does not do

- It decides **authorization**, not payload semantics. A permitted query that
  returns more rows than intended is a query design problem, not a policy outcome.
- It cannot evaluate what it never sees. `guard.wrap` governs the tools you hand
   it; a tool the agent reaches directly is not evaluated. The gateway similarly governs only calls routed through it.
- A permissive rule you wrote yourself is honoured exactly as written. Policy
  quality is the operator's responsibility.
