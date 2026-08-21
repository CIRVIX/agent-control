# Policy reference

A Cirvix policy is an **ordered array of JSON rules**. The on-disk format is
`cirvix.policy.json`. There is no separate policy language, no compiler, and no
expression evaluator — a rule is data, and the engine that reads it is
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
| `effect` | `"permit"` \| `"forbid"` \| `"hold"` | yes | What happens on a match. |
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
| `hold` | `hold` | The call is suspended for a named human. This exact call may still happen. |

An agent that treats `hold` as failure learns to give up on work a person was
about to approve, which is why the SDKs raise a distinct `CirvixHeld` type.

## Glob matching

Patterns are matched by a two-pointer wildcard matcher, **not** a regular
expression.

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
evaluation context. Every condition in the array must hold. **An unknown
operator fails closed** — the condition does not match, so a typo cannot
accidentally widen a rule.

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
| `environment` | string | `--env`, `CIRVIX_ENV`, or the `Guard`'s `environment` |
| `path.insideWorkspace` | boolean | Whether the canonical resource resolves inside the workspace root |
| `egress.external` | boolean | Whether the resource is an http(s) URL to a non-local host |
| `egress.allowlisted` | boolean | Whether the destination is on an egress allowlist |
| `session.touchedSecret` | boolean | Whether this session has already read secret-shaped material |
| `mcp.server` | string \| null | The upstream MCP server, when the call came through the gateway |
| `mcp.tool` | string | The tool name, when the call came through the gateway |

`session.touchedSecret` is the one to understand. It is set once a session
successfully reads something matching `/secret|credential|token|password|\.env/i`,
and it never resets. It is what makes "read a credential, then post it
somewhere" fail even when both calls are individually allowed — see
`deny-external-egress-after-secret` in the starter rules.

A brokered [secret handle](./administration.md#secret-brokering) deliberately
does **not** taint the session: the agent never held the material, which is the
entire point of a handle.

## Actions

Policy is written against a normalized action vocabulary rather than raw tool
names, so one rule covers every tool that does the same thing. `actionForTool`
(Node) / `action_for_tool` (Python) maps a tool name to an action:

| Tool name contains | Action |
|---|---|
| `read`, `get`, `cat`, `fetch` | `fs.read` |
| `write`, `create`, `put`, `save`, `edit` | `fs.write` |
| `delete`, `remove`, `rm`, `unlink`, `drop` | `fs.delete` |
| `list`, `ls`, `search`, `find`, `query`, `grep` | `fs.list` |
| `exec`, `run`, `shell`, `command`, `spawn` | `shell.exec` |
| `request`, `http`, `curl`, `browse`, `scrape` | `http.request` |
| `apply`, `deploy`, `rollout` | `k8s.apply` |
| *no match, via the gateway* | `mcp.<server>.<tool>` |
| *no match, via `wrap`* | `tool.<name>` |

Matching is on whole words delimited by start/end, `.`, `_`, or `-` — so
`read_file` maps to `fs.read` but `spreadsheet` does not.

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

`STARTER_RULES` is what you get with no `--policy` flag. Nine rules, chosen so a
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
the first problem: a missing `name`, an `effect` that is not one of the three, or
a `when` condition using an unknown operator.

**`validateRules(rules)`** — used by the control plane before publishing.
Returns *every* problem as `{ path, message }` rather than throwing on the first,
because publishing fans a rule set out to the entire fleet and an operator fixing
one error at a time across six round trips is an operator who gives up. It
additionally catches duplicate rule names and a `hold` with no `approvers`.

```bash
curl -X POST https://api.example.com/v1/policy/validate \
  -H "authorization: Bearer $CIRVIX_API_KEY" \
  -H "content-type: application/json" \
  -d '{"rules":[{"name":"r","effect":"maybe"}]}'
```

## Testing a rule set

Rules are code. Test them in CI next to everything else — see
[Node SDK](./sdk-node.md#testing-a-policy) and
[Python SDK](./sdk-python.md#testing-a-policy).

## What policy does not do

- It decides **authorization**, not payload semantics. A permitted query that
  returns more rows than intended is a query design problem, not a policy outcome.
- It cannot evaluate what it never sees. `guard.wrap` governs the tools you hand
  it; a tool the agent reaches directly is not evaluated. The gateway does not
  have this limitation because it sits on the wire.
- A permissive rule you wrote yourself is honoured exactly as written. Policy
  quality is the operator's responsibility.
