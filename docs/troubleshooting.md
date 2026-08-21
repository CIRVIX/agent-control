# Troubleshooting

Symptoms, causes, and the check that distinguishes them.

## Policy

### Everything is denied

The rule set is empty or failed to load. **An empty rule set denies everything**
— that is the default-deny property working, not a bug.

```bash
cirvix policy --policy your.policy.json     # how many rules actually loaded?
```

The most common cause in SDK code is passing an option the `Guard` does not
have. `guard.wrap` forwards options to the `Guard` constructor, which takes
`rules`. **There is no `policyDir` option on `wrap`** — passing one leaves
`rules` empty, and every call is denied by no rule matching.

```js
// wrong — rules is never set, everything denies
guard.wrap(tools, { agent: "x", policyDir: "./policies" });

// right
import { readFile } from "node:fs/promises";
import { parseRules } from "@cirvix/agent-control";
const rules = parseRules(JSON.parse(await readFile("cirvix.policy.json", "utf8")));
guard.wrap(tools, { agent: "x", rules });
```

`policyDir` **is** valid on `evaluate()` from the testing subpath. It is not
valid on `wrap`.

### A permit rule is being ignored

Check for a matching `forbid`. **Forbid always wins**, regardless of order or
specificity, and it short-circuits — nothing after it can change the outcome.

```bash
cirvix check --action <action> --resource <resource> --policy your.policy.json
```

The `considered` trace shows every rule examined and which matched.

### A call is held when you expected a permit

**A hold outranks a permit.** If any rule holds, the presence of a permissive
rule does not skip it. That is deliberate — otherwise adding a permit silently
routes around a human.

### A rule matches on Linux but not on Windows (or vice versa)

Resources are canonicalized before matching, and path resolution is
platform-independent by design. If a rule behaves differently across platforms,
the pattern is probably matching a raw string somewhere upstream, or `cwd`
differs.

```bash
cirvix check --cwd /explicit/workspace --action fs.read --resource ../outside
```

The decision's `resource` field is the canonical form actually matched.

### A `when` condition never fires

**An unknown operator fails closed** — the condition does not match, so a typo
silently narrows the rule instead of widening it. Valid operators are `eq`,
`ne`, `in`, `nin`, `gt`, `gte`, `lt`, `lte`, `matches`, `exists`, `contains`,
`supersetOf`.

`parseRules` rejects an unknown operator at load time; `cirvix policy` will tell
you.

Also confirm the path exists in the context — see
[the context table](./policy.md#the-evaluation-context). `cirvix check` sets
`egress.*` and `session.touchedSecret` to `false` and cannot exercise them; use
`evaluate()` from the testing subpath for those.

## Gateway

### The agent reports a protocol error

Something wrote to stdout. The agent owns stdout on the stdio transport, and one
stray `console.log` corrupts the JSON-RPC stream. Every gateway diagnostic goes
to stderr.

If you have added an `onDecision` handler, make sure it does not print.

### The gateway exits immediately with code 2

No upstream servers were configured.

```
  No upstream MCP servers configured. Pass --servers <file>.
```

`--servers` accepts `mcpServers` (Claude Code, Cursor, Windsurf) or `servers`
(VS Code). Only **stdio** entries are loaded — an entry without a `command` is
skipped, as is any entry named `cirvix` (pointing the gateway at a governed
config would make it proxy itself).

### A tool disappeared from `tools/list`

Either its upstream server died — one upstream failing does not take down the
session, its tools simply disappear and calls to it return a clean error — or
its **definition changed and is being withheld**.

A tool's description is instruction text that enters the model's context with
the authority of a system message, and it comes from the server, not from you.
The gateway hashes each definition on first sight and withholds a changed one
until it is re-approved. Check the gateway's stderr.

### Decisions are not reaching the control plane

Without `--api` and `--key` the gateway enforces locally and writes only to
`.cirvix/audit.jsonl`. That is a valid mode, not a failure.

With them, decisions spool to the state directory and ship on the daemon's
interval. A short-lived session flushes on shutdown — but only on a clean one.
`SIGKILL` leaves the spool for the next daemon start in that state directory.

## Control plane

### `/v1/secrets` returns 503, or the routes 404

`CIRVIX_MASTER_KEY` is not set. Secret brokering is optional; without the key
the routes are not registered at all. The boot log says which mode you are in:

```
[cirvix] secret broker disabled — set CIRVIX_MASTER_KEY to enable /v1/secrets
```

### The process refuses to start

```
CIRVIX_JWT_SECRET must be set to at least 32 characters.
Refusing to start with a weak or default signing key.
```

Deliberate. A weak or defaulted signing key lets anyone mint a session.

```bash
openssl rand -hex 32
```

### 403 on a request that should work

The body names the role required:

```json
{ "error": "Role \"member\" cannot policy:write.", "required": "admin" }
```

Check the [permission table](./api.md#roles-and-permissions). Common surprises:
`policy:write` is admin (drafting is member), `sso:manage` and `policy:settings`
are **owner**, and `approval:decide` is admin.

### 403 when granting a role

**A role can only be granted by someone who holds it.** An admin cannot mint an
owner-scoped API key, promote someone to owner, or invite an owner. That ceiling
is what stops `member:manage` being privilege escalation with one extra step.

### Everyone was signed out at once

Either `CIRVIX_JWT_SECRET` was rotated, or a refresh token was replayed.

```json
{ "error": "Session expired. Sign in again.", "reuseDetected": true }
```

`reuseDetected: true` means an already-rotated refresh token was presented
again. That is either the client racing itself or a stolen token, and they
cannot be told apart — so the whole session family is revoked on the assumption
of theft. Signing in again is the correct response. Repeated occurrences for one
user are worth investigating.

### A user still has access after offboarding

If you removed the membership directly, an access token remains valid for up to
15 minutes and a refresh token for 30 days. Use SCIM `active: false` or the
member-delete endpoint — both **revoke sessions**, not just membership.

### SCIM returns 401

The token must be the `scim_…` one created in **Settings → Directory
provisioning**. A console API key cannot authenticate `/scim/v2`, by design and
enforced by a test: a SCIM principal carries no role, so the permission check
could never be satisfied by one.

### SCIM returns 409 removing a user

The directory cannot remove the last owner. Refused deliberately, so a directory
misconfiguration cannot lock an organisation out of itself. Promote another
owner in the console first.

### A publish is refused with 409

Either the draft was **edited after approval** — approvals are bound to a
content hash, so editing un-approves — or a reviewer submitted
`changes_requested`, which blocks publication regardless of how many approvals
follow.

### An outbound webhook or SSO issuer will not save

The destination resolves to a private, loopback, or link-local address, and the
egress guard refuses it. For a self-hosted deployment pointing at an internal
Slack-compatible endpoint or IdP, set `CIRVIX_ALLOW_PRIVATE_EGRESS=1`.

Understand what you are turning off first — see
[private egress](./deployment.md#private-egress).

### 429 with `retryInSeconds`

Rate limited. Defaults: 600/min per credential, **10/min per IP** on login, SSO,
and invitation endpoints. A refused request still counts, so a hot retry loop
will not recover — back off.

## Console

### "Could not reach the control plane", but `curl` works

CSP. `NEXT_PUBLIC_CIRVIX_API` is inlined at build time **and compiled into the
`connect-src` directive**. Changing it requires a rebuild, and the origin must
match exactly — scheme, host, and port.

### It loads, then returns to sign-in immediately

The refresh token was rejected. See "everyone was signed out" above.

### The live indicator says "reconnecting" forever

Your proxy is buffering or timing out SSE.

```nginx
proxy_buffering off;
proxy_read_timeout 3600s;
```

The default 60-second read timeout silently kills the stream, and the console
appears connected while showing nothing new.

### Cross-origin requests are blocked

`CIRVIX_CORS_ORIGIN` must be the console's **exact** origin. There is no
wildcard mode.

## CI

### The scan step fails but I want the report

Set `fail-on: never` on the first run against an existing repository. The point
of a first run is to see the baseline, not to block a merge on it.

SARIF is written **before** the exit-code gate and uploaded with `always()`, so
a failing scan still produces the artifact — findings that only appear when the
build passes are findings nobody acts on.

### SARIF uploads but nothing appears in the Security tab

The job needs `security-events: write`. The upload step is
`continue-on-error`, so a permissions problem shows as a warning rather than
failing the job.

### Dismissed findings keep coming back

They should not — fingerprints are stable across runs specifically so
dismissals stick. If they do reappear, the finding's file path changed.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, or a permitted/held decision |
| `1` | A substantive negative: findings over the gate, a deny, a broken chain, a changed replay |
| `2` | Usage error, or an unhandled exception |

`1` and `2` are distinct so CI can tell "the tool worked and the answer was no"
from "the tool did not run".

## Still stuck

- `cirvix <command> --json` on anything gives the full record rather than the
  rendered summary.
- `cirvix why <decision-id>` explains one decision completely, including every
  rule considered.
- The engine is deterministic and pure. If a decision surprises you,
  `cirvix check` with the same action, resource, `--env` and `--cwd` will
  reproduce it exactly.
