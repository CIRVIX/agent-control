# @cirvix/agent-control

Runtime governance for AI agents. Scan what is ungoverned, evaluate tool calls
against policy, and keep a tamper-evident record of every decision.

**Zero runtime dependencies.** A security tool that drags in a transitive
dependency tree is asking to become the supply-chain incident it exists to
prevent.

## Install in 30 seconds

No account, no signup, no config file, no daemon to leave running.

```bash
npx @cirvix/agent-control scan
```

That reads your machine and tells you which agent runtimes are ungoverned. It
writes nothing and sends nothing anywhere. Then decide one call:

```bash
npx @cirvix/agent-control check --action fs.read --resource .env.production
```

```
  DENY  fs.read .env.production
  rule    deny-dotenv-read
  reason  Reading .env files is denied outside an approved secrets flow. This is
          the single most common path from a prompt injection to a live credential.
  fix     Request the value as a handle: secrets.get("STRIPE_KEY")
```

To govern an agent rather than a single call, wrap its tools — the call cannot
leave without being decided, so there is no verdict to forget to check:

```bash
npm install @cirvix/agent-control
```

```js
import { guard, CirvixDenied, STARTER_RULES } from "@cirvix/agent-control";

const tools = guard.wrap(myTools, { agent: "pr-triage", rules: STARTER_RULES });

try {
  await agent.invoke(input);
} catch (err) {
  if (err instanceof CirvixDenied) {
    console.log(err.policy, err.remediation, err.decisionId);
  }
  throw err;
}
```

Requires Node 20 or later. There is a second implementation of the same engine
for Python — `pip install cirvix` — and the two are held to a shared
conformance fixture that both must pass.

**Full documentation:** [`docs/`](https://www.cirvix.com/docs.html) — [CLI reference](https://www.cirvix.com/docs.html), [Node SDK](https://www.cirvix.com/sdks.html), [policy reference](https://www.cirvix.com/policy-engine.html).

## Licence

Apache-2.0. The local enforcement engine is open source and ships with the
Apache-2.0 licence and attribution notice in this package. The hosted Cirvix
control plane is a separate product and is not included here.

## `cirvix scan`

Read-only inventory of this machine. No account, no network, nothing written.

Finds the agent runtimes you have installed (Claude Code, Cursor, Windsurf,
Cline, VS Code MCP), the frameworks declared in the current project, every MCP
server configured across all of them, and the credential files an agent with
filesystem access could read.

```
  runtimes            2 found
    Claude Code       ~/.claude/settings.json
                      ungoverned · 6 MCP servers
    Cursor            ~/.cursor/mcp.json
                      ungoverned · 4 MCP servers

  mcp servers         7 configured
    filesystem-mcp    stdio   broad scope
    github-mcp        stdio   inline secrets · ×2 runtimes

  credentials         3 paths reachable from agent context
    AWS credentials   On disk and readable by any agent with filesystem access
    .env.production   4 secret-shaped keys: STRIPE_KEY, DATABASE_URL…

  findings            4 high · 3 medium · 1 low
```

**It never prints a secret value.** Key *names* only — reporting a leak by
leaking it would be absurd.

| Flag | Effect |
|---|---|
| `--json` | Machine-readable output |
| `--deep` | Include MCP command lines |
| `--fail-on <high\|medium\|low>` | Exit non-zero at that severity — for CI |
| `--cwd <dir>` | Workspace root |

## `cirvix check`

Evaluate a single tool call against the policy set. Every decision names the
rule that produced it.

```bash
$ cirvix check --action fs.read --resource .env.production

  DENY  fs.read  /repo/.env.production
  rule    deny-dotenv-read
  reason  Reading .env files is denied outside an approved secrets flow.
  fix     Request the value as a handle: secrets.get("STRIPE_KEY")
```

Exit code is `1` on deny, `0` otherwise — so it works as a gate in CI.

## The policy engine

An ordered rule set with three effects: `permit`, `forbid`, `hold`. Three
properties are guaranteed and covered by tests:

1. **`forbid` always wins.** No `permit` can override it, at any position.
   This is what makes a rule set safe to extend — adding a permissive rule can
   never silently punch a hole through an existing prohibition.
2. **Default deny.** A request matching nothing is denied. Fail-open is how a
   control plane becomes decorative the first time a rule file fails to parse.
3. **Resources are canonicalized before matching.** `./x/../.env`, `.env`, and
   the absolute path are one resource. Rules matching raw strings are bypassed
   by the first traversal attempt.

Conditions are **plain data, never expressions** — no `eval`, no
`new Function`. A policy file is exactly the kind of thing that gets templated
by a script, and making it an execution surface would turn the security
product into the vulnerability.

```json
{
  "name": "require-approval-prod-deploy",
  "effect": "hold",
  "actions": ["k8s.apply", "db.migrate"],
  "resources": ["*"],
  "when": [{ "path": "environment", "op": "in", "value": ["production"] }],
  "approvers": ["platform-oncall"]
}
```

Operators: `eq` `ne` `in` `nin` `gt` `gte` `lt` `lte` `matches` `exists`
`contains` `supersetOf`. An unknown operator fails closed.

## `guard.wrap()` — governing an agent that does not speak MCP

The gateway governs everything, including tools added after you deployed it,
because it sits on the wire. It also requires the agent to speak MCP. `wrap` is
for when it does not — a LangChain executor, a crew, a hand-rolled loop over
some functions:

```js
import { guard, CirvixDenied, CirvixHeld } from "@cirvix/agent-control";

const tools = guard.wrap(myTools, {
  agent: "pr-triage",
  environment: process.env.CIRVIX_ENV ?? "local",
  rules,                     // or load them with loadPolicy({ policyDir })
});

try {
  await agent.invoke(input);
} catch (err) {
  if (err instanceof CirvixDenied) {
    console.log(err.policy);      // "deny-dotenv-read"
    console.log(err.remediation); // 'secrets.get("STRIPE_KEY")'
    console.log(err.decisionId);  // pass to `cirvix why`
  }
  throw err;
}
```

**The trade, stated plainly.** You give up the property that makes the gateway
worth deploying — it governs tools nobody told it about — because you are
wrapping a list. You keep everything else: the same engine, the same rules, the
same decision record, the same secret brokering, the same audit chain. That is
not a slogan; `wrap` and the gateway call one `Guard`, so a rule cannot mean
one thing here and another there.

| It accepts | Example |
|---|---|
| An object of `name → function` | `{ read_file, run_query }` |
| An array of tool objects carrying a callable | LangChain, CrewAI, AutoGen |
| A single function | `guard.wrap(fn, { name: "read_file" })` |

Tool objects come back with their descriptions, schemas, and framework
metadata intact — and the array you passed in is left alone, so a framework
holding the originals does not find them governed by surprise.

**`CirvixDenied` vs `CirvixHeld`.** A denial means re-plan. A hold means this
exact call may still happen once a person says yes, and carries `approvers`.
They are separate types because collapsing them teaches an agent to treat both
as failure.

### Testing a policy like code

```js
import { evaluate, expectNoLoosening } from "@cirvix/agent-control/testing";

test("production writes are held for a human", async () => {
  const decision = await evaluate({
    policyDir: "./policies",
    agent: "deploy-bot",
    action: "k8s.apply",
    resource: "production/checkout",
    context: { environment: "production" },
  });

  expect(decision.verdict).toBe("hold");
  expect(decision.approvers).toContain("platform-oncall");
});
```

`expectNoLoosening({ before, after, calls })` is the pull-request counterpart:
it reports any call the change would newly permit. Tightening passes — a
security policy is allowed to move that way without surprising a reviewer.

### Claude Code, Cursor, and other MCP clients

Use the gateway, not `wrap`. They already speak MCP, and pointing them at
`cirvix gateway` governs every server they load — including ones added later:

```json
{ "mcpServers": { "cirvix": { "command": "cirvix", "args": ["gateway", "--servers", "~/.cursor/mcp.json"] } } }
```

### Python

```bash
pip install cirvix
```

```python
from cirvix import guard, CirvixDenied
tools = guard.wrap(my_tools, agent="pr-triage", rules=rules)
```

Same API, native evaluator — not an HTTP client, because a round trip in the
enforcement path would break the offline-first guarantee the daemon exists for.

Which raises the obvious risk: two engines that can silently disagree are worse
than one engine and an honest gap. What makes it safe is
`packages/conformance/policy-conformance.json` — 44 cases both engines must
answer identically, down to the canonical resource and the rule trace. Neither
language gets a private copy. See `packages/cirvix-python`.

## Secret handles

An agent never receives secret material. It receives an opaque handle, and the
real value is substituted into the outbound request at the gateway — after
policy has authorized that specific destination.

```js
import { SecretsClient } from "@cirvix/agent-control/secrets";

const secrets = new SecretsClient({ apiUrl, apiKey, agent: "pr-triage" });

const key = await secrets.get("STRIPE_RESTRICTED_KEY");
// "sec_handle_a89f…" — this is everything the model ever sees.
```

Attach it to the gateway and the rest is automatic:

```js
const gw = new Gateway({ servers, rules, secrets });
```

| | |
|---|---|
| On the way out | Handles in a permitted call's arguments are resolved and substituted |
| Off-path | A handle presented for an unsanctioned destination denies the call, rule `secret-broker` |
| No destination | A call carrying a handle but naming no http(s) endpoint is refused |
| Partially resolvable | If any handle fails, **nothing** is substituted — never a real credential beside a literal handle |
| On the way back | Results are scanned for material this session resolved, and it is swapped back to its handle |

**Substitution does not taint the session.** The `touchedSecret` flag that
blocks egress after a raw credential read is deliberately not set here: an
agent holding a handle never held the material, which is the entire point. The
alternative would deny the second call to the very API the handle was for.

**Leak detection covers material this session resolved, and nothing else.** A
credential Cirvix was never told about cannot be recognised on the return
path. This is a backstop, not a substitute for scoping what a handle reaches.

## The audit chain

Append-only JSONL where each record commits to the hash of its predecessor.

```bash
$ cirvix audit verify --file .cirvix/audit.jsonl

  chain intact  43,675 records verified
```

Alter or delete any record and verification reports **where** it broke:

```
  chain broken  at record 2 of 3
  Record 2 has been modified — its contents no longer match its hash.
```

**What this proves:** no record was altered or removed after it was written.
**What it does not prove:** that a record was written truthfully in the first
place — that comes from the enforcement path, not the log. It also does not
prevent destruction; someone with disk access can delete the file. The chain
guarantees doing so is *visible*.

Hashes are SHA-256 over a canonical JSON serialization with sorted keys, so
two semantically identical records hash identically.

## Tests

```bash
npm test
```

93 tests covering the three policy invariants, traversal bypass attempts, glob
safety under hostile patterns, condition safety, chain tamper detection,
gateway interception against a real child-process MCP server, handle
substitution on both the outbound and return paths, and the `guard.wrap`
surface.

## Status

Pre-release. `scan`, `check`, `policy`, `why`, `replay`, `audit verify`,
`gateway`, and `daemon` work today, as does secret brokering and `guard.wrap`
when a control plane is configured. Not yet built: a Python SDK, and the
hosted control plane — the one in `packages/control-plane` is self-hosted. See
[cirvix.com](https://www.cirvix.com).

## License

See LICENSE. Cirvix is a product of Umang Kumar, trading as Cirvix.
