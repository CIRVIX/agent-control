# Node SDK

```bash
npm install @cirvix_ai/agent-control
```

Zero runtime dependencies. Node 20 or later. ESM only.

## What `wrap` is for

The [gateway](./cli.md#cirvix-gateway) governs everything an agent does,
including tools added after you deployed it, because it sits on the wire. It
also requires the agent to speak MCP.

`guard.wrap` is for the case where it does not: a LangChain executor, a hand-
rolled loop over some functions. **You give up the "governs tools you did not
know about" property** — you are wrapping a list — and you keep every other one:
same engine, same rules, same decision record, same secret brokering, same audit
chain.

That trade is stated here rather than glossed, because an operator who believes
`wrap` is equivalent to the gateway will not understand why a tool the agent
reached directly was never evaluated.

## Quick start

```js
import { guard, CirvixDenied, CirvixHeld, STARTER_RULES } from "@cirvix_ai/agent-control";

const tools = guard.wrap(myTools, {
  agent: "pr-triage",
  environment: process.env.CIRVIX_ENV ?? "local",
  rules: STARTER_RULES,
});

try {
  await agent.invoke(input);
} catch (err) {
  if (err instanceof CirvixHeld) {
    console.log(err.approvers);   // ["platform-oncall"] — a person can release this
  } else if (err instanceof CirvixDenied) {
    console.log(err.policy);      // "deny-dotenv-read"
    console.log(err.remediation); // 'secrets.get("STRIPE_KEY")'
    console.log(err.decisionId);  // pass to `cirvix why`
  }
  throw err;
}
```

> **`rules` is the option, not `policyDir`.** `wrap` forwards its options
> straight to the `Guard` constructor, which takes an in-memory rule array. To
> load from disk, use `loadPolicy` from the testing subpath, or `parseRules` on
> your own `JSON.parse`. Passing an unrecognised option leaves `rules` empty,
> and an empty rule set denies everything.

Loading a rule set from a file:

```js
import { readFile } from "node:fs/promises";
import { guard, parseRules } from "@cirvix_ai/agent-control";

const rules = parseRules(JSON.parse(await readFile("cirvix.policy.json", "utf8")));
const tools = guard.wrap(myTools, { agent: "pr-triage", rules });
```

## Shapes `wrap` accepts

It returns the same shape it was given, so this is a one-line change at the
executor boundary rather than a rewrite of how tools are registered.

| Input | Behaviour |
|---|---|
| `{ name: fn }` | Each function replaced; non-functions passed through |
| `[toolObject, …]` | Each tool **shallow-copied** with its callable replaced |
| `fn` | Wrapped; name from `options.name` or `fn.name` |

For tool objects, the first of `func`, `invoke`, `call`, `execute`, `handler`,
`_call`, `run` that is a function is the one wrapped. LangChain, CrewAI and
AutoGen all land here.

Everything else on the tool — descriptions, schemas, framework metadata — is
preserved by reference, because a framework that reads `tool.schema` after
wrapping must still find it. The copy is deliberate: mutating the originals
would govern the caller's array as a side effect of reading ours.

`fn.name` is preserved on the wrapper. Frameworks introspect it to build their
tool registry, and an anonymous arrow would silently rename every governed tool.

## `Guard`

```js
import { Guard } from "@cirvix_ai/agent-control";

const g = new Guard({
  rules,                      // rule array. Default [] — which denies everything
  agent: "pr-triage",         // default "local"
  environment: "production",  // default "local"
  cwd: process.cwd(),
  audit: chain,               // an AuditChain, optional
  secrets: secretsClient,     // a SecretsClient, optional
  onDecision: (record) => {}, // called with every decision and leak
  log: (message) => {},
  runId: "run_…",             // stamped on every record
});
```

### `authorize({ tool, server?, args? })`

Decides one call and brokers any secret handles it carries.

```js
const { decision, record, args } = await g.authorize({ tool: "read_file", args: { path: ".env" } });
if (decision.verdict !== "permit") throw g.toError(decision);
const result = await realTool(args);   // note: `args`, not the originals
```

Returns the arguments **to forward**, which are not necessarily the ones passed
in — handles are substituted here and nowhere else. If the broker refuses,
the permit becomes a deny carrying `rule: "secret-broker"` rather than emitting
a second decision, so one call always produces exactly one decision.

### `scrub(payload)`

Scans a tool result for material this session resolved and puts the handles
back. Returns `{ payload, findings }` and increments `stats.leaks`.

### `toError(decision)`

Returns `CirvixHeld` for a hold, `CirvixDenied` otherwise.

### `stats`

`{ calls, permitted, denied, held, leaks, latencyTotal }`. Latency is measured
around the decision itself, not the tool round trip — the latter is orders of
magnitude larger and would flatter the number dishonestly.

## Errors

```js
class CirvixDenied extends Error {
  policy      // string | null   — the rule that decided it
  decisionId  // string | null   — hand to `cirvix why`
  reason      // string | null
  remediation // string | null   — frequently names the legitimate path
  appealable  // boolean
  resource    // string | null
  action      // string | null
}

class CirvixHeld extends CirvixDenied {
  approvers   // string[]
  approvalId  // string | null
  appealable  // always true
}
```

They are distinct types because they call for different behaviour: a denial
means re-plan, a hold means this exact call may still happen once somebody says
yes. Collapsing them teaches agents to treat both as failure.

## Testing a policy

Rules are code. Test them in CI next to everything else.

```js
import { evaluate } from "@cirvix_ai/agent-control/testing";

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

`evaluate` accepts exactly one rule source: `rules` (inline array), `policy` or
`policyFile` (one file), or `policyDir` (every `.json`/`.policy` in a
directory, sorted, with duplicate rule names rejected). With none, the starter
rules are used.

The **default context is permissive** on purpose — inside the workspace, no
external egress, no secret touched. A test asserting something is denied should
be denied by the rule it is testing, not by a restrictive default that would
have denied anything.

### `expectNoLoosening`

The pull-request counterpart to `cirvix replay`, for a policy diff where there
is no recorded run to replay against.

```js
import { expectNoLoosening } from "@cirvix_ai/agent-control/testing";

const { ok, loosened } = await expectNoLoosening({
  before: { policyFile: "policies/main.json" },
  after:  { policyFile: "policies/candidate.json" },
  calls: [
    { action: "fs.read", resource: ".env.production" },
    { action: "k8s.apply", resource: "production/api", context: { environment: "production" } },
  ],
});

expect(ok).toBe(true);
```

Only widening counts. A change that denies more is the direction a security
policy is allowed to move without a reviewer being surprised.

## Secret handles

```js
import { SecretsClient } from "@cirvix_ai/agent-control/secrets";

const secrets = new SecretsClient({
  apiUrl: process.env.CIRVIX_API_URL,
  apiKey: process.env.CIRVIX_API_KEY,   // cvx_…
  agent: "billing-bot",
});

const handle = await secrets.get("STRIPE_RESTRICTED_KEY");
// "sec_handle_9f2c…" — opaque, and useless anywhere the secret does not sanction
```

`SecretsClient` is a class, not a module-level singleton. Pass it to a `Guard`
as `secrets` and substitution happens automatically inside `authorize`.

| Method | Does |
|---|---|
| `get(name, { ttlSeconds?, maxUses? })` | Asks the control plane for a handle |
| `substitute(args, { destination })` | Replaces every handle with its material. **Fails closed** |
| `redact(payload)` | Finds resolved material on the return path and puts handles back |
| `forget()` | Drops every value this session resolved |

Substitution is all-or-nothing. If any handle in the payload cannot be resolved
for this destination, nothing is substituted and the caller must refuse the
call — partial substitution would send a real credential alongside a literal
handle, which is the worst of both.

Helpers: `isHandle(value)`, `findHandles(value)`, `HANDLE_PREFIX`.

## Everything exported

From the package root:

| Export | From |
|---|---|
| `evaluate`, `matchGlob`, `parseRules`, `STARTER_RULES`, `EFFECT`, `VERDICT` | policy engine |
| `guard`, `wrap`, `Guard`, `CirvixDenied`, `CirvixHeld` | decision core |
| `actionForTool`, `resourceForCall`, `destinationFor` | call mapping |
| `Gateway`, `fingerprintTool` | MCP gateway |
| `Daemon` | endpoint service |
| `AuditChain` | tamper-evident log |
| `SecretsClient`, `HANDLE_PREFIX`, `findHandles`, `isHandle` | secret brokering |
| `scan` | machine inventory |

Subpath exports, for importing one thing without the rest:

`@cirvix_ai/agent-control/policy` · `/guard` · `/gateway` · `/daemon` · `/audit` ·
`/secrets` · `/testing`

## Parity with Python

Both engines run the same 44-case
[conformance fixture](../packages/conformance/policy-conformance.json). Two
differences are real and intentional:

| | Node | Python |
|---|---|---|
| Secret brokering in `Guard` | yes (`secrets`) | no |
| Audit chain in `Guard` | yes (`audit`) | no |

A Python agent that needs brokering routes through the gateway. See
[Python SDK](./sdk-python.md#what-wrap-does-not-do).
