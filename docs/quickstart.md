# Quickstart

Five minutes, no account, nothing sent anywhere. By the end you will have seen a
real tool call refused by a real rule.

Requires Node 20 or later.

## 1. See what is ungoverned

```bash
npx @cirvix_ai/agent-control scan
```

Read-only. Nothing is changed and nothing leaves the machine.

```
  Cirvix scan · read-only · nothing was changed or sent

  runtimes            1 found
    Claude Code       ~\.claude\settings.json
                      ungoverned · 3 MCP servers

  credentials         2 paths reachable from agent context
    AWS credentials   On disk and readable by any agent with filesystem access
    Docker registry auth

  findings            2 high · 1 medium

    ▲ Claude Code (runtime-ungoverned)
      Tool calls from Claude Code are not routed through a control plane.
      Anything it can reach, it can reach unchecked.
      fix: cirvix gateway --servers ~/.claude/settings.json
```

This is the baseline. It is the answer to "what could an agent on this laptop
reach right now", and for most machines the answer is uncomfortable.

## 2. Ask whether a call would be allowed

```bash
npx @cirvix_ai/agent-control check --action fs.read --resource .env.production
```

```
  DENY  fs.read /work/app/.env.production
  rule    deny-dotenv-read
  reason  Reading .env files is denied outside an approved secrets flow. This is
          the single most common path from a prompt injection to a live credential.
  fix     Request the value as a handle: secrets.get("STRIPE_KEY")

  considered
    → forbid  deny-dotenv-read
```

Exit code `1` — a deny. Nothing was executed; this is the engine answering a
hypothetical.

Try one that passes:

```bash
npx @cirvix_ai/agent-control check --action fs.read --resource src/index.ts
```

```
  PERMIT  fs.read /work/app/src/index.ts
  rule    allow-workspace-read
```

You are running against the [nine starter rules](./policy.md#the-starter-rule-set).
See them:

```bash
npx @cirvix_ai/agent-control policy
```

## 3. Write your own rules

Rules are JSON. Create `cirvix.policy.json`:

```json
{
  "rules": [
    {
      "name": "deny-prod-database",
      "effect": "forbid",
      "actions": ["db.*", "shell.exec"],
      "resources": ["**/prod*", "postgres://prod*"],
      "reason": "Production database access does not go through an agent.",
      "remediation": "Use the staging replica, or open a change request."
    },
    {
      "name": "hold-deploys",
      "effect": "hold",
      "actions": ["k8s.apply", "fs.delete"],
      "resources": ["*"],
      "when": [{ "path": "environment", "op": "eq", "value": "production" }],
      "approvers": ["platform-oncall"],
      "reason": "Production changes wait for a named human."
    },
    {
      "name": "allow-workspace-read",
      "effect": "permit",
      "actions": ["fs.read", "fs.list"],
      "resources": ["*"],
      "when": [{ "path": "path.insideWorkspace", "op": "eq", "value": true }]
    }
  ]
}
```

Check it:

```bash
npx @cirvix_ai/agent-control check --policy cirvix.policy.json \
  --action k8s.apply --resource production/checkout --env production
```

```
  HOLD  k8s.apply production/checkout
  rule    hold-deploys
  reason  Production changes wait for a named human.
  waits   platform-oncall
```

Three things are worth noticing:

- **The rule set is default-deny.** Anything not permitted is refused, so the
  third rule is what keeps ordinary work moving.
- **`forbid` beats `permit` regardless of order.** You can add permissive rules
  without re-reading every guardrail first.
- **`hold` outranks `permit`.** If any rule says a person must see this, no
  other rule quietly skips them.

## 4. Enforce it — pick your integration

### An MCP client (Claude Code, Cursor, Windsurf, VS Code)

Put Cirvix between the agent and its servers. Point it at the config you already
have:

```bash
npx @cirvix_ai/agent-control gateway \
  --servers ~/.cursor/mcp.json \
  --policy cirvix.policy.json
```

Then register the gateway itself as the one MCP server your client talks to:

```json
{
  "mcpServers": {
    "cirvix": {
      "command": "npx",
      "args": ["-y", "@cirvix_ai/agent-control", "gateway",
               "--servers", "/absolute/path/to/mcp.json",
               "--policy", "/absolute/path/to/cirvix.policy.json"]
    }
  }
}
```

Every `tools/call` is now evaluated before it is forwarded, and decisions land
in `.cirvix/audit.jsonl`.

### A Node agent (LangChain, or your own loop)

```js
import { readFile } from "node:fs/promises";
import { guard, parseRules, CirvixDenied } from "@cirvix_ai/agent-control";

const rules = parseRules(JSON.parse(await readFile("cirvix.policy.json", "utf8")));
const tools = guard.wrap(myTools, { agent: "pr-triage", rules });

try {
  await executor.invoke(input);
} catch (err) {
  if (err instanceof CirvixDenied) console.log(err.policy, err.remediation);
  throw err;
}
```

### A Python agent (CrewAI, LangChain)

```python
import json
from cirvix import guard, parse_rules, CirvixDenied

with open("cirvix.policy.json", encoding="utf-8") as fh:
    rules = parse_rules(json.load(fh))

tools = guard.wrap(my_tools, agent="support-triage", rules=rules)

try:
    crew.kickoff()
except CirvixDenied as err:
    print(err.policy, err.remediation)
    raise
```

> `wrap` governs the tools you hand it. A tool the agent reaches directly is
> never evaluated — that is the property the gateway has and `wrap` does not.

## 5. Verify the record

```bash
npx @cirvix_ai/agent-control audit verify
```

```
  chain intact  412 records verified

  Verification proves records were not altered after they were written.
  It does not attest to their content.
```

## 6. Gate CI

```yaml
- uses: cirvix/scan@v1
  with:
    fail-on: never          # first run: see the baseline, do not block
    upload-sarif: true
  permissions:
    security-events: write
```

Findings appear on the pull-request diff and in the Security tab. Switch
`fail-on` to `high` once the baseline is clean.

Test your rules like code:

```js
import { evaluate } from "@cirvix_ai/agent-control/testing";

test("production deploys are held", async () => {
  const d = await evaluate({
    policyFile: "cirvix.policy.json",
    action: "k8s.apply",
    resource: "production/checkout",
    context: { environment: "production" },
  });
  expect(d.verdict).toBe("hold");
});
```

## Where to go next

| | |
|---|---|
| Write real rules | [Policy reference](./policy.md) |
| Understand the decision path | [Architecture](./architecture.md) |
| Run a control plane | [Deployment](./deployment.md) |
| Stop agents holding raw credentials | [Secret brokering](./administration.md#secret-brokering) |
| Everything the CLI does | [CLI reference](./cli.md) |

## What you have not set up yet

Everything above runs with no server. A control plane adds: central policy
distribution, fleet inventory, the approval queue that releases a `hold`,
`cirvix why` and `cirvix replay`, secret brokering, SSO/SCIM, alerting, and
compliance evidence. See [Deployment](./deployment.md).
