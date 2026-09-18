# Quickstart

Node 20+ is required. This guide distinguishes hypothetical policy evaluation, in-process enforcement, and MCP routing. Package installation may use the network; no hosted Cirvix account is needed for local evaluation.

## 1. Install and ask a policy question

```bash
npm install @cirvix_ai/agent-control
npx cirvix check --action fs.read --resource .env.production
npx cirvix check --action fs.read --resource src/index.mjs
```

With starter rules, expect deny (`1`) and permit (`0`) respectively. Existing workspace policies take precedence. `check` reads no target file, executes no tool, and writes no audit decision. A hold also exits `0`; do not treat that status as permission to execute.

Optional `npx cirvix scan` inspects known runtime configurations and credential-path accessibility, including home locations. Skip it when such inspection is unauthorized. It is heuristic inventory, not proof that a running agent is governed. `--sarif` writes a report.

## 2. Write a policy

Create `cirvix.policy.json`:

```json
{
  "rules": [
    {
      "name": "deny-dotenv-read",
      "effect": "forbid",
      "actions": ["fs.read"],
      "resources": ["**/.env", "**/.env.*"]
    },
    {
      "name": "hold-deploys",
      "effect": "hold",
      "actions": ["k8s.apply"],
      "resources": ["**"],
      "when": [{ "path": "environment", "op": "eq", "value": "production" }],
      "approvers": ["platform-oncall"]
    },
    {
      "name": "allow-workspace-read",
      "effect": "permit",
      "actions": ["fs.read", "fs.list"],
      "resources": ["**"],
      "when": [{ "path": "path.insideWorkspace", "op": "eq", "value": true }]
    }
  ]
}
```

```bash
npx cirvix policy check --policy cirvix.policy.json
npx cirvix check --policy cirvix.policy.json --action k8s.apply --resource production/checkout --env production
```

Expect `hold-deploys` to hold the production deployment. Nothing is deployed. Standalone `*` and `**` are both universal special cases in the evaluator. Within a larger pattern, `*` stays in a segment while `**` spans separators. Forbid outranks hold, hold outranks permit, and no match means deny.

## 3. Enforce calls in Node

Save as `quickstart.mjs` beside the policy and run `node quickstart.mjs`:

```js
import { mkdir, readFile } from "node:fs/promises";
import { AuditChain, guard, parseRules, CirvixDenied } from "@cirvix_ai/agent-control";

const rules = parseRules(JSON.parse(await readFile("cirvix.policy.json", "utf8")));
await mkdir(".cirvix", { recursive: true });
const audit = await new AuditChain(".cirvix/audit.jsonl").open();
const tools = guard.wrap(
  { read_file: async ({ path }) => `Fixture read: ${path}` },
  { agent: "pr-triage", rules, audit },
);

console.log(await tools.read_file({ path: "src/index.mjs" }));
try {
  await tools.read_file({ path: ".env.production" });
} catch (err) {
  if (!(err instanceof CirvixDenied)) throw err;
  console.log(err.policy, err.decisionId);
}
await audit.flush();
```

The tool is an in-memory fixture: no credential or source file is read. The wrapper invokes it for the permitted path and refuses the dotenv call. The explicit audit sink records both decisions. When using a framework, construct its executor with these **returned** tools; calling an existing executor still holding originals does not enforce anything.

## 4. Python alternative

```bash
pip install cirvix
```

```python
import json
from cirvix import guard, parse_rules, CirvixDenied

with open("cirvix.policy.json", encoding="utf-8") as fh:
    rules = parse_rules(json.load(fh))

def read_file(path):
    return f"Fixture read: {path}"

tools = guard.wrap({"read_file": read_file}, agent="pr-triage", rules=rules)
print(tools["read_file"](path="src/index.mjs"))
try:
    tools["read_file"](path=".env.production")
except CirvixDenied as err:
    print(err.policy, err.decision_id)
```

Python does not write the Node audit chain or broker handles. Configure `on_decision` for a record sink, or route relevant MCP calls through the Node gateway. Framework executors must use returned wrappers in Python too.

## 5. MCP alternative

Keep upstream definitions in a separate `mcp-upstreams.json`. Do not replace a client config and then point the gateway back at that same gateway-only file. Remove direct upstream entries from the client so there is no alternate ungoverned route.

After installing the CLI globally, a gateway-only client map can use:

```json
{
  "mcpServers": {
    "cirvix": {
      "command": "cirvix",
      "args": ["gateway", "--servers", "/absolute/path/to/mcp-upstreams.json", "--policy", "/absolute/path/to/cirvix.policy.json", "--cwd", "/absolute/path/to/workspace"]
    }
  }
}
```

Replace all paths with actual absolute paths. Upstreams must be configured separately using their documented stdio or HTTP settings. A global CLI install is required for this `command`; a project-local install alone is not generally on an editor's PATH. Starting the gateway is not enough: verify your client's actual routed calls and audit records. Built-in editor tools and non-MCP subprocess traffic remain outside this boundary.

## 6. Inspect evidence

After the Node example or routed gateway calls:

```bash
npx cirvix audit verify --file .cirvix/audit.jsonl
npx cirvix logs
```

Check that the expected decision IDs and a nonzero record count are present. An empty/missing/unreadable file can verify as an empty chain. Chain consistency does not prove successful execution or detect tail deletion/recomputed history without a trusted external checkpoint. Python and `check` alone do not populate this file.

## 7. Test a policy without a framework

Save as `policy.test.mjs` beside the policy:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "@cirvix_ai/agent-control/testing";

test("production deploys are held", async () => {
  const decision = await evaluate({
    policyFile: "cirvix.policy.json",
    action: "k8s.apply",
    resource: "production/checkout",
    context: { environment: "production" },
  });
  assert.equal(decision.verdict, "hold");
});
```

```bash
node --test policy.test.mjs
```

For CI in this repository, the scan action source is `packages/agent-control/action/action.yml`; use it as a local action after checkout. It invokes `npx`, writes reports and may upload SARIF/comment when enabled, so it is not an offline/no-write check. `permissions` belongs at job/workflow scope, not inside an action step. External action publication is not verified by this checkout.

## Next steps and limits

- [Policy reference](./policy.md), [Node SDK](./sdk-node.md), [Python SDK](./sdk-python.md).
- [Deployment](./deployment.md) for local launch and feature wiring; [Operations](./operations.md) for recovery limitations.
- Local approvals need an explicitly wired store and a retry; reviewer names are not authenticated human signatures.
- No hosted control plane, SaaS/frontend/auth/billing/tenant service or enterprise deployment is established here. Remote clients require a separately supplied API.
