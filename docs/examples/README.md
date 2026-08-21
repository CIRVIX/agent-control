# Examples

Working code. Every file here runs against the packages in this repository.

| File | Shows |
|---|---|
| [`cirvix.policy.json`](./cirvix.policy.json) | A realistic rule set with all three effects and several condition operators |
| [`policy.test.mjs`](./policy.test.mjs) | Testing a rule set like code, and gating a policy change |
| [`node-wrap.mjs`](./node-wrap.mjs) | Governing a Node agent's tools with `guard.wrap` |
| [`python_wrap.py`](./python_wrap.py) | The same, in Python |
| [`mcp-gateway.json`](./mcp-gateway.json) | Putting the gateway between an MCP client and its servers |
| [`github-actions.yml`](./github-actions.yml) | Scanning in CI, and gating on a policy diff |

## Run them

From the repository root:

```bash
# Evaluate a call against the example policy
node packages/agent-control/bin/cirvix.mjs check \
  --policy docs/examples/cirvix.policy.json \
  --action fs.read --resource .env.production

# Run the policy tests
node --test docs/examples/policy.test.mjs

# Govern a Node agent
node docs/examples/node-wrap.mjs

# Govern a Python agent
python docs/examples/python_wrap.py
```

The two `wrap` examples print the same six lines in both languages, which is the
point: one engine, two implementations, held together by
[the conformance fixture](../../packages/conformance/policy-conformance.json).
