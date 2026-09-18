# Generic local agent

For a hand-rolled loop, LangChain executor, or another local agent that does
not speak MCP, use `guard.wrap`. It governs the tools you pass to it; direct
calls outside the wrapped object are outside this integration's coverage.

## Install → init → connect

```bash
npm install @cirvix_ai/agent-control
npx cirvix init
```

```js
import { guard, STARTER_RULES, CirvixDenied } from "@cirvix_ai/agent-control";

const tools = guard.wrap(myTools, { agent: "local-agent", rules: STARTER_RULES });
try {
  await tools.read_file({ path: ".env.production" });
} catch (error) {
  if (error instanceof CirvixDenied) console.log(error.policy, error.remediation, error.decisionId);
  throw error;
}
```

## Policy → test → verify

Load a checked-in policy with `parseRules`, run its declared cases with
`cirvix policy test`, then exercise one allowed and one denied call. Verify the
local chain only if an `AuditChain` was explicitly supplied to the wrapper (this short snippet does not supply one). See [Quickstart](../quickstart.md) for a self-contained audited example. Python has no CLI or built-in audit sink; install with `pip install cirvix`, use returned wrappers and configure `on_decision` separately.
